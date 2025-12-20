"""Command Injection and RCE vulnerability scanner."""

import re
import requests
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

import logging
logger = logging.getLogger(__name__)


class CommandInjectionScanner(BaseScanner):
    """Scanner for Command Injection and Remote Code Execution vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize Command Injection scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="command_injection",
            command=None,  # No external command needed
            enabled=enabled,
            scan_mode=scan_mode
        )
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.timeout = 10
        
        # Command injection payloads (time-based and output-based)
        self.command_payloads = [
            # Time-based detection (sleep commands)
            ('; sleep 5', 'sleep'),
            ('| sleep 5', 'sleep'),
            ('& sleep 5', 'sleep'),
            ('`sleep 5`', 'sleep'),
            ('$(sleep 5)', 'sleep'),
            ('; ping -c 3 127.0.0.1', 'ping'),
            ('| ping -c 3 127.0.0.1', 'ping'),
            
            # Output-based detection (command output in response)
            ('; echo "COMMAND_INJECTION_TEST"', 'echo'),
            ('| echo "COMMAND_INJECTION_TEST"', 'echo'),
            ('& echo "COMMAND_INJECTION_TEST"', 'echo'),
            ('`echo "COMMAND_INJECTION_TEST"`', 'echo'),
            ('$(echo "COMMAND_INJECTION_TEST")', 'echo'),
            ('; whoami', 'whoami'),
            ('| whoami', 'whoami'),
            ('; id', 'id'),
            ('| id', 'id'),
            ('; uname -a', 'uname'),
            ('| uname -a', 'uname'),
            
            # Windows-specific
            ('; timeout /t 5', 'timeout'),
            ('| timeout /t 5', 'timeout'),
            ('& timeout /t 5', 'timeout'),
            ('; echo COMMAND_INJECTION_TEST', 'echo'),
            ('| echo COMMAND_INJECTION_TEST', 'echo'),
            
            # Code injection (PHP, Python, etc.)
            ('; php -r "echo 12345;"', 'php'),
            ('| php -r "echo 12345;"', 'php'),
            ('; python -c "print(12345)"', 'python'),
            ('| python -c "print(12345)"', 'python'),
            ('; perl -e "print 12345"', 'perl'),
            ('| perl -e "print 12345"', 'perl'),
        ]
    
    def is_available(self) -> bool:
        """Command injection scanner is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run command injection tests."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        # Test URL parameters
        findings.extend(self._test_url_parameters(target.url))
        
        # Test POST parameters if we can discover forms
        findings.extend(self._test_post_parameters(target.url))
        
        return findings
    
    def _test_url_parameters(self, url: str) -> List[Finding]:
        """Test URL parameters for command injection."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # ONLY test parameters that actually exist in the URL
            # Don't test generic parameter names - this causes false positives
            if params:
                # Test existing parameters
                for param in params.keys():
                    findings.extend(self._test_parameter(url, param, 'GET'))
            else:
                # If no parameters exist, don't test generic ones
                # This prevents false positives from testing non-existent parameters
                logger.debug(f"No parameters found in URL {url}, skipping command injection tests")
        except Exception as e:
            logger.debug(f"Error testing URL parameters: {e}")
        
        return findings
    
    def _test_post_parameters(self, url: str) -> List[Finding]:
        """Test POST parameters for command injection."""
        findings = []
        
        try:
            # Try to discover forms on the page
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                # Look for form inputs
                form_inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
                form_inputs.extend(re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', response.text, re.IGNORECASE))
                
                # Test discovered form inputs (ONLY real form inputs, not generic parameters)
                for input_name in form_inputs[:10]:  # Test up to 10 discovered inputs
                    findings.extend(self._test_parameter(url, input_name, 'POST'))
        except Exception as e:
            logger.debug(f"Error testing POST parameters: {e}")
        
        return findings
    
    def _test_parameter(self, url: str, param_name: str, method: str = 'GET') -> List[Finding]:
        """Test a specific parameter for command injection."""
        findings = []
        
        # Get baseline response time
        try:
            baseline_start = time.time()
            if method == 'GET':
                baseline_response = self.session.get(url, timeout=10)
            else:
                baseline_response = self.session.post(url, data={}, timeout=10)
            baseline_time = time.time() - baseline_start
            baseline_text = baseline_response.text
        except:
            return findings  # Can't test if baseline fails
        
        # Test each payload
        for payload, payload_type in self.command_payloads:
            try:
                test_start = time.time()
                
                if method == 'GET':
                    # Build URL with payload
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = [payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    
                    response = self.session.get(test_url, timeout=15)
                else:
                    # POST with payload
                    data = {param_name: payload}
                    response = self.session.post(url, data=data, timeout=15)
                
                test_time = time.time() - test_start
                response_text = response.text
                
                # Check for command injection indicators
                is_vulnerable = False
                exploitation_details = {}
                
                # Time-based detection (for sleep/ping payloads)
                # Make this more strict to avoid false positives
                if payload_type in ['sleep', 'ping', 'timeout']:
                    # Require significant delay (at least 4 seconds) AND response should be similar
                    # to avoid false positives from slow network/server load
                    time_difference = test_time - baseline_time
                    if time_difference >= 4.0 and time_difference < 30.0:  # Between 4-30 seconds
                        # Also check that response is similar (not an error page)
                        if response.status_code == baseline_response.status_code:
                            is_vulnerable = True
                            exploitation_details['detection_method'] = 'time-based'
                            exploitation_details['baseline_time'] = f"{baseline_time:.2f}s"
                            exploitation_details['test_time'] = f"{test_time:.2f}s"
                            exploitation_details['delay'] = f"{time_difference:.2f}s"
                
                # Output-based detection - be more strict
                elif payload_type in ['echo', 'whoami', 'id', 'uname']:
                    # Only report if the exact test marker is found (not just similar text)
                    if 'COMMAND_INJECTION_TEST' in response_text and 'COMMAND_INJECTION_TEST' not in baseline_text:
                        is_vulnerable = True
                        exploitation_details['detection_method'] = 'output-based'
                        exploitation_details['payload_output'] = 'Command output found in response'
                    elif payload_type == 'whoami':
                        # Check for command output patterns, but be more strict
                        # Look for actual command output patterns, not just the words
                        whoami_patterns = [r'root\s*:', r'admin\s*:', r'uid=\d+', r'gid=\d+']
                        found_pattern = False
                        for pattern in whoami_patterns:
                            if re.search(pattern, response_text, re.IGNORECASE):
                                # Make sure it's not in baseline
                                if not re.search(pattern, baseline_text, re.IGNORECASE):
                                    found_pattern = True
                                    break
                        if found_pattern:
                            is_vulnerable = True
                            exploitation_details['detection_method'] = 'output-based'
                            exploitation_details['payload_output'] = 'Command execution detected'
                
                # Code injection detection
                elif payload_type in ['php', 'python', 'perl']:
                    if '12345' in response_text and '12345' not in baseline_text:
                        is_vulnerable = True
                        exploitation_details['detection_method'] = 'code-injection'
                        exploitation_details['language'] = payload_type
                        exploitation_details['payload_output'] = 'Code execution confirmed'
                
                if is_vulnerable:
                    # Convert exploitation_details dict to string
                    if exploitation_details:
                        details_parts = []
                        if 'detection_method' in exploitation_details:
                            details_parts.append(f"Detection method: {exploitation_details['detection_method']}")
                        if 'baseline_time' in exploitation_details:
                            details_parts.append(f"Baseline time: {exploitation_details['baseline_time']}, Test time: {exploitation_details['test_time']}, Delay: {exploitation_details['delay']}")
                        if 'payload_output' in exploitation_details:
                            details_parts.append(f"Output: {exploitation_details['payload_output']}")
                        if 'language' in exploitation_details:
                            details_parts.append(f"Language: {exploitation_details['language']}")
                        exploitation_details_str = "; ".join(details_parts)
                    else:
                        exploitation_details_str = f"Command injection confirmed in parameter '{param_name}' using {method}"
                    
                    # Determine severity
                    if payload_type in ['sleep', 'ping']:
                        severity = FindingSeverity.HIGH  # Time-based = confirmed RCE
                    elif payload_type in ['php', 'python', 'perl']:
                        severity = FindingSeverity.CRITICAL  # Code injection = CRITICAL
                    else:
                        severity = FindingSeverity.HIGH
                    
                    findings.append(Finding(
                        title=f"Command Injection Vulnerability in {param_name} Parameter",
                        description=f"Command injection vulnerability detected in the '{param_name}' parameter ({method}). "
                                  f"The application executes system commands based on user input, allowing remote code execution. "
                                  f"Detection method: {exploitation_details.get('detection_method', 'unknown')}.",
                        severity=severity,
                        category=FindingCategory.EXPLOITATION,
                        exploitation_details=exploitation_details_str,
                        source_scanner="command_injection",
                        source_id=f"cmd_injection_{param_name}_{method}",
                        url=url if method == 'GET' else f"{url} (POST)",
                        remediation=f"Sanitize and validate all user input in the '{param_name}' parameter. "
                                   f"Use parameterized queries and avoid executing system commands with user input. "
                                   f"Implement input whitelisting and use safe APIs for system operations.",
                        metadata={
                            "parameter": param_name,
                            "method": method,
                            "payload": payload,
                            "payload_type": payload_type,
                            "detection_method": exploitation_details.get('detection_method', 'unknown'),
                            "vulnerable": True,
                        },
                        references=[
                            "https://owasp.org/www-community/attacks/Command_Injection",
                            "https://portswigger.net/web-security/os-command-injection",
                        ],
                    ))
                    break  # Found vulnerability, no need to test more payloads for this parameter
                
                # Small delay to avoid rate limiting
                time.sleep(0.3)
                
            except Exception as e:
                logger.debug(f"Error testing payload {payload} on {param_name}: {e}")
                continue
        
        return findings

