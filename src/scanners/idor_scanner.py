"""Insecure Direct Object Reference (IDOR) vulnerability scanner."""

import requests
import logging
from typing import List, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import re

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)


class IDORScanner(BaseScanner):
    """Test for IDOR vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.OFFENSIVE):
        """Initialize IDOR scanner."""
        super().__init__(
            name="idor_scanner",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Test for IDOR vulnerabilities."""
        findings = []
        
        if not self.is_available():
            return findings
        
        # Only run in offensive mode
        if self.scan_mode == ScanMode.DEFENSIVE:
            return findings
        
        try:
            findings.extend(self._discover_object_references(target.url))
            findings.extend(self._test_idor_manipulation(target.url))
            findings.extend(self._test_idor_sequential(target.url))
            
        except Exception as e:
            logger.error(f"IDOR scanning failed: {e}", exc_info=True)
        
        return findings
    
    def _discover_object_references(self, base_url: str) -> List[Finding]:
        """Discover object reference patterns in URLs."""
        findings = []
        
        try:
            response = self.session.get(base_url, timeout=10)
            content = response.text
            
            # Look for common ID patterns in URLs and content
            id_patterns = [
                r'id=(\d+)',
                r'user_id=(\d+)',
                r'file_id=(\d+)',
                r'document_id=(\d+)',
                r'/user/(\d+)',
                r'/file/(\d+)',
                r'/document/(\d+)',
                r'/api/users/(\d+)',
                r'/api/files/(\d+)',
            ]
            
            found_ids = []
            for pattern in id_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                found_ids.extend(matches)
            
            if found_ids:
                findings.append(Finding(
                    title="Object References Detected",
                    description=f"Found {len(set(found_ids))} potential object references in page content. Verify access controls are enforced.",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Ensure all object references are validated with proper authorization checks.",
                    metadata={'object_ids': list(set(found_ids))[:10]}  # Limit to 10
                ))
        except Exception as e:
            logger.debug(f"Object reference discovery error: {e}")
        
        return findings
    
    def _test_idor_manipulation(self, base_url: str) -> List[Finding]:
        """Test IDOR by manipulating object IDs."""
        findings = []
        
        # Parse URL for existing IDs
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        
        # Common ID parameter names
        id_params = ['id', 'user_id', 'file_id', 'document_id', 'account_id', 'order_id', 'invoice_id']
        
        for param in id_params:
            if param in params:
                original_id = params[param][0]
                
                # Try manipulating the ID
                test_ids = [
                    str(int(original_id) + 1) if original_id.isdigit() else None,
                    str(int(original_id) - 1) if original_id.isdigit() else None,
                    '1',
                    '0',
                    '999999',
                ]
                
                for test_id in test_ids:
                    if test_id is None:
                        continue
                    
                    try:
                        # Build test URL
                        test_params = params.copy()
                        test_params[param] = [test_id]
                        test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        response = self.session.get(test_url, timeout=5, allow_redirects=False)
                        
                        # Check if we got different content (potential IDOR)
                        if response.status_code == 200:
                            # Compare with original response
                            original_response = self.session.get(base_url, timeout=5)
                            
                            if response.text != original_response.text:
                                findings.append(Finding(
                                    title="Potential IDOR Vulnerability",
                                    description=f"Parameter '{param}' may be vulnerable to IDOR. Different content returned for ID {test_id}.",
                                    severity=FindingSeverity.HIGH,
                                    category=FindingCategory.VULNERABILITY,
                                    source_scanner=self.name,
                                    url=test_url,
                                    remediation=f"Implement proper authorization checks for parameter '{param}'. Verify user has access to requested object.",
                                    references=["https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference"],
                                    exploitation_details=f"Parameter '{param}' allows unauthorized access. Original ID: {original_id}, Test ID: {test_id}, Status code: {response.status_code}."
                                ))
                                break  # Only report once per parameter
                    except:
                        continue
        
        return findings
    
    def _test_idor_sequential(self, base_url: str) -> List[Finding]:
        """Test for sequential ID vulnerabilities."""
        findings = []
        
        # Common API endpoints with sequential IDs
        api_patterns = [
            '/api/users/',
            '/api/files/',
            '/api/documents/',
            '/api/orders/',
            '/api/invoices/',
            '/user/',
            '/file/',
            '/document/',
        ]
        
        for pattern in api_patterns:
            # Test sequential IDs
            for test_id in [1, 2, 3, 100, 999]:
                try:
                    test_url = urljoin(base_url, f"{pattern}{test_id}")
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    
                    if response.status_code == 200:
                        # Check if response contains user-specific data
                        content_lower = response.text.lower()
                        sensitive_indicators = ['email', 'phone', 'address', 'ssn', 'credit', 'card', 'password']
                        
                        if any(indicator in content_lower for indicator in sensitive_indicators):
                            findings.append(Finding(
                                title="IDOR via Sequential IDs",
                                description=f"Endpoint {pattern}{test_id} returns sensitive data without proper authorization checks.",
                                severity=FindingSeverity.HIGH,
                                category=FindingCategory.VULNERABILITY,
                                source_scanner=self.name,
                                url=test_url,
                                remediation=f"Implement authorization checks for {pattern} endpoints. Verify user has access to requested resource.",
                                exploitation_details={
                                    'endpoint': pattern,
                                    'test_id': test_id,
                                    'status_code': response.status_code,
                                }
                            ))
                            break  # Only report once per pattern
                except:
                    continue
        
        return findings
    
    def is_available(self) -> bool:
        """IDOR scanner is always available."""
        return True

