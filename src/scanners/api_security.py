"""API security and configuration analyzer."""

import requests
import logging
from typing import List, Optional, Dict
from urllib.parse import urljoin, urlparse
import re

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)


class APISecurityAnalyzer(BaseScanner):
    """Analyze API security configuration."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """Initialize API security analyzer."""
        super().__init__(
            name="api_security",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Analyze API security."""
        findings = []
        
        if not self.is_available():
            return findings
        
        try:
            findings.extend(self._discover_api_endpoints(target.url))
            findings.extend(self._check_api_authentication(target.url))
            findings.extend(self._check_api_documentation(target.url))
            findings.extend(self._check_api_versioning(target.url))
            findings.extend(self._check_api_rate_limiting(target.url))
            
        except Exception as e:
            logger.error(f"API security analysis failed: {e}", exc_info=True)
        
        return findings
    
    def _discover_api_endpoints(self, base_url: str) -> List[Finding]:
        """Discover API endpoints."""
        findings = []
        
        # Common API paths
        api_paths = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/rest',
            '/rest/api',
            '/graphql',
            '/graphql/v1',
            '/v1',
            '/v2',
        ]
        
        discovered_apis = []
        
        for path in api_paths:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 401, 403]:
                    content_type = response.headers.get('Content-Type', '').lower()
                    content = response.text.lower()[:500]
                    
                    # Check for API indicators
                    api_indicators = ['api', 'json', 'xml', 'rest', 'graphql', 'endpoint', 'swagger', 'openapi']
                    
                    if any(indicator in content or indicator in content_type for indicator in api_indicators):
                        discovered_apis.append(path)
            except:
                continue
        
        if discovered_apis:
            findings.append(Finding(
                title="API Endpoints Detected",
                description=f"API endpoints found: {', '.join(discovered_apis)}. Verify proper authentication and authorization.",
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner=self.name,
                url=base_url,
                remediation="Ensure all API endpoints require authentication. Implement rate limiting and input validation.",
                metadata={'api_endpoints': discovered_apis}
            ))
        
        return findings
    
    def _check_api_authentication(self, base_url: str) -> List[Finding]:
        """Check API authentication requirements."""
        findings = []
        
        api_paths = ['/api', '/api/v1', '/rest/api', '/graphql']
        
        for path in api_paths:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                # Check if API requires authentication
                if response.status_code == 401:
                    # Check for authentication headers
                    auth_header = response.headers.get('WWW-Authenticate', '')
                    findings.append(Finding(
                        title="API Authentication Required",
                        description=f"API endpoint {path} requires authentication (HTTP 401). Authentication method: {auth_header or 'Unknown'}",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=test_url,
                        metadata={'auth_method': auth_header}
                    ))
                elif response.status_code == 200:
                    # API accessible without authentication - but this is NOT automatically a vulnerability
                    # Many sites expose public APIs, health endpoints, read-only APIs, etc.
                    # We need to test actual impact: can we read sensitive data or mutate state?
                    
                    content = response.text[:1000]  # Sample content
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    # Check if it's actually an API response (JSON/XML)
                    is_json = 'application/json' in content_type or content.strip().startswith('{')
                    is_xml = 'application/xml' in content_type or content.strip().startswith('<')
                    
                    # Test if we can mutate data (POST/PUT/DELETE)
                    can_mutate = False
                    exposes_data = False
                    
                    # Test POST to see if mutation works
                    try:
                        post_response = self.session.post(test_url, json={'test': 'data'}, timeout=5, allow_redirects=False)
                        # If POST is accepted (not 401/403/405), mutation may be possible
                        if post_response.status_code not in [401, 403, 405]:
                            can_mutate = True
                    except:
                        pass
                    
                    # Check if response contains potentially sensitive data patterns
                    sensitive_patterns = ['password', 'secret', 'token', 'key', 'api_key', 'private', 'admin']
                    content_lower = content.lower()
                    if any(pattern in content_lower for pattern in sensitive_patterns):
                        # Only flag if it's actual JSON/XML data, not just HTML page
                        if is_json or is_xml:
                            exposes_data = True
                    
                    # Only report as HIGH if we can mutate OR expose sensitive data
                    if can_mutate:
                        severity = FindingSeverity.HIGH
                        description = f"API endpoint {path} is accessible without authentication (HTTP 200) and accepts POST requests, allowing data mutation. This may expose sensitive functionality."
                    elif exposes_data and (is_json or is_xml):
                        severity = FindingSeverity.MEDIUM
                        description = f"API endpoint {path} is accessible without authentication (HTTP 200) and may expose sensitive data. Verify if this endpoint should be public."
                    else:
                        # Public API or health endpoint - informational only
                        severity = FindingSeverity.INFO
                        description = f"API endpoint {path} is accessible without authentication (HTTP 200). This is common for public APIs, health endpoints, or read-only APIs. Verify that this endpoint does not expose sensitive data or allow unauthorized state mutation."
                    
                    findings.append(Finding(
                        title="API Endpoint Without Authentication" if severity != FindingSeverity.INFO else "API Endpoint Detected",
                        description=description,
                        severity=severity,
                        category=FindingCategory.MISCONFIGURATION if severity != FindingSeverity.INFO else FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=test_url,
                        remediation=f"Verify that API endpoint {path} does not expose sensitive data or allow unauthorized mutations. If needed, implement authentication.",
                        metadata={
                            'status_code': 200,
                            'can_mutate': can_mutate,
                            'exposes_data': exposes_data,
                            'content_type': content_type
                        }
                    ))
            except:
                continue
        
        return findings
    
    def _check_api_documentation(self, base_url: str) -> List[Finding]:
        """Check for exposed API documentation."""
        findings = []
        
        doc_paths = [
            '/api-docs',
            '/swagger',
            '/swagger.json',
            '/swagger.yaml',
            '/api/swagger',
            '/docs',
            '/api/docs',
            '/openapi.json',
            '/openapi.yaml',
            '/graphql',
            '/graphiql',
            '/playground',
        ]
        
        for path in doc_paths:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check for API documentation indicators
                    doc_indicators = ['swagger', 'openapi', 'api', 'endpoints', 'graphql', 'schema']
                    
                    if any(indicator in content for indicator in doc_indicators):
                        findings.append(Finding(
                            title="API Documentation Exposed",
                            description=f"API documentation found at {path}. This may reveal API structure, endpoints, and parameters.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner=self.name,
                            url=test_url,
                            remediation=f"Restrict access to API documentation at {path}. Use authentication or move to internal network.",
                            references=["https://owasp.org/www-community/vulnerabilities/Information_exposure"]
                        ))
            except:
                continue
        
        return findings
    
    def _check_api_versioning(self, base_url: str) -> List[Finding]:
        """Check API versioning strategy."""
        findings = []
        
        # Check for version in URL
        version_patterns = [
            r'/v\d+/',
            r'/api/v\d+',
            r'/version/\d+',
        ]
        
        parsed = urlparse(base_url)
        path = parsed.path
        
        for pattern in version_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                findings.append(Finding(
                    title="API Versioning Detected",
                    description=f"API uses versioning in URL path: {path}",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=base_url,
                    metadata={'versioning_strategy': 'URL path'}
                ))
                break
        
        return findings
    
    def _check_api_rate_limiting(self, base_url: str) -> List[Finding]:
        """Check for API rate limiting."""
        findings = []
        
        api_paths = ['/api', '/api/v1']
        
        for path in api_paths:
            try:
                test_url = urljoin(base_url, path)
                
                # Make multiple rapid requests
                rate_limit_headers = []
                for i in range(5):
                    response = self.session.get(test_url, timeout=3)
                    headers = response.headers
                    
                    # Check for rate limit headers
                    if 'X-RateLimit-Limit' in headers or 'RateLimit-Limit' in headers:
                        rate_limit_headers.append({
                            'limit': headers.get('X-RateLimit-Limit') or headers.get('RateLimit-Limit'),
                            'remaining': headers.get('X-RateLimit-Remaining') or headers.get('RateLimit-Remaining'),
                        })
                    
                    if response.status_code == 429:
                        findings.append(Finding(
                            title="API Rate Limiting Active",
                            description=f"API endpoint {path} implements rate limiting (HTTP 429).",
                            severity=FindingSeverity.INFO,
                            category=FindingCategory.FINGERPRINTING,
                            source_scanner=self.name,
                            url=test_url,
                        ))
                        break
                
                if not rate_limit_headers and response.status_code == 200:
                    findings.append(Finding(
                        title="API Rate Limiting Not Detected",
                        description=f"API endpoint {path} does not appear to implement rate limiting. This may allow abuse.",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.MISCONFIGURATION,
                        source_scanner=self.name,
                        url=test_url,
                        remediation="Implement rate limiting for API endpoints to prevent abuse and DDoS attacks.",
                    ))
            except:
                continue
        
        return findings
    
    def is_available(self) -> bool:
        """API security analyzer is always available."""
        return True

