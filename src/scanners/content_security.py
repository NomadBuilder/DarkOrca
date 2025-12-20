"""Content security and information disclosure analyzer."""

import requests
import logging
from typing import List, Optional
from urllib.parse import urljoin
import re

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)


class ContentSecurityAnalyzer(BaseScanner):
    """Analyze content security and information disclosure."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """Initialize content security analyzer."""
        super().__init__(
            name="content_security",
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
        """Analyze content security."""
        findings = []
        
        if not self.is_available():
            return findings
        
        try:
            findings.extend(self._check_sri_tags(target.url))
            findings.extend(self._check_sensitive_data_exposure(target.url))
            findings.extend(self._check_version_disclosure(target.url))
            findings.extend(self._check_error_messages(target.url))
            findings.extend(self._check_cache_control(target.url))
            
        except Exception as e:
            logger.error(f"Content security analysis failed: {e}", exc_info=True)
        
        return findings
    
    def _check_sri_tags(self, base_url: str) -> List[Finding]:
        """Check for Subresource Integrity (SRI) tags on external scripts."""
        findings = []
        
        try:
            response = self.session.get(base_url, timeout=10)
            content = response.text
            
            # Find external script tags
            script_pattern = r'<script[^>]+src=["\'](https?://[^"\']+)["\']'
            scripts = re.findall(script_pattern, content, re.IGNORECASE)
            
            external_scripts = []
            scripts_with_sri = []
            
            for script_url in scripts:
                # Check if it's external
                if script_url.startswith('http://') or script_url.startswith('https://'):
                    external_scripts.append(script_url)
                    
                    # Check if SRI is present
                    sri_pattern = r'integrity=["\']([^"\']+)["\']'
                    if re.search(sri_pattern, content, re.IGNORECASE):
                        scripts_with_sri.append(script_url)
            
            if external_scripts:
                scripts_without_sri = [s for s in external_scripts if s not in scripts_with_sri]
                
                if scripts_without_sri:
                    findings.append(Finding(
                        title="External Scripts Without SRI",
                        description=f"Found {len(scripts_without_sri)} external script(s) without Subresource Integrity (SRI) tags. SRI provides protection if a CDN is compromised, but is optional hardening. Many major sites don't use SRI due to CDN asset rotation breaking caching.",
                        severity=FindingSeverity.INFO,  # Changed from MEDIUM - optional hardening, not vulnerability
                        category=FindingCategory.FINGERPRINTING,  # Changed from WEAK_SECURITY - informational
                        source_scanner=self.name,
                        url=base_url,
                        remediation="Consider adding integrity attributes to external script tags. Note: SRI can break caching when CDNs rotate assets, so many sites intentionally don't use it.",
                        references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
                        metadata={'scripts_without_sri': scripts_without_sri[:5]}  # Limit to 5
                    ))
                else:
                    findings.append(Finding(
                        title="SRI Tags Present",
                        description=f"All external scripts use Subresource Integrity (SRI) tags.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=base_url,
                    ))
        except Exception as e:
            logger.debug(f"SRI check error: {e}")
        
        return findings
    
    def _check_sensitive_data_exposure(self, base_url: str) -> List[Finding]:
        """Check for sensitive data in page content."""
        findings = []
        
        try:
            response = self.session.get(base_url, timeout=10)
            content = response.text
            
            # Patterns for sensitive data - but be VERY strict to avoid false positives
            # Only flag actual data values, not form field names or placeholders
            sensitive_patterns = {
                # API keys - look for actual key values (long alphanumeric strings)
                'api_key': r'["\']([A-Za-z0-9_-]{32,})["\']',  # Only very long keys
                # Credit cards - only flag if looks like actual card number (not just "credit_card" text)
                'credit_card': r'\b(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b',  # Visa/MasterCard patterns only
            }
            
            found_sensitive = []
            
            for data_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    # Aggressively filter false positives
                    filtered = [m for m in matches if not any(
                        exclude in str(m).lower() for exclude in [
                            'example.com', 'test@', 'placeholder', 'xxx', 'sample',
                            'your_email', 'your_email@example.com', 'email@example.com',
                            'type=', 'name=', 'id=', 'class=', 'placeholder',
                            'input type', 'form', '<script', 'function'
                        ]
                    )]
                    # Only flag if we have multiple matches or very high confidence
                    if len(filtered) > 2 or (data_type == 'api_key' and len(filtered) > 0):
                        found_sensitive.append(data_type)
            
            # Don't flag email/password/phone/SSN - too many false positives from form fields
            # Only report if we have very high confidence of actual data exposure
            if found_sensitive:
                findings.append(Finding(
                    title="Potential Sensitive Data in Page Content",
                    description=f"Page content may contain sensitive data patterns: {', '.join(found_sensitive)}. Manual verification required - these may be false positives from form fields or placeholders.",
                    severity=FindingSeverity.INFO,  # Changed from MEDIUM - needs manual verification
                    category=FindingCategory.FINGERPRINTING,  # Changed from INFORMATION_DISCLOSURE - unproven
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Review page source manually. Verify if sensitive data is actually exposed or if these are false positives from form field names, placeholders, or example data.",
                    references=["https://owasp.org/www-community/vulnerabilities/Information_exposure"]
                ))
        except Exception as e:
            logger.debug(f"Sensitive data check error: {e}")
        
        return findings
    
    def _check_version_disclosure(self, base_url: str) -> List[Finding]:
        """Check for version information disclosure."""
        findings = []
        
        try:
            response = self.session.get(base_url, timeout=10)
            content = response.text
            headers = response.headers
            
            # Check headers for version info
            version_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Version']
            version_info = []
            
            for header in version_headers:
                value = headers.get(header, '')
                if value and any(char.isdigit() for char in value):
                    version_info.append(f"{header}: {value}")
            
            # Check HTML comments for version info
            comment_pattern = r'<!--.*?version.*?-->'
            comments = re.findall(comment_pattern, content, re.IGNORECASE)
            
            if comments:
                version_info.extend([f"HTML comment: {c[:50]}" for c in comments[:3]])
            
            # Check meta tags
            meta_pattern = r'<meta[^>]+(?:name|property)=["\'](?:version|generator)["\'][^>]+content=["\']([^"\']+)["\']'
            meta_versions = re.findall(meta_pattern, content, re.IGNORECASE)
            
            if meta_versions:
                version_info.extend([f"Meta tag: {v}" for v in meta_versions])
            
            if version_info:
                findings.append(Finding(
                    title="Version Information Disclosure",
                    description=f"Version information found in: {', '.join(version_info[:3])}",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.INFORMATION_DISCLOSURE,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Remove version information from headers, HTML comments, and meta tags to prevent information disclosure.",
                ))
        except Exception as e:
            logger.debug(f"Version disclosure check error: {e}")
        
        return findings
    
    def _check_error_messages(self, base_url: str) -> List[Finding]:
        """Check for information disclosure in error messages."""
        findings = []
        
        # Test error-inducing URLs
        error_paths = [
            '/nonexistent-page-12345',
            '/test/../invalid',
            '/?invalid_param=<script>',
        ]
        
        for path in error_paths:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [400, 404, 500]:
                    content = response.text.lower()
                    
                    # Check for detailed error information
                    error_indicators = [
                        'stack trace',
                        'file path',
                        'line number',
                        'database error',
                        'sql error',
                        'exception',
                        'traceback',
                    ]
                    
                    if any(indicator in content for indicator in error_indicators):
                        findings.append(Finding(
                            title="Detailed Error Messages",
                            description=f"Error page at {path} reveals detailed system information (stack traces, file paths, etc.).",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner=self.name,
                            url=test_url,
                            remediation="Configure custom error pages that don't reveal system information. Disable detailed error messages in production.",
                            references=["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_error_messages"]
                        ))
                        break  # Only report once
            except:
                continue
        
        return findings
    
    def _check_cache_control(self, base_url: str) -> List[Finding]:
        """Check cache control headers."""
        findings = []
        
        try:
            response = self.session.get(base_url, timeout=10)
            headers = response.headers
            
            cache_control = headers.get('Cache-Control', '').lower()
            pragma = headers.get('Pragma', '').lower()
            expires = headers.get('Expires', '')
            
            # Check for sensitive pages that shouldn't be cached
            # But be careful - "login" and "password" in HTML often just mean form fields
            # Only flag if we detect actual sensitive data OR it's a known sensitive endpoint
            content = response.text.lower()
            url_lower = base_url.lower()
            
            # Only flag known sensitive endpoints, not just keywords in content
            sensitive_endpoints = ['/login', '/logout', '/signin', '/signout', '/account', '/profile', '/dashboard', '/admin']
            is_sensitive_endpoint = any(endpoint in url_lower for endpoint in sensitive_endpoints)
            
            # Check for actual sensitive data patterns (not just form fields)
            actual_sensitive_data = re.search(r'\b\d{3}-\d{2}-\d{4}\b', content) or \
                                  re.search(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', content)  # SSN or credit card patterns
            
            if (is_sensitive_endpoint or actual_sensitive_data) and 'no-cache' not in cache_control and 'no-store' not in cache_control:
                findings.append(Finding(
                    title="Cache Control Recommendation for Sensitive Pages",
                    description="Page may contain sensitive data but lacks cache control headers. Consider adding no-store for authenticated pages with private data.",
                    severity=FindingSeverity.INFO,  # Changed from MEDIUM - context-dependent, many public pages should be cached
                    category=FindingCategory.MISCONFIGURATION,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Consider adding Cache-Control: no-store headers to authenticated pages with private user data. Public marketing pages should generally be cacheable.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"]
                ))
            else:
                # Check if cache control is properly configured
                if not cache_control and not expires:
                    findings.append(Finding(
                        title="Cache Control Headers Missing",
                        description="Page lacks cache control headers. Consider adding appropriate caching strategy.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.MISCONFIGURATION,
                        source_scanner=self.name,
                        url=base_url,
                        remediation="Add Cache-Control headers to optimize caching strategy.",
                    ))
        except Exception as e:
            logger.debug(f"Cache control check error: {e}")
        
        return findings
    
    def is_available(self) -> bool:
        """Content security analyzer is always available."""
        return True

