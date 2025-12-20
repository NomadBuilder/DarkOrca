"""Cookie security analyzer."""

import requests
import logging
from typing import List, Optional
from http.cookies import SimpleCookie

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)


class CookieSecurityAnalyzer(BaseScanner):
    """Analyze cookie security configuration."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """Initialize cookie security analyzer."""
        super().__init__(
            name="cookie_security",
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
        """Analyze cookie security."""
        findings = []
        
        if not self.is_available():
            return findings
        
        try:
            response = self.session.get(target.url, timeout=10, allow_redirects=True)
            cookies = response.cookies
            
            if not cookies:
                # Try to trigger cookie setting (e.g., login page, session)
                findings.extend(self._check_set_cookie_header(response))
                return findings
            
            for cookie in cookies:
                findings.extend(self._analyze_cookie(cookie, target.url))
            
            # Also check Set-Cookie headers
            findings.extend(self._check_set_cookie_header(response))
            
        except Exception as e:
            logger.error(f"Cookie security analysis failed: {e}", exc_info=True)
        
        return findings
    
    def _analyze_cookie(self, cookie, base_url: str) -> List[Finding]:
        """Analyze individual cookie security attributes."""
        findings = []
        
        cookie_name = cookie.name
        cookie_value = str(cookie.value)
        
        # Check Secure flag
        if not cookie.secure:
            findings.append(Finding(
                title="Cookie Missing Secure Flag",
                description=f"Cookie '{cookie_name}' is missing the Secure flag, allowing transmission over HTTP.",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.WEAK_SECURITY,
                source_scanner=self.name,
                url=base_url,
                remediation=f"Add Secure flag to cookie '{cookie_name}'. In Set-Cookie header: Set-Cookie: {cookie_name}=...; Secure",
                references=["https://owasp.org/www-community/HttpOnly", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies"]
            ))
        
        # Check HttpOnly flag
        if not hasattr(cookie, '_rest') or 'HttpOnly' not in str(cookie._rest):
            # Try to check via response headers instead
            # This is a limitation - we can't always detect HttpOnly from cookie object
            pass
        
        # Check SameSite attribute
        # Skip CSRF token cookies (crumb, csrf_token, etc.) - they may intentionally be readable by JS
        csrf_token_names = ['crumb', 'csrf_token', 'csrf-token', '_token', 'authenticity_token', 'xsrf']
        is_csrf_token = any(token_name in cookie_name.lower() for token_name in csrf_token_names)
        
        samesite = getattr(cookie, 'samesite', None)
        if samesite is None or samesite == '':
            # Don't flag CSRF token cookies - they may intentionally lack SameSite/HttpOnly
            if not is_csrf_token:
                findings.append(Finding(
                    title="Cookie Missing SameSite Attribute",
                    description=f"Cookie '{cookie_name}' is missing SameSite attribute. Modern browsers default to SameSite=Lax, but explicit setting is recommended for clarity.",
                    severity=FindingSeverity.LOW,  # Changed from MEDIUM - modern browsers default to Lax
                    category=FindingCategory.WEAK_SECURITY,
                    source_scanner=self.name,
                    url=base_url,
                    remediation=f"Add SameSite=Lax or SameSite=Strict to cookie '{cookie_name}' for explicit CSRF protection. Note: Modern browsers default to SameSite=Lax.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"]
                ))
        elif samesite and samesite.lower() == 'none':
            if not cookie.secure:
                findings.append(Finding(
                    title="Cookie SameSite=None Without Secure",
                    description=f"Cookie '{cookie_name}' has SameSite=None but is missing Secure flag, which is invalid.",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.WEAK_SECURITY,
                    source_scanner=self.name,
                    url=base_url,
                    remediation=f"Add Secure flag to cookie '{cookie_name}' when using SameSite=None.",
                ))
        
        # Check domain scope
        if cookie.domain:
            if cookie.domain.startswith('.'):
                findings.append(Finding(
                    title="Cookie Domain Scope Too Broad",
                    description=f"Cookie '{cookie_name}' uses domain '{cookie.domain}', which applies to all subdomains.",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.MISCONFIGURATION,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Use specific domain instead of wildcard domain for cookies when possible.",
                ))
        
        # Check path scope
        if cookie.path and cookie.path != '/':
            findings.append(Finding(
                title="Cookie Path Scope",
                description=f"Cookie '{cookie_name}' is scoped to path '{cookie.path}'.",
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner=self.name,
                url=base_url,
                metadata={'cookie_name': cookie_name, 'path': cookie.path}
            ))
        
        # Check for sensitive cookie names
        sensitive_names = ['session', 'token', 'auth', 'password', 'secret', 'key', 'api']
        if any(name in cookie_name.lower() for name in sensitive_names):
            if not cookie.secure:
                findings.append(Finding(
                    title="Sensitive Cookie Without Secure Flag",
                    description=f"Sensitive cookie '{cookie_name}' is missing Secure flag.",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.WEAK_SECURITY,
                    source_scanner=self.name,
                    url=base_url,
                    remediation=f"Add Secure and HttpOnly flags to sensitive cookie '{cookie_name}'.",
                ))
        
        return findings
    
    def _check_set_cookie_header(self, response) -> List[Finding]:
        """Check Set-Cookie headers for security attributes."""
        findings = []
        
        set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
        if not set_cookie_headers:
            # Try alternative method
            set_cookie = response.headers.get('Set-Cookie', '')
            if set_cookie:
                set_cookie_headers = [set_cookie]
        
        for set_cookie in set_cookie_headers:
            set_cookie_lower = set_cookie.lower()
            
            # Check for Secure flag
            if 'secure' not in set_cookie_lower:
                cookie_name = set_cookie.split('=')[0] if '=' in set_cookie else 'unknown'
                findings.append(Finding(
                    title="Set-Cookie Missing Secure Flag",
                    description=f"Set-Cookie header for '{cookie_name}' is missing Secure flag.",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.WEAK_SECURITY,
                    source_scanner=self.name,
                    url=response.url,
                    remediation="Add 'Secure' flag to Set-Cookie header to prevent transmission over HTTP.",
                ))
            
            # Check for HttpOnly flag
            # Skip CSRF token cookies - they often need to be readable by JavaScript
            cookie_name = set_cookie.split('=')[0] if '=' in set_cookie else 'unknown'
            csrf_token_names = ['crumb', 'csrf_token', 'csrf-token', '_token', 'authenticity_token', 'xsrf']
            is_csrf_token = any(token_name in cookie_name.lower() for token_name in csrf_token_names)
            
            if 'httponly' not in set_cookie_lower:
                if not is_csrf_token:
                    findings.append(Finding(
                        title="Set-Cookie Missing HttpOnly Flag",
                        description=f"Set-Cookie header for '{cookie_name}' is missing HttpOnly flag, making it accessible to JavaScript. This may be intentional for client-side access.",
                        severity=FindingSeverity.LOW,  # Changed from MEDIUM - many legitimate cookies need JS access
                        category=FindingCategory.WEAK_SECURITY,
                        source_scanner=self.name,
                        url=response.url,
                        remediation="Add 'HttpOnly' flag to Set-Cookie header to prevent JavaScript access (protects against XSS). Note: CSRF token cookies typically require JavaScript access.",
                        references=["https://owasp.org/www-community/HttpOnly"]
                    ))
            
            # Check for SameSite attribute
            # Skip CSRF token cookies - they may intentionally lack SameSite
            if 'samesite' not in set_cookie_lower:
                if not is_csrf_token:
                    findings.append(Finding(
                        title="Set-Cookie Missing SameSite Attribute",
                        description=f"Set-Cookie header for '{cookie_name}' is missing SameSite attribute. Modern browsers default to SameSite=Lax.",
                        severity=FindingSeverity.LOW,  # Changed from MEDIUM - browsers default to Lax
                        category=FindingCategory.WEAK_SECURITY,
                        source_scanner=self.name,
                        url=response.url,
                        remediation="Add 'SameSite=Lax' or 'SameSite=Strict' to Set-Cookie header. Note: Modern browsers default to SameSite=Lax.",
                    ))
            elif 'samesite=none' in set_cookie_lower and 'secure' not in set_cookie_lower:
                cookie_name = set_cookie.split('=')[0] if '=' in set_cookie else 'unknown'
                findings.append(Finding(
                    title="Set-Cookie SameSite=None Without Secure",
                    description=f"Set-Cookie header for '{cookie_name}' has SameSite=None but is missing Secure flag.",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.WEAK_SECURITY,
                    source_scanner=self.name,
                    url=response.url,
                    remediation="When using SameSite=None, the Secure flag is required.",
                ))
        
        return findings
    
    def is_available(self) -> bool:
        """Cookie security analyzer is always available."""
        return True

