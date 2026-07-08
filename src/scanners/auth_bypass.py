"""Authentication Bypass Testing Scanner."""

import re
import requests
import time
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.response_validation import is_accessible_response, is_blocked_status

import logging
logger = logging.getLogger(__name__)


class AuthenticationBypassScanner(BaseScanner):
    """Scanner for authentication and authorization bypass vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize authentication bypass scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="auth_bypass",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def is_available(self) -> bool:
        """Authentication bypass scanner is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run authentication bypass tests."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        try:
            findings.extend(self._test_session_fixation(target.url))
            findings.extend(self._test_oauth_misconfigurations(target.url))
            findings.extend(self._test_password_reset_vulnerabilities(target.url))
            findings.extend(self._test_privilege_escalation(target.url))
        
        except Exception as e:
            logger.debug(f"Authentication bypass scan error: {e}")
        
        return findings
    
    def _test_session_fixation(self, url: str) -> List[Finding]:
        """Test for session fixation vulnerabilities."""
        findings = []
        
        # Common login endpoints
        login_endpoints = [
            '/login',
            '/signin',
            '/auth/login',
            '/wp-login.php',
            '/admin/login',
        ]
        
        for login_path in login_endpoints:
            try:
                login_url = urljoin(url, login_path)
                response = self.session.get(login_url, timeout=5)
                
                if response.status_code == 200:
                    # Get initial session ID
                    initial_session_id = self._extract_session_id(response)
                    
                    if initial_session_id:
                        # Attempt login (even with invalid credentials)
                        login_data = {
                            'username': 'test',
                            'password': 'test',
                            'email': 'test@test.com',
                        }
                        
                        login_response = self.session.post(login_url, data=login_data, timeout=5, allow_redirects=False)
                        post_login_session_id = self._extract_session_id(login_response)
                        
                        # If session ID didn't change after login, session fixation vulnerability
                        if post_login_session_id and initial_session_id == post_login_session_id:
                            findings.append(Finding(
                                title="Session Fixation Vulnerability",
                                description=f"Session ID does not change after login at {login_url}, indicating session fixation vulnerability. Attackers can fixate a session ID before login.",
                                severity=FindingSeverity.HIGH,
                                category=FindingCategory.VULNERABILITY,
                                source_scanner=self.name,
                                url=login_url,
                                evidence=f"Session ID remained unchanged: {initial_session_id[:20]}...",
                                remediation="Regenerate session ID after successful authentication. Invalidate old session and create new session with new ID. Do not accept session IDs from query parameters.",
                                references=["https://owasp.org/www-community/attacks/Session_fixation"],
                                metadata={'login_endpoint': login_path, 'session_fixation': True}
                            ))
                            break  # Found, move on
            except:
                continue
        
        return findings
    
    def _extract_session_id(self, response: requests.Response) -> Optional[str]:
        """Extract session ID from cookies or response."""
        # Check cookies
        session_cookies = ['sessionid', 'session', 'sessid', 'PHPSESSID', 'JSESSIONID', 'sid']
        for cookie_name in session_cookies:
            if cookie_name in response.cookies:
                return response.cookies[cookie_name]
        
        # Check Set-Cookie header
        set_cookie = response.headers.get('Set-Cookie', '')
        for cookie_name in session_cookies:
            pattern = rf'{cookie_name}=([^;]+)'
            match = re.search(pattern, set_cookie, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _test_oauth_misconfigurations(self, url: str) -> List[Finding]:
        """Test for OAuth/SAML misconfigurations."""
        findings = []
        
        # Look for OAuth endpoints
        oauth_endpoints = [
            '/oauth/authorize',
            '/oauth/token',
            '/oauth/callback',
            '/auth/oauth',
            '/login/oauth',
            '/saml/sso',
            '/saml/acs',
        ]
        
        for oauth_path in oauth_endpoints:
            try:
                oauth_url = urljoin(url, oauth_path)
                response = self.session.get(oauth_url, timeout=5)
                
                if response.status_code == 200:
                    # Check for common OAuth misconfigurations in response
                    content = response.text.lower()
                    
                    # Check for error messages that reveal information
                    error_indicators = [
                        'invalid client_id',
                        'invalid redirect_uri',
                        'invalid scope',
                        'client_id not found',
                    ]
                    
                    if any(indicator in content for indicator in error_indicators):
                        findings.append(Finding(
                            title="OAuth Endpoint Information Disclosure",
                            description=f"OAuth endpoint at {oauth_url} reveals information about invalid requests, potentially aiding enumeration attacks.",
                            severity=FindingSeverity.LOW,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner=self.name,
                            url=oauth_url,
                            remediation="Use generic error messages for OAuth endpoints. Do not reveal whether client_id, redirect_uri, or other parameters are valid.",
                            metadata={'oauth_endpoint': oauth_path}
                        ))
                        break
                
                # Test for open redirect in OAuth callback
                parsed = urlparse(oauth_url)
                test_redirect = 'http://evil.com'
                callback_url = f"{oauth_url}?redirect_uri={test_redirect}"
                callback_response = self.session.get(callback_url, timeout=5, allow_redirects=False)
                
                if callback_response.status_code in [302, 301]:
                    location = callback_response.headers.get('Location', '')
                    if 'evil.com' in location or test_redirect in location:
                        findings.append(Finding(
                            title="OAuth Open Redirect Vulnerability",
                            description=f"OAuth callback at {oauth_url} allows arbitrary redirect URLs, enabling open redirect attacks.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=callback_url,
                            evidence=f"Redirects to: {location}",
                            remediation="Whitelist allowed redirect_uri values. Validate redirect_uri against registered callback URLs. Do not allow arbitrary redirect destinations.",
                            metadata={'oauth_endpoint': oauth_path, 'open_redirect': True}
                        ))
                        break
            
            except:
                continue
        
        return findings
    
    def _test_password_reset_vulnerabilities(self, url: str) -> List[Finding]:
        """Test for password reset token vulnerabilities."""
        findings = []
        
        # Password reset endpoints
        reset_endpoints = [
            '/password/reset',
            '/reset-password',
            '/forgot-password',
            '/password/forgot',
            '/wp-login.php?action=lostpassword',
        ]
        
        for reset_path in reset_endpoints:
            try:
                reset_url = urljoin(url, reset_path)
                
                # Test 1: Token enumeration (sequential/predictable tokens)
                test_tokens = [
                    '000000',
                    '111111',
                    '123456',
                    'test',
                    'admin',
                    '1',
                    '2',
                    '3',
                ]
                
                for token in test_tokens:
                    test_reset_url = f"{reset_url}?token={token}"
                    response = self.session.get(test_reset_url, timeout=5)
                    
                    # Check if token is accepted (different from "invalid token" error)
                    if response.status_code == 200 and 'invalid' not in response.text.lower()[:200]:
                        findings.append(Finding(
                            title="Predictable Password Reset Token",
                            description=f"Password reset endpoint at {reset_url} may accept predictable tokens. Token '{token}' was processed differently than invalid tokens.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=test_reset_url,
                            remediation="Use cryptographically random tokens for password reset (at least 32 characters). Expire tokens after use or after time limit (15-60 minutes). Use rate limiting on password reset endpoints.",
                            metadata={'reset_endpoint': reset_path, 'token_tested': token}
                        ))
                        break
                
                # Test 2: Check if reset tokens are in URL (vs email only)
                # This is informational - tokens in URL are less secure
                parsed = urlparse(reset_url)
                if 'token' in parse_qs(parsed.query):
                    findings.append(Finding(
                        title="Password Reset Token in URL",
                        description=f"Password reset endpoint at {reset_url} accepts tokens via URL parameter. Tokens in URLs may be logged or leaked via Referer headers.",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.WEAK_SECURITY,
                        source_scanner=self.name,
                        url=reset_url,
                        remediation="Prefer POST requests for password reset tokens, or use tokens sent via email only (not in URL). Ensure tokens are single-use and time-limited.",
                        metadata={'reset_endpoint': reset_path}
                    ))
                    break
            
            except:
                continue
        
        return findings
    
    def _test_privilege_escalation(self, url: str) -> List[Finding]:
        """Test for privilege escalation vulnerabilities."""
        findings = []
        
        # Test for horizontal privilege escalation (IDOR-like)
        # Test common admin/privileged endpoints without authentication
        privileged_endpoints = [
            '/admin',
            '/admin/',
            '/administrator',
            '/wp-admin',
            '/api/admin',
            '/dashboard',
            '/panel',
            '/control',
        ]
        
        accessible_privileged = []
        
        for endpoint_path in privileged_endpoints:
            try:
                endpoint_url = urljoin(url, endpoint_path)
                response = self.session.get(endpoint_url, timeout=5, allow_redirects=False)
                
                # Check status code and content to avoid false positives
                status = response.status_code
                
                # 401/403 = protected (good) - skip
                if is_blocked_status(status):
                    continue

                # 302/301 = redirect to login (good) - skip
                if status in [302, 301, 303, 307, 308]:
                    location = response.headers.get('Location', '').lower()
                    if 'login' in location or 'signin' in location or 'auth' in location:
                        continue

                if is_accessible_response(response):
                    content = response.text.lower()
                    
                    # Check if it's a login page (common false positive)
                    login_indicators = [
                        'login', 'sign in', 'signin', 'password', 'email',
                        'enter your', 'log in', 'authentication required',
                        'please login', 'please sign in'
                    ]
                    is_login_page = any(indicator in content[:2000] for indicator in login_indicators)
                    
                    if is_login_page:
                        # It's a login page, not accessible admin panel - skip
                        continue
                    
                    # Check if it looks like an actual admin panel (not just a page mentioning "admin")
                    admin_panel_indicators = ['dashboard', 'admin panel', 'control panel', 'management console', 'settings page']
                    is_admin_panel = any(indicator in content[:2000] for indicator in admin_panel_indicators)
                    
                    # Also check for forms with admin functionality (not login forms)
                    has_admin_form = 'form' in content and 'admin' in content and 'login' not in content[:1000]
                    
                    if is_admin_panel or has_admin_form:
                        accessible_privileged.append(endpoint_path)
                
            except:
                continue
        
        if accessible_privileged:
            findings.append(Finding(
                title="Privileged Endpoints Accessible Without Authentication",
                description=f"Privileged endpoints appear to be accessible without authentication: {', '.join(accessible_privileged)}. These endpoints returned HTTP 200 and appear to be functional admin panels (not login pages). Manual verification recommended.",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.VULNERABILITY,
                source_scanner=self.name,
                url=url,
                evidence=f"Endpoints returned 200 status (verified not login pages): {', '.join(accessible_privileged)}. Note: Login pages and redirects were filtered out.",
                remediation="Implement authentication and authorization checks for all privileged endpoints. Use role-based access control (RBAC). Verify user permissions on every request.",
                metadata={'accessible_endpoints': accessible_privileged, 'verified_not_login': True}
            ))
        
        return findings
