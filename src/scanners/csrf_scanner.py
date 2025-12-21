"""Cross-Site Request Forgery (CSRF) vulnerability scanner."""

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


class CSRFScanner(BaseScanner):
    """Test for CSRF vulnerabilities."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.OFFENSIVE):
        """Initialize CSRF scanner."""
        super().__init__(
            name="csrf_scanner",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Test for CSRF vulnerabilities."""
        findings = []
        
        if not self.is_available():
            return findings
        
        # Only run in offensive mode
        if self.scan_mode == ScanMode.DEFENSIVE:
            return findings
        
        try:
            findings.extend(self._discover_state_changing_actions(target.url))
            findings.extend(self._test_csrf_tokens(target.url))
            findings.extend(self._test_csrf_protection(target.url))
            
        except Exception as e:
            logger.error(f"CSRF scanning failed: {e}", exc_info=True)
        
        return findings
    
    def _discover_state_changing_actions(self, base_url: str) -> List[Finding]:
        """Discover forms and state-changing endpoints."""
        findings = []
        
        try:
            response = self.session.get(base_url, timeout=10)
            content = response.text
            
            # Find forms
            form_pattern = r'<form[^>]*action=["\']([^"\']+)["\']'
            forms = re.findall(form_pattern, content, re.IGNORECASE)
            
            # Find state-changing methods
            method_pattern = r'<form[^>]*method=["\'](post|put|delete|patch)["\']'
            methods = re.findall(method_pattern, content, re.IGNORECASE)
            
            state_changing_actions = []
            for form_action in forms:
                action_url = urljoin(base_url, form_action)
                # Check if it's a state-changing action
                state_changing_keywords = ['delete', 'update', 'edit', 'create', 'add', 'remove', 'change', 'password', 'email']
                if any(keyword in action_url.lower() for keyword in state_changing_keywords):
                    state_changing_actions.append(action_url)
            
            if state_changing_actions:
                findings.append(Finding(
                    title="State-Changing Actions Detected",
                    description=f"Found {len(state_changing_actions)} potential state-changing actions. Verify CSRF protection is enabled.",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=base_url,
                    remediation="Ensure all state-changing actions are protected with CSRF tokens.",
                    metadata={'actions': state_changing_actions[:10]}  # Limit to 10
                ))
        except Exception as e:
            logger.debug(f"State-changing action discovery error: {e}")
        
        return findings
    
    def _test_csrf_tokens(self, base_url: str) -> List[Finding]:
        """Test for CSRF token presence and validation."""
        findings = []
        
        try:
            response = self.session.get(base_url, timeout=10)
            content = response.text
            
            # Look for CSRF tokens
            csrf_patterns = [
                r'name=["\']csrf[_-]?token["\']',
                r'name=["\']_token["\']',
                r'name=["\']authenticity[_-]?token["\']',
                r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'X-CSRF-Token',
            ]
            
            csrf_found = False
            for pattern in csrf_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    csrf_found = True
                    break
            
            # Check cookies for CSRF tokens
            for cookie in self.session.cookies:
                if 'csrf' in cookie.name.lower() or 'token' in cookie.name.lower():
                    csrf_found = True
                    break
            
            if not csrf_found:
                # Check if there are forms that need protection
                # But be careful - many modern frameworks use header-based CSRF (X-CSRF-Token, etc.)
                # or SameSite cookies which provide CSRF protection
                forms = re.findall(r'<form[^>]*>', content, re.IGNORECASE)
                if forms:
                    # Check for SameSite cookies which provide CSRF protection
                    set_cookie_headers = response.headers.get('Set-Cookie', '')
                    has_samesite_protection = 'samesite' in set_cookie_headers.lower() and 'samesite=none' not in set_cookie_headers.lower()
                    
                    if not has_samesite_protection:
                        findings.append(Finding(
                            title="CSRF Protection Not Detected",
                            description="Forms detected but no CSRF tokens or SameSite cookie protection detected. Note: Modern frameworks may use header-based CSRF tokens (X-CSRF-Token) or SameSite cookies, which this scanner cannot always detect. Manual verification recommended.",
                            severity=FindingSeverity.INFO,  # Changed from MEDIUM - needs manual verification
                            category=FindingCategory.FINGERPRINTING,  # Changed from VULNERABILITY - unproven
                            source_scanner=self.name,
                            url=base_url,
                            remediation="Verify CSRF protection is implemented. Many modern frameworks use header-based tokens (X-CSRF-Token) or SameSite cookies, which may not be visible in HTML. Use frameworks' built-in CSRF protection.",
                            references=["https://owasp.org/www-community/attacks/csrf"],
                        ))
            else:
                findings.append(Finding(
                    title="CSRF Protection Detected",
                    description="CSRF tokens found in forms or cookies. Verify token validation is properly implemented.",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=base_url,
                ))
        except Exception as e:
            logger.debug(f"CSRF token test error: {e}")
        
        return findings
    
    def _test_csrf_protection(self, base_url: str) -> List[Finding]:
        """Test CSRF protection by attempting requests without tokens."""
        findings = []
        
        try:
            response = self.session.get(base_url, timeout=10)
            content = response.text
            
            # Find POST forms
            form_pattern = r'<form[^>]*action=["\']([^"\']+)["\'][^>]*method=["\']post["\']'
            forms = re.findall(form_pattern, content, re.IGNORECASE)
            
            for form_action in forms[:5]:  # Limit to 5 forms
                try:
                    action_url = urljoin(base_url, form_action)
                    
                    # Try submitting without CSRF token
                    test_data = {'test': 'csrf_test'}
                    csrf_response = self.session.post(action_url, data=test_data, timeout=5, allow_redirects=False)
                    
                    # Check if request was accepted (potential CSRF vulnerability)
                    # But note: Many modern frameworks use header-based CSRF or SameSite cookies
                    if csrf_response.status_code in [200, 302, 303]:
                        # Check if it's a state-changing action
                        state_changing_keywords = ['delete', 'update', 'edit', 'create', 'add', 'remove', 'change']
                        if any(keyword in action_url.lower() for keyword in state_changing_keywords):
                            # Check if response indicates rejection (error, redirect to login, etc.)
                            # Many frameworks reject CSRF attempts with 403 or redirect
                            if csrf_response.status_code == 200 and len(csrf_response.text) < 500:
                                # Small response might be error message - be cautious
                                pass
                            else:
                                findings.append(Finding(
                                    title="CSRF Protection Not Verified",
                                    description=f"State-changing action at {form_action} accepted request without visible CSRF token. Note: Framework may use header-based CSRF (X-CSRF-Token) or SameSite cookies which are not detected. Manual verification recommended to confirm CSRF protection.",
                                    severity=FindingSeverity.INFO,  # Changed from MEDIUM - unproven without proper testing
                                    category=FindingCategory.FINGERPRINTING,  # Changed from VULNERABILITY
                                    source_scanner=self.name,
                                    url=action_url,
                                    remediation="Verify CSRF protection is implemented. Many modern frameworks use header-based tokens or SameSite cookies. Test manually by attempting cross-origin requests.",
                                    exploitation_details=f"Endpoint: {form_action}, Status code: {csrf_response.status_code}. CSRF token validation could not be verified - framework may use header-based tokens or SameSite cookies."
                                ))
                except:
                    continue
        except Exception as e:
            logger.debug(f"CSRF protection test error: {e}")
        
        return findings
    
    def is_available(self) -> bool:
        """CSRF scanner is always available."""
        return True

