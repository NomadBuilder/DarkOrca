"""WordPress-specific security analyzer."""

import re
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.response_validation import is_accessible_response


class WordPressAnalyzer(BaseScanner):
    """WordPress-specific security analyzer with comprehensive checks."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize WordPress analyzer.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="wordpress_analyzer",
            command=None,  # No external command needed
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def is_available(self) -> bool:
        """WordPress analyzer is always available (no external tool needed)."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run WordPress-specific security checks."""
        findings = []
        
        # Always capture server and technology information (works for all sites)
        findings.extend(self._capture_server_info(target.url))
        
        # First, check if this is actually a WordPress site
        if not self._is_wordpress_site(target.url):
            return findings  # Not WordPress, skip WordPress-specific checks
        
        # Run all WordPress-specific checks
        findings.extend(self._check_security_headers(target.url))
        findings.extend(self._check_rest_api(target.url))
        findings.extend(self._check_debug_exposure(target.url))
        findings.extend(self._check_file_exposure(target.url))
        findings.extend(self._check_xmlrpc_security(target.url))
        findings.extend(self._check_directory_listing(target.url))
        
        return findings
    
    def _capture_server_info(self, url: str) -> List[Finding]:
        """Capture server information, CDN, and technology stack."""
        findings = []
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            # Server information
            server_header = headers.get('Server', '').strip()
            if server_header:
                findings.append(Finding(
                    title="Web Server Detected",
                    description=f"Server header: {server_header}",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner="wordpress_analyzer",
                    source_id="server_header",
                    url=url,
                    metadata={"server": server_header, "header": "Server"},
                ))
            
            # X-Powered-By header
            powered_by = headers.get('X-Powered-By', '').strip()
            if powered_by:
                findings.append(Finding(
                    title="Technology Stack Detected",
                    description=f"X-Powered-By: {powered_by}",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner="wordpress_analyzer",
                    source_id="x_powered_by",
                    url=url,
                    metadata={"technology": powered_by, "header": "X-Powered-By"},
                ))
            
            # CDN Detection
            cdn_headers = {
                'CF-Ray': 'Cloudflare',
                'X-Cache': 'CDN Cache',
                'X-CDN': 'CDN',
                'Server': None,  # Check Server header for CDN indicators
            }
            
            detected_cdn = None
            for header_name, cdn_name in cdn_headers.items():
                header_value = headers.get(header_name, '').strip()
                if header_value:
                    if header_name == 'Server':
                        # Check if Server header indicates CDN
                        server_lower = header_value.lower()
                        if 'cloudflare' in server_lower:
                            detected_cdn = 'Cloudflare'
                        elif 'cloudfront' in server_lower:
                            detected_cdn = 'AWS CloudFront'
                        elif 'fastly' in server_lower:
                            detected_cdn = 'Fastly'
                        elif 'akamai' in server_lower:
                            detected_cdn = 'Akamai'
                    else:
                        detected_cdn = cdn_name or header_value
            
            if detected_cdn:
                findings.append(Finding(
                    title="CDN Detected",
                    description=f"Content Delivery Network: {detected_cdn}",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner="wordpress_analyzer",
                    source_id="cdn_detected",
                    url=url,
                    metadata={"cdn": detected_cdn},
                ))
            
            # Additional technology indicators
            tech_indicators = {
                'X-AspNet-Version': 'ASP.NET',
                'X-AspNetMvc-Version': 'ASP.NET MVC',
                'X-Drupal-Cache': 'Drupal',
                'X-Generator': 'CMS Generator',
            }
            
            for header_name, tech_name in tech_indicators.items():
                header_value = headers.get(header_name, '').strip()
                if header_value:
                    findings.append(Finding(
                        title=f"{tech_name} Detected",
                        description=f"{header_name}: {header_value}",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner="wordpress_analyzer",
                        source_id=f"tech_{header_name.lower().replace('-', '_')}",
                        url=url,
                        metadata={"technology": tech_name, "value": header_value, "header": header_name},
                    ))
            
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to capture server info: {e}")
        
        return findings
    
    def _is_wordpress_site(self, url: str) -> bool:
        """Check if the target is a WordPress site with stricter validation."""
        try:
            response = self.session.get(url, timeout=10)
            content = response.text.lower()
            
            # Check for WordPress indicators - need multiple strong indicators
            wp_indicators = [
                'wp-content',  # WordPress-specific directory
                'wp-includes',  # WordPress-specific directory
                'wp-admin',  # WordPress admin area
            ]
            
            # Count how many strong WordPress indicators we find
            indicator_count = sum(1 for indicator in wp_indicators if indicator in content)
            
            # Require at least 2 strong indicators to avoid false positives
            if indicator_count >= 2:
                return True
            
            # Check for wp-json endpoint (strong indicator)
            try:
                wp_json_url = urljoin(url, '/wp-json/')
                wp_json_response = self.session.get(wp_json_url, timeout=5)
                if wp_json_response.status_code == 200:
                    # Verify it's actually WordPress JSON API
                    try:
                        json_data = wp_json_response.json()
                        if 'name' in json_data and 'wordpress' in json_data.get('name', '').lower():
                            return True
                        # Check for WordPress API routes
                        if 'routes' in json_data or 'namespaces' in json_data:
                            return True
                    except:
                        # If wp-json returns 200, likely WordPress
                        if 'wp' in wp_json_response.text.lower() or 'wordpress' in wp_json_response.text.lower():
                            return True
            except:
                pass
            
            # Check for WordPress generator meta tag (strong indicator)
            if 'generator' in content and 'wordpress' in content:
                import re
                generator_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']', content, re.IGNORECASE)
                if generator_match and 'wordpress' in generator_match.group(1).lower():
                    return True
            
            return False
        except Exception:
            return False  # If we can't check, assume not WordPress to avoid false positives
    
    def _check_security_headers(self, url: str) -> List[Finding]:
        """Check for missing or misconfigured security headers."""
        findings = []
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            # Security headers to check
            security_headers = {
                'Content-Security-Policy': {
                    'severity': FindingSeverity.HIGH,
                    'description': 'Content Security Policy (CSP) - mitigates XSS and data injection attacks',
                    'recommended_value': "default-src 'self'; script-src 'self' 'nonce-XYZ' 'strict-dynamic'; object-src 'none'",
                },
                'Strict-Transport-Security': {
                    'severity': FindingSeverity.MEDIUM,
                    'description': 'HTTP Strict Transport Security (HSTS) - enforces HTTPS',
                    'recommended_value': 'max-age=31536000; includeSubDomains; preload',
                },
                'X-Content-Type-Options': {
                    'severity': FindingSeverity.LOW,
                    'description': 'X-Content-Type-Options - prevents MIME-sniffing',
                    'recommended_value': 'nosniff',
                },
                'X-Frame-Options': {
                    'severity': FindingSeverity.MEDIUM,
                    'description': 'X-Frame-Options - protects against clickjacking',
                    'recommended_value': 'DENY or SAMEORIGIN',
                },
                'Referrer-Policy': {
                    'severity': FindingSeverity.LOW,
                    'description': 'Referrer-Policy - controls referrer information leakage',
                    'recommended_value': 'strict-origin-when-cross-origin or no-referrer',
                },
                'Permissions-Policy': {
                    'severity': FindingSeverity.LOW,
                    'description': 'Permissions-Policy - controls access to browser features',
                    'recommended_value': "geolocation=(), microphone=(), camera=(), usb=(), payment=()",
                },
            }
            
            missing_headers = []
            misconfigured_headers = []
            highest_severity = FindingSeverity.LOW
            
            for header_name, config in security_headers.items():
                if header_name not in headers:
                    missing_headers.append({
                        'name': header_name,
                        'severity': config['severity'],
                        'description': config['description'],
                        'recommended': config['recommended_value'],
                    })
                    # Track highest severity
                    if config['severity'].value > highest_severity.value:
                        highest_severity = config['severity']
                else:
                    # Check for weak configurations
                    header_value = headers[header_name].lower()
                    
                    if header_name == 'X-Content-Type-Options' and header_value != 'nosniff':
                        misconfigured_headers.append({
                            'name': header_name,
                            'current': headers[header_name],
                            'recommended': 'nosniff',
                        })
                    
                    if header_name == 'X-Frame-Options' and header_value not in ['deny', 'sameorigin']:
                        misconfigured_headers.append({
                            'name': header_name,
                            'current': headers[header_name],
                            'recommended': 'DENY or SAMEORIGIN',
                        })
            
            # Create grouped finding for missing headers
            if missing_headers:
                # Sort by severity (highest first)
                missing_headers.sort(key=lambda x: x['severity'].value, reverse=True)
                
                header_list = ', '.join([h['name'] for h in missing_headers])
                descriptions = '\n'.join([f"  • {h['name']}: {h['description']}" for h in missing_headers])
                
                findings.append(Finding(
                    title=f"Missing Security Headers ({len(missing_headers)} headers)",
                    description=f"The following security headers are missing from the HTTP response: {header_list}.\n\nMissing headers:\n{descriptions}\n\nThis may expose the site to various attacks including XSS, clickjacking, and information disclosure.",
                    severity=highest_severity,
                    category=FindingCategory.MISCONFIGURATION,
                    source_scanner="wordpress_analyzer",
                    source_id="missing_security_headers",
                    url=url,
                    remediation=f"Implement the following security headers in your web server configuration or WordPress theme/plugin:\n\n" + 
                                '\n'.join([f"  • {h['name']}: {h['recommended']}" for h in missing_headers]) +
                                "\n\nFor WordPress, consider using a security plugin (e.g., Wordfence, Sucuri) or add headers via .htaccess or functions.php.",
                    metadata={
                        "missing_headers": [h['name'] for h in missing_headers],
                        "header_count": len(missing_headers),
                        "headers_detail": missing_headers,
                    },
                ))
            
            # Create separate findings for misconfigured headers (these are less common)
            for misconfig in misconfigured_headers:
                findings.append(Finding(
                    title=f"Misconfigured Security Header: {misconfig['name']}",
                    description=f"The {misconfig['name']} header is set to '{misconfig['current']}' but should be '{misconfig['recommended']}'.",
                    severity=FindingSeverity.MEDIUM if misconfig['name'] == 'X-Frame-Options' else FindingSeverity.LOW,
                    category=FindingCategory.MISCONFIGURATION,
                    source_scanner="wordpress_analyzer",
                    source_id=f"weak_header_{misconfig['name'].lower().replace('-', '_')}",
                    url=url,
                    remediation=f"Update {misconfig['name']} header to '{misconfig['recommended']}' in your web server configuration.",
                    metadata={"header_name": misconfig['name'], "current_value": misconfig['current']},
                ))
        
        except Exception as e:
            # Log but don't fail completely
            pass
        
        return findings
    
    def _check_rest_api(self, url: str) -> List[Finding]:
        """Check WordPress REST API endpoints for security issues."""
        findings = []
        
        try:
            # Check if REST API is enabled
            rest_api_url = urljoin(url, '/wp-json/')
            response = self.session.get(rest_api_url, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    # Check for user enumeration endpoint
                    users_endpoint = urljoin(url, '/wp-json/wp/v2/users')
                    users_response = self.session.get(users_endpoint, timeout=5)
                    
                    if users_response.status_code == 200:
                        try:
                            users_data = users_response.json()
                            if isinstance(users_data, list) and len(users_data) > 0:
                                findings.append(Finding(
                                    title="WordPress REST API User Enumeration Enabled",
                                    description=f"WordPress REST API user endpoint is accessible and exposes {len(users_data)} user(s). This allows attackers to enumerate usernames for targeted attacks.",
                                    severity=FindingSeverity.MEDIUM,
                                    category=FindingCategory.INFORMATION_DISCLOSURE,
                                    source_scanner="wordpress_analyzer",
                                    source_id="rest_api_user_enum",
                                    url=users_endpoint,
                                    remediation="Disable user enumeration by blocking /wp-json/wp/v2/users endpoint or restrict access to authenticated users only.",
                                    metadata={"user_count": len(users_data), "users": [u.get('name', u.get('slug', 'unknown')) for u in users_data[:5]]},
                                ))
                        except:
                            pass
                    
                    # Check for exposed namespaces
                    # Note: REST API being accessible is normal WordPress behavior - this is informational only
                    if 'namespaces' in data:
                        findings.append(Finding(
                            title="WordPress REST API Detected",
                            description=f"WordPress REST API is accessible and exposes {len(data.get('namespaces', []))} namespace(s). This is normal WordPress behavior. The REST API is enabled by default and provides programmatic access to WordPress content. Review exposed endpoints to ensure no sensitive information is accessible.",
                            severity=FindingSeverity.INFO,
                            category=FindingCategory.FINGERPRINTING,  # Changed from INFORMATION_DISCLOSURE to FINGERPRINTING since it's informational
                            source_scanner="wordpress_analyzer",
                            source_id="rest_api_exposed",
                            url=rest_api_url,
                            remediation="The REST API is a standard WordPress feature. No action required unless specific endpoints expose sensitive information. If needed, you can disable specific namespaces or restrict access via security plugins.",
                            metadata={"namespaces": data.get('namespaces', [])},
                        ))
                
                except:
                    # REST API exists but not JSON
                    findings.append(Finding(
                        title="WordPress REST API Endpoint Accessible",
                        description="WordPress REST API endpoint is accessible. Review for potential information disclosure.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        source_scanner="wordpress_analyzer",
                        source_id="rest_api_accessible",
                        url=rest_api_url,
                        remediation="Review REST API endpoints and restrict access if they expose sensitive information.",
                    ))
        
        except Exception:
            pass
        
        return findings
    
    def _check_debug_exposure(self, url: str) -> List[Finding]:
        """Check for WordPress debug mode exposure."""
        findings = []
        
        debug_patterns = [
            r'<b>Notice</b>:',
            r'<b>Warning</b>:',
            r'<b>Fatal error</b>:',
            r'<b>Parse error</b>:',
            r'<b>Deprecated</b>:',
            r'Call Stack',
            r'Stack trace',
            r'in\s+.+?\s+on\s+line\s+\d+',
            r'WordPress\s+database\s+error',
        ]
        
        pages_to_check = [
            url,
            urljoin(url, '/wp-login.php'),
            urljoin(url, '/wp-admin/'),
        ]
        
        for page_url in pages_to_check:
            try:
                response = self.session.get(page_url, timeout=5)
                content = response.text
                
                for pattern in debug_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append(Finding(
                            title="WordPress Debug Mode Exposed",
                            description=f"WordPress debug information is exposed on {page_url}. This reveals sensitive information about the site's structure and may aid attackers.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner="wordpress_analyzer",
                            source_id="debug_exposure",
                            url=page_url,
                            remediation="Disable WP_DEBUG in wp-config.php and ensure error display is turned off in production environments.",
                            metadata={"page": page_url, "pattern_matched": pattern},
                        ))
                        break  # Only report once per page
            except:
                continue
        
        return findings
    
    def _check_file_exposure(self, url: str) -> List[Finding]:
        """Check for exposed WordPress files and directories."""
        findings = []
        
        sensitive_paths = [
            ('/wp-config.php', FindingSeverity.CRITICAL, 'WordPress configuration file'),
            ('/wp-config.php.bak', FindingSeverity.HIGH, 'WordPress configuration backup file'),
            ('/wp-config.txt', FindingSeverity.HIGH, 'WordPress configuration text file'),
            ('/.htaccess', FindingSeverity.MEDIUM, 'Apache configuration file'),
            ('/wp-content/debug.log', FindingSeverity.MEDIUM, 'WordPress debug log file'),
            ('/readme.html', FindingSeverity.LOW, 'WordPress readme file'),
            ('/license.txt', FindingSeverity.LOW, 'WordPress license file'),
        ]
        
        # Track which files were tested
        files_tested = []
        files_exposed = []
        files_protected = []
        
        for path, severity, description in sensitive_paths:
            try:
                full_url = urljoin(url, path)
                response = self.session.get(full_url, timeout=5)
                files_tested.append(path)
                
                if is_accessible_response(response):
                    content = response.text

                    # For wp-config.php, verify it's actually WordPress-related
                    if path == '/wp-config.php':
                        wp_keywords = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'WP_', 'wordpress', 'table_prefix']
                        is_wp_config = any(keyword.lower() in content.lower() for keyword in wp_keywords)

                        if not is_wp_config:
                            continue

                    if len(content) > 100:
                        files_exposed.append(path)
                        findings.append(Finding(
                            title=f"File: {path}",
                            description=f"{description} is publicly accessible at {full_url}. This may reveal sensitive information.",
                            severity=severity,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner="wordpress_analyzer",
                            source_id=f"exposed_file_{path.replace('/', '_').replace('.', '_')}",
                            url=full_url,
                            remediation=f"Restrict access to {path} using .htaccess rules or web server configuration.",
                            metadata={"path": path, "file_size": len(response.text), "test_passed": False},
                        ))
                elif response.status_code == 403:
                    # 403 means the file exists but is protected - this is actually good security
                    files_protected.append(path)
                elif response.status_code == 404:
                    # File doesn't exist or is hidden - also good
                    files_protected.append(path)
            except:
                continue
        
        # Report file exposure test results
        if files_tested:
            findings.append(Finding(
                title="Sensitive File Exposure Test",
                description=f"Tested {len(files_tested)} sensitive file(s). {len(files_exposed)} exposed, {len(files_protected)} protected or not found.",
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner="wordpress_analyzer",
                source_id="file_exposure_test",
                url=url,
                remediation="Continue monitoring for exposed sensitive files. Ensure proper access controls are in place.",
                metadata={
                    "files_tested": files_tested,
                    "files_exposed": files_exposed,
                    "files_protected": files_protected,
                    "test_passed": len(files_exposed) == 0,  # Good if no files exposed
                },
            ))
        
        return findings
    
    def _check_xmlrpc_security(self, url: str) -> List[Finding]:
        """Check XML-RPC endpoint for security issues."""
        findings = []
        
        xmlrpc_url = urljoin(url, '/xmlrpc.php')
        
        try:
            response = self.session.get(xmlrpc_url, timeout=5)
            
            if response.status_code == 200:
                # Check if XML-RPC is enabled (we already detect this in WPScan, but add security analysis)
                if 'XML-RPC server accepts POST requests only' in response.text or 'xmlrpc' in response.text.lower():
                    # Check for pingback functionality (common attack vector)
                    findings.append(Finding(
                        title="XML-RPC Endpoint Exposed",
                        description="XML-RPC endpoint is accessible and enabled. This can be used for DDoS attacks via pingback functionality and brute-force attacks.",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.WEAK_SECURITY,
                        source_scanner="wordpress_analyzer",
                        source_id="xmlrpc_security",
                        url=xmlrpc_url,
                        remediation="Disable XML-RPC if not needed, or restrict access to specific IP addresses. Consider using a security plugin to disable pingbacks.",
                        metadata={"endpoint": xmlrpc_url, "status_code": 200},
                    ))
            elif response.status_code == 403:
                # 403 means the file exists but is protected - this is actually good security
                # Don't report as a finding, or report as a positive finding
                pass  # File is protected, no action needed
            elif response.status_code == 404:
                # File doesn't exist or is hidden - also good
                pass
        except:
            pass
        
        return findings
    
    def _check_directory_listing(self, url: str) -> List[Finding]:
        """Check for directory listing vulnerabilities."""
        findings = []
        
        directories_to_check = [
            '/wp-content/',
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-includes/',
        ]
        
        for directory in directories_to_check:
            try:
                dir_url = urljoin(url, directory)
                response = self.session.get(dir_url, timeout=5)
                
                # Check if directory listing is enabled (look for typical listing indicators)
                if response.status_code == 200:
                    listing_indicators = [
                        '<title>Index of',
                        '<h1>Directory Listing',
                        'Parent Directory',
                        'Last modified',
                    ]
                    
                    if any(indicator in response.text for indicator in listing_indicators):
                        findings.append(Finding(
                            title=f"Directory Listing Enabled: {directory}",
                            description=f"Directory listing is enabled for {directory}, exposing file structure and potentially sensitive files.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner="wordpress_analyzer",
                            source_id=f"directory_listing_{directory.replace('/', '_')}",
                            url=dir_url,
                            remediation=f"Disable directory listing for {directory} using .htaccess (Options -Indexes) or web server configuration.",
                            metadata={"directory": directory},
                        ))
            except:
                continue
        
        return findings

