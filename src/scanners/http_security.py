"""HTTP security and configuration analyzer."""

import requests
import re
import logging
from typing import List, Optional
from urllib.parse import urlparse, urljoin

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)


class HTTPSecurityAnalyzer(BaseScanner):
    """Analyze HTTP security configuration and information disclosure."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """Initialize HTTP security analyzer."""
        super().__init__(
            name="http_security",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Analyze HTTP security."""
        findings = []
        
        if not self.is_available():
            return findings
        
        try:
            findings.extend(self._check_http_methods(target.url))
            findings.extend(self._check_server_info(target.url))
            findings.extend(self._check_error_pages(target.url))
            findings.extend(self._check_directory_listing(target.url))
            findings.extend(self._check_robots_txt(target.url))
            findings.extend(self._check_sitemap(target.url))
            findings.extend(self._check_cors_config(target.url))
            findings.extend(self._check_mixed_content(target.url))
            findings.extend(self._check_insecure_redirects(target.url))
            
        except Exception as e:
            logger.error(f"HTTP security analysis failed: {e}", exc_info=True)
        
        return findings
    
    def _check_http_methods(self, url: str) -> List[Finding]:
        """Check allowed HTTP methods."""
        findings = []
        
        try:
            response = self.session.options(url, timeout=10, allow_redirects=False)
            allowed_methods = response.headers.get('Allow', '')
            
            if allowed_methods:
                methods = [m.strip() for m in allowed_methods.split(',')]
                
                # Check for dangerous methods
                dangerous_methods = ['TRACE', 'DELETE', 'PUT', 'PATCH']
                found_dangerous = [m for m in methods if m in dangerous_methods]
                
                if 'TRACE' in methods:
                    findings.append(Finding(
                        title="TRACE Method Enabled",
                        description=f"HTTP TRACE method is enabled. This can be used for XST (Cross-Site Tracing) attacks.",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.MISCONFIGURATION,
                        source_scanner=self.name,
                        url=url,
                        remediation="Disable TRACE method on web server. For Apache: add 'TraceEnable off' to httpd.conf",
                        references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"]
                    ))
                
                if 'DELETE' in methods or 'PUT' in methods:
                    findings.append(Finding(
                        title="Unsafe HTTP Methods Enabled",
                        description=f"HTTP methods {', '.join(found_dangerous)} are enabled. These should be disabled if not needed.",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.MISCONFIGURATION,
                        source_scanner=self.name,
                        url=url,
                        remediation="Disable unnecessary HTTP methods. Only allow GET, POST, HEAD, OPTIONS if possible.",
                    ))
                
                findings.append(Finding(
                    title="HTTP Methods Allowed",
                    description=f"Server allows: {', '.join(methods)}",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=url,
                    metadata={'allowed_methods': methods}
                ))
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logger.debug(f"HTTP methods check error: {e}")
        
        return findings
    
    def _check_server_info(self, url: str) -> List[Finding]:
        """Check for server information disclosure."""
        findings = []
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            # Check Server header
            server = headers.get('Server', '').strip()
            if server:
                # Check for version disclosure
                if any(char.isdigit() for char in server):
                    findings.append(Finding(
                        title="Server Version Disclosure",
                        description=f"Server header reveals version information: {server}",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        source_scanner=self.name,
                        url=url,
                        remediation="Remove or obfuscate version information from Server header.",
                        metadata={'server': server}
                    ))
                else:
                    findings.append(Finding(
                        title="Server Information",
                        description=f"Server: {server}",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=url,
                        metadata={'server': server}
                    ))
            
            # Check X-Powered-By header
            powered_by = headers.get('X-Powered-By', '').strip()
            if powered_by:
                findings.append(Finding(
                    title="Technology Stack Disclosure",
                    description=f"X-Powered-By header reveals: {powered_by}",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.INFORMATION_DISCLOSURE,
                    source_scanner=self.name,
                    url=url,
                    remediation="Remove X-Powered-By header to prevent information disclosure.",
                ))
            
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logger.debug(f"Server info check error: {e}")
        
        return findings
    
    def _check_error_pages(self, url: str) -> List[Finding]:
        """Check for information disclosure in error pages."""
        findings = []
        
        # Test common error paths
        error_paths = ['/nonexistent-page-12345', '/test/../', '/?test=<script>']
        
        for path in error_paths:
            try:
                test_url = urljoin(url, path)
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [404, 500, 403]:
                    content = response.text.lower()
                    
                    # Check for stack traces or detailed errors
                    stack_indicators = ['stack trace', 'exception', 'traceback', 'fatal error', 
                                       'php fatal', 'python traceback', 'java.lang.', 'at line']
                    
                    if any(indicator in content for indicator in stack_indicators):
                        findings.append(Finding(
                            title="Error Page Information Disclosure",
                            description=f"Error page at {path} reveals stack traces or detailed error information.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner=self.name,
                            url=test_url,
                            remediation="Configure custom error pages that don't reveal system information or stack traces.",
                            references=["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_error_messages"]
                        ))
                        break  # Only report once
            except:
                continue
        
        return findings
    
    def _check_directory_listing(self, url: str) -> List[Finding]:
        """Check for directory listing enabled."""
        findings = []
        
        # Common directories that might have listing enabled
        test_dirs = ['/images/', '/files/', '/uploads/', '/assets/', '/static/', '/public/']
        
        for dir_path in test_dirs:
            try:
                test_url = urljoin(url, dir_path)
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    # Check for directory listing indicators
                    if any(indicator in content for indicator in ['index of', 'directory listing', 'parent directory', '<title>index of']):
                        findings.append(Finding(
                            title="Directory Listing Enabled",
                            description=f"Directory listing is enabled at {dir_path}, exposing file structure.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner=self.name,
                            url=test_url,
                            remediation="Disable directory listing on web server. For Apache: add 'Options -Indexes' to .htaccess",
                            references=["https://owasp.org/www-community/OWASP_Testing_Guide_v4/Web_App_Security_Testing/02_Configuration_and_Deploy_Management_Testing/05_Test_for_Directory_Traversal_File_Include"]
                        ))
                        break  # Only report once
            except:
                continue
        
        return findings
    
    def _check_robots_txt(self, url: str) -> List[Finding]:
        """Check robots.txt for sensitive paths."""
        findings = []
        
        try:
            robots_url = urljoin(url, '/robots.txt')
            response = self.session.get(robots_url, timeout=5)
            
            if response.status_code == 200:
                content = response.text
                
                # Check for sensitive paths in robots.txt
                sensitive_patterns = ['admin', 'login', 'wp-admin', 'config', 'backup', 'private', 'secret']
                found_sensitive = []
                
                for line in content.split('\n'):
                    line_lower = line.lower()
                    if 'disallow:' in line_lower:
                        path = line.split(':', 1)[1].strip()
                        if any(pattern in path for pattern in sensitive_patterns):
                            found_sensitive.append(path)
                
                if found_sensitive:
                    findings.append(Finding(
                        title="Sensitive Paths in robots.txt",
                        description=f"robots.txt reveals sensitive paths: {', '.join(found_sensitive[:5])}",
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        source_scanner=self.name,
                        url=robots_url,
                        remediation="Review robots.txt and remove unnecessary path disclosures. Consider using robots.txt only for search engines, not security.",
                    ))
                else:
                    findings.append(Finding(
                        title="robots.txt Present",
                        description="robots.txt file is accessible.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=robots_url,
                    ))
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logger.debug(f"robots.txt check error: {e}")
        
        return findings
    
    def _check_sitemap(self, url: str) -> List[Finding]:
        """Check for sitemap.xml."""
        findings = []
        
        try:
            sitemap_url = urljoin(url, '/sitemap.xml')
            response = self.session.get(sitemap_url, timeout=5)
            
            if response.status_code == 200:
                findings.append(Finding(
                    title="Sitemap.xml Present",
                    description="sitemap.xml is accessible, which may reveal site structure.",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    url=sitemap_url,
                ))
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logger.debug(f"sitemap check error: {e}")
        
        return findings
    
    def _check_cors_config(self, url: str) -> List[Finding]:
        """Check CORS configuration."""
        findings = []
        
        try:
            # Make a cross-origin request simulation
            response = self.session.get(url, timeout=10, headers={
                'Origin': 'https://evil.com'
            })
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao:
                if acao == '*':
                    if acac and acac.lower() == 'true':
                        findings.append(Finding(
                            title="Misconfigured CORS",
                            description="CORS allows all origins (*) with credentials enabled, which is dangerous.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.MISCONFIGURATION,
                            source_scanner=self.name,
                            url=url,
                            remediation="Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Specify exact origins instead.",
                            references=["https://owasp.org/www-community/attacks/CORS"]
                        ))
                    else:
                        findings.append(Finding(
                            title="Permissive CORS Configuration",
                            description="CORS allows all origins (*). This may be acceptable if credentials are not used.",
                            severity=FindingSeverity.LOW,
                            category=FindingCategory.MISCONFIGURATION,
                            source_scanner=self.name,
                            url=url,
                            remediation="Consider restricting CORS to specific origins for better security.",
                        ))
                else:
                    findings.append(Finding(
                        title="CORS Configured",
                        description=f"CORS allows origin: {acao}",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner=self.name,
                        url=url,
                        metadata={'allowed_origin': acao, 'allow_credentials': acac}
                    ))
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logger.debug(f"CORS check error: {e}")
        
        return findings
    
    def _check_mixed_content(self, url: str) -> List[Finding]:
        """Check for mixed content (HTTP resources on HTTPS page)."""
        findings = []
        
        if not url.startswith('https://'):
            return findings
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            
            # Check for HTTP resources
            http_resources = []
            if 'http://' in content and 'https://' not in url:
                # Look for common HTTP resource patterns
                http_patterns = re.findall(r'http://[^\s"\'<>]+', content)
                if http_patterns:
                    http_resources = list(set(http_patterns[:5]))  # Limit to 5 examples
            
            if http_resources:
                findings.append(Finding(
                    title="Mixed Content Detected",
                    description=f"HTTPS page contains HTTP resources, which can be blocked or cause security warnings.",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.MISCONFIGURATION,
                    source_scanner=self.name,
                    url=url,
                    remediation="Update all HTTP resource URLs to HTTPS to prevent mixed content issues.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"]
                ))
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logger.debug(f"Mixed content check error: {e}")
        
        return findings
    
    def _check_insecure_redirects(self, url: str) -> List[Finding]:
        """Check for insecure redirects."""
        findings = []
        
        # Test common redirect parameters
        redirect_params = ['redirect', 'return', 'return_url', 'next', 'url', 'goto', 'destination']
        
        for param in redirect_params:
            try:
                test_url = f"{url}?{param}=http://evil.com"
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if location.startswith('http://'):
                        findings.append(Finding(
                            title="Open Redirect Vulnerability",
                            description=f"Server redirects to external HTTP URLs via {param} parameter, enabling open redirect attacks.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.VULNERABILITY,
                            source_scanner=self.name,
                            url=test_url,
                            remediation="Validate and whitelist redirect URLs. Only allow redirects to same-origin or trusted domains.",
                            references=["https://owasp.org/www-community/vulnerabilities/Unvalidated_Redirects_and_Forwards"]
                        ))
                        break  # Only report once
            except:
                continue
        
        return findings
    
    def is_available(self) -> bool:
        """HTTP security analyzer is always available."""
        return True

