"""Backup file and sensitive file exposure scanner."""

import requests
import logging
from typing import List, Optional
from urllib.parse import urljoin

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode

logger = logging.getLogger(__name__)


class BackupFilesScanner(BaseScanner):
    """Scan for exposed backup files and sensitive files."""
    
    # Common backup file extensions and patterns
    BACKUP_PATTERNS = [
        # Backup extensions
        '.bak', '.backup', '.old', '.orig', '.save', '.swp', '.tmp',
        '.bak~', '.bak1', '.bak2', '.back', '.backup1', '.backup2',
        # Version control
        '.git', '.svn', '.hg',
        # Configuration files
        '.env', '.env.local', '.env.production', '.env.development',
        'config.php', 'config.inc.php', 'config.json', 'config.yaml',
        'settings.php', 'database.yml', 'secrets.yml',
        # Database dumps
        '.sql', '.dump', '.db', '.sqlite', '.sqlite3',
        # Archive files
        '.zip', '.tar', '.tar.gz', '.rar', '.7z',
        # IDE files
        '.idea', '.vscode', '.DS_Store', 'Thumbs.db',
        # Log files
        '.log', 'error.log', 'access.log', 'debug.log',
        # Temporary files
        '.tmp', '.temp', '~', '.cache',
    ]
    
    # Sensitive file paths
    SENSITIVE_PATHS = [
        '/.git/config',
        '/.env',
        '/.env.local',
        '/config.php',
        '/wp-config.php',
        '/application.properties',
        '/.htpasswd',
        '/.htaccess',
        '/web.config',
        '/.gitignore',
        '/package.json',
        '/composer.json',
        '/pom.xml',
        '/.dockerignore',
        '/Dockerfile',
    ]
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """Initialize backup files scanner."""
        super().__init__(
            name="backup_files",
            command=None,  # Python-based
            enabled=enabled,
            scan_mode=scan_mode
        )
        # Use OPSEC-enabled session helper
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()
        # Set session-level timeout
        self.session.timeout = 3
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Scan for backup and sensitive files."""
        findings = []
        
        if not self.is_available():
            return findings
        
        # First, verify the target is reachable with a quick HEAD request
        try:
            test_response = self.session.head(target.url, timeout=5, allow_redirects=True)
            if test_response.status_code >= 500:
                logger.warning(f"Target {target.url} returned server error {test_response.status_code}, skipping backup file scan")
                return findings
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            logger.warning(f"Target {target.url} is unreachable or timing out: {e}, skipping backup file scan")
            return findings  # Skip scan if target is unreachable
        except Exception as e:
            logger.debug(f"Could not verify target reachability: {e}, proceeding anyway")
        
        try:
            findings.extend(self._check_backup_files(target.url))
            findings.extend(self._check_sensitive_files(target.url))
            findings.extend(self._check_version_control(target.url))
            
        except Exception as e:
            logger.error(f"Backup files scanning failed: {e}", exc_info=True)
        
        return findings
    
    def _check_backup_files(self, base_url: str) -> List[Finding]:
        """Check for common backup file patterns."""
        findings = []
        
        # Common files that might have backups
        base_files = ['index', 'index.php', 'index.html', 'index.htm', 'config', 'settings', 'database']
        
        for base_file in base_files:
            for ext in self.BACKUP_PATTERNS[:20]:  # Limit to 20 patterns per base file
                try:
                    # Try base file with extension
                    test_url = urljoin(base_url, f"{base_file}{ext}")
                    response = self.session.get(test_url, timeout=3, allow_redirects=False)
                    
                    if response.status_code == 200:
                        # Check if it's actually a backup file (not just a 200 page)
                        content_type = response.headers.get('Content-Type', '').lower()
                        content_length = len(response.content)
                        
                        # Heuristics: backup files usually have specific content types or sizes
                        if any(indicator in content_type for indicator in ['text/', 'application/', 'octet-stream']) or content_length < 1000000:
                            findings.append(Finding(
                                title="Backup File Exposed",
                                description=f"Backup file found: {base_file}{ext} (HTTP 200). This may expose source code or sensitive information.",
                                severity=FindingSeverity.MEDIUM,
                                category=FindingCategory.INFORMATION_DISCLOSURE,
                                source_scanner=self.name,
                                url=test_url,
                                remediation=f"Remove backup file {base_file}{ext} from web-accessible directory. Use version control instead of backup files.",
                                references=["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"]
                            ))
                            break  # Only report once per base file
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                    # Target is unreachable - stop scanning to save time
                    logger.debug(f"Target unreachable during backup file scan, stopping")
                    return findings
                except Exception as e:
                    logger.debug(f"Error checking {test_url}: {e}")
                    continue
        
        return findings
    
    def _check_sensitive_files(self, base_url: str) -> List[Finding]:
        """Check for sensitive configuration files."""
        findings = []
        
        for path in self.SENSITIVE_PATHS:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=3, allow_redirects=False)
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    content = response.text[:500]  # First 500 chars
                    
                    # Check for sensitive indicators
                    sensitive_indicators = ['password', 'secret', 'key', 'token', 'api_key', 'database', 'db_password']
                    
                    if any(indicator in content.lower() for indicator in sensitive_indicators):
                        findings.append(Finding(
                            title="Sensitive Configuration File Exposed",
                            description=f"Sensitive file found: {path} (HTTP 200). File contains potential secrets or credentials.",
                            severity=FindingSeverity.HIGH,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner=self.name,
                            url=test_url,
                            remediation=f"Immediately remove {path} from web-accessible directory. Move configuration files outside web root or restrict access.",
                            references=["https://owasp.org/www-community/vulnerabilities/Information_exposure"]
                        ))
                    else:
                        findings.append(Finding(
                            title="Configuration File Exposed",
                            description=f"Configuration file found: {path} (HTTP 200). Verify it doesn't contain sensitive information.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.INFORMATION_DISCLOSURE,
                            source_scanner=self.name,
                            url=test_url,
                            remediation=f"Restrict access to {path} or move it outside web root.",
                        ))
            except:
                continue
        
        return findings
    
    def _check_version_control(self, base_url: str) -> List[Finding]:
        """Check for exposed version control directories."""
        findings = []
        
        vc_paths = [
            '/.git/',
            '/.git/config',
            '/.svn/',
            '/.hg/',
            '/.gitignore',
        ]
        
        for path in vc_paths:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.get(test_url, timeout=3, allow_redirects=False)
                
                if response.status_code == 200:
                    findings.append(Finding(
                        title="Version Control Directory Exposed",
                        description=f"Version control directory/file found: {path} (HTTP 200). This may expose source code, commit history, and sensitive information.",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        source_scanner=self.name,
                        url=test_url,
                        remediation=f"Remove {path} from web-accessible directory. Ensure .git, .svn, and .hg directories are not accessible via web server.",
                        references=["https://owasp.org/www-community/vulnerabilities/Information_exposure"]
                    ))
                    break  # Only report once
            except:
                continue
        
        return findings
    
    def is_available(self) -> bool:
        """Backup files scanner is always available."""
        return True

