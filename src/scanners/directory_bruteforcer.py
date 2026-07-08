"""Directory and file brute forcing scanner."""

import os
import json
import re
import logging
from typing import List, Optional
from urllib.parse import urljoin

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..utils.response_validation import is_accessible_response, is_blocked_status

logger = logging.getLogger(__name__)


class DirectoryBruteforcer(BaseScanner):
    """Directory and file brute forcing using ffuf or similar tools."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE, wordlist: Optional[str] = None):
        """
        Initialize directory bruteforcer.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
            wordlist: Path to wordlist file (optional, will use default if available)
        """
        super().__init__(
            name="directory_bruteforcer",
            command="ffuf",  # Try ffuf first
            enabled=enabled,
            scan_mode=scan_mode
        )
        self.wordlist = wordlist
        self.fallback_command = "gobuster"  # Fallback to gobuster
    
    def is_available(self) -> bool:
        """Check if ffuf or gobuster is available."""
        try:
            import shutil
            # Check ffuf in common locations
            if shutil.which("ffuf") or shutil.which(os.path.expanduser("~/go/bin/ffuf")):
                return True
            # Check gobuster as fallback
            if shutil.which(self.fallback_command):
                return True
            return False
        except:
            return False
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run directory brute forcing on target."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            # Directory brute forcing is offensive-only
            return []
        
        if not self.is_available():
            # Not critical, just skip
            import logging
            logger = logging.getLogger(__name__)
            logger.warning("Directory bruteforcer not available (ffuf/gobuster not found). Skipping.")
            return []
        
        findings = []
        
        # Use ffuf if available, otherwise gobuster
        if self._check_command("ffuf"):
            findings.extend(self._scan_with_ffuf(target))
        elif self._check_command("gobuster"):
            findings.extend(self._scan_with_gobuster(target))
        else:
            # Try to find ffuf in Go bin path
            import os
            go_bin_ffuf = os.path.expanduser("~/go/bin/ffuf")
            if os.path.exists(go_bin_ffuf):
                # Temporarily update command path
                original_cmd = self.command
                self.command = go_bin_ffuf
                findings.extend(self._scan_with_ffuf(target))
                self.command = original_cmd
        
        return findings
    
    def _check_command(self, cmd: str) -> bool:
        """Check if a command is available."""
        try:
            import shutil
            import os
            # Check in PATH
            if shutil.which(cmd):
                return True
            # Check common Go binary locations
            if cmd == "ffuf":
                go_path = os.path.expanduser("~/go/bin/ffuf")
                if os.path.exists(go_path):
                    return True
            return False
        except:
            return False
    
    def _scan_with_ffuf(self, target: ScanTarget) -> List[Finding]:
        """Scan using ffuf."""
        findings = []
        
        # Common WordPress directories/files to check
        wordlist_items = [
            "wp-admin", "wp-content", "wp-includes", "wp-login.php",
            "wp-config.php", "readme.html", "license.txt", ".htaccess",
            "xmlrpc.php", "wp-cron.php", "wp-mail.php",
            "backup", "backups", "old", "test", "admin", "administrator",
            "uploads", "files", "private", "secret", "hidden",
        ]
        
        # Create temporary wordlist
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for item in wordlist_items:
                f.write(f"{item}\n")
            temp_wordlist = f.name
        
        try:
            # Determine ffuf path
            import shutil
            import os
            ffuf_path = shutil.which("ffuf")
            if not ffuf_path:
                ffuf_path = os.path.expanduser("~/go/bin/ffuf")
            if not os.path.exists(ffuf_path):
                ffuf_path = "ffuf"  # Fallback to PATH
            
            # Run ffuf
            args = [
                "-u", f"{target.url}/FUZZ",
                "-w", temp_wordlist,
                "-t", "10",  # 10 threads
                "-mc", "200,204,301,302,307",  # Only match actual success/redirect codes (exclude 401,403 to avoid false positives)
                "-fs", "0",  # Filter out 0-byte responses
                "-s",  # Silent mode
                "-o", "/tmp/ffuf_output.json",
                "-of", "json",
            ]
            
            # Use subprocess directly if command path is absolute
            if os.path.isabs(ffuf_path):
                import subprocess
                result = subprocess.run(
                    [ffuf_path] + args,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    errors='replace',
                )
                stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
            else:
                # Use base class method
                original_cmd = self.command
                self.command = ffuf_path
                stdout, stderr, returncode = self.run_command(args, timeout=120)
                self.command = original_cmd
            
            # Parse results and verify each finding
            try:
                with open("/tmp/ffuf_output.json", "r") as f:
                    data = json.load(f)
                    results = data.get("results", [])
                    
                    # Import session for verification
                    from ..utils.scanner_session import create_scanner_session
                    verify_session = create_scanner_session()
                    
                    for result in results[:20]:  # Limit to top 20 findings
                        url_path = result.get("url", "")
                        status = result.get("status", 0)
                        size = result.get("length", 0)
                        
                        if status == 404 or is_blocked_status(status):
                            continue

                        # Only report actual successful responses (200, 204) or valid redirects
                        if status in [200, 204]:
                            try:
                                verify_response = verify_session.get(url_path, timeout=5, allow_redirects=True)
                                if not is_accessible_response(verify_response):
                                    continue
                            except Exception as e:
                                logger.debug(f"Could not verify {url_path}: {e}")
                                continue
                            
                            # Determine severity based on what was found
                            path = url_path.replace(target.url, "").strip("/")
                            
                            if any(sensitive in path.lower() for sensitive in ["wp-config", "backup", "secret", "private", ".htaccess"]):
                                severity = FindingSeverity.HIGH
                            elif any(admin in path.lower() for admin in ["admin", "administrator", "wp-admin"]):
                                severity = FindingSeverity.MEDIUM
                            else:
                                severity = FindingSeverity.LOW
                            
                            findings.append(Finding(
                                title=f"Directory/File Discovered: {path}",
                                description=f"Directory brute forcing discovered {path} at {url_path} (Status: {status}, Size: {size} bytes). This may expose sensitive information or functionality.",
                                severity=severity,
                                category=FindingCategory.EXPOSED_ENDPOINT,
                                source_scanner="directory_bruteforcer",
                                source_id=f"discovered_{path.replace('/', '_')}",
                                url=url_path,
                                remediation=f"Review if {path} should be publicly accessible. Restrict access if it contains sensitive information.",
                                metadata={"status_code": status, "size": size, "path": path},
                            ))
                        
                        # Handle redirects (301, 302, 307) - follow and verify
                        elif status in [301, 302, 307]:
                            try:
                                verify_response = verify_session.get(url_path, timeout=5, allow_redirects=True)
                                final_status = verify_response.status_code
                                
                                # Only report if redirect leads to actual content (200), not error pages
                                if final_status == 200 and is_accessible_response(verify_response):
                                    path = url_path.replace(target.url, "").strip("/")

                                    if any(sensitive in path.lower() for sensitive in ["wp-config", "backup", "secret", "private", ".htaccess"]):
                                        severity = FindingSeverity.HIGH
                                    elif any(admin in path.lower() for admin in ["admin", "administrator", "wp-admin"]):
                                        severity = FindingSeverity.MEDIUM
                                    else:
                                        severity = FindingSeverity.LOW

                                    findings.append(Finding(
                                        title=f"Directory/File Discovered: {path}",
                                        description=f"Directory brute forcing discovered {path} at {url_path} (Status: {status}, redirects to {verify_response.url}). This may expose sensitive information or functionality.",
                                        severity=severity,
                                        category=FindingCategory.EXPOSED_ENDPOINT,
                                        source_scanner="directory_bruteforcer",
                                        source_id=f"discovered_{path.replace('/', '_')}",
                                        url=url_path,
                                        remediation=f"Review if {path} should be publicly accessible. Restrict access if it contains sensitive information.",
                                        metadata={"status_code": status, "final_status": final_status, "redirect_url": str(verify_response.url), "path": path},
                                    ))
                            except Exception as e:
                                # If redirect verification fails, skip to avoid false positives
                                import logging
                                logger = logging.getLogger(__name__)
                                logger.debug(f"Could not verify redirect {url_path}: {e}")
                                continue
                                
            except (FileNotFoundError, json.JSONDecodeError):
                pass
        
        finally:
            # Clean up temp wordlist
            try:
                os.unlink(temp_wordlist)
            except:
                pass
        
        return findings
    
    def _scan_with_gobuster(self, target: ScanTarget) -> List[Finding]:
        """Scan using gobuster (fallback)."""
        findings = []
        
        # Gobuster implementation would go here
        # For now, return empty as ffuf is preferred
        return findings

