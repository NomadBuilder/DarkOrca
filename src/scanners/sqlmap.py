"""SQLMap adapter for SQL injection exploitation."""

import os
import json
import re
from typing import List, Optional

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode


class SQLMapAdapter(BaseScanner):
    """Adapter for SQLMap SQL injection exploitation tool."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize SQLMap adapter.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (only works in offensive mode)
        """
        super().__init__(
            name="sqlmap",
            command="sqlmap",
            enabled=enabled,
            scan_mode=scan_mode
        )
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run SQLMap on target."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            # SQLMap is offensive-only
            return []
        
        if not self.is_available():
            raise RuntimeError("SQLMap is not available. Please install it: https://github.com/sqlmapproject/sqlmap")
        
        findings = []
        
        # SQLMap requires specific URL parameters to test
        # For now, we'll test the base URL and common parameters
        test_urls = [
            f"{target.url}?id=1",  # Most common SQL injection point
            f"{target.url}?page=1",
        ]
        
        for test_url in test_urls:
            try:
                # Build SQLMap command arguments (optimized for speed)
                args = [
                    "-u", test_url,
                    "--batch",  # Non-interactive mode
                    "--level", "1",  # Reduced level for speed (1-5, default 1)
                    "--risk", "1",  # Reduced risk for speed (1-3, default 1)
                    "--threads", "1",  # Single thread to be respectful
                    "--timeout", "5",  # Reduced timeout for speed
                    "--retries", "0",  # No retries for speed
                    "--technique", "BEUSTQ",  # All techniques but faster
                    "--tamper", "",  # No tamper scripts for speed
                    "--output-dir", "/tmp/sqlmap_output",  # Output directory
                    "--fresh-queries",  # Don't use cached queries
                ]
                
                stdout, stderr, returncode = self.run_command(args, timeout=60)  # Reduced from 120 to 60 seconds
                
                # Parse SQLMap output for SQL injection findings
                # Only report actual vulnerabilities, not false positives from disclaimer text
                if stdout:
                    # Check for actual vulnerability indicators (not just disclaimer)
                    # SQLMap outputs specific patterns when it finds vulnerabilities
                    vulnerability_indicators = [
                        r'is vulnerable',
                        r'parameter.*is vulnerable',
                        r'GET parameter.*is vulnerable',
                        r'POST parameter.*is vulnerable',
                        r'injection found',
                        r'payload.*worked',
                        r'back-end DBMS:',  # Database type detection means vulnerability found
                    ]
                    
                    # Check if any real vulnerability indicators are present
                    # Exclude disclaimer text
                    output_lower = stdout.lower()
                    has_vulnerability = False
                    
                    # Skip if output is just the banner/disclaimer
                    if len(stdout.strip()) < 200:  # Just banner, no real output
                        continue
                    
                    for pattern in vulnerability_indicators:
                        if re.search(pattern, output_lower):
                            # Make sure it's not in the disclaimer
                            if "legal disclaimer" not in output_lower[:500]:  # Check first part
                                has_vulnerability = True
                                break
                    
                    if has_vulnerability:
                        # Extract vulnerability details
                        db_type_match = re.search(r'back-end DBMS: ([\w\s]+)', stdout, re.IGNORECASE)
                        db_type = db_type_match.group(1).strip() if db_type_match else None
                        
                        param_match = re.search(r'Parameter: (\w+)', stdout, re.IGNORECASE)
                        if not param_match:
                            param_match = re.search(r'(GET|POST) parameter [\'"]?(\w+)', stdout, re.IGNORECASE)
                            param = param_match.group(2) if param_match else None
                        else:
                            param = param_match.group(1)
                        
                        # Only create finding if we have actual confirmation
                        if db_type or param:
                            finding = Finding(
                                title=f"SQL Injection Vulnerability Detected",
                                description=f"SQLMap confirmed SQL injection vulnerability{f' in parameter \'{param}\'' if param else ''} at {test_url}{f'. Backend DBMS: {db_type}' if db_type else ''}.",
                                severity=FindingSeverity.CRITICAL,
                                category=FindingCategory.EXPLOITATION,
                                source_scanner="sqlmap",
                                source_id="sql_injection",
                                url=test_url,
                                evidence=stdout[:1000] if len(stdout) > 1000 else stdout,  # More evidence
                                exploited=True,
                                exploitation_details=f"SQL injection confirmed{f' in parameter \'{param}\'' if param else ''}{f'. Database type: {db_type}' if db_type else ''}.",
                                remediation="Fix SQL injection by using parameterized queries/prepared statements. Never concatenate user input into SQL queries.",
                                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                            )
                            findings.append(finding)
            
            except TimeoutError:
                continue  # Skip this URL if it times out
            except Exception as e:
                # Log but continue
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"SQLMap scan failed for {test_url}: {e}")
                continue
        
        return findings

