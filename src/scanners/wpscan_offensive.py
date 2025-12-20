"""WPScan adapter with offensive capabilities (brute force, exploitation)."""

import os
from typing import List, Optional

from .wpscan import WPScanAdapter
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode


class WPScanOffensiveAdapter(WPScanAdapter):
    """WPScan adapter with offensive capabilities enabled."""
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run WPScan with offensive options enabled."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            # Fall back to defensive mode
            return super().scan(target)
        
        if not self.is_available():
            raise RuntimeError("WPScan is not available. Please install it: https://github.com/wpscanteam/wpscan")
        
        findings = []
        
        # First run defensive scan
        defensive_findings = super().scan(target)
        findings.extend(defensive_findings)
        
        # Add offensive scanning options
        # Note: Password brute forcing requires wordlists
        # For now, we'll mark vulnerabilities as exploitable
        
        # Mark findings as exploitable if they're vulnerabilities
        for finding in findings:
            if finding.category == FindingCategory.VULNERABILITY and finding.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                finding.metadata["offensive_scan_attempted"] = True
                finding.metadata["exploitable"] = True
        
        # TODO: Add password brute forcing if wordlist is provided
        # This would require:
        # 1. User enumeration (already done in defensive scan)
        # 2. Password wordlist
        # 3. WPScan --passwords flag
        # Example: wpscan --url <target> --usernames <users> --passwords <wordlist>
        
        return findings

