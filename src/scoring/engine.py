"""Risk scoring engine implementation."""

from typing import List

from ..models.finding import Finding
from ..models.risk import RiskScore
from ..models.scan import ScanResult


class RiskScoringEngine:
    """Engine for calculating risk scores from findings."""
    
    @staticmethod
    def calculate_risk(scan_result: ScanResult) -> RiskScore:
        """
        Calculate risk score for scan result.
        
        Args:
            scan_result: Scan result containing findings
            
        Returns:
            RiskScore object
        """
        return RiskScore.calculate(scan_result.findings)
    
    @staticmethod
    def enhance_findings_with_remediation(findings: List[Finding]) -> List[Finding]:
        """
        Enhance findings with additional remediation guidance if missing.
        
        Args:
            findings: List of findings to enhance
            
        Returns:
            Enhanced findings
        """
        enhanced = []
        for finding in findings:
            if not finding.remediation:
                finding.remediation = RiskScoringEngine._generate_remediation(finding)
            enhanced.append(finding)
        return enhanced
    
    @staticmethod
    def _generate_remediation(finding: Finding) -> str:
        """Generate remediation guidance for a finding."""
        category = finding.category
        severity = finding.severity
        
        from ..models.finding import FindingCategory, FindingSeverity
        
        base_remediation = {
            FindingCategory.VULNERABILITY: "Apply security patches or updates. Review vendor advisories for specific remediation steps.",
            FindingCategory.MISCONFIGURATION: "Review and correct the security configuration. Follow security best practices and hardening guides.",
            FindingCategory.INFORMATION_DISCLOSURE: "Restrict access to sensitive information. Implement proper access controls.",
            FindingCategory.EXPOSED_ENDPOINT: "Remove or restrict access to exposed endpoints. Ensure only necessary endpoints are publicly accessible.",
            FindingCategory.WEAK_SECURITY: "Strengthen security controls. Replace weak protocols with secure alternatives.",
            FindingCategory.FINGERPRINTING: "Minimize information disclosure that aids attackers in reconnaissance.",
            FindingCategory.OTHER: "Review the finding and implement appropriate security controls.",
        }
        
        remediation = base_remediation.get(category, "Review and address the security issue.")
        
        if severity == FindingSeverity.CRITICAL:
            remediation = f"URGENT: {remediation} This is a critical finding requiring immediate attention."
        elif severity == FindingSeverity.HIGH:
            remediation = f"HIGH PRIORITY: {remediation}"
        
        return remediation

