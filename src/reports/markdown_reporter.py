"""Markdown report generator."""

from datetime import datetime
from typing import List

from ..models.scan import ScanResult
from ..models.finding import Finding, FindingSeverity, FindingCategory


class MarkdownReporter:
    """Generate Markdown reports from scan results."""
    
    @staticmethod
    def generate(scan_result: ScanResult) -> str:
        """
        Generate Markdown report.
        
        Args:
            scan_result: Scan result to report
            
        Returns:
            Markdown string
        """
        lines = []
        
        # Header
        lines.append("# Security Scan Report")
        lines.append("")
        lines.append(f"**Target:** {scan_result.target.url}")
        lines.append(f"**Domain:** {scan_result.target.domain}")
        lines.append(f"**Scan Mode:** {scan_result.scan_mode.value.upper()}")
        lines.append(f"**Scan Date:** {scan_result.scan_started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if scan_result.scan_completed_at:
            duration = (scan_result.scan_completed_at - scan_result.scan_started_at).total_seconds()
            lines.append(f"**Scan Duration:** {duration:.1f} seconds")
        if scan_result.scan_mode.value == "offensive" and scan_result.exploitations_successful > 0:
            lines.append(f"**⚠️ Successful Exploitations:** {scan_result.exploitations_successful}")
        lines.append("")
        
        # Risk Score Summary
        if scan_result.risk_score:
            risk = scan_result.risk_score
            lines.append("## Risk Assessment")
            lines.append("")
            lines.append(f"**Overall Risk Score:** {risk.overall_score}/100")
            lines.append(f"**Risk Level:** {risk.risk_level.value.upper()}")
            lines.append("")
            lines.append("### Finding Summary")
            lines.append("")
            lines.append(f"- **Critical:** {risk.critical_count}")
            lines.append(f"- **High:** {risk.high_count}")
            lines.append(f"- **Medium:** {risk.medium_count}")
            lines.append(f"- **Low:** {risk.low_count}")
            lines.append(f"- **Info:** {risk.info_count}")
            lines.append("")
            lines.append(f"**Summary:** {risk.summary}")
            lines.append("")
            
            # Attack Vectors
            if risk.attack_vectors:
                lines.append("### Potential Attack Vectors")
                lines.append("")
                for i, vector in enumerate(risk.attack_vectors, 1):
                    lines.append(f"{i}. {vector}")
                lines.append("")
        
        # Scanners Run
        lines.append("## Scanners Executed")
        lines.append("")
        for scanner in scan_result.scanners_run:
            lines.append(f"- {scanner}")
        lines.append("")
        
        # Scanner Errors
        if scan_result.scanner_errors:
            lines.append("## Scanner Errors")
            lines.append("")
            for scanner, error in scan_result.scanner_errors.items():
                lines.append(f"**{scanner}:** {error}")
            lines.append("")
        
        # Findings by Severity
        findings = scan_result.findings
        if findings:
            lines.append("## Findings")
            lines.append("")
            
            # Group by severity
            for severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM, FindingSeverity.LOW, FindingSeverity.INFO]:
                severity_findings = [f for f in findings if f.severity == severity]
                if not severity_findings:
                    continue
                
                lines.append(f"### {severity.value.upper()} Severity ({len(severity_findings)} finding(s))")
                lines.append("")
                
                for finding in severity_findings:
                    lines.append(MarkdownReporter._format_finding(finding))
                    lines.append("")
        else:
            lines.append("## Findings")
            lines.append("")
            lines.append("No security findings detected.")
            lines.append("")
        
        return "\n".join(lines)
    
    @staticmethod
    def _format_finding(finding: Finding) -> str:
        """Format a single finding as Markdown."""
        lines = []
        
        # Title with severity badge
        severity_badge = {
            FindingSeverity.CRITICAL: "🔴",
            FindingSeverity.HIGH: "🟠",
            FindingSeverity.MEDIUM: "🟡",
            FindingSeverity.LOW: "🟢",
            FindingSeverity.INFO: "ℹ️",
        }
        badge = severity_badge.get(finding.severity, "•")
        lines.append(f"#### {badge} {finding.title}")
        lines.append("")
        
        # Metadata
        meta = []
        meta.append(f"**Category:** {finding.category.value}")
        meta.append(f"**Source:** {finding.source_scanner}")
        if finding.source_id:
            meta.append(f"**ID:** {finding.source_id}")
        if finding.cve:
            meta.append(f"**CVE:** {finding.cve}")
        if finding.url:
            meta.append(f"**URL:** {finding.url}")
        lines.append(" | ".join(meta))
        lines.append("")
        
        # Description
        lines.append(f"**Description:** {finding.description}")
        lines.append("")
        
        # Evidence
        if finding.evidence:
            lines.append(f"**Evidence:** {finding.evidence}")
            lines.append("")
        
        # Exploitation details (if exploited)
        if finding.exploited:
            lines.append("**⚠️ EXPLOITED:** This vulnerability was successfully exploited during the scan.")
            lines.append("")
            if finding.exploitation_details:
                lines.append(f"**Exploitation Details:** {finding.exploitation_details}")
                lines.append("")
        
        # Remediation
        if finding.remediation:
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(f"> {finding.remediation}")
            lines.append("")
        
        # References
        if finding.references:
            lines.append("**References:**")
            lines.append("")
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")
        
        return "\n".join(lines)
    
    @staticmethod
    def save(scan_result: ScanResult, filepath: str):
        """
        Save Markdown report to file.
        
        Args:
            scan_result: Scan result to report
            filepath: Output file path
        """
        markdown = MarkdownReporter.generate(scan_result)
        with open(filepath, "w") as f:
            f.write(markdown)

