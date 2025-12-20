"""Parser for Nuclei JSON output."""

import json
from typing import List, Dict, Any

from ..models.finding import Finding, FindingSeverity, FindingCategory


class NucleiParser:
    """Parse Nuclei JSON output into Finding objects."""
    
    @staticmethod
    def parse(json_output: str) -> List[Finding]:
        """
        Parse Nuclei JSON output.
        
        Nuclei JSON structure (one JSON object per line):
        {
            "template-id": "...",
            "info": {
                "name": "...",
                "severity": "...",
                "description": "...",
                "reference": [...]
            },
            "matched-at": "https://example.com/path",
            "extracted-results": [...],
            "curl-command": "..."
        }
        """
        findings = []
        lines = json_output.strip().split("\n")
        
        for line in lines:
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                finding = NucleiParser._parse_finding(data)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                # Skip invalid JSON lines
                continue
        
        return findings
    
    @staticmethod
    def _parse_finding(data: Dict[str, Any]) -> Finding:
        """Parse a single Nuclei finding."""
        template_id = data.get("template-id", "unknown")
        info = data.get("info", {})
        
        name = info.get("name", "Nuclei Finding")
        description = info.get("description", "No description provided")
        severity_str = info.get("severity", "info").lower()
        matched_at = data.get("matched-at", "")
        references = info.get("reference", [])
        if not isinstance(references, list):
            references = [references] if references else []
        
        # Map Nuclei severity to our severity
        severity_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        severity = severity_map.get(severity_str, FindingSeverity.INFO)
        
        # Adjust severity for generic findings that are over-classified
        severity = NucleiParser._adjust_severity_for_generic_findings(
            template_id, description, name, severity
        )
        
        # Determine category based on template ID and description
        category = NucleiParser._infer_category(template_id, description, severity)
        
        # Extract CVE if present
        cve = None
        if "cve" in template_id.lower() or "cve" in description.lower():
            # Try to extract CVE from description or template ID
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', description + " " + template_id, re.IGNORECASE)
            if cve_match:
                cve = cve_match.group(0)
        
        # Generate remediation guidance
        remediation = NucleiParser._generate_remediation(category, description, template_id)
        
        # Extract evidence
        evidence = None
        if "curl-command" in data:
            evidence = f"Detection command: {data['curl-command']}"
        if "extracted-results" in data and data["extracted-results"]:
            evidence = f"Extracted data: {', '.join(data['extracted-results'])}"
        
        return Finding(
            title=name,
            description=description,
            severity=severity,
            category=category,
            source_scanner="nuclei",
            source_id=template_id,
            url=matched_at,
            evidence=evidence,
            cve=cve,
            remediation=remediation,
            references=references,
            metadata={
                "template_id": template_id,
                "nuclei_data": data,
            },
        )
    
    @staticmethod
    def _adjust_severity_for_generic_findings(
        template_id: str, description: str, name: str, severity: FindingSeverity
    ) -> FindingSeverity:
        """Adjust severity for generic findings that are over-classified."""
        # Combine all text for checking
        combined_text = f"{template_id} {description} {name}".lower()
        
        # SSTI findings without confirmed code execution should be HIGH, not CRITICAL
        if severity == FindingSeverity.CRITICAL:
            if "ssti" in combined_text or "template injection" in combined_text:
                # Only keep as CRITICAL if code execution is explicitly mentioned
                if not any(keyword in combined_text for keyword in [
                    "code execution", "rce", "remote code", "command execution",
                    "arbitrary code", "exec(", "popen", "system("
                ]):
                    # Downgrade to HIGH for generic SSTI detection
                    return FindingSeverity.HIGH
        
        # Generic information disclosure findings shouldn't be CRITICAL
        if severity == FindingSeverity.CRITICAL:
            if "information disclosure" in combined_text or "info disclosure" in combined_text:
                # Downgrade generic info disclosure to HIGH
                if not any(keyword in combined_text for keyword in [
                    "credentials", "password", "secret", "api key", "token leak",
                    "private key", "ssh key", "credit card"
                ]):
                    return FindingSeverity.HIGH
        
        # Generic fingerprinting findings should not be CRITICAL
        if severity == FindingSeverity.CRITICAL:
            if any(keyword in combined_text for keyword in [
                "version detection", "technology detection", "framework detected",
                "fingerprint", "version disclosure"
            ]):
                # Downgrade fingerprinting to INFO or LOW
                return FindingSeverity.INFO
        
        return severity
    
    @staticmethod
    def _infer_category(template_id: str, description: str, severity: FindingSeverity) -> FindingCategory:
        """Infer finding category from template ID and description."""
        template_lower = template_id.lower()
        desc_lower = description.lower()
        
        # Check for vulnerability indicators
        if any(keyword in template_lower or keyword in desc_lower for keyword in [
            "cve", "vulnerability", "rce", "sqli", "xss", "ssrf", "xxe", "lfi", "rfi"
        ]):
            return FindingCategory.VULNERABILITY
        
        # Check for misconfiguration
        if any(keyword in template_lower or keyword in desc_lower for keyword in [
            "misconfig", "exposed", "default", "weak", "insecure"
        ]):
            return FindingCategory.MISCONFIGURATION
        
        # Check for information disclosure
        if any(keyword in template_lower or keyword in desc_lower for keyword in [
            "disclosure", "leak", "exposed", "sensitive", "credential", "token", "api-key"
        ]):
            return FindingCategory.INFORMATION_DISCLOSURE
        
        # Check for exposed endpoints
        if any(keyword in template_lower or keyword in desc_lower for keyword in [
            "endpoint", "path", "directory", "file", "backup", "config"
        ]):
            return FindingCategory.EXPOSED_ENDPOINT
        
        # Default based on severity
        if severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
            return FindingCategory.VULNERABILITY
        elif severity == FindingSeverity.MEDIUM:
            return FindingCategory.MISCONFIGURATION
        else:
            return FindingCategory.OTHER
    
    @staticmethod
    def _generate_remediation(category: FindingCategory, description: str, template_id: str) -> str:
        """Generate remediation guidance based on category."""
        if category == FindingCategory.VULNERABILITY:
            return "Review and apply security patches or updates. If a CVE is referenced, check vendor advisories for specific remediation steps."
        elif category == FindingCategory.MISCONFIGURATION:
            return "Review and correct the security configuration. Ensure default credentials are changed and unnecessary services are disabled."
        elif category == FindingCategory.INFORMATION_DISCLOSURE:
            return "Restrict access to sensitive information. Implement proper access controls and ensure sensitive data is not exposed in error messages or responses."
        elif category == FindingCategory.EXPOSED_ENDPOINT:
            return "Remove or restrict access to exposed endpoints. Ensure only necessary endpoints are publicly accessible."
        else:
            return "Review the finding and implement appropriate security controls based on the specific issue."

