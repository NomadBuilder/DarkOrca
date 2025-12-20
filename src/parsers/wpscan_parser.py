"""Parser for WPScan JSON output."""

import json
from typing import List, Dict, Any, Optional

from ..models.finding import Finding, FindingSeverity, FindingCategory


class WPScanParser:
    """Parse WPScan JSON output into Finding objects."""
    
    @staticmethod
    def parse(json_output: str) -> List[Finding]:
        """
        Parse WPScan JSON output.
        
        WPScan JSON structure:
        {
            "version": {...},
            "plugins": {...},
            "themes": {...},
            "users": {...},
            "main_theme": {...},
            "interesting_findings": [...],
            "version": {...}
        }
        """
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid WPScan JSON: {e}")
        
        findings = []
        
        # Parse version vulnerabilities
        if "version" in data and data["version"]:
            version_data = data["version"]
            if "vulnerabilities" in version_data:
                for vuln in version_data["vulnerabilities"]:
                    findings.append(WPScanParser._parse_vulnerability(
                        vuln,
                        "WordPress Core",
                        version_data.get("number", "unknown"),
                    ))
        
        # Parse plugin vulnerabilities
        if "plugins" in data:
            for plugin_name, plugin_data in data["plugins"].items():
                if "vulnerabilities" in plugin_data:
                    for vuln in plugin_data["vulnerabilities"]:
                        findings.append(WPScanParser._parse_vulnerability(
                            vuln,
                            f"Plugin: {plugin_name}",
                            plugin_data.get("version", "unknown"),
                        ))
        
        # Parse theme vulnerabilities
        if "themes" in data:
            for theme_name, theme_data in data["themes"].items():
                if "vulnerabilities" in theme_data:
                    for vuln in theme_data["vulnerabilities"]:
                        findings.append(WPScanParser._parse_vulnerability(
                            vuln,
                            f"Theme: {theme_name}",
                            theme_data.get("version", "unknown"),
                        ))
        
        # Parse user enumeration findings
        if "users" in data and data["users"]:
            users_data = data["users"]
            user_list = []
            
            # Handle both list and dict formats
            if isinstance(users_data, list):
                user_list = users_data
            elif isinstance(users_data, dict):
                user_list = list(users_data.keys())
            
            user_count = len(user_list)
            if user_count > 0:
                # Extract usernames if available
                usernames = []
                if isinstance(users_data, dict):
                    for username, user_info in users_data.items():
                        if isinstance(user_info, dict):
                            usernames.append(username)
                        else:
                            usernames.append(str(user_info))
                else:
                    usernames = [str(u) for u in user_list[:10]]  # Limit to first 10
                
                username_list = ", ".join(usernames[:5])  # Show first 5
                if len(usernames) > 5:
                    username_list += f", and {len(usernames) - 5} more"
                
                findings.append(Finding(
                    title="WordPress User Enumeration Successful",
                    description=f"WPScan successfully enumerated {user_count} WordPress user(s): {username_list}. This information can be used for targeted brute-force attacks.",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.INFORMATION_DISCLOSURE,
                    source_scanner="wpscan",
                    source_id="user_enumeration",
                    remediation="Disable user enumeration by blocking access to author archives (/author/username), REST API user endpoints (/wp-json/wp/v2/users), and XML-RPC user enumeration.",
                    metadata={"user_count": user_count, "usernames": usernames},
                ))
        
        # Parse interesting findings
        if "interesting_findings" in data:
            for finding_data in data["interesting_findings"]:
                findings.append(WPScanParser._parse_interesting_finding(finding_data))
        
        # Parse detected plugins and themes (even without vulnerabilities)
        if "plugins" in data:
            for plugin_name, plugin_data in data["plugins"].items():
                if isinstance(plugin_data, dict):
                    version = plugin_data.get("version", "unknown")
                    # Handle None version (intentionally hidden for security)
                    if version is None or version == "None" or str(version).lower() == "none":
                        version_display = "hidden (not disclosed)"
                        description = f"Plugin '{plugin_name}' is installed. Review for known vulnerabilities and keep updated."
                    else:
                        version_display = version
                        description = f"Plugin '{plugin_name}' version {version} is installed. Review for known vulnerabilities and keep updated."
                    
                    # Create info finding for detected plugin
                    # Format plugin name for title
                    plugin_title = plugin_name.replace('-', ' ').replace('_', ' ').title()
                    findings.append(Finding(
                        title=f"WordPress Plugin Detected: {plugin_title}",
                        description=description,
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner="wpscan",
                        source_id=f"plugin_{plugin_name}",
                        remediation=f"Keep plugin '{plugin_name}' updated to the latest version. Review changelog for security patches.",
                        metadata={"plugin": plugin_name, "version": version, "version_display": version_display, "wpscan_data": plugin_data},
                    ))
        
        # Parse detected themes
        if "themes" in data:
            for theme_name, theme_data in data["themes"].items():
                if isinstance(theme_data, dict):
                    version = theme_data.get("version", "unknown")
                    # Handle None version (intentionally hidden for security)
                    if version is None or version == "None" or str(version).lower() == "none":
                        version_display = "hidden (not disclosed)"
                        description = f"Theme '{theme_name}' is installed. Review for known vulnerabilities and keep updated."
                    else:
                        version_display = version
                        description = f"Theme '{theme_name}' version {version} is installed. Review for known vulnerabilities and keep updated."
                    
                    # Format theme name for title
                    theme_title = theme_name.replace('-', ' ').replace('_', ' ').title()
                    findings.append(Finding(
                        title=f"WordPress Theme Detected: {theme_title}",
                        description=description,
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner="wpscan",
                        source_id=f"theme_{theme_name}",
                        remediation=f"Keep theme '{theme_name}' updated to the latest version. Review changelog for security patches.",
                        metadata={"theme": theme_name, "version": version, "version_display": version_display, "wpscan_data": theme_data},
                    ))
        
        # Parse WordPress version
        if "version" in data and data["version"]:
            version_data = data["version"]
            if isinstance(version_data, dict):
                wp_version = version_data.get("number", "unknown")
                if wp_version != "unknown":
                    findings.append(Finding(
                        title=f"WordPress Version Detected: {wp_version}",
                        description=f"WordPress version {wp_version} is running. Check for known vulnerabilities in this version.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.FINGERPRINTING,
                        source_scanner="wpscan",
                        source_id="wp_version",
                        remediation=f"Keep WordPress updated to the latest version. Current version {wp_version} may have known security issues.",
                        metadata={"version": wp_version, "wpscan_data": version_data},
                    ))
        
        return findings
    
    @staticmethod
    def _parse_vulnerability(vuln: Dict[str, Any], component: str, version: str) -> Finding:
        """Parse a vulnerability entry."""
        title = vuln.get("title", "Unknown Vulnerability")
        cve = vuln.get("cve")
        severity_str = vuln.get("severity", "medium").lower()
        
        # Map WPScan severity to our severity
        severity_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
        }
        severity = severity_map.get(severity_str, FindingSeverity.MEDIUM)
        
        description = f"Vulnerability in {component}"
        if version and version != "unknown":
            description += f" version {version}"
        description += f": {title}"
        if cve:
            description += f" - CVE {cve}"
        
        references = []
        if "references" in vuln:
            refs = vuln["references"]
            if isinstance(refs, dict):
                for ref_type, ref_list in refs.items():
                    if isinstance(ref_list, list):
                        references.extend(ref_list)
        
        remediation = f"Update {component} to a version that addresses this vulnerability."
        if cve:
            remediation += f" See CVE-{cve} for details."
        
        return Finding(
            title=f"{component} Vulnerability: {title}",
            description=description,
            severity=severity,
            category=FindingCategory.VULNERABILITY,
            source_scanner="wpscan",
            source_id=cve or title,
            cve=cve,
            remediation=remediation,
            references=references,
            metadata={
                "component": component,
                "version": version,
                "wpscan_data": vuln,
            },
        )
    
    @staticmethod
    def _parse_interesting_finding(finding_data: Dict[str, Any]) -> Finding:
        """Parse an interesting finding entry."""
        import requests
        
        url = finding_data.get("url", "")
        finding_type = finding_data.get("type", "unknown")
        
        # Skip low-value findings that are often false positives
        skip_types = ["headers", "license", "readme"]  # These are usually not security issues
        
        if finding_type in skip_types:
            # Still create finding but with INFO severity and note it's informational
            finding_type_formatted = finding_type.replace('_', ' ').title()
            return Finding(
                title=f"{finding_type_formatted} File Detected",
                description=f"WPScan detected {finding_type} file at {url}. This is typically informational and not a security concern.",
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner="wpscan",
                source_id=f"interesting_{finding_type}",
                url=url,
                remediation=f"The {finding_type} file is typically harmless. No action required unless it contains sensitive information.",
                metadata={"finding_type": finding_type, "wpscan_data": finding_data, "is_accessible": True},
            )
        
        # For xmlrpc findings, verify if it's actually accessible (not 403)
        is_accessible = True
        if finding_type == "xmlrpc" or "xmlrpc" in url.lower():
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)
                if response.status_code == 403:
                    # 403 means protected, not exposed - update description
                    is_accessible = False
                elif response.status_code == 404:
                    # 404 means not found - also not exposed
                    is_accessible = False
            except:
                # If we can't verify, assume it might be accessible
                pass
        
        # Map finding types to categories
        category_map = {
            "backup": FindingCategory.EXPOSED_ENDPOINT,
            "config": FindingCategory.INFORMATION_DISCLOSURE,
            "debug": FindingCategory.INFORMATION_DISCLOSURE,
            "error": FindingCategory.INFORMATION_DISCLOSURE,
            "readme": FindingCategory.INFORMATION_DISCLOSURE,
            "robots": FindingCategory.INFORMATION_DISCLOSURE,
        }
        category = category_map.get(finding_type, FindingCategory.OTHER)
        
        severity = FindingSeverity.LOW
        if finding_type in ["backup", "config"]:
            severity = FindingSeverity.MEDIUM
        
        # Format finding type nicely
        finding_type_formatted = finding_type.replace('_', ' ').title()
        
        # Adjust title and description based on accessibility
        if not is_accessible and (finding_type == "xmlrpc" or "xmlrpc" in url.lower()):
            title = f"{finding_type_formatted} File Detected (Protected)"
            description = f"WPScan detected {finding_type} file at {url}, but access is blocked (403 Forbidden). This indicates the file exists but is protected, which is a good security practice."
            severity = FindingSeverity.INFO  # Lower severity since it's protected
            remediation = f"The {finding_type} file is currently protected. No action needed unless you want to completely remove it."
        else:
            title = f"{finding_type_formatted} File"
            description = f"WPScan detected an exposed {finding_type} file at {url}. This may reveal sensitive information."
            remediation = f"Remove or restrict access to {url}. Ensure sensitive files are not publicly accessible."
        
        return Finding(
            title=title,
            description=description,
            severity=severity,
            category=category,
            source_scanner="wpscan",
            source_id=f"interesting_{finding_type}",
            url=url,
            remediation=remediation,
            metadata={"finding_type": finding_type, "wpscan_data": finding_data, "is_accessible": is_accessible},
        )

