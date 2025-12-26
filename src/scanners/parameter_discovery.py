"""HTTP parameter discovery scanner using Arjun."""

import os
import json
from typing import List, Optional

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode


class ParameterDiscovery(BaseScanner):
    """HTTP parameter discovery using Arjun."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize parameter discovery scanner.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="parameter_discovery",
            command="arjun",
            enabled=enabled,
            scan_mode=scan_mode
        )
    
    def is_available(self) -> bool:
        """Check if arjun is available."""
        try:
            import shutil
            import os
            # Check in PATH
            if shutil.which("arjun"):
                return True
            # Check common installation paths
            common_paths = [
                "/opt/homebrew/bin/arjun",
                "/usr/local/bin/arjun",
                os.path.expanduser("~/go/bin/arjun"),
            ]
            for path in common_paths:
                if os.path.exists(path):
                    return True
            return False
        except:
            return False
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run parameter discovery on target."""
        if self.scan_mode == ScanMode.DEFENSIVE:
            # Parameter discovery is offensive-only
            return []
        
        if not self.is_available():
            # Not critical, just skip
            import logging
            logger = logging.getLogger(__name__)
            logger.warning("Parameter discovery not available (Arjun not found). Skipping.")
            return []
        
        findings = []
        
        try:
            # Find arjun path
            import shutil
            import os
            arjun_path = shutil.which("arjun")
            if not arjun_path:
                for path in ["/opt/homebrew/bin/arjun", "/usr/local/bin/arjun"]:
                    if os.path.exists(path):
                        arjun_path = path
                        break
                if not arjun_path:
                    arjun_path = "arjun"  # Fallback
            
            # Run Arjun
            args = [
                "-u", target.url,
                "-o", "/tmp/arjun_output.json",
                "-q",  # Quiet mode
                "-t", "10",  # 10 threads
            ]
            
            # Use subprocess directly if absolute path
            if os.path.isabs(arjun_path):
                import subprocess
                result = subprocess.run(
                    [arjun_path] + args,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    errors='replace',
                )
                stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
            else:
                original_cmd = self.command
                self.command = arjun_path
                stdout, stderr, returncode = self.run_command(args, timeout=120)
                self.command = original_cmd
            
            # Parse results
            try:
                with open("/tmp/arjun_output.json", "r") as f:
                    data = json.load(f)
                    
                    # Arjun output format may vary, handle different formats
                    if isinstance(data, dict):
                        params = data.get("params", []) or data.get("parameters", [])
                    elif isinstance(data, list):
                        params = data
                    else:
                        params = []
                    
                    if params:
                        # Group parameters by URL if multiple URLs tested
                        param_dict = {}
                        for param in params:
                            if isinstance(param, dict):
                                url = param.get("url", target.url)
                                param_name = param.get("name") or param.get("parameter")
                                if url and param_name:
                                    if url not in param_dict:
                                        param_dict[url] = []
                                    param_dict[url].append(param_name)
                            elif isinstance(param, str):
                                # Simple list of parameter names
                                if target.url not in param_dict:
                                    param_dict[target.url] = []
                                param_dict[target.url].append(param)
                        
                        for url, param_list in param_dict.items():
                            if param_list:
                                # Filter out HTML-escaped entities (false positives from HTML scraping)
                                # Common patterns: &lt; (less than), &amp; (ampersand), &quot; (quote), etc.
                                html_entity_patterns = ['&lt;', '&gt;', '&amp;', '&quot;', '&nbsp;', '&apos;']
                                filtered_params = [
                                    p for p in param_list 
                                    if not any(entity in p for entity in html_entity_patterns)
                                    and not p.startswith('&')  # Filter params starting with &
                                    and len(p) > 1  # Filter single character "params"
                                ]
                                
                                if not filtered_params:
                                    # All params were HTML entities - skip this finding
                                    continue
                                
                                # Check for sensitive parameters
                                sensitive_params = [p for p in filtered_params if any(
                                    keyword in p.lower() for keyword in 
                                    ["pass", "password", "token", "key", "secret", "auth", "admin", "id", "user"]
                                )]
                                
                                # Parameter discovery is informational - finding parameters doesn't mean vulnerability
                                severity = FindingSeverity.INFO  # Changed from HIGH/MEDIUM - just discovery, not vulnerability
                                
                                # Don't create "sensitive data exposure" findings - parameters with "password" etc. are common in forms
                                # These are just form field names, not exposed data
                                findings.append(Finding(
                                    title=f"HTTP Parameters Discovered ({len(param_list)} parameters)",
                                    description=f"Parameter discovery found {len(filtered_params)} parameter(s) for {url}: {', '.join(filtered_params[:10])}{'...' if len(filtered_params) > 10 else ''}. {'Parameters with sensitive-sounding names: ' + ', '.join(sensitive_params) if sensitive_params else ''} Note: Parameter names alone do not indicate a vulnerability - these may be form field names. HTML-escaped entities have been filtered out.",
                                    severity=severity,
                                    category=FindingCategory.FINGERPRINTING,  # Changed from INFORMATION_DISCLOSURE - just discovery
                                    source_scanner="parameter_discovery",
                                    source_id="discovered_parameters",
                                    url=url,
                                    remediation="Review discovered parameters for security implications. Test for injection vulnerabilities, authorization bypass, and information disclosure. Note: Parameter names like 'password' are common in forms and do not indicate data exposure.",
                                    metadata={"parameters": filtered_params, "sensitive_params": sensitive_params, "count": len(filtered_params), "filtered_html_entities": len(param_list) - len(filtered_params)},
                                ))
            
            except (FileNotFoundError, json.JSONDecodeError, KeyError):
                # Arjun may not produce JSON in some cases, try parsing stdout
                if stdout and "parameter" in stdout.lower():
                    findings.append(Finding(
                        title="Parameter Discovery Attempted",
                        description="Parameter discovery was attempted but results could not be parsed. Review Arjun output manually.",
                        severity=FindingSeverity.INFO,
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        source_scanner="parameter_discovery",
                        source_id="parameter_discovery_attempted",
                        url=target.url,
                        remediation="Manually review parameter discovery results for potential security issues.",
                        metadata={"raw_output": stdout[:500]},
                    ))
        
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Parameter discovery failed: {e}")
        
        return findings

