"""Nuclei adapter."""

import os
import json
from typing import List

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding
from ..models.scan_mode import ScanMode
from ..parsers.nuclei_parser import NucleiParser


class NucleiAdapter(BaseScanner):
    """Adapter for Nuclei vulnerability scanner."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize Nuclei adapter.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="nuclei",
            command="nuclei",
            enabled=enabled,
            scan_mode=scan_mode
        )
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run Nuclei on target."""
        if not self.is_available():
            raise RuntimeError("Nuclei is not available. Please install it: https://github.com/projectdiscovery/nuclei")
        
        # Build Nuclei command arguments
        args = [
            "-u", target.url,
            "-jsonl",  # JSON lines format (correct for Nuclei v3)
            "-no-color",
            "-silent",
        ]
        
        # Configure based on scan mode
        if self.scan_mode == ScanMode.DEFENSIVE:
            # Defensive mode: Only passive/info templates
            args.extend([
                "-severity", "info,low,medium",
                "-tags", "passive,info,exposure",
            ])
        else:
            # Offensive mode: All severities including exploits
            # Add WordPress-specific tags for better coverage
            args.extend([
                "-severity", "info,low,medium,high,critical",
                "-tags", "wordpress,wp,cms",  # WordPress-specific templates
            ])
        
        # Common settings
        args.extend([
            # Rate limiting to be respectful (increased for speed)
            "-rate-limit", "100",
            # Timeout per request (reduced for speed)
            "-timeout", "5",
            # Retry failed requests
            "-retries", "1",
            # Limit number of templates to speed up
            "-l", "50",  # Limit to 50 templates max
        ])
        
        # Run scan
        try:
            stdout, stderr, returncode = self.run_command(args, timeout=120)  # Reduced from 300 to 120 seconds
        except TimeoutError:
            # Return empty findings rather than failing completely
            return []
        except Exception as e:
            raise RuntimeError(f"Nuclei execution failed: {e}")
        
        # Nuclei outputs one JSON object per line
        if not stdout or not stdout.strip():
            # Check stderr for meaningful errors
            if stderr and "error" in stderr.lower() and "no templates" not in stderr.lower():
                # "no templates" is OK - just means no matching templates
                raise RuntimeError(f"Nuclei error: {stderr[:500]}")  # Limit error message length
            return []
        
        # Parse output
        try:
            findings = NucleiParser.parse(stdout)
            return findings
        except Exception as e:
            # If parsing fails, log but don't fail completely
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to parse some Nuclei output: {e}")
            # Try to parse what we can
            try:
                # Try parsing line by line
                lines = stdout.strip().split("\n")
                findings = []
                for line in lines:
                    if line.strip():
                        try:
                            finding = NucleiParser._parse_finding(json.loads(line))
                            if finding:
                                findings.append(finding)
                        except:
                            continue
                return findings
            except:
                return []  # Return empty if we can't parse anything

