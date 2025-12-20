"""Nmap adapter."""

import os
from typing import List

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding
from ..models.scan_mode import ScanMode
from ..parsers.nmap_parser import NmapParser


class NmapAdapter(BaseScanner):
    """Adapter for Nmap network scanner."""
    
    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize Nmap adapter.
        
        Args:
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="nmap",
            command="nmap",
            enabled=enabled,
            scan_mode=scan_mode
        )
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run Nmap on target."""
        if not self.is_available():
            raise RuntimeError("Nmap is not available. Please install it: https://nmap.org/")
        
        # Extract hostname/IP from target
        # Prefer domain, fall back to extracting from URL
        if target.domain:
            host = target.domain
        else:
            # Extract host from URL
            from urllib.parse import urlparse
            parsed = urlparse(target.url)
            host = parsed.netloc or parsed.path.split("/")[0]
            if not host:
                raise ValueError(f"Could not extract host from target URL: {target.url}")
        
        # Build Nmap command arguments (optimized for speed)
        args = [
            host,
            "-F",  # Fast scan (top 100 ports instead of 1000)
            "-sV",  # Version detection
            "--version-intensity", "2",  # Reduced intensity for speed (0-9, default 7)
            "-oX", "-",  # Output XML to stdout
            "--no-stylesheet",  # No XSL stylesheet in output
            "--host-timeout", "30s",  # Reduced timeout per host
            "--max-retries", "1",  # Reduce retries for speed
        ]
        
        # Configure based on scan mode
        if self.scan_mode == ScanMode.DEFENSIVE:
            # Defensive mode: Only safe scripts, minimal for speed
            args.extend([
                "--script", "http-title,http-server-header,ssl-cert",  # Only essential scripts
            ])
        else:
            # Offensive mode: More aggressive scanning
            args.extend([
                "-sC",  # Default scripts
                "--script", "vuln,exploit",  # Vulnerability and exploit scripts
            ])
        
        # Run scan
        try:
            stdout, stderr, returncode = self.run_command(args, timeout=120)  # Reduced from 300 to 120 seconds
        except TimeoutError:
            # Return empty findings rather than failing completely
            return []
        except Exception as e:
            raise RuntimeError(f"Nmap execution failed: {e}")
        
        if not stdout or not stdout.strip():
            # Check stderr for meaningful errors
            if stderr and "error" in stderr.lower():
                # Some errors are OK (like host down)
                if "host seems down" not in stderr.lower() and "no targets" not in stderr.lower():
                    raise RuntimeError(f"Nmap error: {stderr[:500]}")  # Limit error message length
            return []
        
        # Parse output
        try:
            findings = NmapParser.parse(xml_output=stdout)
            return findings
        except Exception as e:
            # If parsing fails, log but don't fail completely
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to parse Nmap output: {e}")
            return []  # Return empty findings if parsing fails

