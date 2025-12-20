"""WPScan adapter."""

import os
import json
import tempfile
from typing import List

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding
from ..models.scan_mode import ScanMode
from ..parsers.wpscan_parser import WPScanParser


class WPScanAdapter(BaseScanner):
    """Adapter for WPScan WordPress vulnerability scanner."""
    
    def __init__(self, api_token: str = None, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize WPScan adapter.
        
        Args:
            api_token: WPScan API token (optional, for vulnerability database access)
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        super().__init__(
            name="wpscan",
            command="wpscan",
            enabled=enabled,
            scan_mode=scan_mode
        )
        self.api_token = api_token or os.getenv("WPSCAN_API_TOKEN")
    
    def scan(self, target: ScanTarget) -> List[Finding]:
        """Run WPScan on target."""
        if not self.is_available():
            raise RuntimeError("WPScan is not available. Please install it: https://github.com/wpscanteam/wpscan")
        
        # Build WPScan command arguments
        args = [
            "--url", target.url,
            "--format", "json",
            "--no-banner",
            "--random-user-agent",
            "--disable-tls-checks",  # Allow scanning sites with SSL issues
        ]
        
        # Configure based on scan mode
        if self.scan_mode == ScanMode.DEFENSIVE:
            # Defensive mode: Faster, less aggressive
            args.extend([
                "--stealthy",  # Stealthy mode (faster, less aggressive)
                "--plugins-detection", "passive",  # Only passive plugin detection
                "--themes-detection", "passive",  # Only passive theme detection
            ])
        else:
            # Offensive mode: Comprehensive enumeration and testing
            args.extend([
                # Enumerate everything (vp=vulnerable plugins, ap=all plugins, vt=vulnerable themes, at=all themes, u=users, tt=timthumbs)
                # Note: Can't use vp and ap together, so use ap (all plugins) to get everything
                "--enumerate", "ap,at,u,tt",  # All plugins, all themes, users, timthumbs
                # More aggressive detection
                "--plugins-detection", "mixed",  # Mixed detection (passive + aggressive)
                "--themes-detection", "mixed",  # Mixed detection
                "--plugins-version-detection", "mixed",  # Check plugin versions
            ])
        
        # Add API token if available
        if self.api_token:
            args.extend(["--api-token", self.api_token])
        
        # Run scan with timeout (WPScan can take a while, but limit for speed)
        try:
            stdout, stderr, returncode = self.run_command(args, timeout=120)  # Reduced from 600 to 120 seconds
        except TimeoutError:
            # Return empty findings rather than failing completely
            return []
        except Exception as e:
            raise RuntimeError(f"WPScan execution failed: {e}")
        
        # WPScan may return non-zero exit codes even on success
        # Check if we got valid output
        if not stdout or not stdout.strip():
            # Check stderr for meaningful errors
            if stderr and ("error" in stderr.lower() or "failed" in stderr.lower()):
                # Only raise if it's a real error, not just warnings
                if "connection" not in stderr.lower() and "timeout" not in stderr.lower():
                    raise RuntimeError(f"WPScan error: {stderr[:500]}")  # Limit error message length
            # Empty output is OK - might mean no WordPress site
            return []
        
        # Parse output
        try:
            findings = WPScanParser.parse(stdout)
            return findings
        except json.JSONDecodeError as e:
            # If JSON parsing fails, check if it's actually a WordPress site
            if "not a WordPress site" in stdout.lower() or "not running WordPress" in stdout.lower():
                return []  # Not a WordPress site, no findings
            raise RuntimeError(f"Failed to parse WPScan JSON output: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to parse WPScan output: {e}")

