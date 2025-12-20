"""Base scanner interface."""

from abc import ABC, abstractmethod
from typing import List, Optional
import subprocess
import json
import os

from ..models.finding import Finding
from ..models.scan import ScanTarget
from ..models.scan_mode import ScanMode


class BaseScanner(ABC):
    """Abstract base class for all scanners."""
    
    def __init__(self, name: str, command: Optional[str] = None, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        """
        Initialize scanner.
        
        Args:
            name: Scanner name identifier
            command: Command to run (if None, scanner is assumed to be library-based)
            enabled: Whether scanner is enabled
            scan_mode: Scan mode (defensive or offensive)
        """
        self.name = name
        self.command = command
        self.enabled = enabled
        self.scan_mode = scan_mode
    
    @abstractmethod
    def scan(self, target: ScanTarget) -> List[Finding]:
        """
        Run scan on target and return findings.
        
        Args:
            target: Target to scan
            
        Returns:
            List of findings
        """
        pass
    
    def parse_output(self, output: str) -> List[Finding]:
        """
        Parse scanner output into findings.
        
        This method can be overridden by subclasses, but is not required
        if parsing is handled directly in the scan() method.
        
        Args:
            output: Raw scanner output (JSON, XML, etc.)
            
        Returns:
            List of findings
        """
        raise NotImplementedError("Subclasses should implement parse_output or handle parsing in scan()")
    
    def is_available(self) -> bool:
        """Check if scanner command is available."""
        if not self.command:
            return True  # Library-based scanner
        
        try:
            # Try to run the command with --version or --help
            result = subprocess.run(
                [self.command, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,  # Suppress stderr for version checks
                timeout=5,
                check=False,
            )
            # Some tools return 0, some return 1 for --version, both are OK
            return result.returncode in [0, 1]
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False
    
    def run_command(self, args: List[str], timeout: Optional[int] = None) -> tuple[str, str, int]:
        """
        Run scanner command.
        
        Args:
            args: Command arguments
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, returncode)
        """
        if not self.command:
            raise ValueError(f"Scanner {self.name} does not have a command configured")
        
        # Validate arguments
        if not isinstance(args, list):
            raise ValueError(f"Arguments must be a list, got {type(args)}")
        
        # Check command exists before running
        import shutil
        if not shutil.which(self.command):
            raise FileNotFoundError(
                f"Scanner command '{self.command}' not found in PATH. "
                f"Please install {self.name}. "
                f"If using Nuclei, ensure Go bin is in PATH: export PATH=$PATH:$(go env GOPATH)/bin"
            )
        
        try:
            result = subprocess.run(
                [self.command] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                errors='replace',  # Replace encoding errors instead of failing
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as e:
            raise TimeoutError(
                f"Scanner {self.name} timed out after {timeout} seconds. "
                f"This may indicate the target is slow or unreachable."
            ) from e
        except FileNotFoundError as e:
            raise FileNotFoundError(
                f"Scanner command '{self.command}' not found. Please install {self.name}."
            ) from e
        except OSError as e:
            raise RuntimeError(f"Failed to execute {self.name}: {e}") from e

