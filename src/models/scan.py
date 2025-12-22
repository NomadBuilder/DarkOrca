"""Scan target and result data models."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

from .finding import Finding
from .risk import RiskScore
from .scan_mode import ScanMode


@dataclass
class ScanTarget:
    """Represents a scan target (domain or URL)."""
    
    url: str
    domain: Optional[str] = None
    protocol: Optional[str] = None
    
    def __post_init__(self):
        """Parse URL and extract components."""
        if not self.url or not isinstance(self.url, str):
            raise ValueError("URL must be a non-empty string")
        
        # Clean and validate URL
        url = self.url.strip()
        if not url:
            raise ValueError("URL cannot be empty")
        
        # Basic validation - check if it looks like a domain or URL
        if not ("." in url or url.startswith("http://") or url.startswith("https://")):
            # Might be invalid, but let urlparse decide
            pass
        
        parsed = urlparse(url)
        if not parsed.scheme:
            # Assume https if no scheme provided
            url = f"https://{url}"
            parsed = urlparse(url)
        
        # Validate scheme
        if parsed.scheme not in ["http", "https"]:
            raise ValueError(f"Unsupported URL scheme: {parsed.scheme}. Only http and https are supported.")
        
        # Extract domain
        domain = parsed.netloc or parsed.path.split("/")[0]
        if not domain or domain == url:
            # If we can't extract a proper domain, try to validate the input
            # Remove scheme and path to get just the domain part
            if "/" in url.replace("://", ""):
                parts = url.replace("https://", "").replace("http://", "").split("/")
                domain = parts[0] if parts else None
            
            if not domain or not ("." in domain or domain == "localhost"):
                raise ValueError(f"Invalid URL: could not extract valid domain from '{self.url}'")
        
        # Remove port from domain for cleaner output
        if ":" in domain:
            domain = domain.split(":")[0]
        
        self.url = url
        self.protocol = parsed.scheme
        self.domain = domain
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert target to dictionary."""
        return {
            "url": self.url,
            "domain": self.domain,
            "protocol": self.protocol,
        }


@dataclass
class ScanResult:
    """Aggregated results from all scanners."""
    
    target: ScanTarget
    findings: List[Finding] = field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    scan_started_at: datetime = field(default_factory=datetime.utcnow)
    scan_completed_at: Optional[datetime] = None
    scanners_run: List[str] = field(default_factory=list)
    scanner_errors: Dict[str, str] = field(default_factory=dict)  # scanner_name -> error_message
    metadata: Dict[str, Any] = field(default_factory=dict)
    scan_mode: ScanMode = ScanMode.DEFENSIVE  # Mode used for this scan
    exploitations_successful: int = 0  # Count of successful exploitations
    ai_analysis: Optional[str] = None  # AI-powered analysis of scan results
    
    def add_finding(self, finding: Finding):
        """Add a finding to the results, avoiding duplicates."""
        # Check for duplicates based on URL and title (or source_id if available)
        # This prevents the same finding from multiple scanners
        is_duplicate = False
        for existing in self.findings:
            # Same URL and same title = duplicate
            if existing.url == finding.url and existing.title == finding.title:
                is_duplicate = True
                break
            # Same source_id = duplicate (more specific check)
            if finding.source_id and existing.source_id == finding.source_id:
                is_duplicate = True
                break
            # Same scanner, same URL, similar title = likely duplicate
            if (existing.source_scanner == finding.source_scanner and 
                existing.url == finding.url and
                existing.title.lower() == finding.title.lower()):
                is_duplicate = True
                break
        
        if not is_duplicate:
            self.findings.append(finding)
    
    def get_findings_by_severity(self, severity) -> List[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_category(self, category) -> List[Finding]:
        """Get findings filtered by category."""
        return [f for f in self.findings if f.category == category]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "target": self.target.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score.to_dict() if self.risk_score else None,
            "scan_started_at": self.scan_started_at.isoformat(),
            "scan_completed_at": self.scan_completed_at.isoformat() if self.scan_completed_at else None,
            "scanners_run": self.scanners_run,
            "scanner_errors": self.scanner_errors,
            "metadata": self.metadata,
            "scan_mode": self.scan_mode.value,
            "exploitations_successful": self.exploitations_successful,
            "ai_analysis": self.ai_analysis,
        }

