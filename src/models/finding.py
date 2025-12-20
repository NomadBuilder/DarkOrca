"""Finding data model for security scan results."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any


class FindingSeverity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(Enum):
    """Categories for security findings."""
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION_DISCLOSURE = "information_disclosure"
    EXPOSED_ENDPOINT = "exposed_endpoint"
    WEAK_SECURITY = "weak_security"
    FINGERPRINTING = "fingerprinting"
    EXPLOITATION = "exploitation"  # Successful exploitation
    COMPROMISE = "compromise"  # System compromise evidence
    OTHER = "other"


@dataclass
class Finding:
    """Represents a single security finding."""
    
    title: str
    description: str
    severity: FindingSeverity
    category: FindingCategory
    source_scanner: str  # e.g., "wpscan", "nuclei", "nmap"
    source_id: Optional[str] = None  # Original ID from scanner (CVE, template ID, etc.)
    url: Optional[str] = None  # Affected URL/endpoint
    evidence: Optional[str] = None  # Supporting evidence
    cve: Optional[str] = None  # CVE identifier if applicable
    remediation: Optional[str] = None  # Remediation guidance
    references: List[str] = field(default_factory=list)  # Reference URLs
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional scanner-specific data
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    exploited: bool = False  # Whether this vulnerability was successfully exploited
    exploitation_details: Optional[str] = None  # Details about successful exploitation
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        # Recursively convert metadata to ensure all enums are serialized
        def serialize_metadata(obj):
            """Recursively serialize metadata, converting enums to values."""
            if isinstance(obj, Enum):
                return obj.value
            elif isinstance(obj, dict):
                return {k: serialize_metadata(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [serialize_metadata(item) for item in obj]
            elif hasattr(obj, 'isoformat'):  # datetime objects
                return obj.isoformat()
            else:
                return obj
        
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "source_scanner": self.source_scanner,
            "source_id": self.source_id,
            "url": self.url,
            "evidence": self.evidence,
            "cve": self.cve,
            "remediation": self.remediation,
            "references": self.references,
            "metadata": serialize_metadata(self.metadata),
            "discovered_at": self.discovered_at.isoformat(),
            "exploited": self.exploited,
            "exploitation_details": self.exploitation_details,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create finding from dictionary."""
        return cls(
            title=data["title"],
            description=data["description"],
            severity=FindingSeverity(data["severity"]),
            category=FindingCategory(data["category"]),
            source_scanner=data["source_scanner"],
            source_id=data.get("source_id"),
            url=data.get("url"),
            evidence=data.get("evidence"),
            cve=data.get("cve"),
            remediation=data.get("remediation"),
            references=data.get("references", []),
            metadata=data.get("metadata", {}),
            discovered_at=datetime.fromisoformat(data.get("discovered_at", datetime.utcnow().isoformat())),
            exploited=data.get("exploited", False),
            exploitation_details=data.get("exploitation_details"),
        )

