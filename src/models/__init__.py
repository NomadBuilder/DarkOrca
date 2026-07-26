"""Data models for security scan results and findings."""

from .finding import Finding, FindingCategory, FindingSeverity
from .scan import ScanResult, ScanTarget
from .risk import RiskScore, RiskLevel
from .platform import SitePlatform

__all__ = [
    "Finding",
    "FindingCategory",
    "FindingSeverity",
    "ScanResult",
    "ScanTarget",
    "RiskScore",
    "RiskLevel",
    "SitePlatform",
]

