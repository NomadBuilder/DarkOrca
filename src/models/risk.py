"""Risk scoring models."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List

from .finding import FindingSeverity


class RiskLevel(Enum):
    """Overall risk level assessment."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class RiskScore:
    """Comprehensive risk score and assessment."""
    
    overall_score: float  # 0.0 to 100.0
    risk_level: RiskLevel
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    category_scores: Dict[str, float] = field(default_factory=dict)  # category -> score
    attack_vectors: List[str] = field(default_factory=list)  # High-level attack vector descriptions
    summary: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert risk score to dictionary."""
        return {
            "overall_score": self.overall_score,
            "risk_level": self.risk_level.value,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "category_scores": self.category_scores,
            "attack_vectors": self.attack_vectors,
            "summary": self.summary,
        }
    
    @classmethod
    def calculate(cls, findings: List["Finding"]) -> "RiskScore":
        """Calculate risk score from findings."""
        from .finding import Finding
        
        # Count findings by severity
        critical = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        high = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        medium = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
        low = sum(1 for f in findings if f.severity == FindingSeverity.LOW)
        info = sum(1 for f in findings if f.severity == FindingSeverity.INFO)
        
        # Calculate weighted score (0-100) using logarithmic scaling to prevent over-penalization
        # Base weights: Critical=40, High=20, Medium=8, Low=2, Info=0
        # But use diminishing returns - each additional finding adds less
        critical_score = min(60.0, critical * 40.0)  # 1 critical = 40, 2 = 60 (diminishing)
        high_score = min(30.0, high * 15.0)  # 1 high = 15, 2 = 30
        medium_score = min(15.0, medium * 5.0)  # 1 medium = 5, 3 = 15
        low_score = min(5.0, low * 1.0)  # 5 low = 5 max
        
        # Combine scores (max 100)
        score = min(100.0, critical_score + high_score + medium_score + low_score)
        
        # Determine risk level (more nuanced thresholds)
        if critical >= 3 or score >= 75:
            risk_level = RiskLevel.CRITICAL  # Multiple critical or very high score
        elif critical > 0 or score >= 50:
            risk_level = RiskLevel.HIGH  # At least 1 critical or high score
        elif high > 0 or score >= 25:
            risk_level = RiskLevel.MEDIUM  # High severity findings or medium score
        elif medium > 0 or score >= 10:
            risk_level = RiskLevel.LOW  # Medium findings or low score
        elif low > 0 or score >= 2:
            risk_level = RiskLevel.MINIMAL
        else:
            risk_level = RiskLevel.MINIMAL
        
        # Calculate category scores
        category_scores = {}
        categories = set(f.category.value for f in findings)
        for category in categories:
            cat_findings = [f for f in findings if f.category.value == category]
            # Use same scoring logic as overall score
            cat_critical = sum(1 for f in cat_findings if f.severity == FindingSeverity.CRITICAL)
            cat_high = sum(1 for f in cat_findings if f.severity == FindingSeverity.HIGH)
            cat_medium = sum(1 for f in cat_findings if f.severity == FindingSeverity.MEDIUM)
            cat_low = sum(1 for f in cat_findings if f.severity == FindingSeverity.LOW)
            
            cat_critical_score = min(60.0, cat_critical * 40.0)
            cat_high_score = min(30.0, cat_high * 15.0)
            cat_medium_score = min(15.0, cat_medium * 5.0)
            cat_low_score = min(5.0, cat_low * 1.0)
            cat_score = min(100.0, cat_critical_score + cat_high_score + cat_medium_score + cat_low_score)
            category_scores[category] = cat_score
        
        # Generate attack vectors (high-level, non-procedural)
        attack_vectors = cls._generate_attack_vectors(findings)
        
        # Generate summary
        summary = cls._generate_summary(findings, risk_level, score)
        
        return cls(
            overall_score=round(score, 2),
            risk_level=risk_level,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            category_scores=category_scores,
            attack_vectors=attack_vectors,
            summary=summary,
        )
    
    @staticmethod
    def _generate_attack_vectors(findings: List["Finding"]) -> List[str]:
        """Generate high-level attack vector descriptions."""
        vectors = []
        
        # Group by category to identify patterns
        vulns = [f for f in findings if f.category.value == "vulnerability" and f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]]
        misconfigs = [f for f in findings if f.category.value == "misconfiguration" and f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]]
        exposed = [f for f in findings if f.category.value == "exposed_endpoint" and f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]]
        info_disclosure = [f for f in findings if f.category.value == "information_disclosure" and f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]]
        
        if vulns:
            vectors.append("Known vulnerabilities could be exploited to gain unauthorized access or execute code")
        
        if misconfigs:
            vectors.append("Security misconfigurations may allow attackers to bypass security controls")
        
        if exposed:
            vectors.append("Exposed endpoints and files may reveal sensitive information or provide attack surfaces")
        
        if info_disclosure:
            vectors.append("Information disclosure findings could aid attackers in reconnaissance and targeted attacks")
        
        # Check for WordPress-specific vectors
        wp_findings = [f for f in findings if "wordpress" in f.source_scanner.lower() or "wp" in f.source_scanner.lower()]
        if wp_findings and any(f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH] for f in wp_findings):
            vectors.append("WordPress-specific vulnerabilities and exposed components could be targeted by automated scanners")
        
        if not vectors:
            vectors.append("Low to moderate risk findings present minimal immediate attack surface")
        
        return vectors
    
    @staticmethod
    def _generate_summary(findings: List["Finding"], risk_level: RiskLevel, score: float) -> str:
        """Generate human-readable summary."""
        total = len(findings)
        critical = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        high = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        
        if total == 0:
            return "No security findings detected. Target appears to have minimal exposed attack surface."
        
        summary_parts = [
            f"Security assessment identified {total} finding(s) with an overall risk score of {score:.1f}/100.",
            f"Risk level: {risk_level.value.upper()}."
        ]
        
        if critical > 0:
            summary_parts.append(f"{critical} critical finding(s) require immediate attention.")
        if high > 0:
            summary_parts.append(f"{high} high-severity finding(s) should be prioritized for remediation.")
        
        return " ".join(summary_parts)

