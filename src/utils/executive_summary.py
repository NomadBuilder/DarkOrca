"""Build client-facing executive summaries from scan results."""

from __future__ import annotations

from typing import Any, Dict, List

from .finding_confidence import classify_finding_confidence, confidence_label


def _is_actionable(finding: Dict[str, Any]) -> bool:
    title = (finding.get("title") or "").lower()
    category = (finding.get("category") or "").lower()
    severity = (finding.get("severity") or "info").lower()
    if severity == "info" and category == "fingerprinting":
        return False
    if "plugin detected" in title or "theme detected" in title or "version detected" in title:
        return False
    return True


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity.lower(), 5)


def build_executive_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    """Generate executive summary block for API, UI, and PDF."""
    findings = result.get("findings") or []
    risk = result.get("risk_score") or {}
    target = (result.get("target") or {}).get("url") or "Unknown target"

    actionable = [f for f in findings if _is_actionable(f)]
    for finding in actionable:
        finding["confidence"] = classify_finding_confidence(finding)

    prioritized = sorted(
        actionable,
        key=lambda f: (_severity_rank(f.get("severity", "info")), f.get("confidence") != "confirmed"),
    )

    top_priorities: List[Dict[str, str]] = []
    for finding in prioritized[:5]:
        top_priorities.append({
            "title": finding.get("title", "Finding"),
            "severity": (finding.get("severity") or "info").title(),
            "confidence": confidence_label(finding.get("confidence", "informational")),
            "remediation": (finding.get("remediation") or "")[:280],
        })

    confirmed = sum(1 for f in actionable if f.get("confidence") == "confirmed")
    likely = sum(1 for f in actionable if f.get("confidence") == "likely")

    overall = risk.get("overall_score", 0)
    level = (risk.get("risk_level") or "minimal").upper()
    preset = result.get("scan_preset_label") or result.get("scan_preset") or "Standard Audit"

    if not actionable:
        overview = (
            f"DarkOrca completed a {preset} for {target}. No actionable security issues were identified "
            f"in this assessment. Continue routine patching and monitoring."
        )
        recommendation = "Maintain regular updates and schedule periodic reassessments."
    else:
        overview = (
            f"DarkOrca completed a {preset} for {target}. Overall risk score: {overall:.1f}/100 ({level}). "
            f"{len(actionable)} actionable finding(s) identified"
            + (f", including {confirmed} confirmed issue(s)." if confirmed else ".")
        )
        if top_priorities:
            recommendation = f"Priority focus: {top_priorities[0]['title']} — {top_priorities[0].get('remediation') or 'Review and remediate promptly.'}"
        else:
            recommendation = "Review findings by severity and address critical and high items first."

    return {
        "overview": overview,
        "recommendation": recommendation,
        "risk_score": overall,
        "risk_level": level,
        "actionable_count": len(actionable),
        "confirmed_count": confirmed,
        "likely_count": likely,
        "top_priorities": top_priorities,
        "prepared_by": "Dark AI — DarkOrca Managed Security Audits",
    }
