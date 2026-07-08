"""Customer-facing confidence labels for findings."""

from __future__ import annotations

from typing import Any, Dict


def classify_finding_confidence(finding: Dict[str, Any]) -> str:
    """
    Return confidence tier: confirmed, likely, or informational.

    Used in executive summaries and client-facing reports instead of raw scanner output.
    """
    severity = (finding.get("severity") or "info").lower()
    category = (finding.get("category") or "").lower()
    metadata = finding.get("metadata") or {}

    if finding.get("exploited"):
        return "confirmed"

    if metadata.get("execution_proven") is True or metadata.get("vulnerable") is True:
        return "confirmed"

    if metadata.get("contains_credentials") or metadata.get("contains_database"):
        return "confirmed"

    if finding.get("cve"):
        return "likely"

    if category in {"vulnerability", "exploitation", "compromise"}:
        return "likely"

    if category in {"misconfiguration", "information_disclosure", "exposed_endpoint", "weak_security"}:
        if severity in {"critical", "high"}:
            return "likely"
        return "informational"

    if severity in {"critical", "high"} and finding.get("evidence"):
        return "likely"

    if category == "fingerprinting" or severity == "info":
        return "informational"

    if severity in {"medium", "low"}:
        return "informational"

    return "informational"


def confidence_label(confidence: str) -> str:
    return {
        "confirmed": "Confirmed",
        "likely": "Likely",
        "informational": "Informational",
    }.get(confidence, "Informational")
