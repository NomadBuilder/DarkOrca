"""Scan preset definitions for customer-facing audit tiers."""

from __future__ import annotations

from typing import Any, Dict, Optional, Set

from ..models.platform import SitePlatform, WORDPRESS_SCANNERS, SQUARESPACE_SCANNERS


SCAN_PRESETS: Dict[str, Dict[str, Any]] = {
    "quick": {
        "label": "Quick Audit",
        "description": "Fast baseline check (~15 min): SSL, headers, platform fingerprint, exposed files.",
        "scan_mode": "defensive",
        "exhaustive": False,
        "enable_wpscan": True,
        "enable_nuclei": False,
        "enable_nmap": False,
        "enable_sqlmap": False,
        "estimated_minutes": 15,
    },
    "standard": {
        "label": "Standard Audit",
        "description": "Full defensive assessment (~45 min): all read-only checks plus Nuclei and Nmap.",
        "scan_mode": "defensive",
        "exhaustive": False,
        "enable_wpscan": True,
        "enable_nuclei": True,
        "enable_nmap": True,
        "enable_sqlmap": False,
        "estimated_minutes": 45,
    },
    "deep": {
        "label": "Deep Audit",
        "description": "Comprehensive authorized test: defensive recon plus offensive exploitation checks.",
        "scan_mode": "comprehensive",
        "exhaustive": True,
        "enable_wpscan": True,
        "enable_nuclei": True,
        "enable_nmap": True,
        "enable_sqlmap": True,
        "estimated_minutes": 120,
        "requires_authorization": True,
    },
}

# Scanners included in quick audit (subset of defensive scanners).
QUICK_SCANNER_ALLOWLIST: Set[str] = {
    "website_info",
    "ssl_analyzer",
    "security_headers",
    "http_security",
    "wordpress_analyzer",
    "squarespace_analyzer",
    "wpscan",
    "backup_files",
    "dns_security",
    "cookie_security",
    "wordpress_vulnerabilities",
}


def get_preset(name: Optional[str]) -> Optional[Dict[str, Any]]:
    if not name:
        return None
    return SCAN_PRESETS.get(name.lower())


def get_allowed_scanners_for_preset(
    preset: Optional[str],
    platform: Optional[SitePlatform] = None,
) -> Optional[Set[str]]:
    """Return allowlist for preset, or None to allow all scanners for the scan mode."""
    if not preset or preset.lower() != "quick":
        return None

    allowed = set(QUICK_SCANNER_ALLOWLIST)
    platform = platform or SitePlatform.OTHER

    if platform != SitePlatform.WORDPRESS:
        allowed -= WORDPRESS_SCANNERS
    if platform != SitePlatform.SQUARESPACE:
        allowed -= SQUARESPACE_SCANNERS

    return allowed


def resolve_scan_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """Merge API request with preset defaults and platform selection."""
    preset_name = (data.get("scan_preset") or data.get("preset") or "standard").lower()
    preset = get_preset(preset_name) or SCAN_PRESETS["standard"]
    platform = SitePlatform.from_value(data.get("platform") or data.get("site_platform"))

    enable_wpscan = data.get("enable_wpscan", preset["enable_wpscan"])
    if platform != SitePlatform.WORDPRESS:
        enable_wpscan = False

    return {
        "preset": preset_name,
        "preset_label": preset["label"],
        "platform": platform.value,
        "platform_label": platform.label,
        "scan_mode": data.get("scan_mode") or preset["scan_mode"],
        "exhaustive": data.get("exhaustive", preset["exhaustive"]),
        "enable_wpscan": enable_wpscan,
        "enable_nuclei": data.get("enable_nuclei", preset["enable_nuclei"]),
        "enable_nmap": data.get("enable_nmap", preset["enable_nmap"]),
        "enable_sqlmap": data.get("enable_sqlmap", preset["enable_sqlmap"]),
        "requires_authorization": preset.get("requires_authorization", False),
        "estimated_minutes": preset.get("estimated_minutes"),
    }
