"""Site platform / CMS selection for targeted scanning."""

from __future__ import annotations

from enum import Enum
from typing import Optional, Set


class SitePlatform(str, Enum):
    """Supported site platforms for scan targeting."""

    WORDPRESS = "wordpress"
    SQUARESPACE = "squarespace"
    OTHER = "other"

    @classmethod
    def from_value(cls, value: Optional[str]) -> "SitePlatform":
        if not value:
            return cls.OTHER
        normalized = str(value).strip().lower()
        aliases = {
            "wp": cls.WORDPRESS,
            "wordpress": cls.WORDPRESS,
            "sqsp": cls.SQUARESPACE,
            "squarespace": cls.SQUARESPACE,
            "other": cls.OTHER,
            "generic": cls.OTHER,
            "unknown": cls.OTHER,
        }
        return aliases.get(normalized, cls.OTHER)

    @property
    def label(self) -> str:
        return {
            SitePlatform.WORDPRESS: "WordPress",
            SitePlatform.SQUARESPACE: "Squarespace",
            SitePlatform.OTHER: "Other / Generic",
        }[self]


WORDPRESS_SCANNERS: Set[str] = {
    "wpscan",
    "wordpress_analyzer",
    "wordpress_offensive",
    "wordpress_vulnerabilities",
}

SQUARESPACE_SCANNERS: Set[str] = {
    "squarespace_analyzer",
}


def scanners_for_platform(platform: SitePlatform) -> Optional[Set[str]]:
    """
    Return None to keep the full scanner set for this mode, or a denylist
    of scanner names that must be excluded for the given platform.

    Prefer exclude-list semantics so generic scanners stay enabled.
    """
    return None  # use should_enable_scanner instead


def should_enable_scanner(scanner_name: str, platform: SitePlatform) -> bool:
    """Return False when a scanner is platform-specific and does not match."""
    name = (scanner_name or "").lower()
    if name in WORDPRESS_SCANNERS:
        return platform == SitePlatform.WORDPRESS
    if name in SQUARESPACE_SCANNERS:
        return platform == SitePlatform.SQUARESPACE
    return True
