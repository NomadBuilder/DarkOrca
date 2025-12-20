"""Scan mode definitions."""

from enum import Enum


class ScanMode(Enum):
    """Scan operation modes."""
    DEFENSIVE = "defensive"  # Read-only, passive scanning
    OFFENSIVE = "offensive"  # Active exploitation and attacks
    COMPREHENSIVE = "comprehensive"  # Both defensive and offensive scans

