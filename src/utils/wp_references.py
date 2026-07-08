"""Reference URLs for WordPress version, plugin, and theme vulnerability research."""

from __future__ import annotations

from typing import List, Optional
from urllib.parse import quote_plus


def wpscan_core_url(version: str) -> str:
    return f"https://wpscan.com/wordpress/{version}"


def wpscan_plugin_url(slug: str) -> str:
    return f"https://wpscan.com/plugin/{slug}"


def wpscan_theme_url(slug: str) -> str:
    return f"https://wpscan.com/theme/{slug}"


def nvd_cve_url(cve: str) -> str:
    cve_id = cve.upper().replace("CVE-", "").strip()
    return f"https://nvd.nist.gov/vuln/detail/CVE-{cve_id}"


def nvd_search_url(query: str) -> str:
    return f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&query={quote_plus(query)}"


def wordpress_core_references(version: str) -> List[str]:
    refs = [wpscan_core_url(version)]
    refs.append(nvd_search_url(f"WordPress {version}"))
    return refs


def wordpress_plugin_references(slug: str, version: Optional[str] = None) -> List[str]:
    refs = [wpscan_plugin_url(slug)]
    if version and version not in ("unknown", "None", "hidden (not disclosed)"):
        refs.append(nvd_search_url(f"WordPress plugin {slug} {version}"))
    else:
        refs.append(nvd_search_url(f"WordPress plugin {slug}"))
    return refs


def wordpress_theme_references(slug: str, version: Optional[str] = None) -> List[str]:
    refs = [wpscan_theme_url(slug)]
    if version and version not in ("unknown", "None", "hidden (not disclosed)"):
        refs.append(nvd_search_url(f"WordPress theme {slug} {version}"))
    else:
        refs.append(nvd_search_url(f"WordPress theme {slug}"))
    return refs


def enrich_cve_references(cve: Optional[str], existing: Optional[List[str]] = None) -> List[str]:
    """Ensure CVE findings include NVD and WPScan CVE database links."""
    refs = list(existing or [])
    if not cve:
        return refs

    cve_upper = cve.upper()
    if not cve_upper.startswith("CVE-"):
        cve_upper = f"CVE-{cve_upper}"

    nvd = nvd_cve_url(cve_upper)
    wpscan_cve = f"https://wpscan.com/cve/{cve_upper}"

    for url in (nvd, wpscan_cve):
        if url not in refs:
            refs.append(url)
    return refs
