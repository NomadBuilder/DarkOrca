"""Squarespace-specific security analyzer."""

from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from .base import BaseScanner
from ..models.scan import ScanTarget
from ..models.finding import Finding, FindingSeverity, FindingCategory
from ..models.scan_mode import ScanMode
from ..models.platform import SitePlatform
from ..utils.response_validation import (
    fetch_soft_404_baseline,
    is_accessible_response,
    validate_resource_access,
)

import logging

logger = logging.getLogger(__name__)


class SquarespaceAnalyzer(BaseScanner):
    """Squarespace site fingerprinting and security checks."""

    SENSITIVE_PATHS = [
        ("/config", FindingSeverity.MEDIUM, "Squarespace site configuration / login"),
        ("/config/settings", FindingSeverity.MEDIUM, "Squarespace settings panel"),
        ("/api/1/config", FindingSeverity.HIGH, "Squarespace config API"),
        ("/api/population/batch", FindingSeverity.MEDIUM, "Squarespace population API"),
        ("/api/context", FindingSeverity.LOW, "Squarespace context API"),
        ("/api/cart/get", FindingSeverity.LOW, "Squarespace commerce cart API"),
        ("/api/form/FormSubmissionKey", FindingSeverity.MEDIUM, "Squarespace form submission API"),
        ("/.well-known/security.txt", FindingSeverity.INFO, "security.txt"),
    ]

    def __init__(self, enabled: bool = True, scan_mode: ScanMode = ScanMode.DEFENSIVE):
        super().__init__(
            name="squarespace_analyzer",
            command=None,
            enabled=enabled,
            scan_mode=scan_mode,
        )
        from ..utils.scanner_session import create_scanner_session
        self.session = create_scanner_session()

    def is_available(self) -> bool:
        return True

    def scan(self, target: ScanTarget) -> List[Finding]:
        findings: List[Finding] = []

        if target.platform and target.platform != SitePlatform.SQUARESPACE:
            return findings

        fetch_soft_404_baseline(self.session, target.url)

        is_sqsp, evidence = self._detect_squarespace(target.url)
        if not is_sqsp and target.platform != SitePlatform.SQUARESPACE:
            return findings

        if is_sqsp:
            findings.append(Finding(
                title="Squarespace Platform Detected",
                description=(
                    f"Site appears to run on Squarespace. Evidence: {', '.join(evidence) or 'platform flag'}."
                ),
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner=self.name,
                source_id="sqsp_detected",
                url=target.url,
                remediation=(
                    "Confirm the site is managed in Squarespace. Keep the Squarespace plan updated, "
                    "review Connected Accounts, and limit who has contributor access."
                ),
                metadata={"evidence": evidence, "platform": "squarespace"},
            ))
        elif target.platform == SitePlatform.SQUARESPACE:
            findings.append(Finding(
                title="Squarespace Selected — Weak Fingerprint",
                description=(
                    "Scan was configured as Squarespace, but strong Squarespace fingerprints were not "
                    "found in the homepage response. Continuing Squarespace-specific checks anyway."
                ),
                severity=FindingSeverity.INFO,
                category=FindingCategory.FINGERPRINTING,
                source_scanner=self.name,
                source_id="sqsp_weak_fingerprint",
                url=target.url,
                remediation="Verify the correct site URL and platform selection.",
            ))

        findings.extend(self._check_sensitive_paths(target.url))
        findings.extend(self._check_config_login(target.url))
        findings.extend(self._check_robots_and_sitemap(target.url))
        findings.extend(self._check_static_asset_disclosure(target.url))
        findings.extend(self._check_member_and_password_pages(target.url))
        findings.extend(self._check_forms_and_csrf(target.url))
        findings.extend(self._check_security_headers(target.url))

        if self.scan_mode in (ScanMode.OFFENSIVE, ScanMode.COMPREHENSIVE):
            findings.extend(self._check_api_data_leakage(target.url))

        return findings

    def _detect_squarespace(self, url: str) -> tuple[bool, List[str]]:
        evidence: List[str] = []
        try:
            response = self.session.get(url, timeout=10)
            body = (response.text or "").lower()
            headers = {k.lower(): v for k, v in response.headers.items()}

            markers = [
                ("static.squarespace.com", "static.squarespace.com assets"),
                ("images.squarespace-cdn.com", "squarespace-cdn images"),
                ("squarespace.com", "squarespace.com reference"),
                ("sqsp.net", "sqsp.net assets"),
                ("squarespace-cdn", "squarespace-cdn"),
                ("data-controller=\"website\"", "Squarespace website controller"),
                ("squarespace-headers", "Squarespace headers script"),
                ("squarespace.com/universal", "Squarespace universal scripts"),
                ("window.static!", "Squarespace Static context"),
                ("\"staticbaseurl\"", "Squarespace StaticBaseUrl"),
            ]
            for needle, label in markers:
                if needle in body:
                    evidence.append(label)

            for header_name, label in (
                ("x-servedby", "X-ServedBy header"),
                ("x-contextid", "X-ContextId header"),
            ):
                if header_name in headers:
                    evidence.append(label)

            server = headers.get("server", "").lower()
            if "squarespace" in server:
                evidence.append(f"Server: {headers.get('server')}")

            set_cookie = headers.get("set-cookie", "")
            if "crumb=" in set_cookie.lower() or "ss_cid" in set_cookie.lower():
                evidence.append("Squarespace session cookies")

        except Exception as e:
            logger.debug(f"Squarespace detection failed: {e}")

        return (len(evidence) > 0, evidence)

    def _check_sensitive_paths(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        for path, severity, description in self.SENSITIVE_PATHS:
            try:
                full_url = urljoin(url, path)
                response = self.session.get(full_url, timeout=8, allow_redirects=True)
                if not validate_resource_access(
                    response, path, session=self.session, base_url=url, min_content_length=20
                ):
                    continue

                content = (response.text or "").lower()
                # Skip soft CMS shells that look like the main site chrome only
                if path.startswith("/api/") and (
                    "application/json" in response.headers.get("Content-Type", "").lower()
                    or content.strip().startswith("{")
                    or content.strip().startswith("[")
                ):
                    findings.append(Finding(
                        title=f"Squarespace API Endpoint Accessible: {path}",
                        description=(
                            f"{description} at {full_url} returned usable data "
                            f"(HTTP {response.status_code}). Review whether this endpoint should be public."
                        ),
                        severity=severity,
                        category=FindingCategory.EXPOSED_ENDPOINT,
                        source_scanner=self.name,
                        source_id=f"sqsp_path_{path.replace('/', '_')}",
                        url=full_url,
                        remediation=(
                            "Review Squarespace site permissions, disable unused features, "
                            "and ensure commerce/form APIs do not leak PII."
                        ),
                        metadata={"path": path, "status_code": response.status_code},
                    ))
                elif path.startswith("/config") and any(
                    token in content for token in ("login", "password", "squarespace", "email")
                ):
                    findings.append(Finding(
                        title="Squarespace Config / Login Surface Accessible",
                        description=(
                            f"{description} is reachable at {full_url}. Attackers can attempt "
                            "credential stuffing against the Squarespace admin login."
                        ),
                        severity=severity,
                        category=FindingCategory.EXPOSED_ENDPOINT,
                        source_scanner=self.name,
                        source_id="sqsp_config_login",
                        url=full_url,
                        remediation=(
                            "Enforce strong Squarespace account passwords and 2FA. "
                            "Monitor for brute-force attempts against /config."
                        ),
                        metadata={"path": path, "status_code": response.status_code},
                        references=[
                            "https://support.squarespace.com/hc/en-us/articles/205815528",
                        ],
                    ))
            except Exception:
                continue
        return findings

    def _check_config_login(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        config_url = urljoin(url, "/config")
        try:
            response = self.session.get(config_url, timeout=8, allow_redirects=True)
            if response.status_code not in (200, 401, 403) and not is_accessible_response(response):
                return findings

            # Even a redirect to login.squarespace.com is useful intel
            final = str(response.url).lower()
            body = (response.text or "").lower()
            if "login.squarespace.com" in final or "squarespace" in body:
                has_2fa_hint = any(x in body for x in ("two-factor", "2fa", "authenticator", "mfa"))
                findings.append(Finding(
                    title="Squarespace Admin Login Reachable",
                    description=(
                        f"Admin login flow is reachable via {config_url} "
                        f"(final URL: {response.url}). "
                        + (
                            "Login page mentions multi-factor authentication."
                            if has_2fa_hint
                            else "Ensure 2FA is enabled on all Squarespace contributor accounts."
                        )
                    ),
                    severity=FindingSeverity.LOW if has_2fa_hint else FindingSeverity.MEDIUM,
                    category=FindingCategory.EXPOSED_ENDPOINT,
                    source_scanner=self.name,
                    source_id="sqsp_admin_login",
                    url=config_url,
                    remediation=(
                        "Enable two-factor authentication for all Squarespace users, "
                        "use unique passwords, and review contributor roles regularly."
                    ),
                    references=[
                        "https://support.squarespace.com/hc/en-us/articles/206543167",
                    ],
                    metadata={"final_url": str(response.url), "has_2fa_hint": has_2fa_hint},
                ))
        except Exception as e:
            logger.debug(f"Config login check failed: {e}")
        return findings

    def _check_robots_and_sitemap(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            robots_url = urljoin(url, "/robots.txt")
            response = self.session.get(robots_url, timeout=5)
            if not is_accessible_response(response, min_content_length=10):
                return findings

            content = response.text or ""
            interesting = []
            for line in content.splitlines():
                lower = line.lower()
                if "disallow:" in lower:
                    path = line.split(":", 1)[-1].strip()
                    if any(token in path.lower() for token in (
                        "config", "api", "cart", "checkout", "account", "member", "commerce", "search"
                    )):
                        interesting.append(path)

            if interesting:
                findings.append(Finding(
                    title="Sensitive Paths Disclosed in robots.txt",
                    description=(
                        "robots.txt lists Squarespace-related paths that may aid recon: "
                        + ", ".join(interesting[:8])
                    ),
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.INFORMATION_DISCLOSURE,
                    source_scanner=self.name,
                    source_id="sqsp_robots",
                    url=robots_url,
                    remediation=(
                        "robots.txt is public by design; ensure listed paths are properly "
                        "authenticated and do not leak private member or commerce data."
                    ),
                    metadata={"paths": interesting[:15]},
                ))
        except Exception:
            pass
        return findings

    def _check_static_asset_disclosure(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            response = self.session.get(url, timeout=10)
            body = response.text or ""

            # Template / version hints in Squarespace markup
            template_match = re.search(
                r'static\.squarespace\.com/universal/[^"\']+',
                body,
                re.IGNORECASE,
            )
            version_match = re.search(
                r'squarespace\.com[^"\']*?[?&]v=([0-9.]+)',
                body,
                re.IGNORECASE,
            )
            site_id_match = re.search(
                r'"websiteId"\s*:\s*"([^"]+)"',
                body,
            ) or re.search(r'data-site-id=["\']([^"\']+)["\']', body, re.IGNORECASE)

            details = []
            if template_match:
                details.append(f"static asset path: {template_match.group(0)[:120]}")
            if version_match:
                details.append(f"asset version param: {version_match.group(1)}")
            if site_id_match:
                details.append(f"websiteId: {site_id_match.group(1)}")

            if details:
                findings.append(Finding(
                    title="Squarespace Site Metadata Disclosed",
                    description=(
                        "Public HTML exposes Squarespace site metadata that aids fingerprinting: "
                        + "; ".join(details)
                    ),
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    source_id="sqsp_metadata",
                    url=url,
                    remediation=(
                        "This is common on Squarespace. Focus on account security, "
                        "form privacy, and third-party integrations rather than hiding IDs."
                    ),
                    metadata={"details": details},
                ))
        except Exception:
            pass
        return findings

    def _check_member_and_password_pages(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        paths = [
            "/account/login",
            "/account/signup",
            "/member-area",
            "/members",
            "/client-login",
            "/password",
        ]
        for path in paths:
            try:
                full_url = urljoin(url, path)
                response = self.session.get(full_url, timeout=6, allow_redirects=True)
                if not is_accessible_response(response, min_content_length=30):
                    continue
                content = (response.text or "").lower()
                if any(token in content for token in (
                    "password", "member", "login", "sign in", "create account", "protected"
                )):
                    findings.append(Finding(
                        title=f"Squarespace Access-Controlled Page Found: {path}",
                        description=(
                            f"Potential member/password page at {full_url}. "
                            "Verify authentication is enforced and content is not leaked in HTML/JSON."
                        ),
                        severity=FindingSeverity.LOW,
                        category=FindingCategory.EXPOSED_ENDPOINT,
                        source_scanner=self.name,
                        source_id=f"sqsp_member_{path.replace('/', '_')}",
                        url=full_url,
                        remediation=(
                            "Review member-site and password-page settings in Squarespace. "
                            "Do not embed private content in publicly crawlable collection JSON."
                        ),
                    ))
            except Exception:
                continue
        return findings

    def _check_forms_and_csrf(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            response = self.session.get(url, timeout=10)
            body = response.text or ""
            lower = body.lower()

            has_form = "squarespace.com/api/form" in lower or "data-form-id" in lower or "form-block" in lower
            has_crumb = "crumb=" in response.headers.get("Set-Cookie", "").lower() or 'name="crumb"' in lower

            if has_form and not has_crumb:
                findings.append(Finding(
                    title="Squarespace Form Without Visible CSRF Token",
                    description=(
                        "A Squarespace form was detected, but no crumb/CSRF token was observed "
                        "in cookies or form fields on the homepage response."
                    ),
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.WEAK_SECURITY,
                    source_scanner=self.name,
                    source_id="sqsp_form_csrf",
                    url=url,
                    remediation=(
                        "Confirm Squarespace form submissions still require crumb tokens. "
                        "Avoid custom form endpoints that bypass platform CSRF protections."
                    ),
                ))
            elif has_form:
                findings.append(Finding(
                    title="Squarespace Forms Detected",
                    description=(
                        "Squarespace form blocks are present. Ensure form notifications "
                        "do not forward submissions to unmonitored inboxes and that "
                        "spam protection is enabled."
                    ),
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.FINGERPRINTING,
                    source_scanner=self.name,
                    source_id="sqsp_forms",
                    url=url,
                    remediation=(
                        "Enable reCAPTCHA / form spam protection in Squarespace form settings "
                        "and restrict who receives form notifications."
                    ),
                ))
        except Exception:
            pass
        return findings

    def _check_security_headers(self, url: str) -> List[Finding]:
        """Squarespace-specific notes on missing headers (platform often omits some)."""
        findings: List[Finding] = []
        try:
            response = self.session.get(url, timeout=10)
            headers = {k.lower(): v for k, v in response.headers.items()}
            missing = []
            for header in (
                "content-security-policy",
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
            ):
                if header not in headers:
                    missing.append(header)

            if missing:
                findings.append(Finding(
                    title="Security Headers Incomplete on Squarespace Site",
                    description=(
                        "Important security headers are missing: "
                        + ", ".join(missing)
                        + ". Squarespace code-injection / developer mode can add some headers "
                        "depending on plan; otherwise rely on Squarespace defaults and CDN settings."
                    ),
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.WEAK_SECURITY,
                    source_scanner=self.name,
                    source_id="sqsp_headers",
                    url=url,
                    remediation=(
                        "Add missing headers via Squarespace code injection where supported, "
                        "or a reverse proxy / Cloudflare in front of the site."
                    ),
                    metadata={"missing_headers": missing},
                    references=[
                        "https://support.squarespace.com/hc/en-us/articles/205815908",
                    ],
                ))
        except Exception:
            pass
        return findings

    def _check_api_data_leakage(self, url: str) -> List[Finding]:
        """Offensive: probe collection/commerce JSON for unexpected public data."""
        findings: List[Finding] = []
        api_paths = [
            "/api/1/commerce/products",
            "/api/1/commerce/orders",
            "/api/rest/collection",
            "/api/content/",
        ]
        for path in api_paths:
            try:
                full_url = urljoin(url, path)
                response = self.session.get(full_url, timeout=8, allow_redirects=False)
                ctype = response.headers.get("Content-Type", "").lower()
                body = response.text or ""
                if response.status_code != 200:
                    continue
                if "json" not in ctype and not body.strip().startswith(("{", "[")):
                    continue
                # Orders / private commerce should not be public
                sensitive = any(token in body.lower() for token in (
                    "email", "customer", "ordernumber", "shippingaddress", "phone", "billing"
                ))
                severity = FindingSeverity.HIGH if "orders" in path or sensitive else FindingSeverity.MEDIUM
                findings.append(Finding(
                    title=f"Squarespace API Data Accessible: {path}",
                    description=(
                        f"API endpoint {full_url} returned JSON (HTTP 200)"
                        + (" containing potentially sensitive fields." if sensitive else ".")
                    ),
                    severity=severity,
                    category=FindingCategory.INFORMATION_DISCLOSURE,
                    source_scanner=self.name,
                    source_id=f"sqsp_api_{path.replace('/', '_')}",
                    url=full_url,
                    remediation=(
                        "Restrict commerce and collection APIs. Remove public access to order "
                        "or customer data. Review Squarespace permissions and third-party apps."
                    ),
                    metadata={"path": path, "sensitive_fields_hint": sensitive},
                ))
            except Exception:
                continue
        return findings
