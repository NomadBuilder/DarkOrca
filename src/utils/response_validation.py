"""Shared HTTP response checks to reduce false-positive 'accessible' findings."""

from __future__ import annotations

import re
from typing import Iterable, Optional, Set, Union

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore


# Status codes that must never be reported as publicly accessible.
BLOCKED_STATUS_CODES: Set[int] = {401, 403, 404, 405, 410, 429, 451}

# Phrases commonly found in generic error, WAF, and default server pages.
ERROR_PAGE_INDICATORS: tuple[str, ...] = (
    "page not found",
    "not found",
    "error 404",
    "404 error",
    "404 - ",
    "403 forbidden",
    "forbidden",
    "access denied",
    "access is denied",
    "you don't have permission",
    "you do not have permission",
    "unauthorized",
    "request blocked",
    "request rejected",
    "sorry, you have been blocked",
    "you have been blocked",
    "security service",
    "web application firewall",
    "attention required",
    "captcha",
    "rate limit",
    "too many requests",
    "the page you requested was not found",
    "file not found",
    "document not found",
    "resource not found",
    "nothing found",
    "does not exist",
    "cannot be found",
    "no se encontró",
    "nicht gefunden",
    "introuvable",
    "page est introuvable",
    "perdue dans",
    "cyber-espace",
    "requête s'est perdue",
    "équipe est en route",
    # Default nginx / apache pages
    "welcome to nginx",
    "<center>nginx",
    "nginx/</center>",
    "powered by nginx",
    "openresty",
    "apache/",
    "apache tomcat",
    "iis windows server",
    "bad gateway",
    "service unavailable",
    "service temporarily unavailable",
    "internal server error",
    "cloudflare",
    "incapsula",
    "sucuri",
    "wordfence",
    "you are unable to access",
)

# Title-tag patterns for default server error pages (case-insensitive).
ERROR_TITLE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"<title>\s*403\s+Forbidden\s*</title>",
        r"<title>\s*404\s+Not\s+Found\s*</title>",
        r"<title>\s*502\s+Bad\s+Gateway\s*</title>",
        r"<title>\s*503\s+Service\s+(?:Temporarily\s+)?Unavailable\s*</title>",
        r"<title>\s*500\s+Internal\s+Server\s+Error\s*</title>",
        r"<title>\s*Error\s+404\s*</title>",
        r"<title>\s*Access\s+Denied\s*</title>",
        r"<title>\s*Forbidden\s*</title>",
    )
)


def is_blocked_status(status_code: int) -> bool:
    """Return True when the status code indicates blocked or missing content."""
    return status_code in BLOCKED_STATUS_CODES or status_code >= 500


def _normalize_content(content: Union[str, bytes, None]) -> str:
    if content is None:
        return ""
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return content


def content_looks_like_error_page(
    content: Union[str, bytes, None],
    *,
    content_type: str = "",
    status_code: int = 200,
    min_content_length: int = 50,
) -> bool:
    """
    Return True when body content looks like an error/WAF/default server page
    rather than the requested resource.
    """
    text = _normalize_content(content)
    if not text:
        return status_code != 200

    lowered = text.lower()

    for pattern in ERROR_TITLE_PATTERNS:
        if pattern.search(text):
            return True

    if any(indicator in lowered for indicator in ERROR_PAGE_INDICATORS):
        # Short HTML responses with error phrases are almost always soft 404/403 pages.
        if "text/html" in content_type.lower() or "<html" in lowered or "<body" in lowered:
            return True
        if len(text) < 5000:
            return True

    # Very small HTML documents are usually generic error pages.
    if len(text) < min_content_length and ("<html" in lowered or "<body" in lowered):
        return True

    # nginx/apache default error layout: short page with server signature.
    if len(text) < 800 and re.search(r"<center>\s*(nginx|apache|openresty)", lowered):
        return True

    return False


def is_accessible_response(
    response: "requests.Response",
    *,
    require_status: Iterable[int] = (200, 204),
    min_content_length: int = 50,
) -> bool:
    """
    Return True only when a response represents real, accessible content.

    Filters blocked status codes, nginx/apache default pages, WAF blocks,
    and common soft-404 HTML responses that return HTTP 200.
    """
    if response.status_code not in require_status:
        return False

    if is_blocked_status(response.status_code):
        return False

    content_type = response.headers.get("Content-Type", "")
    if content_looks_like_error_page(
        response.text,
        content_type=content_type,
        status_code=response.status_code,
        min_content_length=min_content_length,
    ):
        return False

    return True


def get_inaccessibility_reason(
    response: "requests.Response",
    *,
    min_content_length: int = 50,
) -> Optional[str]:
    """Human-readable reason a response was treated as inaccessible."""
    if is_blocked_status(response.status_code):
        return f"HTTP {response.status_code}"

    content_type = response.headers.get("Content-Type", "")
    if content_looks_like_error_page(
        response.text,
        content_type=content_type,
        status_code=response.status_code,
        min_content_length=min_content_length,
    ):
        server = response.headers.get("Server", "")
        if "nginx" in server.lower() or "nginx" in response.text.lower():
            return "nginx or generic error page"
        return "error or block page content"
    return None
