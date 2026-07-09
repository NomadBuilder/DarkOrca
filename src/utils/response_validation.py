"""Shared HTTP response checks to reduce false-positive 'accessible' findings."""

from __future__ import annotations

import re
import uuid
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, Optional, Set, Union
from urllib.parse import urljoin, urlparse

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
    "429 too many",
    "the page you requested was not found",
    "file not found",
    "document not found",
    "resource not found",
    "nothing found",
    "nothing was found",
    "can't find",
    "cannot find",
    "couldn't find",
    "could not find",
    "does not exist",
    "doesn't exist",
    "cannot be found",
    "no results found",
    "no se encontró",
    "nicht gefunden",
    "introuvable",
    "page est introuvable",
    "perdue dans",
    "cyber-espace",
    "requête s'est perdue",
    "équipe est en route",
    # WordPress / CMS soft 404s
    "that page can't be found",
    "page can't be found",
    "page cannot be found",
    "we can't find",
    "looks like nothing",
    "nothing here",
    "error-404",
    "error 404",
    "class=\"404",
    "id=\"404",
    "oops",
    "oh no",
    "lost in space",
    "go back home",
    "return to homepage",
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
        r"<title>\s*429\s+Too\s+Many\s+Requests\s*</title>",
        r"<title>\s*502\s+Bad\s+Gateway\s*</title>",
        r"<title>\s*503\s+Service\s+(?:Temporarily\s+)?Unavailable\s*</title>",
        r"<title>\s*500\s+Internal\s+Server\s+Error\s*</title>",
        r"<title>\s*Error\s+404\s*</title>",
        r"<title>\s*Access\s+Denied\s*</title>",
        r"<title>\s*Forbidden\s*</title>",
        r"<title>\s*Page\s+Not\s+Found\s*</title>",
    )
)

# Per-filename content expectations for sensitive paths (lowercase keys).
RESOURCE_SIGNATURES: Dict[str, Dict[str, Any]] = {
    ".htaccess": {
        "reject_html": True,
        "required_any": (
            "rewriteengine",
            "rewrite ",
            "options ",
            "deny from",
            "allow from",
            "require ",
            "order ",
            "filesmatch",
            "mod_rewrite",
            "authuserfile",
            "authtype",
            "errordocument",
        ),
        "allow_comment_only": True,
    },
    ".htpasswd": {
        "reject_html": True,
        "required_pattern": r"^\s*[\w.-]+:\{?\w+\}?",
    },
    "wp-config.php": {
        "reject_html": True,
        "required_any": ("db_name", "db_user", "db_password", "table_prefix"),
    },
    ".env": {
        "reject_html": True,
        "required_pattern": r"(?:^|\n)[A-Z_][A-Z0-9_]*\s*=",
    },
    ".git/config": {
        "reject_html": True,
        "required_any": ("[core]", "[remote"),
    },
    "readme.html": {
        "required_any": ("wordpress", "wp version", "installing wordpress"),
        "reject_if_html_error": True,
    },
    "license.txt": {
        "required_any": ("wordpress", "gnu general public"),
        "reject_if_html_error": True,
    },
    "web.config": {
        "reject_html": True,
        "required_any": ("<configuration", "<system.webserver", "<system.web"),
    },
}

_BASELINE_CACHE: Dict[str, Optional[str]] = {}


def clear_baseline_cache() -> None:
    """Clear cached soft-404 baselines (useful in tests)."""
    _BASELINE_CACHE.clear()


def is_blocked_status(status_code: int) -> bool:
    """Return True when the status code indicates blocked or missing content."""
    return status_code in BLOCKED_STATUS_CODES or status_code >= 500


def _normalize_content(content: Union[str, bytes, None]) -> str:
    if content is None:
        return ""
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return content


def looks_like_html_document(content: Union[str, bytes, None]) -> bool:
    """Return True when content appears to be an HTML document."""
    text = _normalize_content(content).lstrip().lower()
    if not text:
        return False
    return (
        text.startswith("<!doctype html")
        or text.startswith("<html")
        or "<body" in text[:4000]
        or ("<head" in text[:4000] and "<title" in text[:4000])
    )


def _normalize_for_comparison(content: str) -> str:
    """Collapse whitespace for fuzzy body comparison."""
    return re.sub(r"\s+", " ", content.strip().lower())


def _extract_title(content: str) -> Optional[str]:
    match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip().lower()


def content_similarity(a: str, b: str) -> float:
    """Return similarity ratio between two response bodies (0.0–1.0)."""
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, _normalize_for_comparison(a), _normalize_for_comparison(b)).ratio()


def matches_soft_404_baseline(
    content: Union[str, bytes, None],
    baseline: Optional[str],
    *,
    threshold: float = 0.82,
) -> bool:
    """
    Return True when content closely matches a previously captured soft-404 page.
    """
    if not baseline:
        return False

    text = _normalize_content(content)
    if not text:
        return False

    ratio = content_similarity(text, baseline)
    if ratio >= threshold:
        return True

    title_a = _extract_title(text)
    title_b = _extract_title(baseline)
    if title_a and title_b and title_a == title_b and looks_like_html_document(text):
        if ratio >= 0.55:
            return True

    len_a, len_b = len(text), len(baseline)
    if len_a > 200 and len_b > 200:
        size_delta = abs(len_a - len_b) / max(len_a, len_b)
        if size_delta < 0.03 and ratio >= 0.70:
            return True

    return False


def fetch_soft_404_baseline(session: Any, base_url: str) -> Optional[str]:
    """
    Probe random non-existent URLs and cache a representative soft-404 body.

    Many sites return HTTP 200 with the same themed HTML for every missing path
    (including /.htaccess). Comparing against this baseline removes those FPs.
    """
    netloc = urlparse(base_url).netloc
    if netloc in _BASELINE_CACHE:
        return _BASELINE_CACHE[netloc]

    bodies: list[str] = []
    probes = (
        f"/__darkorca_probe_{uuid.uuid4().hex[:16]}",
        f"/.htaccess-probe-{uuid.uuid4().hex[:10]}",
    )

    for probe in probes:
        probe_url = urljoin(base_url.rstrip("/") + "/", probe.lstrip("/"))
        try:
            response = session.get(probe_url, timeout=8, allow_redirects=True)
            if response.status_code in (200, 403, 404, 410, 429):
                body = _normalize_content(response.text)
                if body:
                    bodies.append(body)
        except Exception:
            continue

    baseline = max(bodies, key=len) if bodies else None
    _BASELINE_CACHE[netloc] = baseline
    return baseline


def _resource_key(resource_path: str) -> str:
    path = resource_path.split("?", 1)[0].rstrip("/").lower()
    name = path.rsplit("/", 1)[-1]
    if name == "config" and path.endswith(".git/config"):
        return ".git/config"
    return name


def is_plausible_resource_response(
    response: "requests.Response",
    resource_path: str,
) -> bool:
    """
    Return True when response body matches what we expect for the requested path.

    Rejects HTML error pages served for config files like .htaccess.
    """
    content = _normalize_content(response.text)
    if not content:
        return False

    key = _resource_key(resource_path)
    rules = RESOURCE_SIGNATURES.get(key)
    if not rules:
        return True

    lowered = content.lower()
    content_type = response.headers.get("Content-Type", "").lower()

    if rules.get("reject_html") and (
        looks_like_html_document(content) or "text/html" in content_type
    ):
        return False

    if rules.get("reject_if_html_error") and content_looks_like_error_page(
        content,
        content_type=content_type,
        status_code=response.status_code,
    ):
        return False

    required_any = rules.get("required_any")
    if required_any and not any(token in lowered for token in required_any):
        if rules.get("allow_comment_only") and any(
            line.strip().startswith("#") for line in content.splitlines() if line.strip()
        ):
            return True
        return False

    required_pattern = rules.get("required_pattern")
    if required_pattern and not re.search(required_pattern, content, re.IGNORECASE | re.MULTILINE):
        return False

    return True


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
        if "text/html" in content_type.lower() or looks_like_html_document(text):
            return True
        if len(text) < 5000:
            return True

    # Very small HTML documents are usually generic error pages.
    if len(text) < min_content_length and looks_like_html_document(text):
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
    resource_path: str = "",
    baseline_content: Optional[str] = None,
) -> bool:
    """
    Return True only when a response represents real, accessible content.

    Filters blocked status codes, nginx/apache default pages, WAF blocks,
    common soft-404 HTML responses that return HTTP 200, themed CMS 404 pages
    (via baseline comparison), and implausible bodies for sensitive paths.
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

    if baseline_content and matches_soft_404_baseline(response.text, baseline_content):
        return False

    if resource_path and not is_plausible_resource_response(response, resource_path):
        return False

    return True


def validate_resource_access(
    response: "requests.Response",
    resource_path: str,
    *,
    session: Any = None,
    base_url: str = "",
    min_content_length: int = 50,
) -> bool:
    """
    Convenience wrapper: accessibility check + soft-404 baseline + path rules.
    """
    baseline = None
    if session is not None and base_url:
        baseline = fetch_soft_404_baseline(session, base_url)

    return is_accessible_response(
        response,
        min_content_length=min_content_length,
        resource_path=resource_path,
        baseline_content=baseline,
    )


def get_inaccessibility_reason(
    response: "requests.Response",
    *,
    min_content_length: int = 50,
    resource_path: str = "",
    baseline_content: Optional[str] = None,
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

    if baseline_content and matches_soft_404_baseline(response.text, baseline_content):
        return "matches site soft-404 page"

    if resource_path and not is_plausible_resource_response(response, resource_path):
        return f"body does not match expected content for {resource_path}"

    return None
