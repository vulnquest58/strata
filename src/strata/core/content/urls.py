"""URL canonicalization and endpoint scoring primitives (P2).

Absorbs the reusable, transport-free parts of VulnHarvest's dedup/filter
layers: normalization for the (run_id, kind, asset_value) dedup key, path
clustering for reports, endpoint validity checks, and interest scoring.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

NOISE_PARAMS = frozenset(
    {
        "fbclid",
        "gclid",
        "dclid",
        "msclkid",
        "yclid",
        "twclid",
        "igshid",
        "mc_eid",
        "mc_cid",
        "_ga",
        "_gl",
        "_hsenc",
        "_hsmi",
        "ref_src",
        "ref_url",
        "utm_campaign",
        "utm_content",
        "utm_medium",
        "utm_source",
        "utm_term",
        "utm_id",
        "utm_name",
        "utm_reader",
        "utm_social",
        "utm_social-type",
    }
)

STATIC_EXTENSIONS = frozenset(
    {
        ".7z",
        ".avi",
        ".bmp",
        ".css",
        ".csv",
        ".eot",
        ".gif",
        ".gz",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".map",
        ".m4a",
        ".mkv",
        ".mov",
        ".mp3",
        ".mp4",
        ".mpeg",
        ".ogg",
        ".otf",
        ".pdf",
        ".png",
        ".rar",
        ".svg",
        ".tar",
        ".tgz",
        ".tif",
        ".tiff",
        ".ttf",
        ".wav",
        ".webm",
        ".webp",
        ".woff",
        ".woff2",
        ".zip",
    }
)

INTEREST_RULES: tuple[tuple[str, tuple[str, ...], int], ...] = (
    ("api", ("/api/", "/api", "/rest/", "/v1/", "/v2/", "/v3/"), 25),
    ("admin", ("admin", "manage", "dashboard", "console"), 25),
    ("auth", ("auth", "login", "logout", "oauth", "token", "session"), 20),
    ("graphql", ("graphql", "gql"), 20),
    ("upload", ("upload", "attachment", "file", "import"), 15),
    ("debug", ("debug", "test", "dev", "staging", "internal"), 20),
    ("backup", ("backup", "dump", "export", "archive"), 20),
    ("docs", ("swagger", "openapi", "docs", "redoc"), 15),
    ("object", ("user", "account", "order", "invoice", "profile"), 10),
)

INTERESTING_PARAMS = frozenset(
    {
        "account",
        "admin",
        "callback",
        "cmd",
        "debug",
        "exec",
        "file",
        "id",
        "include",
        "key",
        "next",
        "page",
        "path",
        "redirect",
        "return",
        "role",
        "secret",
        "template",
        "token",
        "url",
        "user",
        "view",
    }
)

_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
_NUMERIC_ID_RE = re.compile(r"(?<![A-Za-z0-9])\d{2,}(?![A-Za-z0-9])")
_TEMPLATE_CHARS = frozenset("{}<>`\\\"' ")


def _is_noise_param(name: str) -> bool:
    lowered = name.lower()
    return lowered in NOISE_PARAMS or lowered.startswith("utm_")


def normalise_url(raw: str) -> str:
    """Canonical form used for deduplication: lowercase host, sorted query,
    tracking parameters and fragments removed."""
    raw = raw.strip()
    if not raw:
        raise ValueError("URL is blank")
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError(f"URL has no host: {raw!r}")
    scheme = (parsed.scheme or "https").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme: {scheme!r}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid port in URL: {raw!r}") from exc
    if port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    query = sorted(
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if not _is_noise_param(key)
    )
    return urlunparse((scheme, host, path, "", urlencode(query, doseq=True), ""))


def param_names(url: str) -> list[str]:
    return sorted({key for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)})


def cluster_path(path: str) -> str:
    """Replace unstable path segments with placeholders for reporting."""
    path = _UUID_RE.sub("{uuid}", path)
    path = _HEX_RE.sub("{hash}", path)
    return _NUMERIC_ID_RE.sub("{id}", path)


def is_valid_endpoint(url: str, target_domain: str) -> tuple[bool, str]:
    """Validate an absolute endpoint URL against scope and noise rules."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return False, "malformed"
    if parsed.scheme not in ("http", "https"):
        return False, "scheme"
    if not host:
        return False, "host"
    target = target_domain.strip().lower().lstrip(".")
    if not (host == target or host.endswith("." + target)):
        return False, "out_of_scope"
    if any(char in url for char in _TEMPLATE_CHARS):
        return False, "template"
    if len(url) > 2048:
        return False, "too_long"
    last_segment = parsed.path.rsplit("/", 1)[-1]
    if "." in last_segment:
        extension = "." + last_segment.rsplit(".", 1)[-1].lower()
        if extension in STATIC_EXTENSIONS:
            return False, "static_asset"
    return True, ""


def interest_score(url: str, params: list[str] | None = None) -> tuple[int, list[str]]:
    """Score an endpoint 0-100 with human-readable interest flags."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    names = params if params is not None else param_names(url)
    score = 10
    flags: list[str] = []
    if names:
        score += 20
        flags.append("params")
    for flag, needles, weight in INTEREST_RULES:
        if any(needle in path for needle in needles):
            score += weight
            flags.append(flag)
    if INTERESTING_PARAMS.intersection(names):
        score += 15
        flags.append("interesting_params")
    return max(0, min(100, score)), sorted(set(flags))


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()
