"""Redaction helpers for URLs and log lines.

Attack-surface findings frequently contain URLs with credentials, tokens, or
signed query parameters. Reports and terminal output must never echo those
values, even when the finding itself is valid.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "apikey",
        "api_key",
        "auth",
        "authorization",
        "code",
        "credential",
        "id_token",
        "jwt",
        "key",
        "password",
        "passwd",
        "pwd",
        "refresh_token",
        "secret",
        "session",
        "sessionid",
        "sig",
        "signature",
        "token",
    }
)

_MASK = "***"
_KEY_VALUE_RE = re.compile(
    r"(?P<key>[A-Za-z0-9_.-]*(?:token|secret|password|passwd|pwd|api[_-]?key|"
    r"authorization|session|signature|sig|credential|jwt)[A-Za-z0-9_.-]*)"
    r"(?P<sep>\s*[=:]\s*)"
    r"(?P<value>[^\s&;,]+)",
    re.IGNORECASE,
)


def _is_sensitive(key: str) -> bool:
    lowered = key.strip().lower()
    return lowered in SENSITIVE_KEYS or any(
        marker in lowered
        for marker in ("token", "secret", "password", "passwd", "apikey", "api_key")
    )


def redact_url(url: str) -> str:
    """Strip userinfo and sensitive query values while preserving the route."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return url

    if not parsed.scheme and "://" not in url:
        return url

    netloc = parsed.netloc
    if "@" in netloc:
        host = parsed.hostname or ""
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        else:
            netloc = host

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    safe_pairs = [
        (key, _MASK if _is_sensitive(key) else value) for key, value in query_pairs
    ]
    query = urlencode(safe_pairs, doseq=True, safe="*")

    fragment = parsed.fragment
    if fragment and _KEY_VALUE_RE.search(fragment):
        fragment = _KEY_VALUE_RE.sub(
            lambda match: f"{match.group('key')}{match.group('sep')}{_MASK}",
            fragment,
        )

    return urlunparse(parsed._replace(netloc=netloc, query=query, fragment=fragment))


def redact_text(text: str) -> str:
    """Mask sensitive key/value pairs in free-form log or evidence text."""
    return _KEY_VALUE_RE.sub(
        lambda match: f"{match.group('key')}{match.group('sep')}{_MASK}",
        text,
    )


__all__ = ["SENSITIVE_KEYS", "redact_text", "redact_url"]
