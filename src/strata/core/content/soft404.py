"""Soft-404 discrimination for HTTP probing.

Modern stacks return HTTP 200 with "not found" content for arbitrary paths —
SPAs, CMS templates, and WAF error pages all do it. Killing candidates on
status 404 alone both over-kills (custom 404 handling) and under-kills
(200-with-404-content). The fix is a per-host baseline:

1. Request a path that cannot exist (random label) on the same host.
2. Whatever comes back *is* the host's "not found" page.
3. Classify every probe response against that baseline: bodies that look like
   the baseline (token similarity) are soft-404s regardless of status.

The classifier is deliberately conservative: only clear evidence kills a
claim, and anything ambiguous (5xx, empty baseline) keeps the candidate.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from strata.core.content.fetch import FetchResponse, HttpTransport, decode_body

SOFT404_SIMILARITY = 0.85
SOFT404_WEAK_SIMILARITY = 0.65

_VERDICTS = ("live", "soft404", "not_found", "uncertain")

_GENERIC_404_RE = re.compile(
    r"page\s+not\s+found|not\s+found|nothing\s+found|cannot\s+be\s+found|"
    r"doesn.?t\s+exist|no\s+longer\s+exist|resource\s+not\s+found|"
    r"error\s+404|\b404\b",
    re.IGNORECASE,
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_WORD_RE = re.compile(r"[a-z0-9]{3,}")

_STOPWORDS = frozenset(
    {
        "the", "and", "for", "with", "that", "this", "from", "have", "not",
        "was", "are", "you", "your", "our", "can", "all", "now", "has",
        "http", "https", "www", "com", "org", "html", "css", "js", "utf",
    }
)


@dataclass(frozen=True)
class Soft404Profile:
    """What this host returns for a path that cannot exist."""

    host: str
    status: int
    title: str
    tokens: frozenset[str]
    length: int
    generic_404: bool


def extract_title(body: str) -> str:
    match = _TITLE_RE.search(body)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


def tokenize(body: str) -> frozenset[str]:
    """Lowercase word tokens from text with markup stripped."""
    text = _TAG_RE.sub(" ", body)
    return frozenset(
        token for token in _WORD_RE.findall(text.lower())
        if token not in _STOPWORDS
    )


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def build_profile(response: FetchResponse) -> Soft404Profile:
    text = decode_body(response, limit=100_000)
    title = extract_title(text)
    return Soft404Profile(
        host=_host_of(response.url),
        status=response.status,
        title=title,
        tokens=tokenize(text),
        length=len(text),
        generic_404=bool(_GENERIC_404_RE.search(title) or _GENERIC_404_RE.search(text[:2_000])),
    )


def token_similarity(a: frozenset[str], b: frozenset[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def classify_response(
    response: FetchResponse,
    baseline: Soft404Profile | None,
) -> str:
    """Verdict for a probe response: live | soft404 | not_found | uncertain."""
    if response.status == 0:
        return "uncertain"
    if response.status in (404, 410):
        return "not_found"
    if response.status >= 500:
        return "uncertain"

    if baseline is None or baseline.length == 0:
        return "live" if response.status < 400 else "uncertain"

    text = decode_body(response, limit=100_000)
    title = extract_title(text)
    similarity = token_similarity(tokenize(text), baseline.tokens)
    same_title = bool(title) and title == baseline.title
    short_clone = (
        abs(len(text) - baseline.length) <= 48 and similarity >= SOFT404_WEAK_SIMILARITY
    )

    if same_title and similarity >= SOFT404_WEAK_SIMILARITY:
        return "soft404"
    if similarity >= SOFT404_SIMILARITY:
        return "soft404"
    if short_clone:
        return "soft404"
    if (
        response.status < 400
        and baseline.generic_404
        and _GENERIC_404_RE.search(title or text[:2_000])
        and similarity >= 0.4
    ):
        return "soft404"
    return "live"


async def fetch_baseline(
    url: str,
    transport: HttpTransport,
    *,
    timeout: float = 10.0,
) -> Soft404Profile | None:
    """Fetch the host's not-found page by requesting an unguessable path."""
    split = urlsplit(url)
    host = (split.hostname or "").lower()
    if not host:
        return None
    scheme = split.scheme or "https"
    probe_url = f"{scheme}://{host}/{uuid.uuid4().hex}"
    try:
        response = await transport.get(probe_url, timeout=timeout, max_bytes=200_000)
    except Exception:
        return None
    if response.status == 0 or response.status >= 500:
        return None
    profile = build_profile(response)
    if profile.length == 0:
        return None
    return profile


def verdict_summary(verdict: str) -> str:
    if verdict not in _VERDICTS:  # pragma: no cover - defensive
        return "uncertain"
    return verdict


def baseline_meta(profile: Soft404Profile | None) -> dict[str, object]:
    """Redacted baseline fingerprint for evidence metadata."""
    if profile is None:
        return {"baseline_status": None, "baseline_title": ""}
    return {
        "baseline_status": profile.status,
        "baseline_title": profile.title[:120],
        "baseline_tokens": len(profile.tokens),
    }


__all__ = [
    "SOFT404_SIMILARITY",
    "SOFT404_WEAK_SIMILARITY",
    "Soft404Profile",
    "baseline_meta",
    "build_profile",
    "classify_response",
    "extract_title",
    "fetch_baseline",
    "token_similarity",
    "tokenize",
    "verdict_summary",
]
