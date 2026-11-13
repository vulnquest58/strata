"""Secret detection primitives (P2).

Absorbs the deterministic detection half of VulnHarvest's entropy scanner and
jsast's secret patterns. Values are never persisted raw: findings are keyed by
a salted hash and carry only a masked preview.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass

_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    (
        "private_key_pem",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        90.0,
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 85.0),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 85.0),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"), 85.0),
    ("stripe_secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), 85.0),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 80.0),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), 80.0),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
        75.0,
    ),
    (
        "basic_auth_url",
        re.compile(r"https?://[^/\s:@]{1,64}:[^/\s@]{1,64}@[^\s\"'<>]+"),
        60.0,
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{20,})"),
        55.0,
    ),
)

_GENERIC_RE = re.compile(
    r"(?i)(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)"
    r"\s*[:=]\s*[\"'`]([A-Za-z0-9_./+=\-]{16,})[\"'`]"
)

_PLACEHOLDER_HINTS = (
    "example",
    "your_",
    "your-",
    "changeme",
    "placeholder",
    "dummy",
    "sample",
    "xxxx",
    "****",
    "redacted",
    "replace_me",
    "todo",
    "fixme",
    "{{",
    "}}",
    "${",
    "<",
    ">",
)


@dataclass(frozen=True)
class SecretHit:
    kind: str
    value: str
    line: int
    entropy: float
    base_confidence: float


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in _PLACEHOLDER_HINTS)


def _looks_like_ui_string(value: str) -> bool:
    return len(set(value)) < 4


def detect_secrets(text: str) -> list[SecretHit]:
    """Find provider-specific and high-entropy assigned secrets in source text."""
    hits: list[SecretHit] = []
    seen: set[tuple[str, str]] = set()
    specific_values: set[str] = set()
    for kind, pattern, base in _PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            value = value.strip().rstrip(".,;:)]}\"'")
            if not value or (kind, value) in seen:
                continue
            if _looks_like_placeholder(value) or _looks_like_ui_string(value):
                continue
            entropy = round(shannon_entropy(value), 2)
            if kind == "bearer_token" and entropy < 3.0:
                continue
            seen.add((kind, value))
            specific_values.add(value)
            hits.append(
                SecretHit(
                    kind=kind,
                    value=value,
                    line=text.count("\n", 0, match.start()) + 1,
                    entropy=entropy,
                    base_confidence=base,
                )
            )
    for match in _GENERIC_RE.finditer(text):
        value = match.group(1).strip()
        if not value or value in specific_values or ("generic_secret", value) in seen:
            continue
        if _looks_like_placeholder(value) or _looks_like_ui_string(value):
            continue
        entropy = shannon_entropy(value)
        if entropy < 3.2:
            continue
        seen.add(("generic_secret", value))
        hits.append(
            SecretHit(
                kind="generic_secret",
                value=value,
                line=text.count("\n", 0, match.start()) + 1,
                entropy=round(entropy, 2),
                base_confidence=50.0,
            )
        )
    hits.sort(key=lambda hit: (hit.line, hit.kind, hit.value))
    return hits


def secret_confidence(hit: SecretHit) -> float:
    bonus = min(10.0, max(0.0, hit.entropy - 3.0) * 5.0)
    return round(min(100.0, hit.base_confidence + bonus), 1)


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:6]}...{value[-4:]}"


def secret_asset_id(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}\x00{value}".encode()).hexdigest()
    return f"secret:{kind}:{digest[:16]}"
