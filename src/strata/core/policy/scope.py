"""Scope policy: an explicit allowlist gate every engine must pass through."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScopePolicy:
    allowed: tuple[str, ...]

    @classmethod
    def from_spec(cls, spec: str) -> ScopePolicy:
        items = tuple(
            item.strip().lower() for item in spec.split(",") if item.strip()
        )
        if not items:
            raise ValueError("scope spec produced an empty allowlist")
        return cls(allowed=items)

    @classmethod
    def from_list(cls, items: list[str]) -> ScopePolicy:
        cleaned = tuple(item.strip().lower() for item in items if item.strip())
        if not cleaned:
            raise ValueError("scope list produced an empty allowlist")
        return cls(allowed=cleaned)

    @classmethod
    def from_file(cls, path: Path) -> ScopePolicy:
        """Load an allowlist from a text file (one domain per line).

        Blank lines and ``#`` comments are ignored, so bug-bounty program
        scope files can be used directly.
        """
        text = Path(path).read_text(encoding="utf-8")
        items = tuple(
            line.strip().lower()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
        if not items:
            raise ValueError(f"scope file {path} produced an empty allowlist")
        return cls(allowed=items)

    def merged(self, other: ScopePolicy) -> ScopePolicy:
        """Union of two allowlists (used when --scope-file extends the target)."""
        combined = []
        for item in self.allowed + other.allowed:
            if item not in combined:
                combined.append(item)
        if not combined:
            raise ValueError("merged scope produced an empty allowlist")
        return ScopePolicy(allowed=tuple(combined))

    def allows_domain(self, domain: str) -> bool:
        domain = domain.strip().lower()
        return any(domain == s or domain.endswith("." + s) for s in self.allowed)

    def allows_host(self, host: str) -> bool:
        return self.allows_domain(host)
