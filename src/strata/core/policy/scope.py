"""Scope policy: an explicit allowlist gate every engine must pass through."""

from __future__ import annotations

from dataclasses import dataclass


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

    def allows_domain(self, domain: str) -> bool:
        domain = domain.strip().lower()
        return any(domain == s or domain.endswith("." + s) for s in self.allowed)

    def allows_host(self, host: str) -> bool:
        return self.allows_domain(host)
