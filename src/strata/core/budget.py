"""Request budget enforcement for external scans.

A budget is the contract between a scan and its operator: it caps HTTP
requests, response bytes, and wall-clock time. Transports check the budget
before every request, so the limit is enforced at the network boundary rather
than being an advisory counter.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from strata.core.errors import BudgetExceeded


@dataclass
class RequestBudget:
    max_requests: int = 0
    max_bytes: int = 0
    max_seconds: float = 0.0
    requests: int = 0
    bytes_used: int = 0
    started_at: float = field(default_factory=time.monotonic)

    @property
    def enabled(self) -> bool:
        return bool(self.max_requests or self.max_bytes or self.max_seconds)

    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def _check_time(self) -> None:
        if self.max_seconds and self.elapsed() >= self.max_seconds:
            raise BudgetExceeded(
                f"time budget exhausted after {self.elapsed():.1f}s "
                f"(limit {self.max_seconds:.1f}s)"
            )

    def before_request(self) -> None:
        self._check_time()
        if self.max_requests and self.requests >= self.max_requests:
            raise BudgetExceeded(
                f"request budget exhausted ({self.requests}/{self.max_requests})"
            )
        self.requests += 1

    def record_bytes(self, count: int) -> None:
        self.bytes_used += max(0, count)
        if self.max_bytes and self.bytes_used > self.max_bytes:
            raise BudgetExceeded(
                f"byte budget exhausted ({self.bytes_used}/{self.max_bytes})"
            )

    def snapshot(self) -> dict[str, Any]:
        return {
            "max_requests": self.max_requests,
            "max_bytes": self.max_bytes,
            "max_seconds": self.max_seconds,
            "requests": self.requests,
            "bytes_used": self.bytes_used,
            "elapsed": round(self.elapsed(), 3),
        }


__all__ = ["RequestBudget"]
