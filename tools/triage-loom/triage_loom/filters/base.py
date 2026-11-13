"""
Filter base — abstract class and result type shared by all 5 filter stages.

Each filter is a stateless transformation: it receives context (the
ApertureFinding + accumulated TriagedFinding state) and returns a
FilterResult that either passes or rejects the finding, with full evidence.

Design invariant: a filter NEVER drops findings silently. Rejected findings
are moved to low_confidence, not deleted. This is enforced via the
FilterResult.passed flag and the pipeline's routing logic.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FilterResult:
    """
    The outcome of a single filter stage applied to one asset/endpoint.

    Attributes:
        passed:    Whether this filter considers the finding corroborated.
        evidence:  Machine-readable evidence supporting the decision (for explain command).
        layer_tag: The CorroborationLayer value this filter contributes if passed.
        metadata:  Additional structured data produced during filtering (e.g., archive URLs).
    """
    passed: bool
    evidence: dict[str, Any] = field(default_factory=dict)
    layer_tag: str | None = None          # matches a CorroborationLayer enum value
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseFilter(ABC):
    """
    Abstract base for all Triage Loom filter stages.

    Subclasses implement either:
    - run(finding) → FilterResult           for synchronous filters
    - run_async(finding) → FilterResult     for async filters (liveness, archive)

    The pipeline calls the appropriate method and handles async scheduling.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable filter name, shown in `explain` output."""
        ...

    @property
    @abstractmethod
    def stage(self) -> int:
        """Pipeline stage number (1–5)."""
        ...

    @abstractmethod
    async def run(self, asset_id: str, **context: Any) -> FilterResult:
        """
        Apply this filter to the given asset.

        Args:
            asset_id: The hostname or URL being evaluated.
            **context: Stage-specific keyword arguments (e.g., root_domain, db).

        Returns:
            FilterResult with passed=True if the asset meets this filter's criteria.
        """
        ...
