"""Audit-grade run manifests.

Every non-dry run emits a manifest next to its report. The manifest pins the
tool version, scope, effective options, host environment, stage outcomes, and
budget usage, and carries a deterministic fingerprint of the run inputs.
"""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strata import __version__

MANIFEST_SCHEMA_VERSION = "1"


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class RunManifest:
    target: str
    scope: str
    options: dict[str, Any]
    started_at: str = field(default_factory=_now)
    finished_at: str | None = None
    stats: dict[str, Any] = field(default_factory=dict)
    stages: list[dict[str, Any]] = field(default_factory=list)
    report: str | None = None
    budget: dict[str, Any] | None = None
    calibration: dict[str, Any] | None = None
    strata_version: str = __version__
    schema_version: str = MANIFEST_SCHEMA_VERSION
    python: str = field(default_factory=platform.python_version)
    platform: str = field(default_factory=platform.platform)

    def identity(self) -> dict[str, Any]:
        """Stable inputs used for the fingerprint (excludes volatile output)."""
        return {
            "schema_version": self.schema_version,
            "strata_version": self.strata_version,
            "target": self.target,
            "scope": self.scope,
            "options": self.options,
            "started_at": self.started_at,
        }

    def fingerprint(self) -> str:
        payload = json.dumps(
            self.identity(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def finish(
        self,
        *,
        stats: dict[str, Any],
        stages: list[dict[str, Any]],
        report: str | None,
        budget: dict[str, Any] | None = None,
        calibration: dict[str, Any] | None = None,
    ) -> None:
        self.finished_at = _now()
        self.stats = dict(stats)
        self.stages = list(stages)
        self.report = report
        self.budget = budget
        self.calibration = calibration

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "strata_version": self.strata_version,
            "target": self.target,
            "scope": self.scope,
            "options": self.options,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stats": self.stats,
            "stages": self.stages,
            "report": self.report,
            "budget": self.budget,
            "calibration": self.calibration,
            "python": self.python,
            "platform": self.platform,
            "fingerprint": self.fingerprint(),
        }

    def write(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return output


def manifest_path_for(report_path: str | Path) -> Path:
    report = Path(report_path)
    return report.with_name(f"{report.stem}.manifest.json")


__all__ = [
    "MANIFEST_SCHEMA_VERSION",
    "RunManifest",
    "manifest_path_for",
]
