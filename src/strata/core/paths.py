from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path


def project_root() -> Path:
    """Return the Strata project root, walking up from this module."""
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "pyproject.toml").is_file() or (parent / ".git").exists():
            return parent
    return current.parents[-1] if current.parents else current


def reports_dir() -> Path:
    """Return the project-local reports directory."""
    return project_root() / "reports"


def timestamped_report_path(
    *,
    prefix: str = "strata",
    extension: str = "md",
) -> Path:
    """Build a deterministic, timestamped report path under reports/."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return reports_dir() / f"{prefix}-{stamp}.{extension}"


__all__ = [
    "project_root",
    "reports_dir",
    "timestamped_report_path",
]
