"""
JSONL ingestion layer — reads Aperture findings from a .jsonl file
and yields ApertureFinding objects one at a time (streaming, no full load).

Design: uses stdlib json rather than polars here because the input is a
stream of heterogeneous JSON objects, not a columnar dataset. polars is
used later in Filter 4 when we're operating on a uniform URL table.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from pydantic import ValidationError
from rich.console import Console

from triage_loom.models import ApertureFinding

console = Console(stderr=True)


def stream_findings(jsonl_path: str | Path) -> Iterator[ApertureFinding]:
    """
    Yields ApertureFinding objects from a JSONL file one at a time.

    Malformed lines are logged and skipped — a single bad line does not
    abort the ingestion of the rest of the file.

    Args:
        jsonl_path: Path to the Aperture JSONL output file.

    Yields:
        ApertureFinding for each valid line in the file.
    """
    path = Path(jsonl_path)
    if not path.exists():
        raise FileNotFoundError(f"Aperture JSONL file not found: {path}")

    skipped = 0
    total = 0

    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                data = json.loads(line)
                finding = ApertureFinding.model_validate(data)
                yield finding
            except json.JSONDecodeError as exc:
                skipped += 1
                console.log(f"[yellow]Line {lineno}: invalid JSON — {exc}[/yellow]")
            except ValidationError as exc:
                skipped += 1
                console.log(f"[yellow]Line {lineno}: schema mismatch — {exc.error_count()} errors[/yellow]")

    if skipped > 0:
        console.log(
            f"[yellow]Ingestion complete: {total - skipped}/{total} findings loaded "
            f"({skipped} skipped)[/yellow]"
        )


def load_all(jsonl_path: str | Path) -> list[ApertureFinding]:
    """
    Loads all findings from a JSONL file into memory.
    Use stream_findings() for large files to avoid memory pressure.
    """
    return list(stream_findings(jsonl_path))
