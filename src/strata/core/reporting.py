"""Report rendering for Strata findings (P5).

Produces deterministic, human- and machine-readable output formats: Markdown,
HTML, SARIF 2.1.0, and JSONL.
"""

from __future__ import annotations

import enum
import html
import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from strata.core.schema.models import UnifiedFinding


class ReportFormat(enum.StrEnum):
    HTML = "html"
    MARKDOWN = "md"
    SARIF = "sarif"
    JSONL = "jsonl"


@dataclass(frozen=True)
class ReportSummary:
    findings: int
    by_status: dict[str, int]
    by_kind: dict[str, int]

    @property
    def verified(self) -> int:
        return self.by_status.get("verified", 0)

    @property
    def candidate(self) -> int:
        return self.by_status.get("candidate", 0)

    @property
    def dead(self) -> int:
        return self.by_status.get("dead", 0)


def summarise(findings: Iterable[UnifiedFinding]) -> ReportSummary:
    items = list(findings)
    by_status = Counter(f.status.value for f in items)
    by_kind = Counter(f.kind.value for f in items)
    return ReportSummary(
        findings=len(items),
        by_status=dict(sorted(by_status.items())),
        by_kind=dict(sorted(by_kind.items())),
    )


def _ordered(findings: Iterable[UnifiedFinding]) -> list[UnifiedFinding]:
    return sorted(
        findings,
        key=lambda finding: (
            -finding.confidence.value,
            finding.status.value,
            finding.kind.value,
            finding.asset_value,
        ),
    )


def _source_count(finding: UnifiedFinding) -> int:
    value = finding.metadata.get("source_count")
    return int(value) if isinstance(value, int) else 1


def _confidence_buckets(items: Iterable[UnifiedFinding]) -> list[tuple[str, int]]:
    buckets = {"0-24": 0, "25-49": 0, "50-74": 0, "75-100": 0}
    for finding in items:
        value = finding.confidence.value
        if value < 25:
            buckets["0-24"] += 1
        elif value < 50:
            buckets["25-49"] += 1
        elif value < 75:
            buckets["50-74"] += 1
        else:
            buckets["75-100"] += 1
    return list(buckets.items())


def _tension_buckets(
    items: Iterable[UnifiedFinding],
) -> list[tuple[str, int]]:
    labels = ["hot", "ghost", "shadow", "stable"]
    counts = {label: 0 for label in labels}
    for finding in items:
        tension = finding.metadata.get("tension")
        if not isinstance(tension, dict):
            continue
        label = tension.get("label")
        if label in counts:
            counts[label] += 1
    return [(label, counts[label]) for label in labels]


def _confidence_level(finding: UnifiedFinding) -> str:
    if finding.confidence.value >= 80:
        return "error"
    if finding.confidence.value >= 50:
        return "warning"
    return "note"


def _location(finding: UnifiedFinding) -> dict | None:
    url = finding.asset_value
    if not (url.startswith("http://") or url.startswith("https://")):
        if finding.parent and (
            finding.parent.startswith("http://")
            or finding.parent.startswith("https://")
        ):
            url = finding.parent
        else:
            return None
    line = finding.metadata.get("line_number")
    start_line = int(line) if isinstance(line, int) and line > 0 else 1
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": url},
            "region": {"startLine": start_line},
        }
    }


def sarif_report(findings: Iterable[UnifiedFinding]) -> dict:
    results: list[dict] = []
    for finding in _ordered(findings):
        result: dict = {
            "ruleId": finding.kind.value,
            "level": _confidence_level(finding),
            "message": {
                "text": (
                    f"{finding.kind.value} {finding.asset_value} "
                    f"({finding.status.value}, confidence={finding.confidence.value:.1f})"
                )
            },
            "properties": {
                "status": finding.status.value,
                "confidence": finding.confidence.value,
                "evidence_count": len(finding.evidence),
                "source_count": _source_count(finding),
            },
        }
        location = _location(finding)
        if location:
            result["locations"] = [location]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "strata",
                        "informationUri": "https://github.com/vulnquest58",
                        "rules": [
                            {"id": kind}
                            for kind in sorted({f.kind.value for f in findings})
                        ],
                    }
                },
                "results": results,
            }
        ],
    }


def markdown_report(
    findings: Iterable[UnifiedFinding], *, title: str = "Strata report"
) -> str:
    items = _ordered(findings)
    summary = summarise(items)
    lines = [
        f"# {title}",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Findings | {summary.findings} |",
        f"| Verified | {summary.verified} |",
        f"| Candidate | {summary.candidate} |",
        f"| Dead | {summary.dead} |",
        "",
        "## Breakdown",
        "",
        "| Kind | Count |",
        "|---|---:|",
    ]
    for kind, count in summary.by_kind.items():
        lines.append(f"| {kind} | {count} |")
    lines.extend(
        [
            "",
            "## Confidence distribution",
            "",
            "| Range | Count |",
            "|---|---:|",
        ]
    )
    for bucket, count in _confidence_buckets(items):
        lines.append(f"| {bucket} | {count} |")
    lines.extend(
        [
            "",
            "## Evidence tension",
            "",
            "| Label | Count |",
            "|---|---:|",
        ]
    )
    for label, count in _tension_buckets(items):
        lines.append(f"| {label} | {count} |")
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Confidence | Status | Kind | Asset | Evidence | Sources |",
            "|---:|---|---|---|---:|---:|",
        ]
    )
    for finding in items:
        asset = finding.asset_value.replace("|", "\\|")
        lines.append(
            f"| {finding.confidence.value:.1f} | {finding.status.value} | "
            f"{finding.kind.value} | {asset} | {len(finding.evidence)} | "
            f"{_source_count(finding)} |"
        )
    return "\n".join(lines) + "\n"


def _html_row(finding: UnifiedFinding) -> str:
    confidence = finding.confidence.value
    return (
        "<tr>"
        f"<td class=\"conf\"><span class=\"bar\" style=\"width:{confidence:.0f}%\"></span>"
        f"<span class=\"num\">{confidence:.1f}</span></td>"
        f"<td><span class=\"badge badge-{html.escape(finding.status.value)}\">"
        f"{html.escape(finding.status.value)}</span></td>"
        f"<td>{html.escape(finding.kind.value)}</td>"
        f"<td><code>{html.escape(finding.asset_value)}</code></td>"
        f"<td class=\"num\">{len(finding.evidence)}</td>"
        f"<td class=\"num\">{_source_count(finding)}</td>"
        "</tr>"
    )


def html_report(
    findings: Iterable[UnifiedFinding], *, title: str = "Strata report"
) -> str:
    items = _ordered(findings)
    summary = summarise(items)
    rows = "".join(_html_row(f) for f in items)
    kind_rows = "".join(
        f"<tr><td>{html.escape(kind)}</td><td class=\"num\">{count}</td></tr>"
        for kind, count in summary.by_kind.items()
    )
    bucket_rows = "".join(
        f"<tr><td>{html.escape(bucket)}</td><td class=\"num\">{count}</td></tr>"
        for bucket, count in _confidence_buckets(items)
    )
    tension_rows = "".join(
        f"<tr><td>{html.escape(label)}</td><td class=\"num\">{count}</td></tr>"
        for label, count in _tension_buckets(items)
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; max-width: 1200px; }}
h1 {{ margin-bottom: 0.25rem; }}
h2 {{ margin-top: 1.5rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: 1rem; }}
.card {{ padding: 0.8rem 1rem; border: 1px solid #8884; border-radius: 0.6rem; }}
.card .num {{ font-size: 1.4rem; font-weight: 600; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.9rem; }}
th, td {{ border-bottom: 1px solid #8884; padding: 0.45rem 0.6rem; text-align: left; }}
th {{ font-weight: 600; }}
.conf {{ width: 12rem; }}
.bar {{
    display: block; height: 0.6rem; background: currentColor; opacity: 0.3;
    border-radius: 3px;
}}
.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
code {{ font-size: 0.85rem; word-break: break-all; }}
.badge {{
    padding: 0.1rem 0.45rem; border-radius: 3px; font-size: 0.8rem; border: 1px solid #8886;
}}
.badge-verified {{ color: #15803d; }}
.badge-candidate {{ color: #2563eb; }}
.badge-dead {{ color: #b91c1c; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<div class="grid">
<div class="card"><div class="num">{summary.findings}</div>Findings</div>
<div class="card"><div class="num">{summary.verified}</div>Verified</div>
<div class="card"><div class="num">{summary.candidate}</div>Candidate</div>
<div class="card"><div class="num">{summary.dead}</div>Dead</div>
</div>
<h2>Breakdown</h2>
<table>
<thead><tr><th>Kind</th><th class="num">Count</th></tr></thead>
<tbody>
{kind_rows}
</tbody>
</table>
<h2>Confidence distribution</h2>
<table>
<thead><tr><th>Range</th><th class="num">Count</th></tr></thead>
<tbody>
{bucket_rows}
</tbody>
</table>
<h2>Evidence tension</h2>
<table>
<thead><tr><th>Label</th><th class="num">Count</th></tr></thead>
<tbody>
{tension_rows}
</tbody>
</table>
<h2>Findings</h2>
<table>
<thead>
<tr>
<th>Confidence</th>
<th>Status</th>
<th>Kind</th>
<th>Asset</th>
<th class="num">Evidence</th>
<th class="num">Sources</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""


def jsonl_lines(findings: Iterable[UnifiedFinding]) -> list[str]:
    return [finding.model_dump_json() for finding in _ordered(findings)]


def write_report(
    findings: Iterable[UnifiedFinding],
    path: str | Path,
    fmt: ReportFormat | str,
    *,
    title: str = "Strata report",
) -> ReportSummary:
    items = _ordered(findings)
    summary = summarise(items)
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    format_value = ReportFormat(fmt)
    if format_value is ReportFormat.HTML:
        output.write_text(
            html_report(items, title=title), encoding="utf-8", newline="\n"
        )
    elif format_value is ReportFormat.MARKDOWN:
        output.write_text(
            markdown_report(items, title=title), encoding="utf-8", newline="\n"
        )
    elif format_value is ReportFormat.SARIF:
        output.write_text(
            json.dumps(sarif_report(items), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    elif format_value is ReportFormat.JSONL:
        with output.open("w", encoding="utf-8", newline="\n") as fh:
            for line in jsonl_lines(items):
                fh.write(line + "\n")
    else:
        raise ValueError(f"unsupported report format: {fmt}")
    return summary


__all__ = [
    "ReportFormat",
    "ReportSummary",
    "html_report",
    "jsonl_lines",
    "markdown_report",
    "sarif_report",
    "summarise",
    "write_report",
]
