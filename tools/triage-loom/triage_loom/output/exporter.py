"""
JSONL export and explain output for Triage Loom.

Produces three output files:
- high_confidence_targets.jsonl   ≥2 corroboration layers
- low_confidence_targets.jsonl    <2 corroboration layers (manual review optional)
- endpoint_clusters.json          full cluster data for reference
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from triage_loom.models import TriagedFinding
from triage_loom.ranking.priority import explain

console = Console()


class Exporter:
    """Writes triage results to JSONL files in the given output directory."""

    def __init__(self, output_dir: str | Path) -> None:
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def export(self, findings: list[TriagedFinding]) -> dict[str, int]:
        """
        Split findings into high/low confidence and write both JSONL files.
        Also writes the full cluster reference JSON.

        Returns:
            dict with 'high', 'low', 'total' counts.
        """
        high = [f for f in findings if f.is_high_confidence]
        low = [f for f in findings if not f.is_high_confidence]

        self._write_jsonl(high, "high_confidence_targets.jsonl")
        self._write_jsonl(low, "low_confidence_targets.jsonl")
        self._write_clusters_json(findings)

        return {"high": len(high), "low": len(low), "total": len(findings)}

    def _write_jsonl(self, findings: list[TriagedFinding], filename: str) -> None:
        path = self._dir / filename
        with path.open("w", encoding="utf-8") as fh:
            for f in findings:
                fh.write(f.model_dump_json() + "\n")
        console.log(f"[green]Wrote {len(findings)} findings -> {path}[/green]")

    def _write_clusters_json(self, findings: list[TriagedFinding]) -> None:
        """Write the full cluster reference as a pretty-printed JSON array."""
        path = self._dir / "endpoint_clusters.json"
        clusters = []
        for f in sorted(findings, key=lambda x: x.investigation_priority, reverse=True):
            clusters.append({
                "pattern": f.endpoint_pattern,
                "representative_url": f.representative_url,
                "cluster_size": f.cluster_size,
                "parameters": f.parameters,
                "corroboration_layers": [l.value for l in f.corroboration_layers],
                "investigation_priority": f.investigation_priority,
                "is_high_confidence": f.is_high_confidence,
                "infra_context": f.infra_context,
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                "last_confirmed_live": f.last_confirmed_live.isoformat()
                if f.last_confirmed_live
                else None,
            })
        with path.open("w", encoding="utf-8") as fh:
            json.dump(clusters, fh, indent=2)
        console.log(f"[green]Wrote cluster reference -> {path}[/green]")


class Explainer:
    """Produces rich terminal output for the `triage-loom explain` command."""

    def display(self, finding: TriagedFinding) -> None:
        """Print a full human-readable explanation for a single finding."""
        audit = explain(finding)

        console.print()
        console.print(Panel(
            f"[bold cyan]{finding.endpoint_pattern}[/bold cyan]\n"
            f"[dim]{finding.representative_url}[/dim]",
            title="[bold]Triage Loom — Finding Explanation[/bold]",
            border_style="cyan",
        ))

        # Priority breakdown
        pb = audit["priority_breakdown"]
        prio_table = Table(title="Investigation Priority Breakdown", show_header=True)
        prio_table.add_column("Component", style="bold")
        prio_table.add_column("Value", justify="right")
        prio_table.add_column("Weight")
        prio_table.add_row("Corroboration layers", str(pb["values"]["corroboration_layers"]), "×1")
        prio_table.add_row("Novelty score", str(pb["values"]["novelty_score"]), "×1")
        prio_table.add_row(
            "Structural complexity",
            f'{pb["values"]["structural_complexity"]} ({"capped at 3" if pb["values"]["cap_applied"] else "raw"})',
            "×1",
        )
        prio_table.add_row("[bold green]PRIORITY[/bold green]", f'[bold]{pb["result"]}[/bold]', "")
        console.print(prio_table)

        # Corroboration layers
        corr = audit["corroboration"]
        console.print(f"\n[bold]Corroboration ({corr['total_layers']}/{corr['threshold_for_high_confidence']} for HIGH confidence)[/bold]")
        for layer in corr["layers"]:
            icon = "✅"
            console.print(f"  {icon} [green]{layer['layer']}[/green] — {layer['explanation']}")

        # Novelty breakdown
        if audit["novelty"].get("available", True):
            n = audit["novelty"]
            console.print(f"\n[bold]Novelty Score: {n['total_score']:.4f}[/bold]")
            for comp_name, comp in n["components"].items():
                bar = "█" * int(comp["score"] * 20)
                console.print(
                    f"  {comp_name:25s} {comp['score']:.3f} (weight={comp['weight']}) {bar}"
                )

        # Parameters
        params = audit["parameters"]
        if params["corroborated"]:
            console.print(f"\n[bold]Corroborated Parameters ({params['count']}):[/bold]")
            console.print("  " + ", ".join(f"[cyan]{p}[/cyan]" for p in params["corroborated"]))

        # Temporal
        t = audit["temporal"]
        console.print(f"\n[bold]Temporal:[/bold]")
        console.print(f"  First seen:         {t['first_seen'] or 'unknown'}")
        console.print(f"  Last confirmed live: {t['last_confirmed_live'] or 'unknown'}")
        console.print()
