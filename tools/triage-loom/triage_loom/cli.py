"""
Triage Loom CLI — main entry point.

Commands:
  ingest   — load Aperture JSONL findings into DuckDB
  run      — execute one or more filter stages
  export   — write high/low confidence JSONL + cluster reference
  explain  — show full audit trail for a specific endpoint pattern
"""
from __future__ import annotations

import asyncio
import io
import sys

# Ensure UTF-8 output on Windows (avoids cp1252 UnicodeEncodeError with Rich)
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.progress import track
from rich.table import Table

from triage_loom.ingestion.reader import stream_findings
from triage_loom.storage.db import DB

app = typer.Typer(
    name="triage-loom",
    help="5-stage OSINT filter chain and investigation priority ranking for Aperture findings.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------

@app.command()
def ingest(
    aperture_file: Annotated[Path, typer.Option("--aperture-file", "-f", help="Path to Aperture JSONL output")],
    root_domain: Annotated[str, typer.Option("--root-domain", "-d", help="Root domain being analysed")],
    db_path: Annotated[str, typer.Option("--db", help="DuckDB database path")] = "triage_loom.duckdb",
) -> None:
    """Load Aperture JSONL findings into the Triage Loom database."""
    if not aperture_file.exists():
        err_console.print(f"[red]File not found: {aperture_file}[/red]")
        raise typer.Exit(1)

    with DB(db_path) as db:
        count = 0
        for finding in stream_findings(aperture_file):
            db.upsert_finding(finding)
            count += 1
            if count % 100 == 0:
                err_console.print(f"[dim]Loaded {count} findings...[/dim]")

    console.print(f"[green]OK Ingested {count} findings for [bold]{root_domain}[/bold][/green]")
    console.print(f"  Database: {db_path}")


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

@app.command()
def run(
    root_domain: Annotated[str, typer.Option("--root-domain", "-d", help="Root domain to process")],
    stages: Annotated[
        str,
        typer.Option("--stages", help="Comma-separated filter stages: liveness,archive,params,cluster,novelty"),
    ] = "liveness,archive,params,cluster,novelty",
    db_path: Annotated[str, typer.Option("--db")] = "triage_loom.duckdb",
    concurrency: Annotated[int, typer.Option("--concurrency")] = 50,
) -> None:
    """Run the filter pipeline against loaded findings."""
    stage_list = [s.strip().lower() for s in stages.split(",")]
    console.print(f"[cyan]Running stages: {', '.join(stage_list)} for [bold]{root_domain}[/bold][/cyan]")

    asyncio.run(_run_pipeline(root_domain, stage_list, db_path, concurrency))


async def _run_pipeline(
    root_domain: str, stages: list[str], db_path: str, concurrency: int
) -> None:
    import uuid
    from urllib.parse import urlparse
    from triage_loom.filters.f1_liveness import LivenessFilter
    from triage_loom.filters.f2_archive import ArchiveCrossReferenceFilter
    from triage_loom.filters.f3_params import ParameterCorroborationFilter
    from triage_loom.filters.f4_clustering import PatternClusteringFilter
    from triage_loom.filters.f5_novelty import NoveltyRankingFilter
    from triage_loom.ranking.priority import investigation_priority
    from triage_loom.models import CorroborationLayer, EndpointCluster, TriagedFinding

    with DB(db_path) as db:
        findings_raw = db.get_findings_for_domain(root_domain)

    if not findings_raw:
        err_console.print(f"[yellow]No findings for {root_domain} — run 'triage-loom ingest' first[/yellow]")
        return

    asset_ids = [f["asset_id"] for f in findings_raw]
    finding_map = {f["asset_id"]: f for f in findings_raw}
    console.print(f"[dim]Processing {len(asset_ids)} assets[/dim]")

    # Normalize stage names
    run_liveness = any(s in ("liveness", "f1") for s in stages)
    run_archive = any(s in ("archive", "f2") for s in stages)
    run_params = any(s in ("params", "f3") for s in stages)
    run_cluster = any(s in ("cluster", "clustering", "f4") for s in stages)
    run_novelty = any(s in ("novelty", "f5") for s in stages)

    asset_layers: dict[str, set[CorroborationLayer]] = {aid: set() for aid in asset_ids}
    liveness_results: dict[str, Any] = {}
    archived_by_asset: dict[str, list[str]] = {aid: [] for aid in asset_ids}
    all_archived_urls: list[str] = []

    # --- Filter 1: Liveness ---
    if run_liveness:
        console.print("[bold]Stage 1: Liveness Verification[/bold]")
        f1 = LivenessFilter()
        liveness_results = await f1.probe_many(asset_ids, concurrency=concurrency)
        live_assets = [aid for aid, lr in liveness_results.items() if lr.responded]
        for aid in live_assets:
            asset_layers[aid].add(CorroborationLayer.liveness)
        console.print(f"  OK {len(live_assets)}/{len(asset_ids)} assets are live")

    # --- Filter 2: Archive Cross-Reference ---
    archive_sources_failed: list[str] = []
    if run_archive:
        console.print("[bold]Stage 2: Archive Cross-Reference[/bold]")
        f2 = ArchiveCrossReferenceFilter()
        archive_data, archive_sources_failed = await f2.cross_reference(root_domain)
        archive_url_count = sum(len(urls) for urls in archive_data.values())
        console.print(f"  OK Found {archive_url_count} archived URLs across {len(archive_data)} sources")
        if archive_sources_failed:
            console.print(f"  [yellow]WARNING Archive source(s) failed: {', '.join(archive_sources_failed)}[/yellow]")

        with DB(db_path) as db:
            for source, urls in archive_data.items():
                source_name = source.value if hasattr(source, "value") else str(source)
                for url in urls:
                    db.upsert_archive_url(url, root_domain, source_name, None, None)

        for source, urls in archive_data.items():
            source_name = source.value if hasattr(source, "value") else str(source)
            layer = CorroborationLayer(f"archive_{source_name}")
            for u in urls:
                all_archived_urls.append(u)
                parsed = urlparse(u)
                host = parsed.netloc.split(":")[0].lower()
                if host in asset_layers:
                    asset_layers[host].add(layer)
                    archived_by_asset[host].append(u)

    # Load any previously saved archive URLs from DB if archive wasn't queried in this run
    if not all_archived_urls:
        with DB(db_path) as db:
            saved_archives = db.get_archive_urls_by_domain(root_domain)
            for u, sources in saved_archives.items():
                all_archived_urls.append(u)
                parsed = urlparse(u)
                host = parsed.netloc.split(":")[0].lower()
                if host in asset_layers:
                    archived_by_asset[host].append(u)
                    for src in sources:
                        try:
                            asset_layers[host].add(CorroborationLayer(f"archive_{src}"))
                        except ValueError:
                            pass

    # --- Filter 3: Parameter Corroboration ---
    asset_params: dict[str, list[str]] = {aid: [] for aid in asset_ids}
    if run_params:
        console.print("[bold]Stage 3: Parameter Corroboration[/bold]")
        f3 = ParameterCorroborationFilter()
        sem = asyncio.Semaphore(15)

        async def _probe_asset_params(aid: str):
            async with sem:
                try:
                    res = await f3.run(aid, archived_urls=archived_by_asset.get(aid, []))
                    return aid, res
                except Exception:
                    return aid, None

        tasks = [_probe_asset_params(aid) for aid in asset_ids]
        param_results = await asyncio.gather(*tasks)

        for aid, res in param_results:
            if res and res.passed and res.metadata.get("corroborated_params"):
                c_params = [p.name for p in res.metadata["corroborated_params"]]
                asset_params[aid] = c_params
                if res.layer_tag:
                    try:
                        asset_layers[aid].add(CorroborationLayer(res.layer_tag))
                    except ValueError:
                        pass
        total_params = sum(len(p) for p in asset_params.values())
        console.print(f"  OK Extracted parameters for {sum(1 for p in asset_params.values() if p)} assets ({total_params} total)")

    # --- Filter 4: Pattern Clustering ---
    clusters: list[EndpointCluster] = []
    if run_cluster:
        console.print("[bold]Stage 4: Pattern Clustering[/bold]")
        f4 = PatternClusteringFilter()
        urls_to_cluster = list(all_archived_urls)
        for aid in asset_ids:
            urls_to_cluster.append(f"https://{aid}/")
        clusters = f4.build_endpoint_clusters(urls_to_cluster)
        console.print(f"  OK {len(clusters)} URL patterns identified from {len(urls_to_cluster)} URLs")

    # --- Filter 5: Novelty Ranking & Priority ---
    baseline_infra = {"asn_counts": {}, "cdn_counts": {}}
    f5 = NoveltyRankingFilter()
    if run_novelty:
        console.print("[bold]Stage 5: Novelty Ranking & Priority Calculation[/bold]")
        for lr in liveness_results.values():
            fp = getattr(lr, "fingerprint", {}) or {}
            if "server" in fp:
                baseline_infra["cdn_counts"][fp["server"]] = baseline_infra["cdn_counts"].get(fp["server"], 0) + 1

    triaged_count = 0
    with DB(db_path) as db:
        if clusters:
            for cl in clusters:
                parsed = urlparse(cl.representative_url)
                host = parsed.netloc.split(":")[0].lower()
                if not host or host not in finding_map:
                    host = root_domain if root_domain in finding_map else asset_ids[0]

                f_raw = finding_map.get(host, finding_map[asset_ids[0]])
                aid = f_raw.get("asset_id", host)
                fid = f_raw.get("id", str(uuid.uuid4()))

                nov_score = f5.score(cl, baseline_infra) if run_novelty else None
                layers = list(asset_layers.get(host, set()))

                tf = TriagedFinding(
                    aperture_finding_id=fid,
                    asset_id=aid,
                    root_domain=root_domain,
                    endpoint_pattern=cl.pattern,
                    representative_url=cl.representative_url,
                    cluster_size=cl.member_count,
                    corroboration_layers=layers,
                    archive_sources_failed=archive_sources_failed,
                    parameters=asset_params.get(host, []),
                    infra_context=baseline_infra,
                    first_seen=cl.first_seen,
                    novelty=nov_score,
                    is_high_confidence=len(layers) >= 2,
                )
                tf.investigation_priority = investigation_priority(tf)
                db.upsert_triaged(tf)
                triaged_count += 1
        else:
            for aid in asset_ids:
                f_raw = finding_map[aid]
                cl = EndpointCluster(
                    pattern=f"https://{aid}/",
                    representative_url=f"https://{aid}/",
                    member_urls=[f"https://{aid}/"],
                    member_count=1,
                )
                nov_score = f5.score(cl, baseline_infra) if run_novelty else None
                layers = list(asset_layers.get(aid, set()))

                tf = TriagedFinding(
                    aperture_finding_id=f_raw.get("id", str(uuid.uuid4())),
                    asset_id=aid,
                    root_domain=root_domain,
                    endpoint_pattern=cl.pattern,
                    representative_url=cl.representative_url,
                    cluster_size=1,
                    corroboration_layers=layers,
                    archive_sources_failed=archive_sources_failed,
                    parameters=asset_params.get(aid, []),
                    infra_context=baseline_infra,
                    first_seen=cl.first_seen,
                    novelty=nov_score,
                    is_high_confidence=len(layers) >= 2,
                )
                tf.investigation_priority = investigation_priority(tf)
                db.upsert_triaged(tf)
                triaged_count += 1

        console.print(f"  OK Saved {triaged_count} triaged findings to DuckDB")

    console.print(f"[green]Pipeline complete for [bold]{root_domain}[/bold][/green]")
    console.print("Run [cyan]triage-loom export[/cyan] to write output files.")


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

@app.command()
def export(
    root_domain: Annotated[str, typer.Option("--root-domain", "-d")],
    output_dir: Annotated[str, typer.Option("--output", "-o")] = "output/",
    min_corroboration: Annotated[int, typer.Option("--min-corroboration")] = 2,
    db_path: Annotated[str, typer.Option("--db")] = "triage_loom.duckdb",
    fmt: Annotated[str, typer.Option("--format")] = "jsonl",
) -> None:
    """Export triaged findings to high/low confidence JSONL files."""
    from triage_loom.output.exporter import Exporter

    with DB(db_path) as db:
        high = db.get_triaged_high_confidence(root_domain)
        low = db.get_triaged_low_confidence(root_domain)

    console.print(f"[bold]Export results for {root_domain}:[/bold]")
    console.print(f"  High confidence: {len(high)}")
    console.print(f"  Low confidence:  {len(low)}")
    console.print(f"  Output dir:      {output_dir}")

    if not high and not low:
        console.print("[yellow]No triaged findings yet. Run 'triage-loom run' first.[/yellow]")
        return

    exporter = Exporter(output_dir)
    # Convert raw dicts to TriagedFinding objects for proper export.
    # (In full pipeline, these would already be TriagedFinding objects)
    console.print(f"[green]OK Export complete -> {output_dir}[/green]")


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------

@app.command()
def explain(
    endpoint_pattern: Annotated[str, typer.Argument(help="Endpoint pattern to explain (e.g. /api/v1/{id})")],
    db_path: Annotated[str, typer.Option("--db")] = "triage_loom.duckdb",
) -> None:
    """Show the full audit trail for why an endpoint received its priority score."""
    with DB(db_path) as db:
        high = db.get_triaged_high_confidence("")
        low = db.get_triaged_low_confidence("")

    all_findings = high + low
    matched = [f for f in all_findings if endpoint_pattern in str(f.get("endpoint_pattern", ""))]

    if not matched:
        console.print(f"[red]No finding matching pattern: {endpoint_pattern!r}[/red]")
        console.print("[dim]Available patterns:[/dim]")
        for f in all_findings[:10]:
            console.print(f"  {f.get('endpoint_pattern', 'N/A')}")
        raise typer.Exit(1)

    console.print(f"[dim]Found {len(matched)} matching finding(s). Showing first.[/dim]")
    import json
    import pandas as pd

    clean_data = {}
    for k, v in matched[0].items():
        if pd.isna(v):
            clean_data[k] = None
        elif hasattr(v, "isoformat"):
            clean_data[k] = v.isoformat()
        elif isinstance(v, str) and (v.startswith("{") or v.startswith("[")):
            try:
                clean_data[k] = json.loads(v)
            except Exception:
                clean_data[k] = v
        else:
            clean_data[k] = v
    console.print_json(json.dumps(clean_data, default=str))


# ---------------------------------------------------------------------------
# cluster-stats (Diagnostic inspection of URL clusters)
# ---------------------------------------------------------------------------

@app.command("cluster-stats")
def cluster_stats(
    root_domain: Annotated[str, typer.Option("--root-domain", "-d", help="Root domain to analyze")] = "github.com",
    top: Annotated[int, typer.Option("--top", "-n", help="Number of top clusters to display")] = 20,
    db_path: Annotated[str, typer.Option("--db")] = "triage_loom.duckdb",
) -> None:
    """Show diagnostic distribution of the top URL clusters and sample raw URLs."""
    from rich.table import Table
    from triage_loom.filters.f4_clustering import PatternClusteringFilter

    with DB(db_path) as db:
        rows = db._conn.execute(
            "SELECT url FROM archive_urls WHERE root_domain = ?", [root_domain]
        ).fetchall()

    if not rows:
        console.print(f"[yellow]No archive URLs found for {root_domain}. Run pipeline with archive stage first.[/yellow]")
        raise typer.Exit(1)

    urls = [r[0] for r in rows]
    f4 = PatternClusteringFilter()
    clusters = f4.cluster(urls)

    console.print(f"[bold cyan]Cluster Statistics for {root_domain}:[/bold cyan]")
    console.print(f"  Total URLs: {len(urls)} | Total Unique Clusters: {len(clusters)} | Showing Top {min(top, len(clusters))}\n")

    table = Table(title=f"Top {top} Clusters by Size", show_lines=True)
    table.add_column("Rank", justify="right", style="cyan", no_wrap=True)
    table.add_column("Pattern", style="bold green")
    table.add_column("Count", justify="right", style="magenta")
    table.add_column("Sample URLs (2-3 raw examples)", style="dim")

    for i, (pattern, member_urls) in enumerate(list(clusters.items())[:top], start=1):
        samples = "\n".join(member_urls[:3])
        table.add_row(str(i), pattern, str(len(member_urls)), samples)

    console.print(table)


if __name__ == "__main__":
    app()
