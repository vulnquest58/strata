"""Strata CLI (P2): DNS + content discovery and archive importers over the
P0 store."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

from strata.adapters.aperture import load_aperture_jsonl
from strata.core.dns.resolver import DnspythonTransport, NxDomain, Resolver
from strata.core.policy.scope import ScopePolicy
from strata.core.schema.models import (
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
)
from strata.core.store.db import StrataDB
from strata.engines.fusion import fuse_findings


def cmd_import_aperture(args: argparse.Namespace) -> int:
    db = StrataDB(args.db)
    imported = 0
    errors = 0
    for finding in load_aperture_jsonl(args.file):
        try:
            db.upsert_finding(finding)
            imported += 1
        except ValueError as exc:
            print(f"skip: {exc}", file=sys.stderr)
            errors += 1
    stats = db.stats()
    db.close()
    print(f"imported={imported} errors={errors}")
    print(
        f"findings={stats['findings']} evidence={stats['evidence']} "
        + " ".join(f"{k}={v}" for k, v in sorted(stats.items()) if k.startswith("status_"))
    )
    return 0 if errors == 0 else 1


def _import_content_report(args: argparse.Namespace, loader) -> int:
    db = StrataDB(args.db)
    imported = 0
    try:
        for finding in loader(args.file):
            db.upsert_finding(finding)
            imported += 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        db.close()
        return 2
    stats = db.stats()
    db.close()
    print(f"imported={imported}")
    print(
        f"findings={stats['findings']} evidence={stats['evidence']} "
        + " ".join(f"{k}={v}" for k, v in sorted(stats.items()) if k.startswith("status_"))
    )
    return 0


def cmd_import_vulnharvest(args: argparse.Namespace) -> int:
    from strata.adapters.vulnharvest import load_vulnharvest_report

    return _import_content_report(args, load_vulnharvest_report)


def cmd_import_jsast(args: argparse.Namespace) -> int:
    from strata.adapters.jsast import load_jsast_report

    return _import_content_report(args, load_jsast_report)


def cmd_content(args: argparse.Namespace) -> int:
    from strata.core.content.fetch import UrllibTransport
    from strata.engines.js_content import ContentDiscoveryEngine

    host = urlparse(args.url).hostname
    if not host:
        print("error: content URL needs a host", file=sys.stderr)
        return 2
    scope = args.scope or host

    async def run() -> int:
        policy = ScopePolicy.from_spec(scope)
        known: set[str] = set()
        if args.resume:
            db = StrataDB(args.db)
            known = {
                finding.asset_value
                for finding in db.iter_findings()
                if finding.kind in (FindingClass.ENDPOINT, FindingClass.SECRET)
            }
            db.close()
        engine = ContentDiscoveryEngine(
            UrllibTransport(),
            policy,
            max_scripts=args.max_scripts,
            max_probe=args.max_probe,
            probe=not args.no_probe,
            robots=not args.no_robots,
            timeout=args.timeout,
            known=known,
        )
        result = await engine.run(args.url)

        db = StrataDB(args.db)
        for finding in result.findings:
            db.upsert_finding(finding)
        stats = db.stats()
        db.close()

        s = result.stats
        print(
            f"pages={s.pages_fetched} scripts={s.scripts_fetched} "
            f"endpoints_raw={s.endpoints_extracted} "
            f"out_of_scope={s.endpoints_out_of_scope} "
            f"endpoints={s.endpoints_stored} secrets={s.secrets_found}"
        )
        print(
            f"probed={s.probed} verified={s.verified} dead={s.dead} "
            f"errors={s.errors} total_in_db={stats['findings']} "
            f"evidence_in_db={stats['evidence']}"
        )
        for finding in result.findings[:10]:
            print(
                f"  {finding.kind.value:8s} {finding.status.value:9s} "
                f"{finding.confidence.value:6.1f} {finding.asset_value}"
            )
        return 0

    try:
        return asyncio.run(run())
    except (PermissionError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def cmd_import_triage_loom(args: argparse.Namespace) -> int:
    from strata.adapters.triage_loom import load_triage_loom_jsonl

    return _import_content_report(args, load_triage_loom_jsonl)


def cmd_report(args: argparse.Namespace) -> int:
    from strata.core.paths import timestamped_report_path
    from strata.core.reporting import ReportFormat, write_report

    db = StrataDB(args.db)
    findings = list(db.iter_findings())
    db.close()
    if args.min_confidence is not None:
        findings = [
            finding
            for finding in findings
            if finding.confidence.value >= args.min_confidence
        ]
    if args.limit:
        findings = findings[: args.limit]

    fmt = ReportFormat(args.format)
    if args.out:
        report_path = Path(args.out)
    else:
        report_path = timestamped_report_path(
            prefix="strata-report", extension=fmt.value
        )
    write_report(findings, report_path, fmt, title=args.title)
    print(f"report={report_path}")

    if args.strict and findings:
        return 1
    return 0


def cmd_tension(args: argparse.Namespace) -> int:
    from strata.core.paths import timestamped_report_path
    from strata.engines.tension import summarise_tension, tension_markdown

    db = StrataDB(args.db)
    findings = list(db.iter_findings())
    db.close()
    report_path = timestamped_report_path(prefix="strata-tension", extension="md")
    report_path.write_text(
        tension_markdown(findings, title="Strata tension report"),
        encoding="utf-8",
        newline="\n",
    )
    summary, items = summarise_tension(findings)
    print(
        f"findings={summary.total} hot={summary.hot} ghost={summary.ghost} "
        f"shadow={summary.shadow} stable={summary.stable} "
        f"mean_tension={summary.mean_score}"
    )
    print(f"report={report_path}")
    for assessment in items[:10]:
        print(
            f"  {assessment.score:3d} {assessment.label:6s} "
            f"{assessment.confidence:5.1f} {assessment.asset_value}"
        )
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from strata.engines.orchestrator import Orchestrator, RunOptions

    target = args.target or args.target_option
    if not target:
        print("error: target is required", file=sys.stderr)
        return 2
    if args.target and args.target_option and args.target != args.target_option:
        print("error: target specified twice with different values", file=sys.stderr)
        return 2

    options = RunOptions(
        target=target,
        db_path=args.db,
        scope=args.scope,
        wordlist=args.wordlist,
        max_concurrency=args.concurrency,
        timeout=args.timeout,
        max_scripts=args.max_scripts,
        max_probe=args.max_probe,
        max_candidates=args.max_candidates,
        probe=not args.no_probe,
        robots=not args.no_robots,
        mutate=not args.no_mutations,
        resume=not args.no_resume,
        no_dns=args.no_dns,
        no_content=args.no_content,
        no_param=args.no_param,
        no_fuse=args.no_fuse,
        min_sources=args.min_sources,
        report_format=args.report_format,
        report_out=args.report_out,
        title=args.title,
        dry_run=args.dry_run,
        import_aperture=args.import_aperture and Path(args.import_aperture),
        import_jsast=args.import_jsast and Path(args.import_jsast),
        import_vulnharvest=args.import_vulnharvest and Path(args.import_vulnharvest),
        import_triage_loom=args.import_triage_loom and Path(args.import_triage_loom),
    )
    try:
        orchestrator = Orchestrator(options)
        result = asyncio.run(orchestrator.run())
    except (PermissionError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if result.report_path:
        print(f"report={result.report_path}")
    return 0


def cmd_fuse(args: argparse.Namespace) -> int:
    db = StrataDB(args.db)
    findings = list(db.iter_findings())
    fused = [
        finding
        for finding in fuse_findings(findings)
        if finding.metadata.get("source_count", 1) >= args.min_sources
    ]
    for finding in fused:
        db.upsert_finding(finding)
    stats = db.stats()
    db.close()
    print(f"findings={len(findings)} fused={len(fused)}")
    print(
        f"evidence={stats['evidence']} "
        + " ".join(f"{k}={v}" for k, v in sorted(stats.items()) if k.startswith("status_"))
    )
    for finding in fused[:10]:
        print(
            f"  {finding.kind.value:8s} {finding.status.value:9s} "
            f"{finding.confidence.value:6.1f} {finding.asset_value}"
        )
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    db = StrataDB(args.db)
    stats = db.stats()
    db.close()
    for key in sorted(stats):
        print(f"{key}={stats[key]}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    db = StrataDB(args.db)
    count = 0
    for finding in db.iter_findings():
        count += 1
        if args.limit and count > args.limit:
            break
        strongest = finding.strongest_evidence()
        strongest = strongest.value if strongest else "-"
        print(
            f"{finding.asset_value:40s} {finding.kind.value:10s} "
            f"{finding.status.value:9s} {finding.confidence.value:6.1f} "
            f"ev={len(finding.evidence)} top={strongest}"
        )
    db.close()
    return 0


def cmd_dns(args: argparse.Namespace) -> int:
    from strata.engines.dns_brute import DnsDiscoveryEngine

    async def run() -> int:
        policy = ScopePolicy.from_list([args.domain])
        transport = DnspythonTransport(timeout=args.timeout)
        known: set[str] = set()
        if args.resume:
            db = StrataDB(args.db)
            known = {
                finding.asset_value
                for finding in db.iter_findings()
                if finding.kind is FindingClass.SUBDOMAIN
            }
            db.close()
        engine = DnsDiscoveryEngine(
            resolver=Resolver(transport),
            policy=policy,
            wordlist=args.wordlist,
            max_concurrency=args.concurrency,
            mutate=not args.no_mutations,
            known=known,
        )
        result = await engine.run(args.domain)

        db = StrataDB(args.db)
        for finding in result.findings:
            db.upsert_finding(finding)
        stats = db.stats()
        db.close()

        s = result.stats
        print(f"wildcard_base={'yes' if result.wildcard else 'no'}")
        print(
            f"tested={s.candidates_tested} resolved={s.resolved} "
            f"wildcard_filtered={s.wildcard_filtered} mutations={s.mutation_candidates} "
            f"errors={s.errors}"
        )
        print(
            f"stored_findings={s.findings} total_in_db={stats['findings']} "
            f"evidence_in_db={stats['evidence']}"
        )
        for finding in sorted(result.findings, key=lambda f: -f.confidence.value)[:10]:
            origin = finding.evidence[0].meta.get("origin_provider", "-")
            print(
                f"  {finding.asset_value:40s} {finding.confidence.value:6.1f} "
                f"origin={origin}"
            )
        return 0

    try:
        return asyncio.run(run())
    except PermissionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def cmd_verify(args: argparse.Namespace) -> int:
    """Re-resolve candidate subdomains: DNS answer -> verified, NXDOMAIN -> dead."""

    async def run() -> tuple[int, int, int]:
        transport = DnspythonTransport(timeout=args.timeout)
        resolver = Resolver(transport)
        db = StrataDB(args.db)
        verified = dead = failed = 0
        for finding in db.iter_findings():
            if finding.kind is not FindingClass.SUBDOMAIN:
                continue
            if finding.status is not FindingStatus.CANDIDATE:
                continue
            try:
                host = await resolver.resolve(finding.asset_value)
            except NxDomain:
                host = None
            except Exception:
                failed += 1
                continue
            if host is None:
                finding.status = FindingStatus.DEAD
                finding.evidence.append(
                    Evidence(
                        engine="dns_verify",
                        technique="resolver_consensus",
                        observation="NXDOMAIN / no records on re-resolution",
                        strength=EvidenceStrength.WEAK,
                    )
                )
                dead += 1
            else:
                finding.status = FindingStatus.VERIFIED
                finding.evidence.append(
                    Evidence(
                        engine="dns_verify",
                        technique="resolver_consensus",
                        observation=(
                            f"re-resolved to {len(host.ips)} address(es) "
                            f"(cname={host.cname or 'none'})"
                        ),
                        strength=EvidenceStrength.CORROBORATED,
                        meta={"a_records": list(host.a), "cname": host.cname},
                    )
                )
                verified += 1
            db.upsert_finding(finding)
        db.close()
        return verified, dead, failed

    verified, dead, failed = asyncio.run(run())
    print(f"verified={verified} dead={dead} failed={failed}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strata",
        description="Unified attack-surface intelligence engine",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import-aperture", help="import an aperture JSONL output file")
    imp.add_argument("file", help="path to aperture .jsonl")
    imp.add_argument("--db", default="strata.db", help="Strata SQLite database path")
    imp.set_defaults(func=cmd_import_aperture)

    stats = sub.add_parser("stats", help="show database statistics")
    stats.add_argument("--db", default="strata.db")
    stats.set_defaults(func=cmd_stats)

    lst = sub.add_parser("list", help="list findings")
    lst.add_argument("--db", default="strata.db")
    lst.add_argument("--limit", type=int, default=50)
    lst.set_defaults(func=cmd_list)

    dns = sub.add_parser("dns", help="DNS discovery (wordlist brute + echo mutations)")
    dns.add_argument("domain", help="in-scope root domain to enumerate")
    dns.add_argument("--db", default="strata.db")
    dns.add_argument("--wordlist", default="base", help="packaged wordlist name (base|common)")
    dns.add_argument("--concurrency", type=int, default=50)
    dns.add_argument("--timeout", type=float, default=5.0)
    dns.add_argument("--no-mutations", action="store_true", help="skip echo mutation passes")
    dns.add_argument(
        "--resume", action="store_true", help="skip subdomains already stored"
    )
    dns.set_defaults(func=cmd_dns)

    verify = sub.add_parser("verify", help="re-resolve stored candidates (verified/dead)")
    verify.add_argument("--db", default="strata.db")
    verify.add_argument("--timeout", type=float, default=5.0)
    verify.set_defaults(func=cmd_verify)

    content = sub.add_parser(
        "content", help="JS/robots/sitemap content discovery and secret scan"
    )
    content.add_argument("url", help="seed URL (http/https)")
    content.add_argument("--db", default="strata.db")
    content.add_argument("--scope", help="scope allowlist (default: seed host)")
    content.add_argument("--max-scripts", type=int, default=25)
    content.add_argument("--max-probe", type=int, default=50)
    content.add_argument("--timeout", type=float, default=10.0)
    content.add_argument("--no-probe", action="store_true", help="skip live endpoint probing")
    content.add_argument(
        "--no-robots", action="store_true", help="skip robots/sitemap discovery"
    )
    content.add_argument(
        "--resume", action="store_true", help="skip endpoints/secrets already stored"
    )
    content.set_defaults(func=cmd_content)

    vulnharvest = sub.add_parser(
        "import-vulnharvest", help="import a VulnHarvest JSON report"
    )
    vulnharvest.add_argument("file", help="path to a VulnHarvest report .json")
    vulnharvest.add_argument("--db", default="strata.db")
    vulnharvest.set_defaults(func=cmd_import_vulnharvest)

    jsast = sub.add_parser("import-jsast", help="import a jsast JSON report")
    jsast.add_argument("file", help="path to a jsast JSON export")
    jsast.add_argument("--db", default="strata.db")
    jsast.set_defaults(func=cmd_import_jsast)

    triage = sub.add_parser(
        "import-triage-loom", help="import a Triage Loom JSONL export"
    )
    triage.add_argument("file", help="path to a Triage Loom .jsonl export")
    triage.add_argument("--db", default="strata.db")
    triage.set_defaults(func=cmd_import_triage_loom)

    fuse = sub.add_parser("fuse", help="fuse duplicate entities across runs")
    fuse.add_argument("--db", default="strata.db")
    fuse.add_argument("--min-sources", type=int, default=2)
    fuse.set_defaults(func=cmd_fuse)

    run = sub.add_parser(
        "run", help="run the coordinated pipeline on one target"
    )
    run.add_argument(
        "target", nargs="?", help="in-scope root domain or URL"
    )
    run.add_argument(
        "--target", dest="target_option", help="same as positional target"
    )
    run.add_argument("--db", default="strata.db")
    run.add_argument("--scope", help="scope allowlist (default: target host)")
    run.add_argument("--wordlist", default="base", choices=["base", "common"])
    run.add_argument("--concurrency", type=int, default=50)
    run.add_argument("--timeout", type=float, default=5.0)
    run.add_argument("--max-scripts", type=int, default=25)
    run.add_argument("--max-probe", type=int, default=50)
    run.add_argument("--max-candidates", type=int, default=50)
    run.add_argument(
        "--no-mutations", action="store_true", help="skip DNS echo mutations"
    )
    run.add_argument(
        "--no-probe", action="store_true", help="skip live endpoint probing"
    )
    run.add_argument(
        "--no-robots", action="store_true", help="skip robots/sitemap discovery"
    )
    run.add_argument("--no-dns", action="store_true", help="skip DNS discovery")
    run.add_argument(
        "--no-content", action="store_true", help="skip content discovery"
    )
    run.add_argument(
        "--no-param", action="store_true", help="skip parameter probing"
    )
    run.add_argument("--no-fuse", action="store_true", help="skip entity fusion")
    run.add_argument(
        "--import-aperture", help="import an aperture JSONL output file before the run"
    )
    run.add_argument(
        "--import-jsast", help="import a jsast JSON report before the run"
    )
    run.add_argument(
        "--import-vulnharvest", help="import a VulnHarvest JSON report before the run"
    )
    run.add_argument(
        "--import-triage-loom", help="import a Triage Loom JSONL export before the run"
    )
    run.add_argument(
        "--no-resume", action="store_true", help="ignore stored findings and rescan"
    )
    run.add_argument("--min-sources", type=int, default=2)
    run.add_argument(
        "--report-format",
        choices=["md", "html", "sarif", "jsonl"],
        default="md",
    )
    run.add_argument("--report-out", help="write the report to this path")
    run.add_argument("--title", default="Strata run")
    run.add_argument(
        "--dry-run", action="store_true", help="show the plan without executing"
    )
    run.set_defaults(func=cmd_run)

    tension = sub.add_parser(
        "tension", help="evidence tension analysis over stored findings"
    )
    tension.add_argument("--db", default="strata.db")
    tension.set_defaults(func=cmd_tension)

    report = sub.add_parser("report", help="write findings as HTML/MD/SARIF/JSONL")
    report.add_argument("--db", default="strata.db")
    report.add_argument(
        "--format", choices=["html", "md", "sarif", "jsonl"], default="md"
    )
    report.add_argument("--out", help="output path (stdout when omitted)")
    report.add_argument("--title", default="Strata report")
    report.add_argument("--min-confidence", type=float, default=None)
    report.add_argument("--limit", type=int, default=0)
    report.add_argument(
        "--strict", action="store_true", help="exit 1 when any finding is emitted"
    )
    report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
