"""Strata CLI — unified attack-surface intelligence engine."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from strata import __version__ as _VERSION
from strata.adapters.aperture import load_aperture_jsonl
from strata.cli.ui import (
    KV,
    C,
    Icon,
    Spinner,
    err,
    info,
    ok,
    print_banner,
    print_config_hint,
    print_dns_finding,
    print_findings_table,
    print_import_summary,
    print_kv_table,
    print_summary_box,
    section,
    stage_done,
    stage_start,
    warn,
)
from strata.core.dns.resolver import DnspythonTransport, NxDomain, Resolver
from strata.core.policy.scope import ScopePolicy
from strata.core.redact import redact_url
from strata.core.schema.models import (
    Evidence,
    EvidenceStrength,
    FindingClass,
    FindingStatus,
)
from strata.core.store.db import StrataDB
from strata.engines.fusion import fuse_findings, superseded_finding_ids


def _scoped_target(db: StrataDB, requested: str | None) -> str | None:
    """Resolve the read scope: explicit flag, single stored target, or all."""
    targets = db.targets()
    if requested:
        return requested.strip().lower()
    if len(targets) == 1:
        return next(iter(targets))
    if len(targets) > 1:
        warn(
            f"DB contains {len(targets)} targets; showing all findings. "
            f"Use {C.CYAN}--target <name>{C.RST} for strict isolation."
        )
    return None


# ─────────────────────────── import-aperture ────────────────────────────────
def cmd_import_aperture(args: argparse.Namespace) -> int:
    print_banner(_VERSION)
    db = StrataDB(args.db)
    imported = 0
    errors = 0
    with Spinner(f"Importing aperture -> {args.file}"):
        for finding in load_aperture_jsonl(args.file):
            try:
                db.upsert_finding(finding, target=args.target)
                imported += 1
            except ValueError as exc:
                warn(f"skip: {exc}")
                errors += 1
    stats = db.stats()
    db.close()
    print_import_summary("aperture", imported, errors, stats)
    return 0 if errors == 0 else 1


# ─────────────────────────── generic import helper ──────────────────────────

def _import_content_report(args: argparse.Namespace, loader, source: str) -> int:
    db = StrataDB(args.db)
    imported = 0
    with Spinner(f"Importing {source} -> {args.file}"):
        try:
            for finding in loader(args.file):
                db.upsert_finding(finding, target=args.target)
                imported += 1
        except ValueError as exc:
            err(str(exc))
            db.close()
            return 2
    stats = db.stats()
    db.close()
    print_import_summary(source, imported, 0, stats)
    return 0


def cmd_import_vulnharvest(args: argparse.Namespace) -> int:
    from strata.adapters.vulnharvest import load_vulnharvest_report
    print_banner(_VERSION)
    return _import_content_report(args, load_vulnharvest_report, "vulnharvest")


def cmd_import_jsast(args: argparse.Namespace) -> int:
    from strata.adapters.jsast import load_jsast_report
    print_banner(_VERSION)
    return _import_content_report(args, load_jsast_report, "jsast")


def cmd_import_triage_loom(args: argparse.Namespace) -> int:
    from strata.adapters.triage_loom import load_triage_loom_jsonl
    print_banner(_VERSION)
    return _import_content_report(args, load_triage_loom_jsonl, "triage-loom")


# ─────────────────────────── content ────────────────────────────────────────

def cmd_content(args: argparse.Namespace) -> int:
    from strata.core.budget import RequestBudget
    from strata.core.content.fetch import UrllibTransport
    from strata.engines.js_content import ContentDiscoveryEngine

    host = urlparse(args.url).hostname
    if not host:
        err("content URL needs a host component")
        return 2
    scope = args.scope or host
    budget = RequestBudget(
        max_requests=args.max_requests,
        max_bytes=args.max_bytes,
        max_seconds=args.max_seconds,
    )

    print_banner(_VERSION, target=args.url)

    async def run() -> int:
        policy = ScopePolicy.from_spec(scope)
        known: set[str] = set()
        if args.resume:
            db = StrataDB(args.db)
            known = {
                f.asset_value
                for f in db.iter_findings(target=host)
                if f.kind in (FindingClass.ENDPOINT, FindingClass.SECRET)
            }
            db.close()
            info(f"Resuming — {len(known)} known assets skipped")

        engine = ContentDiscoveryEngine(
            UrllibTransport(budget=budget if budget.enabled else None),
            policy,
            max_scripts=args.max_scripts,
            max_probe=args.max_probe,
            probe=not args.no_probe,
            robots=not args.no_robots,
            timeout=args.timeout,
            known=known,
        )

        stage_start("Content Discovery", args.url)
        t0 = time.monotonic()
        result = await engine.run(args.url)
        elapsed = time.monotonic() - t0

        db = StrataDB(args.db)
        for finding in result.findings:
            db.upsert_finding(finding, target=host)
        stats = db.stats(target=host)
        db.close()

        s = result.stats
        stage_done("content", {
            "pages": s.pages_fetched,
            "scripts": s.scripts_fetched,
            "endpoints": s.endpoints_stored,
            "secrets": s.secrets_found,
            "probed": s.probed,
            "verified": s.verified,
            "dead": s.dead,
            "errors": s.errors,
        })
        print_findings_table(result.findings[:20])
        print_summary_box(
            args.url,
            {"endpoints": s.endpoints_stored, "secrets": s.secrets_found,
             "total_in_db": stats["findings"]},
            elapsed,
        )
        return 0

    try:
        return asyncio.run(run())
    except (PermissionError, ValueError) as exc:
        err(str(exc))
        return 2


# ─────────────────────────── report ─────────────────────────────────────────

def cmd_report(args: argparse.Namespace) -> int:
    from strata.core.paths import timestamped_report_path
    from strata.core.reporting import ReportFormat, write_report

    print_banner(_VERSION)
    db = StrataDB(args.db)
    target = _scoped_target(db, args.target)
    findings = list(db.iter_findings(target=target))
    db.close()

    if args.min_confidence is not None:
        findings = [f for f in findings if f.confidence.value >= args.min_confidence]
    if args.limit:
        findings = findings[: args.limit]

    fmt = ReportFormat(args.format)
    prefix = (
        f"strata-{target.replace('.', '-')}" if target else "strata-report"
    )
    report_path = Path(args.out) if args.out else timestamped_report_path(
        prefix=prefix, extension=fmt.value
    )
    write_report(findings, report_path, fmt, title=args.title)

    section("Report", Icon.OK)
    print_kv_table([
        KV("target",   target or "all",         C.WHITE),
        KV("format",   fmt.value,              C.CYAN),
        KV("findings", str(len(findings)),      C.BGREEN),
        KV("output",   str(report_path),        C.WHITE),
    ])
    print()

    if args.strict and findings:
        return 1
    return 0


# ─────────────────────────── tension ────────────────────────────────────────

def cmd_tension(args: argparse.Namespace) -> int:
    from strata.core.paths import timestamped_report_path
    from strata.engines.tension import summarise_tension, tension_markdown

    print_banner(_VERSION)
    db = StrataDB(args.db)
    target = _scoped_target(db, args.target)
    findings = list(db.iter_findings(target=target))
    db.close()

    prefix = f"strata-tension-{target.replace('.', '-')}" if target else "strata-tension"
    report_path = Path(args.out) if args.out else timestamped_report_path(
        prefix=prefix, extension="md"
    )
    report_path.write_text(
        tension_markdown(findings, title="Strata tension report"),
        encoding="utf-8",
        newline="\n",
    )
    summary, items = summarise_tension(findings)

    section("Evidence Tension Analysis", Icon.FIRE)
    print_kv_table([
        KV("target",       target or "all",            C.WHITE),
        KV("total",        str(summary.total),       C.WHITE),
        KV("hot",          str(summary.hot),          C.RED),
        KV("ghost",        str(summary.ghost),        C.GRAY),
        KV("shadow",       str(summary.shadow),       C.YELLOW),
        KV("stable",       str(summary.stable),       C.GREEN),
        KV("mean_tension", f"{summary.mean_score}",   C.CYAN),
    ])
    print()

    if items:
        section("Top Tension Findings", Icon.FIRE)
        for a in items[:10]:
            sc = C.RED if a.score >= 70 else C.YELLOW if a.score >= 40 else C.GRAY
            print(
                f"  {sc}{a.score:>3}{C.RST}  "
                f"{C.BOLD}{a.label:<6}{C.RST}  "
                f"{C.CYAN}{a.confidence:5.1f}{C.RST}  "
                f"{redact_url(a.asset_value)}"
            )
    print()
    ok(f"Tension report -> {C.CYAN}{report_path}{C.RST}")
    return 0


# ─────────────────────────── calibrate ──────────────────────────────────────

def cmd_calibrate(args: argparse.Namespace) -> int:
    from strata.core.paths import timestamped_report_path

    print_banner(_VERSION)
    db = StrataDB(args.db)
    target = _scoped_target(db, args.target)
    data = db.calibration(target=target)
    db.close()

    prefix = f"strata-calibration-{target.replace('.', '-')}" if target else "strata-calibration"
    report_path = Path(args.out) if args.out else timestamped_report_path(
        prefix=prefix, extension="md"
    )
    lines = [
        "# Strata calibration report",
        "",
        f"- target: {target or 'all'}",
        f"- outcomes: {data['outcomes']}",
        f"- verified: {data['verified']}",
        f"- dead: {data['dead']}",
        f"- brier: {data['brier'] if data['brier'] is not None else 'n/a'}",
        f"- log_loss: {data['log_loss'] if data['log_loss'] is not None else 'n/a'}",
        f"- accuracy: {data['accuracy'] if data['accuracy'] is not None else 'n/a'}",
        "",
        "| Band | Count | Mean predicted | Observed rate |",
        "|---|---:|---:|---:|",
    ]
    for band in data["bands"]:
        mean = band["mean_predicted"] if band["mean_predicted"] is not None else "-"
        observed = band["observed_rate"] if band["observed_rate"] is not None else "-"
        lines.append(
            f"| {band['band']} | {band['count']} | {mean} | {observed} |"
        )
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    section("Confidence Calibration", Icon.INFO)
    print_kv_table([
        KV("target",   target or "all",                                       C.WHITE),
        KV("outcomes", str(data["outcomes"]),                                 C.WHITE),
        KV("verified", str(data["verified"]),                                 C.GREEN),
        KV("dead",     str(data["dead"]),                                     C.RED),
        KV("brier",    str(data["brier"]) if data["brier"] is not None else "-", C.CYAN),
        KV("log_loss", str(data["log_loss"]) if data["log_loss"] is not None else "-", C.CYAN),
        KV("accuracy", str(data["accuracy"]) if data["accuracy"] is not None else "-", C.CYAN),
    ])
    if data["outcomes"] == 0:
        warn("no verification outcomes yet — run `strata verify` or re-run the pipeline")
    print()
    if data["outcomes"]:
        section("Reliability bands", Icon.BULLET)
        for band in data["bands"]:
            mean = band["mean_predicted"] if band["mean_predicted"] is not None else "-"
            observed = band["observed_rate"] if band["observed_rate"] is not None else "-"
            print(
                f"  {C.BOLD}{band['band']:<7}{C.RST} "
                f"n={band['count']:<4} predicted={mean:<6} observed={observed}"
            )
        print()
    ok(f"Calibration report -> {C.CYAN}{report_path}{C.RST}")
    return 0


# ─────────────────────────── run ────────────────────────────────────────────

def cmd_run(args: argparse.Namespace) -> int:
    from strata.engines.orchestrator import Orchestrator, RunOptions

    target = args.target or args.target_option
    if not target:
        err("target is required")
        return 2
    if args.target and args.target_option and args.target != args.target_option:
        err("target specified twice with different values")
        return 2

    print_banner(_VERSION, target=target)

    # config hint
    try:
        from strata.core.config import get_config
        print_config_hint(get_config())
    except Exception:
        pass

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
        no_passive=getattr(args, "no_passive", False),
        no_fingerprint=getattr(args, "no_fingerprint", False),
        min_sources=args.min_sources,
        max_requests=args.max_requests,
        max_bytes=args.max_bytes,
        max_seconds=args.max_seconds,
        strict_stages=args.strict_stages,
        report_format=args.report_format,
        report_out=args.report_out,
        title=args.title,
        dry_run=args.dry_run,
        import_aperture=args.import_aperture and Path(args.import_aperture),
        import_jsast=args.import_jsast and Path(args.import_jsast),
        import_vulnharvest=args.import_vulnharvest and Path(args.import_vulnharvest),
        import_triage_loom=args.import_triage_loom and Path(args.import_triage_loom),
    )

    t0 = time.monotonic()
    try:
        orchestrator = Orchestrator(options)
        result = asyncio.run(orchestrator.run())
    except (PermissionError, ValueError) as exc:
        err(str(exc))
        return 2

    elapsed = time.monotonic() - t0

    db = StrataDB(options.db_path)
    findings = list(db.iter_findings(target=result.target))
    total_findings = db.stats()["findings"]
    db.close()
    other_count = max(0, total_findings - len(findings))
    if other_count > 0:
        warn(
            f"DB contains {other_count} findings from other targets "
            f"(excluded from display). "
            f"Use {C.CYAN}--db {result.target.replace('.', '-')}.db{C.RST} "
            f"for isolated target DBs."
        )

    if findings:
        section("Top Findings", Icon.BULLET)
        print_findings_table(sorted(findings, key=lambda f: -f.confidence.value)[:15])

    scoped_stats: dict[str, int | str] = {
        "findings":  len(findings),
        "verified":  sum(1 for f in findings if f.status == FindingStatus.VERIFIED),
        "candidate": sum(1 for f in findings if f.status == FindingStatus.CANDIDATE),
        "dead":      sum(1 for f in findings if f.status == FindingStatus.DEAD),
    }
    print_summary_box(
        result.target,
        scoped_stats,
        elapsed,
        str(result.report_path) if result.report_path else None,
    )
    if result.manifest_path:
        ok(f"manifest -> {C.CYAN}{result.manifest_path}{C.RST}")
    return 0


# ─────────────────────────── fuse ───────────────────────────────────────────

def cmd_fuse(args: argparse.Namespace) -> int:
    print_banner(_VERSION)
    db = StrataDB(args.db)
    target = _scoped_target(db, args.target)
    if target is None and len(db.targets()) > 1:
        db.close()
        err("fusing across multiple targets is unsafe; pass --target <name>")
        return 2
    findings = list(db.iter_findings(target=target))
    with Spinner("Fusing entities…"):
        fused = [
            f for f in fuse_findings(findings)
            if f.metadata.get("source_count", 1) >= args.min_sources
        ]
        superseded = 0
        for f in fused:
            db.upsert_finding(f, target=target)
            superseded += db.delete_findings(superseded_finding_ids(f))
    stats = db.stats(target=target)
    db.close()

    section("Entity Fusion", Icon.ARROW)
    print_kv_table([
        KV("target",         target or "all",              C.WHITE),
        KV("input_findings", str(len(findings)), C.WHITE),
        KV("fused",          str(len(fused)),    C.BGREEN),
        KV("superseded",     str(superseded),    C.YELLOW),
        KV("total_in_db",    str(stats.get("findings", 0)), C.CYAN),
    ])
    if fused:
        print()
        print_findings_table(fused[:10])
    return 0


# ─────────────────────────── stats ──────────────────────────────────────────

def cmd_stats(args: argparse.Namespace) -> int:
    print_banner(_VERSION)
    db = StrataDB(args.db)
    target = _scoped_target(db, args.target)
    stats = db.stats(target=target)
    db.close()

    section("Database Statistics", Icon.INFO)
    rows = [KV("target", target or "all", C.WHITE)]
    rows.extend(
        KV(k, str(v), C.BWHITE if isinstance(v, int) and v > 0 else C.GRAY)
        for k, v in sorted(stats.items())
    )
    print_kv_table(rows)
    print()
    return 0


# ─────────────────────────── list ───────────────────────────────────────────

def cmd_list(args: argparse.Namespace) -> int:
    print_banner(_VERSION)
    db = StrataDB(args.db)
    target = _scoped_target(db, args.target)
    total = db.stats(target=target)["findings"]
    findings = []
    for finding in db.iter_findings(target=target):
        if args.limit and len(findings) >= args.limit:
            break
        findings.append(finding)
    db.close()

    section(f"Findings ({len(findings)} of {total}) — {target or 'all targets'}", Icon.BULLET)
    print_findings_table(findings, max_rows=args.limit or 50)
    return 0


# ─────────────────────────── dns ────────────────────────────────────────────

def cmd_dns(args: argparse.Namespace) -> int:
    from strata.engines.dns_brute import DnsDiscoveryEngine

    print_banner(_VERSION, target=args.domain)

    async def run() -> int:
        policy    = ScopePolicy.from_list([args.domain])
        transport = DnspythonTransport(timeout=args.timeout)
        known: set[str] = set()
        if args.resume:
            db = StrataDB(args.db)
            known = {
                f.asset_value for f in db.iter_findings(target=args.domain)
                if f.kind is FindingClass.SUBDOMAIN
            }
            db.close()
            info(f"Resuming — {len(known)} already-known subdomains skipped")

        engine = DnsDiscoveryEngine(
            resolver=Resolver(transport),
            policy=policy,
            wordlist=args.wordlist,
            max_concurrency=args.concurrency,
            mutate=not args.no_mutations,
            known=known,
        )

        stage_start("DNS Bruteforce", f"wordlist={args.wordlist}  concurrency={args.concurrency}")
        t0 = time.monotonic()
        result = await engine.run(args.domain)
        elapsed = time.monotonic() - t0

        db = StrataDB(args.db)
        for f in result.findings:
            db.upsert_finding(f, target=args.domain)
        stats = db.stats(target=args.domain)
        db.close()

        s = result.stats
        stage_done("dns", {
            "tested": s.candidates_tested,
            "resolved": s.resolved,
            "wildcard_filtered": s.wildcard_filtered,
            "mutations": s.mutation_candidates,
            "errors": s.errors,
        })

        if result.wildcard:
            warn(f"Wildcard detected on {C.YELLOW}{args.domain}{C.RST} — results may be noisy")

        if result.findings:
            section(f"Subdomains Found ({len(result.findings)})", Icon.PASS)
            for f in sorted(result.findings, key=lambda x: -x.confidence.value)[:25]:
                print_dns_finding(f)

        print_summary_box(
            args.domain,
            {"subdomains": len(result.findings), "total_in_db": stats["findings"]},
            elapsed,
        )
        return 0

    try:
        return asyncio.run(run())
    except PermissionError as exc:
        err(str(exc))
        return 2


# ─────────────────────────── verify ─────────────────────────────────────────

def cmd_verify(args: argparse.Namespace) -> int:
    """Re-resolve candidate subdomains: DNS answer -> verified, NXDOMAIN -> dead."""
    print_banner(_VERSION)

    async def run() -> tuple[int, int, int]:
        transport = DnspythonTransport(timeout=args.timeout)
        resolver  = Resolver(transport)
        db        = StrataDB(args.db)
        target    = _scoped_target(db, args.target)
        verified  = dead = failed = 0

        candidates = [
            f for f in db.iter_findings(target=target)
            if f.kind is FindingClass.SUBDOMAIN
            and f.status is FindingStatus.CANDIDATE
        ]

        stage_start("DNS Verify", f"{len(candidates)} candidates")
        t0 = time.monotonic()

        for finding in candidates:
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
            db.upsert_finding(finding, target=target)

        db.close()
        elapsed = time.monotonic() - t0
        stage_done("verify", {"verified": verified, "dead": dead, "failed": failed})
        print_summary_box(
            "dns-verify",
            {"verified": verified, "dead": dead, "failed": failed},
            elapsed,
        )
        return verified, dead, failed

    asyncio.run(run())
    return 0


# ─────────────────────────── argument parser ────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strata",
        description=(
            f"{C.BOLD}Strata{C.RST} — unified attack-surface intelligence engine\n"
            f"  passive DNS  •  DNS bruteforce  •  HTTP fingerprinting\n"
            f"  content crawl  •  parameter probing  •  evidence fusion"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # import-aperture
    imp = sub.add_parser("import-aperture", help="import an Aperture JSONL output file")
    imp.add_argument("file", help="path to aperture .jsonl")
    imp.add_argument("--db", default="strata.db", help="SQLite database path")
    imp.add_argument("--target", help="attach imported findings to this target")
    imp.set_defaults(func=cmd_import_aperture)

    # stats
    stats = sub.add_parser("stats", help="show database statistics")
    stats.add_argument("--db", default="strata.db")
    stats.add_argument("--target", help="scope statistics to one target")
    stats.set_defaults(func=cmd_stats)

    # list
    lst = sub.add_parser("list", help="list findings from the database")
    lst.add_argument("--db", default="strata.db")
    lst.add_argument("--limit", type=int, default=50)
    lst.add_argument("--target", help="scope listing to one target")
    lst.set_defaults(func=cmd_list)

    # dns
    dns = sub.add_parser("dns", help="DNS discovery — wordlist bruteforce + echo mutations")
    dns.add_argument("domain", help="in-scope root domain to enumerate")
    dns.add_argument("--db", default="strata.db")
    dns.add_argument("--wordlist", default="base", choices=["base", "common"])
    dns.add_argument("--concurrency", type=int, default=50)
    dns.add_argument("--timeout", type=float, default=5.0)
    dns.add_argument("--no-mutations", action="store_true", help="skip echo mutation passes")
    dns.add_argument("--resume", action="store_true", help="skip subdomains already stored")
    dns.set_defaults(func=cmd_dns)

    # verify
    verify = sub.add_parser("verify", help="re-resolve stored candidates to verified / dead")
    verify.add_argument("--db", default="strata.db")
    verify.add_argument("--timeout", type=float, default=5.0)
    verify.add_argument("--target", help="scope verification to one target")
    verify.set_defaults(func=cmd_verify)

    # content
    content = sub.add_parser(
        "content", help="JS/robots/sitemap content discovery and secret scan"
    )
    content.add_argument("url", help="seed URL (http/https)")
    content.add_argument("--db", default="strata.db")
    content.add_argument("--scope", help="scope allowlist (default: seed host)")
    content.add_argument("--max-scripts", type=int, default=25)
    content.add_argument("--max-probe", type=int, default=50)
    content.add_argument("--timeout", type=float, default=10.0)
    content.add_argument("--no-probe", action="store_true")
    content.add_argument("--no-robots", action="store_true")
    content.add_argument("--resume", action="store_true")
    content.add_argument("--max-requests", type=int, default=0, help="0 = unlimited")
    content.add_argument("--max-bytes", type=int, default=0, help="0 = unlimited")
    content.add_argument("--max-seconds", type=float, default=0.0, help="0 = unlimited")
    content.set_defaults(func=cmd_content)

    # import-vulnharvest
    vh = sub.add_parser("import-vulnharvest", help="import a VulnHarvest JSON report")
    vh.add_argument("file")
    vh.add_argument("--db", default="strata.db")
    vh.add_argument("--target", help="attach imported findings to this target")
    vh.set_defaults(func=cmd_import_vulnharvest)

    # import-jsast
    jsast = sub.add_parser("import-jsast", help="import a jsast JSON report")
    jsast.add_argument("file")
    jsast.add_argument("--db", default="strata.db")
    jsast.add_argument("--target", help="attach imported findings to this target")
    jsast.set_defaults(func=cmd_import_jsast)

    # import-triage-loom
    triage = sub.add_parser("import-triage-loom", help="import a Triage Loom JSONL export")
    triage.add_argument("file")
    triage.add_argument("--db", default="strata.db")
    triage.add_argument("--target", help="attach imported findings to this target")
    triage.set_defaults(func=cmd_import_triage_loom)

    # fuse
    fuse = sub.add_parser("fuse", help="fuse duplicate entities across runs")
    fuse.add_argument("--db", default="strata.db")
    fuse.add_argument("--min-sources", type=int, default=2)
    fuse.add_argument("--target", help="scope fusion to one target")
    fuse.set_defaults(func=cmd_fuse)

    # run
    run = sub.add_parser(
        "run",
        help="run the full coordinated pipeline on a target",
        description=(
            "Runs all pipeline stages in order:\n"
            "  passive DNS > DNS bruteforce > HTTP fingerprint"
            " > content crawl > param probe > triage\n\n"
            "API keys are always optional — the pipeline runs with zero config."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run.add_argument("target", nargs="?", help="in-scope root domain or URL")
    run.add_argument("--target", dest="target_option", help="same as positional target")
    run.add_argument("--db", default="strata.db")
    run.add_argument("--scope", help="scope allowlist (default: target host)")
    run.add_argument("--wordlist", default="base", choices=["base", "common"])
    run.add_argument("--concurrency", type=int, default=50)
    run.add_argument("--timeout", type=float, default=5.0)
    run.add_argument("--max-scripts", type=int, default=25)
    run.add_argument("--max-probe", type=int, default=50)
    run.add_argument("--max-candidates", type=int, default=50)
    run.add_argument("--no-mutations", action="store_true")
    run.add_argument("--no-probe", action="store_true")
    run.add_argument("--no-robots", action="store_true")
    run.add_argument("--no-dns", action="store_true")
    run.add_argument("--no-content", action="store_true")
    run.add_argument("--no-param", action="store_true")
    run.add_argument("--no-fuse", action="store_true")
    run.add_argument("--no-passive", action="store_true", help="skip passive DNS collection")
    run.add_argument("--no-fingerprint", action="store_true", help="skip HTTP fingerprinting")
    run.add_argument("--import-aperture")
    run.add_argument("--import-jsast")
    run.add_argument("--import-vulnharvest")
    run.add_argument("--import-triage-loom")
    run.add_argument("--no-resume", action="store_true")
    run.add_argument("--min-sources", type=int, default=2)
    run.add_argument(
        "--max-requests", type=int, default=0, help="HTTP request budget (0 = unlimited)"
    )
    run.add_argument(
        "--max-bytes", type=int, default=0, help="response byte budget (0 = unlimited)"
    )
    run.add_argument(
        "--max-seconds", type=float, default=0.0, help="wall-clock budget (0 = unlimited)"
    )
    run.add_argument(
        "--strict-stages", action="store_true", help="re-raise unexpected stage errors"
    )
    run.add_argument("--report-format", choices=["md", "html", "sarif", "jsonl"], default="md")
    run.add_argument("--report-out")
    run.add_argument("--title", default="Strata run")
    run.add_argument("--dry-run", action="store_true", help="show execution plan only")
    run.set_defaults(func=cmd_run)

    # tension
    tension = sub.add_parser("tension", help="evidence tension analysis over stored findings")
    tension.add_argument("--db", default="strata.db")
    tension.add_argument("--target", help="scope tension analysis to one target")
    tension.add_argument("--out", help="explicit report path")
    tension.set_defaults(func=cmd_tension)

    # calibrate
    calibrate = sub.add_parser(
        "calibrate", help="confidence calibration from verified/dead outcomes"
    )
    calibrate.add_argument("--db", default="strata.db")
    calibrate.add_argument("--target", help="scope calibration to one target")
    calibrate.add_argument("--out", help="explicit report path")
    calibrate.set_defaults(func=cmd_calibrate)

    # report
    report = sub.add_parser("report", help="write findings as HTML / MD / SARIF / JSONL")
    report.add_argument("--db", default="strata.db")
    report.add_argument("--target", help="scope report to one target")
    report.add_argument("--format", choices=["html", "md", "sarif", "jsonl"], default="md")
    report.add_argument("--out")
    report.add_argument("--title", default="Strata report")
    report.add_argument("--min-confidence", type=float, default=None)
    report.add_argument("--limit", type=int, default=0)
    report.add_argument("--strict", action="store_true")
    report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
