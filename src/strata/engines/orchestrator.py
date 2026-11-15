"""Run orchestrator (P6).

One entry point that reads the current surface, plans the next useful work,
executes DNS/content/param stages, reconciles duplicate entities, and reports.
It keeps lightweight per-target memory so the next run can adapt instead of
blindly repeating the same plan.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from strata.adapters.aperture import load_aperture_jsonl
from strata.adapters.jsast import load_jsast_report
from strata.adapters.nuclei import load_nuclei_jsonl
from strata.adapters.passive_dns import passive_dns_to_findings, query_passive_dns
from strata.adapters.triage_loom import load_triage_loom_jsonl
from strata.adapters.vulnharvest import load_vulnharvest_report
from strata.core.budget import RequestBudget
from strata.core.config import get_config
from strata.core.content.fetch import HttpTransport, ThrottledTransport, UrllibTransport
from strata.core.content.urls import host_of
from strata.core.dns.resolver import DnspythonTransport, Resolver
from strata.core.errors import classify_exception
from strata.core.manifest import RunManifest, manifest_path_for
from strata.core.paths import timestamped_report_path
from strata.core.policy.scope import ScopePolicy
from strata.core.reliability import reliability_weights
from strata.core.reporting import ReportFormat, summarise, write_report
from strata.core.schedule import PROBEABLE_KINDS
from strata.core.schema.models import FindingClass, FindingStatus, is_probable_domain
from strata.core.store.db import StrataDB
from strata.core.vulns import cve_findings
from strata.engines.dns_brute import DnsDiscoveryEngine
from strata.engines.fusion import fuse_findings, superseded_finding_ids
from strata.engines.http_fp import fingerprint_url
from strata.engines.js_content import ContentDiscoveryEngine
from strata.engines.param_oracle import ParamOracle
from strata.engines.probe_engine import ProbeEngine
from strata.engines.tension import summarise_tension


@dataclass
class StageMemory:
    runs: int = 0
    new_findings: int = 0
    total_findings: int = 0
    last_seen: str | None = None

    @classmethod
    def from_dict(cls, data: Any) -> StageMemory:
        if not isinstance(data, dict):
            return cls()
        return cls(
            runs=int(data.get("runs", 0) or 0),
            new_findings=int(data.get("new_findings", 0) or 0),
            total_findings=int(data.get("total_findings", 0) or 0),
            last_seen=data.get("last_seen") or None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "runs": self.runs,
            "new_findings": self.new_findings,
            "total_findings": self.total_findings,
            "last_seen": self.last_seen,
        }


@dataclass
class RunMemory:
    runs: int = 0
    stages: dict[str, StageMemory] = field(default_factory=dict)
    insights: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunMemory:
        if not isinstance(data, dict):
            return cls()
        stages_raw = data.get("stages") or {}
        stages = {
            key: StageMemory.from_dict(value)
            for key, value in stages_raw.items()
            if isinstance(value, dict)
        }
        insights_raw = data.get("insights") or []
        insights = [str(item) for item in insights_raw if str(item)]
        return cls(
            runs=int(data.get("runs", 0) or 0),
            stages=stages,
            insights=insights[-10:],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "runs": self.runs,
            "stages": {k: v.to_dict() for k, v in sorted(self.stages.items())},
            "insights": self.insights[-10:],
        }

    def record(
        self,
        stage: str,
        *,
        new_findings: int,
        total_findings: int,
        insight: str | None = None,
    ) -> None:
        current = self.stages.get(stage, StageMemory())
        current.runs += 1
        current.new_findings = new_findings
        current.total_findings = total_findings
        current.last_seen = datetime.now(UTC).isoformat()
        self.stages[stage] = current
        if insight:
            self.insights.append(insight)

    def suggestions(self) -> dict[str, Any]:
        """Turn previous outcomes into conservative next-run adjustments."""
        suggestions: dict[str, Any] = {}
        dns = self.stages.get("dns")
        if dns and dns.runs and dns.new_findings <= 3:
            suggestions["wordlist"] = "common"
        content = self.stages.get("content")
        if content and content.runs and content.new_findings > 20:
            suggestions["max_scripts"] = 50
            suggestions["max_probe"] = 100
        param = self.stages.get("param")
        if param and param.runs and param.new_findings <= 3:
            suggestions["max_candidates"] = 100
        return suggestions


@dataclass
class StageResult:
    stage: str
    new_findings: int = 0
    total_findings: int = 0
    stats: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    status: str = "ok"


@dataclass
class RunResult:
    target: str
    stages: list[StageResult] = field(default_factory=list)
    report_path: Path | None = None
    memory: RunMemory | None = None
    db_stats: dict[str, int] = field(default_factory=dict)
    manifest: dict[str, Any] | None = None
    manifest_path: Path | None = None


@dataclass(frozen=True)
class RunOptions:
    target: str
    db_path: str | Path = "strata.db"
    scope: str | None = None
    wordlist: str = "base"
    max_concurrency: int = 50
    timeout: float = 5.0
    max_scripts: int = 25
    max_probe: int = 50
    max_candidates: int = 50
    probe: bool = True
    robots: bool = True
    mutate: bool = True
    resume: bool = True
    no_dns: bool = False
    no_passive: bool = False        # skip passive DNS (crt.sh + API sources)
    no_fingerprint: bool = False    # skip HTTP fingerprinting
    no_content: bool = False
    no_param: bool = False
    no_fuse: bool = False
    min_sources: int = 2
    max_requests: int = 0           # 0 = unlimited (HTTP requests)
    max_bytes: int = 0              # 0 = unlimited (response bytes)
    max_seconds: float = 0.0        # 0 = unlimited (wall clock)
    strict_stages: bool = False     # re-raise unexpected stage exceptions
    report_format: ReportFormat | str = ReportFormat.MARKDOWN
    report_out: str | Path | None = None
    title: str = "Strata run"
    dry_run: bool = False
    import_aperture: Path | None = None
    import_jsast: Path | None = None
    import_vulnharvest: Path | None = None
    import_triage_loom: Path | None = None
    import_nuclei: Path | None = None
    # Authenticated surface discovery: session headers applied to every
    # in-scope HTTP request. Values are never written to reports/manifests.
    extra_headers: dict[str, str] = field(default_factory=dict)
    scope_file: Path | None = None
    notify_url: str | None = None
    auto_snapshot: bool = False


class RunLog:
    """Styled terminal output for the orchestrator pipeline."""

    # Lazy import of ui to avoid circular deps and keep tests fast
    @staticmethod
    def _ui():  # type: ignore[return]
        try:
            from strata.cli import ui
            return ui
        except ImportError:
            return None

    def header(self, target: str) -> None:
        u = self._ui()
        if u:
            u.section("Pipeline", u.Icon.RUN)
            u.print_kv_table([
                u.KV("target", target, u.C.GREEN),
            ])
        else:
            print(f"strata run - {target}")

    def field(self, name: str, value: Any) -> None:
        u = self._ui()
        if u:
            u.print_kv_table([u.KV(name, str(value), u.C.WHITE)])
        else:
            print(f"  {name:<9}: {value}")

    def stage(self, name: str, reason: str) -> None:
        u = self._ui()
        if u:
            u.stage_start(name, reason)
        else:
            print(f"\n  [{name}] {reason}")

    def stat(self, text: str) -> None:
        u = self._ui()
        if u:
            u.info(text)
        else:
            print(f"    {text}")

    def note(self, text: str) -> None:
        u = self._ui()
        if u:
            u.info(text)
        else:
            print(f"    {text}")

    def insight(self, text: str) -> None:
        u = self._ui()
        if u:
            # green bullet for learning insights
            print(f"  {u.C.GREEN}★{u.C.RST}  {u.C.GRAY}learning:{u.C.RST} {text}")
        else:
            print(f"    learning: {text}")

    def footer(self, stats: dict[str, int]) -> None:
        findings  = stats.get("findings", 0)
        verified  = stats.get("status_verified", 0)
        candidate = stats.get("status_candidate", 0)
        dead      = stats.get("status_dead", 0)
        u = self._ui()
        if u:
            u.print_kv_table([
                u.KV("findings",  str(findings),  u.C.BWHITE),
                u.KV("verified",  str(verified),  u.C.BGREEN  if verified  > 0 else u.C.GRAY),
                u.KV("candidate", str(candidate), u.C.BYELLOW if candidate > 0 else u.C.GRAY),
                u.KV("dead",      str(dead),       u.C.GRAY),
            ])
        else:
            print(
                f"\n  done      : {findings} findings, {verified} verified, "
                f"{candidate} candidate, {dead} dead"
            )


def _normalize_target(target: str) -> str:
    value = target.strip().lower()
    if "://" in value:
        parsed = urlparse(value)
        host = (parsed.hostname or "").strip().lower()
        if not host:
            raise ValueError(f"target URL has no host: {target!r}")
        return host
    if not value:
        raise ValueError("target is blank")
    if not is_probable_domain(value):
        raise ValueError(f"target is not a plausible domain: {target!r}")
    return value


def _seed_url(target_raw: str, target_host: str) -> str:
    value = target_raw.strip()
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme in ("http", "https"):
            return value
    return f"https://{target_host}"


def _db_stats_line(stats: dict[str, int]) -> str:
    return " ".join(f"{key}={value}" for key, value in sorted(stats.items()))


def _package_version() -> str:
    from strata import __version__

    return __version__


class Orchestrator:
    def __init__(
        self,
        options: RunOptions,
        *,
        resolver: Resolver | None = None,
        transport: HttpTransport | None = None,
        fingerprint_transport: HttpTransport | None = None,
    ):
        self._options = options
        self._target_raw = options.target
        self._target = _normalize_target(options.target)
        self._scope = options.scope or self._target
        self._policy = ScopePolicy.from_spec(self._scope)
        if options.scope_file is not None:
            self._policy = self._policy.merged(ScopePolicy.from_file(options.scope_file))
            self._scope = ",".join(self._policy.allowed)
        self._seed = _seed_url(options.target, self._target)
        if resolver is not None:
            self._resolver = resolver
        elif transport is not None:
            self._resolver = Resolver(transport)  # type: ignore[arg-type]
        else:
            self._resolver = Resolver(DnspythonTransport(timeout=options.timeout))
        self._budget = (
            RequestBudget(
                max_requests=options.max_requests,
                max_bytes=options.max_bytes,
                max_seconds=options.max_seconds,
            )
            if (options.max_requests or options.max_bytes or options.max_seconds)
            else None
        )
        auth_headers = dict(options.extra_headers or {})
        self._transport = transport or UrllibTransport(
            budget=self._budget, extra_headers=auth_headers
        )
        self._fingerprint_transport = fingerprint_transport
        self._extra_headers = auth_headers
        self._log = RunLog()
        self._started_at = datetime.now(UTC)
        self._stages_this_run: list[StageResult] = []
        self._version = _package_version()
        self._report_path: Path | None = None
        self._manifest = RunManifest(
            target=self._target,
            scope=self._scope,
            options=self._options_snapshot(),
        )

    def _options_snapshot(self) -> dict[str, Any]:
        options = self._options
        keys = (
            "wordlist",
            "max_concurrency",
            "timeout",
            "max_scripts",
            "max_probe",
            "max_candidates",
            "probe",
            "robots",
            "mutate",
            "resume",
            "no_dns",
            "no_passive",
            "no_fingerprint",
            "no_content",
            "no_param",
            "no_fuse",
            "min_sources",
            "max_requests",
            "max_bytes",
            "max_seconds",
            "strict_stages",
            "report_format",
            "dry_run",
        )
        snapshot: dict[str, Any] = {}
        for key in keys:
            value = getattr(options, key)
            if isinstance(value, ReportFormat):
                value = value.value
            snapshot[key] = value
        return snapshot

    async def run(self) -> RunResult:
        db = StrataDB(self._options.db_path)
        stats = db.stats(target=self._target)
        memory = RunMemory.from_dict(db.get_run_memory(self._target))
        suggestions = memory.suggestions()
        plan = self._build_plan(suggestions)
        result = RunResult(target=self._target, memory=memory, db_stats=stats)

        self._log.header(self._target)
        self._log.field("scope", self._scope)
        self._log.field("plan", " -> ".join(name for name, _ in plan))
        if self._extra_headers:
            self._log.insight(
                f"authenticated mode: {len(self._extra_headers)} session "
                "header(s) applied to in-scope requests (values never logged)"
            )
        self._log.field("memory", f"{memory.runs} prior runs")
        if self._budget is not None:
            self._log.field(
                "budget",
                f"requests={self._options.max_requests or '-'} "
                f"bytes={self._options.max_bytes or '-'} "
                f"seconds={self._options.max_seconds or '-'}",
            )
        if suggestions:
            self._log.insight(
                "prior run suggests: " + ", ".join(f"{k}={v}" for k, v in suggestions.items())
            )
        if self._options.dry_run:
            for name, reason in plan:
                self._log.stage(name, reason)
            db.close()
            return result

        for stage_name, _reason in plan:
            try:
                stage_result = await self._execute(stage_name, db, memory)
            except Exception as exc:
                info = classify_exception(exc)
                if not info.expected and self._options.strict_stages:
                    db.close()
                    raise
                label = (
                    "skipped"
                    if info.expected and info.code != "STAGE_FAILED"
                    else "failed"
                )
                note = f"stage {stage_name!r} {label} [{info.code}]: {info.message}"
                self._log.note(note)
                stage_result = StageResult(
                    stage=stage_name,
                    stats={"error_code": info.code},
                    notes=[note],
                    status=label,
                )
            if stage_result is not None:
                result.stages.append(stage_result)
                self._stages_this_run.append(stage_result)
                memory.record(
                    stage_result.stage,
                    new_findings=stage_result.new_findings,
                    total_findings=stage_result.total_findings,
                    insight=stage_result.notes[0] if stage_result.notes else None,
                )

        final_stats = db.stats(target=self._target)
        result.db_stats = final_stats
        result.report_path = self._report_path
        result.memory = memory
        memory.runs += 1
        self._log.footer(final_stats)
        if not self._options.dry_run:
            db.save_run_memory(self._target, memory.to_dict())
            manifest_path = (
                manifest_path_for(self._report_path)
                if self._report_path
                else timestamped_report_path(
                    prefix=f"strata-{self._target.replace('.', '-')}",
                    extension="manifest.json",
                )
            )
            self._manifest.finish(
                stats=final_stats,
                stages=[
                    {
                        "stage": stage.stage,
                        "status": stage.status,
                        "new_findings": stage.new_findings,
                        "total_findings": stage.total_findings,
                        "stats": stage.stats,
                        "notes": stage.notes,
                    }
                    for stage in result.stages
                ],
                report=str(self._report_path) if self._report_path else None,
                budget=self._budget.snapshot() if self._budget else None,
            )
            self._manifest.write(manifest_path)
            result.manifest_path = manifest_path
            result.manifest = self._manifest.to_dict()
            if self._options.auto_snapshot:
                self._write_auto_snapshot(db)
        vuln_findings = (
            final_stats.get("kind_vuln", 0) if isinstance(final_stats, dict) else 0
        )
        if self._options.notify_url:
            self._notify_run(final_stats, vuln_findings)
        db.close()
        return result

    def _write_auto_snapshot(self, db: StrataDB) -> None:
        import json

        from strata.core.diff import snapshot_from_findings
        from strata.core.paths import timestamped_report_path

        try:
            findings = list(db.iter_findings(target=self._target))
            snapshot = snapshot_from_findings(
                findings, target=self._target, strata_version=self._version
            )
            snapshot_path = timestamped_report_path(
                prefix=f"strata-snapshot-{self._target.replace('.', '-')}",
                extension="json",
            )
            snapshot_path.write_text(
                json.dumps(snapshot.to_dict(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            self._log.note(f"auto-snapshot -> {snapshot_path}")
        except OSError as exc:
            self._log.note(f"auto-snapshot failed: {exc}")

    def _notify_run(self, stats: dict[str, int], vuln_findings: int) -> None:
        from strata.core.notify import RunSummary, notify

        elapsed = (datetime.now(UTC) - self._started_at).total_seconds()
        summary = RunSummary(
            target=self._target,
            findings=stats.get("findings", 0),
            verified=stats.get("status_verified", 0),
            candidate=stats.get("status_candidate", 0),
            dead=stats.get("status_dead", 0),
            new_findings=sum(s.new_findings for s in self._stages_this_run),
            vulns=vuln_findings,
            elapsed_seconds=elapsed,
            report_path=str(self._report_path) if self._report_path else None,
        )
        delivered = notify(self._options.notify_url, summary)
        if delivered:
            self._log.note("run summary delivered to notification webhook")
        else:
            self._log.note("notification webhook unreachable (run unaffected)")

    def _build_plan(
        self, suggestions: dict[str, Any]
    ) -> list[tuple[str, str]]:
        options = self._options
        absorb_reason = "inventory the current surface and prior learning"
        if any(
            (
                options.import_aperture,
                options.import_jsast,
                options.import_vulnharvest,
                options.import_triage_loom,
                options.import_nuclei,
            )
        ):
            absorb_reason = (
                "inventory the current surface and import companion tool outputs"
            )
        plan: list[tuple[str, str]] = [("absorb", absorb_reason)]
        if not self._options.no_passive:
            plan.append(("passive", "collect subdomains from CT logs and passive sources"))
        if not self._options.no_dns:
            reason = "enumerate candidate names"
            if suggestions.get("wordlist") == "common":
                reason = "prior DNS was sparse; expand the wordlist"
            plan.append(("dns", reason))
        if not self._options.no_fingerprint:
            plan.append(("fingerprint", "fingerprint live hosts (WAF, tech, headers)"))
        if not self._options.no_content:
            reason = "map content, endpoints, and secrets"
            if suggestions.get("max_scripts"):
                reason = "prior content was dense; widen the crawl"
            plan.append(("content", reason))
        if not self._options.no_param:
            reason = "probe interesting parameters"
            if suggestions.get("max_candidates"):
                reason = "prior parameter probing was sparse; widen the budget"
            plan.append(("param", reason))
        if self._options.probe and self._options.max_probe > 0:
            plan.append(
                ("probe", "verify the most uncertain claims (EIG-ranked, soft-404 aware)")
            )
        if not self._options.no_fuse:
            plan.append(("fuse", "reconcile duplicate entities across engines"))
        plan.append(("tension", "score evidence tension for prioritization"))
        plan.append(("report", "summarize and persist the current picture"))
        return plan

    async def _execute(
        self, stage: str, db: StrataDB, memory: RunMemory
    ) -> StageResult | None:
        before = db.stats(target=self._target)
        if stage == "absorb":
            return self._stage_absorb(db, before, memory)
        if stage == "passive":
            return await self._stage_passive(db, before)
        if stage == "dns":
            return await self._stage_dns(db, before, memory)
        if stage == "fingerprint":
            return await self._stage_fingerprint(db, before)
        if stage == "content":
            return await self._stage_content(db, before, memory)
        if stage == "param":
            return await self._stage_param(db, before, memory)
        if stage == "probe":
            return await self._stage_probe(db, before)
        if stage == "fuse":
            return self._stage_fuse(db, before)
        if stage == "tension":
            return self._stage_tension(db, before)
        if stage == "report":
            return self._stage_report(db, before)
        return None

    def _stage_absorb(
        self, db: StrataDB, before: dict[str, int], memory: RunMemory
    ) -> StageResult:
        self._log.stage("absorb", "inventory the current surface")
        imported = self._import_external_findings(db)
        if imported:
            self._log.stat(f"imported={imported}")
            before = db.stats(target=self._target)
        self._log.stat(_db_stats_line(before))
        notes: list[str] = []
        if imported:
            notes.append(f"{imported} findings imported from companion tools")
        if memory.runs == 0:
            notes.append("cold start; no prior stage outcomes yet")
        else:
            notes.append(f"{memory.runs} prior runs; continuing with memory")
        if before.get("findings", 0):
            notes.append(f"{before['findings']} findings already stored")
        if self._options.resume:
            notes.append("resume mode: known assets will be skipped")
        for note in notes:
            self._log.note(note)
        stats = dict(before)
        if imported:
            stats["imported"] = imported
        return StageResult(
            stage="absorb",
            new_findings=imported,
            total_findings=before.get("findings", 0),
            stats=stats,
            notes=notes,
        )

    def _import_external_findings(self, db: StrataDB) -> int:
        options = self._options
        sources: list[tuple[str, Path | None, Any]] = [
            ("aperture", options.import_aperture, load_aperture_jsonl),
            ("triage-loom", options.import_triage_loom, load_triage_loom_jsonl),
            ("jsast", options.import_jsast, load_jsast_report),
            ("vulnharvest", options.import_vulnharvest, load_vulnharvest_report),
            ("nuclei", options.import_nuclei, load_nuclei_jsonl),
        ]
        count = 0
        for _name, path, loader in sources:
            if not path:
                continue
            try:
                for finding in loader(path):
                    db.upsert_finding(finding, target=self._target)
                    count += 1
            except (OSError, ValueError) as exc:
                self._log.note(f"import error: {path} ({exc})")
        return count

    async def _stage_passive(
        self, db: StrataDB, before: dict[str, int]
    ) -> StageResult:
        self._log.stage("passive", "collect subdomains from CT logs and passive sources")
        cfg = get_config()
        results = await query_passive_dns(self._target, config=cfg)
        findings = passive_dns_to_findings(results, policy=self._policy)
        for finding in findings:
            db.upsert_finding(finding, target=self._target)
        after = db.stats(target=self._target)
        total_subs = sum(len(r.subdomains) for r in results)
        active_sources = [r.source for r in results if not r.error]
        stats = {
            "sources_queried": len(results),
            "sources_ok": len(active_sources),
            "raw_subdomains": total_subs,
            "stored": max(0, after.get("findings", 0) - before.get("findings", 0)),
        }
        self._log.stat(_db_stats_line(stats))
        notes: list[str] = []
        if active_sources:
            notes.append(f"queried: {', '.join(active_sources)}")
        # Distinguish key-gated sources from network errors
        key_gated = {"virustotal", "securitytrails"}
        no_key_srcs  = [r.source for r in results if r.error and r.source in key_gated]
        net_err_srcs = [r.source for r in results if r.error and r.source not in key_gated]
        if no_key_srcs:
            notes.append(f"skipped (no API key): {', '.join(no_key_srcs)}")
        if net_err_srcs:
            # Include the first error message for quick diagnosis
            first_err = next(r.error for r in results if r.source in net_err_srcs)
            short_err = first_err[:60] if first_err else "network error"
            notes.append(f"failed (network error): {', '.join(net_err_srcs)} — {short_err}")
        if total_subs:
            notes.append(f"{total_subs} raw names → {stats['stored']} new findings")
        else:
            notes.append("no passive DNS results")
        for note in notes:
            self._log.note(note)
        return StageResult(
            stage="passive",
            new_findings=stats["stored"],
            total_findings=after.get("findings", 0),
            stats=stats,
            notes=notes,
        )

    async def _stage_fingerprint(
        self, db: StrataDB, before: dict[str, int]
    ) -> StageResult:
        self._log.stage("fingerprint", "fingerprint live hosts (tech stack, WAF, security headers)")
        # Collect verified subdomains and seed URL
        targets: list[str] = [self._seed]
        for finding in db.iter_findings(target=self._target):
            if finding.kind is FindingClass.SUBDOMAIN:
                targets.append(f"https://{finding.asset_value}")
        # Deduplicate, cap at 20 hosts
        seen: set[str] = set()
        unique: list[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique.append(t)
        unique = unique[:20]

        transport = self._fingerprint_transport or ThrottledTransport(
            per_host_delay=0.5, budget=self._budget, extra_headers=self._extra_headers
        )
        fp_findings = []
        vuln_count = 0
        errors = 0
        for url in unique:
            fp = await fingerprint_url(
                url,
                transport=transport,
                timeout=self._options.timeout,
                run_id=f"fp:{self._target}",
            )
            if fp and fp.finding:
                db.upsert_finding(fp.finding, target=self._target)
                fp_findings.append(fp)
                vulns = cve_findings(fp.finding, run_id=f"vuln:{self._target}")
                for vuln in vulns:
                    db.upsert_finding(vuln, target=self._target)
                    vuln_count += 1
            elif not fp:
                errors += 1

        after = db.stats(target=self._target)
        waf_found = [fp.waf for fp in fp_findings if fp.waf]
        tech_found = list({t for fp in fp_findings for t in fp.tech_stack})
        stats = {
            "hosts_probed": len(unique),
            "fingerprinted": len(fp_findings),
            "vulns": vuln_count,
            "errors": errors,
        }
        self._log.stat(_db_stats_line(stats))
        notes: list[str] = []
        if waf_found:
            notes.append(f"WAF detected: {', '.join(set(waf_found))}")
        if tech_found:
            notes.append(f"tech stack: {', '.join(tech_found[:8])}")
        if vuln_count:
            notes.append(
                f"{vuln_count} disclosed-version CVE matches recorded "
                "(VULN findings; verify before acting)"
            )
        if not notes:
            notes.append("no distinctive fingerprints")
        for note in notes:
            self._log.note(note)
        return StageResult(
            stage="fingerprint",
            new_findings=max(0, after.get("findings", 0) - before.get("findings", 0)),
            total_findings=after.get("findings", 0),
            stats=stats,
            notes=notes,
        )

    async def _stage_dns(
        self, db: StrataDB, before: dict[str, int], memory: RunMemory
    ) -> StageResult:
        suggestions = memory.suggestions()
        reason = "enumerate candidate names"
        if suggestions.get("wordlist") == "common":
            reason = "prior DNS was sparse; expand the wordlist"
        self._log.stage("dns", reason)
        known: set[str] = set()
        if self._options.resume:
            known = {
                finding.asset_value
                for finding in db.iter_findings(target=self._target)
                if finding.kind is FindingClass.SUBDOMAIN
            }
        learned = db.technique_stats("dns")
        priorities = {
            word: entry["rate"] for word, entry in learned.items() if entry["rate"] > 0
        }
        if priorities:
            self._log.insight(
                f"self-calibrated wordlist: prioritising {len(priorities)} "
                "historically productive words"
            )
        engine = DnsDiscoveryEngine(
            resolver=self._resolver,
            policy=self._policy,
            wordlist=suggestions.get("wordlist", self._options.wordlist),
            max_concurrency=self._options.max_concurrency,
            mutate=self._options.mutate,
            known=known,
            priorities=priorities,
        )
        result = await engine.run(self._target)
        for finding in result.findings:
            db.upsert_finding(finding, target=self._target)
        for finding in result.dead_findings:
            db.upsert_finding(finding, target=self._target)
        if result.word_stats:
            db.record_technique_stats(
                "dns",
                {
                    word: (entry["attempts"], entry["successes"])
                    for word, entry in result.word_stats.items()
                },
            )
        after = db.stats(target=self._target)
        s = result.stats
        stats = {
            "tested": s.candidates_tested,
            "resolved": s.resolved,
            "wildcards": s.wildcard_filtered,
            "mutations": s.mutation_candidates,
            "dead_recorded": s.recorded_dead,
            "errors": s.errors,
        }
        self._log.stat(_db_stats_line(stats))
        notes: list[str] = []
        if s.resolved == 0:
            notes.append("no new names resolved")
        elif s.resolved <= 3:
            notes.append("sparse name map; consider expanding the wordlist next run")
        else:
            notes.append(f"{s.resolved} names resolved")
        if s.recorded_dead:
            notes.append(
                f"{s.recorded_dead} unresolvable claims recorded; fusion will "
                "mark contradictions as contested"
            )
        if result.wildcard:
            notes.append("wildcard base detected and filtered")
        for note in notes:
            self._log.note(note)
        return StageResult(
            stage="dns",
            new_findings=max(0, after.get("findings", 0) - before.get("findings", 0)),
            total_findings=after.get("findings", 0),
            stats=stats,
            notes=notes,
        )

    async def _stage_content(
        self, db: StrataDB, before: dict[str, int], memory: RunMemory
    ) -> StageResult:
        suggestions = memory.suggestions()
        reason = "map content, endpoints, and secrets"
        if suggestions.get("max_scripts"):
            reason = "prior content was dense; widen the crawl"
        self._log.stage("content", reason)
        known: set[str] = set()
        if self._options.resume:
            known = {
                finding.asset_value
                for finding in db.iter_findings(target=self._target)
                if finding.kind in (FindingClass.ENDPOINT, FindingClass.SECRET)
            }
        engine = ContentDiscoveryEngine(
            self._transport,
            self._policy,
            max_scripts=int(suggestions.get("max_scripts", self._options.max_scripts)),
            max_probe=int(suggestions.get("max_probe", self._options.max_probe)),
            probe=self._options.probe,
            robots=self._options.robots,
            timeout=self._options.timeout,
            known=known,
        )
        result = await engine.run(self._seed)
        for finding in result.findings:
            db.upsert_finding(finding, target=self._target)
        after = db.stats(target=self._target)
        s = result.stats
        stats = {
            "pages": s.pages_fetched,
            "scripts": s.scripts_fetched,
            "endpoints": s.endpoints_stored,
            "secrets": s.secrets_found,
            "probed": s.probed,
            "verified": s.verified,
            "dead": s.dead,
            "errors": s.errors,
            "info_bits_per_probe": (
                round(s.expected_information_bits / s.probed, 3) if s.probed else 0.0
            ),
        }
        self._log.stat(_db_stats_line(stats))
        notes: list[str] = []
        if s.endpoints_stored:
            notes.append(f"{s.endpoints_stored} endpoints discovered")
        if s.probed:
            notes.append(
                f"probe budget spent at {s.expected_information_bits / s.probed:.2f} "
                "bits of uncertainty resolved per request"
            )
        if s.secrets_found:
            notes.append(f"{s.secrets_found} secret candidates")
        if not s.endpoints_stored and not s.secrets_found:
            notes.append("no endpoint or secret surface exposed")
        if s.errors:
            notes.append(f"{s.errors} fetch errors")
        for note in notes:
            self._log.note(note)
        return StageResult(
            stage="content",
            new_findings=max(0, after.get("findings", 0) - before.get("findings", 0)),
            total_findings=after.get("findings", 0),
            stats=stats,
            notes=notes,
        )

    async def _stage_param(
        self, db: StrataDB, before: dict[str, int], memory: RunMemory
    ) -> StageResult:
        suggestions = memory.suggestions()
        reason = "probe interesting parameters"
        if suggestions.get("max_candidates"):
            reason = "prior parameter probing was sparse; widen the budget"
        self._log.stage("param", reason)
        endpoints = [
            finding
            for finding in db.iter_findings(target=self._target)
            if finding.kind is FindingClass.ENDPOINT
        ]
        if not endpoints:
            self._log.note("no endpoint surface to probe")
            after = db.stats(target=self._target)
            return StageResult(
                stage="param",
                new_findings=0,
                total_findings=after.get("findings", 0),
                stats={"endpoints": 0, "candidates": 0, "confirmed": 0},
                notes=["no endpoint surface to probe"],
            )
        engine = ParamOracle(
            self._transport,
            self._policy,
            max_candidates=int(
                suggestions.get("max_candidates", self._options.max_candidates)
            ),
            timeout=self._options.timeout,
            max_bytes=2_000_000,
        )
        result = await engine.run(endpoints)
        for finding in result.findings:
            db.upsert_finding(finding, target=self._target)
        after = db.stats(target=self._target)
        s = result.stats
        stats = {
            "endpoints": s.endpoints_scanned,
            "candidates": s.candidates_tested,
            "confirmed": s.confirmed,
            "errors": s.errors,
        }
        self._log.stat(_db_stats_line(stats))
        notes: list[str] = []
        if s.confirmed:
            notes.append(f"{s.confirmed} parameter signals confirmed")
        else:
            notes.append("no strong parameter signal yet")
        for note in notes:
            self._log.note(note)
        return StageResult(
            stage="param",
            new_findings=max(0, after.get("findings", 0) - before.get("findings", 0)),
            total_findings=after.get("findings", 0),
            stats=stats,
            notes=notes,
        )

    async def _stage_probe(
        self, db: StrataDB, before: dict[str, int]
    ) -> StageResult:
        reason = "verify the most uncertain claims (EIG-ranked, soft-404 aware)"
        self._log.stage("probe", reason)
        candidates = [
            finding
            for finding in db.iter_findings(target=self._target)
            if finding.status in (FindingStatus.CANDIDATE, FindingStatus.STALE)
            and finding.kind in PROBEABLE_KINDS
        ]
        engine = ProbeEngine(
            self._transport,
            max_probe=self._options.max_probe,
            concurrency=min(self._options.max_concurrency, 8),
            timeout=self._options.timeout,
            run_id=f"probe:{self._target}",
        )
        result = await engine.run(candidates, policy=self._policy)
        for finding in result.findings:
            db.upsert_finding(finding, target=self._target)
        s = result.stats
        stats = {
            "eligible": s.eligible,
            "selected": s.selected,
            "probed": s.probed,
            "verified": s.verified,
            "dead": s.dead,
            "soft404": s.soft404,
            "bits_per_probe": round(
                s.expected_information_bits / s.probed, 3
            ) if s.probed else 0.0,
            "out_of_scope": s.out_of_scope,
            "errors": s.errors,
        }
        self._log.stat(_db_stats_line(stats))
        notes: list[str] = []
        if s.selected:
            notes.append(
                f"probed {s.selected} of {s.eligible} candidates at "
                f"{stats['bits_per_probe']} bits of uncertainty per request"
            )
        if s.soft404:
            notes.append(
                f"{s.soft404} soft-404 pages killed (HTTP 200 with not-found content)"
            )
        if s.selected and s.verified == 0 and s.dead == 0:
            notes.append("no claim resolved by probing")
        for note in notes:
            self._log.note(note)
        after = db.stats(target=self._target)
        return StageResult(
            stage="probe",
            new_findings=max(0, after.get("findings", 0) - before.get("findings", 0)),
            total_findings=after.get("findings", 0),
            stats=stats,
            notes=notes,
        )

    def _stage_fuse(self, db: StrataDB, before: dict[str, int]) -> StageResult:
        self._log.stage("fuse", "reconcile duplicate entities across engines")
        findings = list(db.iter_findings(target=self._target))
        reliability = reliability_weights(db.source_reliability(target=self._target))
        if reliability:
            top = sorted(reliability.items(), key=lambda kv: -kv[1])[:3]
            self._log.insight(
                "reliability-weighted fusion active for: "
                + ", ".join(f"{name}={weight}" for name, weight in top)
            )
        fused = [
            finding
            for finding in fuse_findings(findings, reliability=reliability)
            if finding.metadata.get("source_count", 1) >= self._options.min_sources
        ]
        for finding in fused:
            db.upsert_finding(finding, target=self._target)
            db.delete_findings(superseded_finding_ids(finding))
        after = db.stats(target=self._target)
        contested = sum(
            1 for finding in fused if finding.metadata.get("contested")
        )
        stats = {"sources": len(findings), "fused": len(fused), "contested": contested}
        self._log.stat(_db_stats_line(stats))
        notes: list[str] = []
        if not fused:
            notes.append("no duplicate entities to reconcile")
        else:
            notes.append(f"{len(fused)} entities now carry corroborated confidence")
        if contested:
            notes.append(
                f"{contested} contested claims: sources disagree on existence"
            )
        for note in notes:
            self._log.note(note)
        return StageResult(
            stage="fuse",
            new_findings=max(0, after.get("findings", 0) - before.get("findings", 0)),
            total_findings=after.get("findings", 0),
            stats=stats,
            notes=notes,
        )

    def _stage_tension(self, db: StrataDB, before: dict[str, int]) -> StageResult:
        self._log.stage("tension", "score evidence tension for prioritization")
        findings = list(db.iter_findings(target=self._target))
        dead_parents: set[str] = set()
        for finding in findings:
            if finding.status is not FindingStatus.DEAD:
                continue
            dead_parents.add(finding.asset_value)
            host = host_of(finding.asset_value)
            if host:
                dead_parents.add(host)
        summary, assessments = summarise_tension(findings, dead_parents=dead_parents)
        by_id = {assessment.finding_id: assessment for assessment in assessments}
        stamped = 0
        for finding in findings:
            assessment = by_id.get(finding.finding_id)
            if assessment is None:
                continue
            tension_meta = {
                "score": assessment.score,
                "label": assessment.label,
                "reasons": assessment.reasons,
                "effective_confidence": assessment.effective_confidence,
                "age_days": assessment.age_days,
            }
            if finding.metadata.get("tension") == tension_meta:
                continue
            metadata = dict(finding.metadata)
            metadata["tension"] = tension_meta
            db.upsert_finding(
                finding.model_copy(update={"metadata": metadata}),
                target=self._target,
            )
            stamped += 1
        stats = {
            "stamped": stamped,
            "hot": summary.hot,
            "ghost": summary.ghost,
            "shadow": summary.shadow,
            "stable": summary.stable,
            "mean_tension": summary.mean_score,
        }
        self._log.stat(_db_stats_line(stats))
        notes = [
            f"{summary.hot} hot, {summary.shadow} shadow, {summary.ghost} ghost, "
            f"{summary.stable} stable claims",
        ]
        if summary.worst is not None:
            notes.append(
                f"highest tension {summary.worst.score} on {summary.worst.asset_value}"
            )
        for note in notes:
            self._log.note(note)
        return StageResult(
            stage="tension",
            new_findings=0,
            total_findings=len(findings),
            stats=stats,
            notes=notes,
        )

    def _stage_report(self, db: StrataDB, before: dict[str, int]) -> StageResult:
        self._log.stage("report", "summarize and persist the current picture")
        findings = list(db.iter_findings(target=self._target))
        summary = summarise(findings)
        report_path: Path | None = None
        fmt = ReportFormat(self._options.report_format)
        if self._options.report_out:
            report_path = Path(self._options.report_out)
        else:
            report_path = timestamped_report_path(
                prefix=f"strata-{self._target.replace('.', '-')}",
                extension=fmt.value,
            )
        write_report(
            findings,
            report_path,
            fmt,
            title=self._options.title,
            manifest=self._manifest.to_dict(),
        )
        self._report_path = report_path
        self._log.stat(f"report={report_path} format={fmt.value}")
        notes = [
            f"{summary.findings} findings in the current picture",
        ]
        if report_path:
            notes.append(f"report written to {report_path}")
        for note in notes:
            self._log.note(note)
        return StageResult(
            stage="report",
            new_findings=0,
            total_findings=len(findings),
            stats={
                "findings": summary.findings,
                "verified": summary.verified,
                "candidate": summary.candidate,
                "dead": summary.dead,
            },
            notes=notes,
        )


def run_orchestrator(options: RunOptions, **kwargs: Any) -> RunResult:
    """Async entry point used by the CLI and tests."""
    orchestrator = Orchestrator(options, **kwargs)
    return asyncio.run(orchestrator.run())


__all__ = [
    "Orchestrator",
    "RunMemory",
    "RunOptions",
    "RunResult",
    "StageMemory",
    "StageResult",
    "run_orchestrator",
]
