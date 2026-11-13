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
from strata.adapters.triage_loom import load_triage_loom_jsonl
from strata.adapters.vulnharvest import load_vulnharvest_report
from strata.core.content.fetch import HttpTransport, UrllibTransport
from strata.core.dns.resolver import DnspythonTransport, Resolver
from strata.core.paths import timestamped_report_path
from strata.core.policy.scope import ScopePolicy
from strata.core.reporting import ReportFormat, summarise, write_report
from strata.core.schema.models import FindingClass, is_probable_domain
from strata.core.store.db import StrataDB
from strata.engines.dns_brute import DnsDiscoveryEngine
from strata.engines.fusion import fuse_findings
from strata.engines.js_content import ContentDiscoveryEngine
from strata.engines.param_oracle import ParamOracle
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


@dataclass
class RunResult:
    target: str
    stages: list[StageResult] = field(default_factory=list)
    report_path: Path | None = None
    memory: RunMemory | None = None
    db_stats: dict[str, int] = field(default_factory=dict)


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
    no_content: bool = False
    no_param: bool = False
    no_fuse: bool = False
    min_sources: int = 2
    report_format: ReportFormat | str = ReportFormat.MARKDOWN
    report_out: str | Path | None = None
    title: str = "Strata run"
    dry_run: bool = False
    import_aperture: Path | None = None
    import_jsast: Path | None = None
    import_vulnharvest: Path | None = None
    import_triage_loom: Path | None = None


class RunLog:
    def header(self, target: str) -> None:
        print(f"strata run - {target}")

    def field(self, name: str, value: Any) -> None:
        print(f"  {name:<9}: {value}")

    def stage(self, name: str, reason: str) -> None:
        print(f"\n  [{name}] {reason}")

    def stat(self, text: str) -> None:
        print(f"    {text}")

    def note(self, text: str) -> None:
        print(f"    {text}")

    def insight(self, text: str) -> None:
        print(f"    learning: {text}")

    def footer(self, stats: dict[str, int]) -> None:
        findings = stats.get("findings", 0)
        verified = stats.get("status_verified", 0)
        candidate = stats.get("status_candidate", 0)
        dead = stats.get("status_dead", 0)
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


class Orchestrator:
    def __init__(
        self,
        options: RunOptions,
        *,
        resolver: Resolver | None = None,
        transport: HttpTransport | None = None,
    ):
        self._options = options
        self._target_raw = options.target
        self._target = _normalize_target(options.target)
        self._scope = options.scope or self._target
        self._policy = ScopePolicy.from_spec(self._scope)
        self._seed = _seed_url(options.target, self._target)
        if resolver is not None:
            self._resolver = resolver
        elif transport is not None:
            self._resolver = Resolver(transport)  # type: ignore[arg-type]
        else:
            self._resolver = Resolver(DnspythonTransport(timeout=options.timeout))
        self._transport = transport or UrllibTransport()
        self._log = RunLog()
        self._report_path: Path | None = None

    async def run(self) -> RunResult:
        db = StrataDB(self._options.db_path)
        stats = db.stats()
        memory = RunMemory.from_dict(db.get_run_memory(self._target))
        suggestions = memory.suggestions()
        plan = self._build_plan(suggestions)
        result = RunResult(target=self._target, memory=memory, db_stats=stats)

        self._log.header(self._target)
        self._log.field("scope", self._scope)
        self._log.field("plan", " -> ".join(name for name, _ in plan))
        self._log.field("memory", f"{memory.runs} prior runs")
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
            stage_result = await self._execute(stage_name, db, memory)
            if stage_result is not None:
                result.stages.append(stage_result)
                memory.record(
                    stage_result.stage,
                    new_findings=stage_result.new_findings,
                    total_findings=stage_result.total_findings,
                    insight=stage_result.notes[0] if stage_result.notes else None,
                )

        final_stats = db.stats()
        result.db_stats = final_stats
        result.report_path = self._report_path
        result.memory = memory
        memory.runs += 1
        self._log.footer(final_stats)
        if not self._options.dry_run:
            db.save_run_memory(self._target, memory.to_dict())
        db.close()
        return result

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
            )
        ):
            absorb_reason = (
                "inventory the current surface and import companion tool outputs"
            )
        plan: list[tuple[str, str]] = [("absorb", absorb_reason)]
        if not self._options.no_dns:
            reason = "enumerate candidate names"
            if suggestions.get("wordlist") == "common":
                reason = "prior DNS was sparse; expand the wordlist"
            plan.append(("dns", reason))
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
        if not self._options.no_fuse:
            plan.append(("fuse", "reconcile duplicate entities across engines"))
        plan.append(("tension", "score evidence tension for prioritization"))
        plan.append(("report", "summarize and persist the current picture"))
        return plan

    async def _execute(
        self, stage: str, db: StrataDB, memory: RunMemory
    ) -> StageResult | None:
        before = db.stats()
        if stage == "absorb":
            return self._stage_absorb(db, before, memory)
        if stage == "dns":
            return await self._stage_dns(db, before, memory)
        if stage == "content":
            return await self._stage_content(db, before, memory)
        if stage == "param":
            return await self._stage_param(db, before, memory)
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
            before = db.stats()
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
        ]
        count = 0
        for _name, path, loader in sources:
            if not path:
                continue
            try:
                for finding in loader(path):
                    db.upsert_finding(finding)
                    count += 1
            except (OSError, ValueError) as exc:
                self._log.note(f"import error: {path} ({exc})")
        return count

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
                for finding in db.iter_findings()
                if finding.kind is FindingClass.SUBDOMAIN
            }
        engine = DnsDiscoveryEngine(
            resolver=self._resolver,
            policy=self._policy,
            wordlist=suggestions.get("wordlist", self._options.wordlist),
            max_concurrency=self._options.max_concurrency,
            mutate=self._options.mutate,
            known=known,
        )
        result = await engine.run(self._target)
        for finding in result.findings:
            db.upsert_finding(finding)
        after = db.stats()
        s = result.stats
        stats = {
            "tested": s.candidates_tested,
            "resolved": s.resolved,
            "wildcards": s.wildcard_filtered,
            "mutations": s.mutation_candidates,
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
                for finding in db.iter_findings()
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
            db.upsert_finding(finding)
        after = db.stats()
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
        }
        self._log.stat(_db_stats_line(stats))
        notes: list[str] = []
        if s.endpoints_stored:
            notes.append(f"{s.endpoints_stored} endpoints discovered")
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
            for finding in db.iter_findings()
            if finding.kind is FindingClass.ENDPOINT
        ]
        if not endpoints:
            self._log.note("no endpoint surface to probe")
            after = db.stats()
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
            db.upsert_finding(finding)
        after = db.stats()
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

    def _stage_fuse(self, db: StrataDB, before: dict[str, int]) -> StageResult:
        self._log.stage("fuse", "reconcile duplicate entities across engines")
        findings = list(db.iter_findings())
        fused = [
            finding
            for finding in fuse_findings(findings)
            if finding.metadata.get("source_count", 1) >= self._options.min_sources
        ]
        for finding in fused:
            db.upsert_finding(finding)
        after = db.stats()
        stats = {"sources": len(findings), "fused": len(fused)}
        self._log.stat(_db_stats_line(stats))
        notes: list[str] = []
        if not fused:
            notes.append("no duplicate entities to reconcile")
        else:
            notes.append(f"{len(fused)} entities now carry corroborated confidence")
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
        findings = list(db.iter_findings())
        summary, assessments = summarise_tension(findings)
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
            }
            if finding.metadata.get("tension") == tension_meta:
                continue
            metadata = dict(finding.metadata)
            metadata["tension"] = tension_meta
            db.upsert_finding(
                finding.model_copy(update={"metadata": metadata})
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
        findings = list(db.iter_findings())
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
        write_report(findings, report_path, fmt, title=self._options.title)
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
