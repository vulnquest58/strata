"""Terminal UI helpers — zero third-party dependencies.

Provides ANSI colour, a banner, spinner, progress, and structured output
that rivals nuclei/httpx/subfinder style output on modern terminals.

Auto-detects NO_COLOR / dumb terminals and falls back to plain text.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TextIO

# ─────────────────────────── colour detection ──────────────────────────────

def _supports_colour(stream: TextIO = sys.stderr) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if not hasattr(stream, "isatty"):
        return False
    return stream.isatty()


_COLOR = _supports_colour()


class C:
    """ANSI colour / style constants."""
    # Reset
    RST  = "\033[0m"   if _COLOR else ""
    BOLD = "\033[1m"   if _COLOR else ""
    DIM  = "\033[2m"   if _COLOR else ""
    ITAL = "\033[3m"   if _COLOR else ""
    UL   = "\033[4m"   if _COLOR else ""

    # Foreground
    RED    = "\033[91m" if _COLOR else ""
    GREEN  = "\033[92m" if _COLOR else ""
    YELLOW = "\033[93m" if _COLOR else ""
    BLUE   = "\033[94m" if _COLOR else ""
    MAGENTA= "\033[95m" if _COLOR else ""
    CYAN   = "\033[96m" if _COLOR else ""
    WHITE  = "\033[97m" if _COLOR else ""
    GRAY   = "\033[90m" if _COLOR else ""

    # Background
    BG_RED   = "\033[41m" if _COLOR else ""
    BG_GREEN = "\033[42m" if _COLOR else ""
    BG_BLUE  = "\033[44m" if _COLOR else ""
    BG_BLACK = "\033[40m" if _COLOR else ""

    # Compounds
    BRED   = BOLD + RED
    BGREEN = BOLD + GREEN
    BYELLOW= BOLD + YELLOW
    BCYAN  = BOLD + CYAN
    BWHITE = BOLD + WHITE
    BMAGENTA = BOLD + MAGENTA


# ──────────────────────────── icon helpers ──────────────────────────────────

class Icon:
    OK    = f"{C.BGREEN}✔{C.RST}"
    FAIL  = f"{C.BRED}✘{C.RST}"
    WARN  = f"{C.BYELLOW}⚠{C.RST}"
    INFO  = f"{C.BCYAN}ℹ{C.RST}"
    ARROW = f"{C.CYAN}›{C.RST}"
    BULLET= f"{C.MAGENTA}•{C.RST}"
    SKULL = f"{C.GRAY}☠{C.RST}"
    LOCK  = f"{C.YELLOW}⚿{C.RST}"
    GLOBE = f"{C.CYAN}⊕{C.RST}"
    FIRE  = f"{C.RED}🔥{C.RST}"
    TAG   = f"{C.MAGENTA}##{C.RST}"
    RUN   = f"{C.GREEN}▶{C.RST}"
    PASS  = f"{C.GREEN}●{C.RST}"


# ───────────────────────────── banner ────────────────────────────────────────

_BANNER = r"""
  ███████╗████████╗██████╗  █████╗ ████████╗ █████╗
  ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗
  ███████╗   ██║   ██████╔╝███████║   ██║   ███████║
  ╚════██║   ██║   ██╔══██╗██╔══██║   ██║   ██╔══██║
  ███████║   ██║   ██║  ██║██║  ██║   ██║   ██║  ██║
  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═╝   ╚═╝  ╚═╝
"""

def print_banner(version: str = "0.3.0", target: str = "") -> None:
    term_w = shutil.get_terminal_size((80, 20)).columns
    banner_lines = _BANNER.strip("\n").split("\n")

    print()
    for line in banner_lines:
        colored = C.CYAN + C.BOLD + line + C.RST
        print(colored)

    # tagline row
    tagline = (
        f"  {C.GRAY}attack-surface intelligence engine{C.RST}  "
        f"{C.BWHITE}v{version}{C.RST}  "
        f"{C.GRAY}│{C.RST}  "
        f"{C.YELLOW}github.com/vulnquest58/strata{C.RST}"
    )
    print(tagline)

    if target:
        sep = C.GRAY + "─" * min(term_w, 65) + C.RST
        print(f"\n{sep}")
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        print(
            f"  {Icon.ARROW} {C.BOLD}Target{C.RST}  {C.GREEN}{target}{C.RST}"
            f"   {C.GRAY}{ts}{C.RST}"
        )
        print(sep + "\n")
    else:
        print()


# ─────────────────────────── section header ─────────────────────────────────

def section(title: str, icon: str = Icon.ARROW) -> None:
    term_w = shutil.get_terminal_size((80, 20)).columns
    left = f"\n{icon} {C.BOLD}{C.WHITE}{title}{C.RST} "
    fill = C.GRAY + "─" * max(0, min(term_w, 72) - len(title) - 4) + C.RST
    print(left + fill)


# ─────────────────────────── status lines ───────────────────────────────────

def ok(msg: str) -> None:
    print(f"  {Icon.OK}  {msg}")

def fail(msg: str) -> None:
    print(f"  {Icon.FAIL}  {C.RED}{msg}{C.RST}", file=sys.stderr)

def warn(msg: str) -> None:
    print(f"  {Icon.WARN}  {C.YELLOW}{msg}{C.RST}")

def info(msg: str) -> None:
    print(f"  {Icon.INFO}  {C.GRAY}{msg}{C.RST}")

def bullet(msg: str) -> None:
    print(f"  {Icon.BULLET}  {msg}")

def err(msg: str) -> None:
    print(f"\n  {Icon.FAIL}  {C.BRED}Error:{C.RST} {msg}\n", file=sys.stderr)


# ─────────────────────────── key-value table ────────────────────────────────

@dataclass
class KV:
    key: str
    value: str
    color: str = ""

def print_kv_table(rows: list[KV], indent: int = 4) -> None:
    if not rows:
        return
    max_k = max(len(r.key) for r in rows)
    pad = " " * indent
    for r in rows:
        col = r.color or C.WHITE
        print(
            f"{pad}{C.GRAY}{r.key:<{max_k}}{C.RST}  "
            f"{col}{r.value}{C.RST}"
        )


# ─────────────────────────── findings table ─────────────────────────────────

_KIND_COLOR = {
    "subdomain"  : C.CYAN,
    "endpoint"   : C.GREEN,
    "secret"     : C.RED,
    "live_host"  : C.MAGENTA,
    "parameter"  : C.YELLOW,
    "finding"    : C.WHITE,
}

_STATUS_COLOR = {
    "verified"  : C.BGREEN,
    "candidate" : C.BYELLOW,
    "dead"      : C.GRAY,
    "suppressed": C.GRAY,
}

_STATUS_ICON = {
    "verified"  : "●",
    "candidate" : "○",
    "dead"      : "✘",
    "suppressed": "–",
}

def _conf_color(val: float) -> str:
    if val >= 85:
        return C.BGREEN
    if val >= 65:
        return C.GREEN
    if val >= 45:
        return C.YELLOW
    return C.GRAY


def print_findings_table(findings: list, max_rows: int = 20) -> None:
    """Pretty-print a list of UnifiedFinding objects."""
    if not findings:
        info("No findings to display.")
        return

    term_w = shutil.get_terminal_size((120, 20)).columns
    asset_w = max(30, min(55, term_w - 42))

    # header
    hdr = (
        f"  {C.BOLD}{C.GRAY}"
        f"{'ASSET':<{asset_w}}  {'KIND':<11}  {'STATUS':<11}  {'CONF':>5}  SOURCES"
        f"{C.RST}"
    )
    sep = f"  {C.GRAY}" + "─" * min(term_w - 4, 80) + C.RST
    print(sep)
    print(hdr)
    print(sep)

    shown = findings[:max_rows]
    for f in shown:
        kind   = f.kind.value.lower()
        status = f.status.value.lower()
        conf   = f.confidence.value
        asset  = f.asset_value

        kc = _KIND_COLOR.get(kind, C.WHITE)
        sc = _STATUS_COLOR.get(status, C.WHITE)
        si = _STATUS_ICON.get(status, "?")
        cc = _conf_color(conf)

        # source count from evidence
        src_count = len({e.engine for e in f.evidence})
        src_str = f"{C.GRAY}src={src_count}{C.RST}" if src_count else ""

        # truncate long asset names
        if len(asset) > asset_w:
            asset = asset[:asset_w - 2] + ".."

        print(
            f"  {kc}{asset:<{asset_w}}{C.RST}  "
            f"{kc}{kind:<11}{C.RST}  "
            f"{sc}{si} {status:<9}{C.RST}  "
            f"{cc}{conf:5.1f}{C.RST}  "
            f"{src_str}"
        )

    if len(findings) > max_rows:
        info(f"… {len(findings) - max_rows} more findings (use --limit to see more)")
    print(sep)


# ─────────────────────────── passive DNS source table ───────────────────────

def print_passive_dns_results(results: list) -> None:
    """Display PassiveDnsResult list as a coloured source table."""
    if not results:
        return
    section("Passive DNS", Icon.GLOBE)
    total = sum(len(r.subdomains) for r in results)
    for r in results:
        n = len(r.subdomains)
        pct = int(n / total * 20) if total else 0
        bar = C.CYAN + "█" * pct + C.GRAY + "░" * (20 - pct) + C.RST
        status = Icon.OK if not r.error else Icon.WARN
        err_note = f" {C.GRAY}({r.error[:40]}){C.RST}" if r.error else ""
        print(
            f"  {status}  {C.BOLD}{r.source:<16}{C.RST}"
            f"  {bar}  {C.BWHITE}{n:>4}{C.RST} subdomains{err_note}"
        )
    print(
        f"\n  {Icon.INFO}  "
        f"{C.BOLD}Total unique candidates:{C.RST}  {C.BGREEN}{total}{C.RST}"
    )


# ─────────────────────────── fingerprint results ────────────────────────────

def print_fingerprint_result(finding) -> None:
    """Display a single HTTP fingerprint UnifiedFinding."""
    m = finding.metadata if hasattr(finding, "metadata") else {}
    url = finding.asset_value

    waf  = m.get("waf")
    cdn  = m.get("cdn")
    tech = m.get("tech_stack", [])
    sec  = m.get("sec_headers", {})
    srv  = m.get("server")
    code = m.get("status_code", 0)

    # status code colour
    if 200 <= code < 300:
        code_c = C.BGREEN
    elif 300 <= code < 400:
        code_c = C.CYAN
    elif 400 <= code < 500:
        code_c = C.YELLOW
    else:
        code_c = C.RED

    code_s = f"{code_c}[{code}]{C.RST}" if code else ""

    print(
        f"\n  {Icon.GLOBE}  {C.BOLD}{url}{C.RST}  {code_s}"
    )

    if waf:
        print(f"    {C.RED}⚡ WAF{C.RST}  {C.YELLOW}{waf}{C.RST}")
    if cdn:
        print(f"    {C.BLUE}☁ CDN{C.RST}  {C.CYAN}{cdn}{C.RST}")
    if srv:
        print(f"    {C.GRAY}⚙ Server{C.RST}  {C.WHITE}{srv}{C.RST}")
    if tech:
        tech_str = "  ".join(f"{C.MAGENTA}{t}{C.RST}" for t in tech[:8])
        print(f"    {C.GRAY}◈ Tech{C.RST}  {tech_str}")

    # security header mini-scorecard
    if sec:
        present  = [h for h, v in sec.items() if v]
        missing  = [h for h, v in sec.items() if not v]
        score    = len(present)
        total    = len(sec)
        pct      = int(score / total * 16) if total else 0
        bar      = C.GREEN + "█" * pct + C.GRAY + "░" * (16 - pct) + C.RST
        grade_c  = (
            C.BGREEN if score >= total * 0.75
            else C.YELLOW if score >= total * 0.4
            else C.RED
        )
        print(
            f"    {C.GRAY}◉ SecHdr{C.RST}  {bar}  "
            f"{grade_c}{score}/{total}{C.RST}"
        )
        if missing:
            miss_s = "  ".join(f"{C.RED}{h}{C.RST}" for h in missing[:5])
            print(f"           {C.GRAY}missing: {miss_s}{C.RST}")


# ─────────────────────────── DNS result line ────────────────────────────────

def print_dns_finding(finding) -> None:
    conf = finding.confidence.value
    cc   = _conf_color(conf)
    status = finding.status.value.lower()
    sc = _STATUS_COLOR.get(status, C.WHITE)
    si = _STATUS_ICON.get(status, "?")
    origin = ""
    if finding.evidence:
        origin = finding.evidence[0].meta.get("origin_provider", "")
    origin_s = f" {C.GRAY}[{origin}]{C.RST}" if origin else ""
    print(
        f"  {Icon.PASS}  {C.CYAN}{finding.asset_value:<45}{C.RST}"
        f"  {cc}{conf:5.1f}%{C.RST}"
        f"  {sc}{si} {status:<9}{C.RST}"
        f"{origin_s}"
    )


# ─────────────────────────── pipeline stage ─────────────────────────────────

def stage_start(name: str, detail: str = "") -> None:
    detail_s = f"  {C.GRAY}{detail}{C.RST}" if detail else ""
    print(f"\n  {Icon.RUN}  {C.BOLD}{C.WHITE}{name}{C.RST}{detail_s}")


def stage_done(name: str, stats: dict[str, int | str]) -> None:
    pairs = "  ".join(
        f"{C.GRAY}{k}={C.RST}{C.BWHITE}{v}{C.RST}"
        for k, v in stats.items()
    )
    print(f"  {Icon.OK}  {C.BOLD}{name}{C.RST}  {pairs}")


def stage_skip(name: str, reason: str = "") -> None:
    r = f"  {C.GRAY}{reason}{C.RST}" if reason else ""
    print(f"  {Icon.SKULL}  {C.GRAY}{name} (skipped){r}{C.RST}")


# ─────────────────────────── spinner ────────────────────────────────────────

class Spinner:
    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, label: str, stream: TextIO = sys.stderr) -> None:
        self._label  = label
        self._stream = stream
        self._stop   = threading.Event()
        self._thread: threading.Thread | None = None
        self._active = _COLOR and stream.isatty()

    def start(self) -> Spinner:
        if not self._active:
            self._stream.write(f"  … {self._label}\n")
            self._stream.flush()
            return self
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def _spin(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            self._stream.write(
                f"\r  {C.CYAN}{frame}{C.RST}  {C.BOLD}{self._label}{C.RST}  "
            )
            self._stream.flush()
            time.sleep(0.08)
            i += 1

    def stop(self, done_msg: str = "") -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        if self._active:
            self._stream.write(f"\r{' ' * 60}\r")
            self._stream.flush()
        if done_msg:
            self._stream.write(f"  {Icon.OK}  {done_msg}\n")
            self._stream.flush()

    def __enter__(self) -> Spinner:
        return self.start()

    def __exit__(self, *_) -> None:
        self.stop()


# ─────────────────────────── progress bar ───────────────────────────────────

class ProgressBar:
    """Single-line ASCII/Unicode progress bar printed to stderr."""

    def __init__(self, total: int, label: str = "", width: int = 30) -> None:
        self._total  = max(total, 1)
        self._done   = 0
        self._label  = label
        self._width  = width
        self._active = _COLOR and sys.stderr.isatty()
        self._start  = time.monotonic()

    def update(self, n: int = 1) -> None:
        self._done = min(self._done + n, self._total)
        if not self._active:
            return
        pct  = self._done / self._total
        fill = int(pct * self._width)
        bar  = C.GREEN + "█" * fill + C.GRAY + "░" * (self._width - fill) + C.RST
        elapsed = time.monotonic() - self._start
        eta = ""
        if pct > 0:
            remaining = elapsed / pct * (1 - pct)
            eta = f"  {C.GRAY}ETA {remaining:.0f}s{C.RST}"
        sys.stderr.write(
            f"\r  {bar}  {C.BWHITE}{self._done}/{self._total}{C.RST}  "
            f"{C.YELLOW}{pct*100:.0f}%{C.RST}{eta}  "
            f"{C.GRAY}{self._label}{C.RST}"
            + " " * 10
        )
        sys.stderr.flush()

    def finish(self) -> None:
        if self._active:
            sys.stderr.write(f"\r{' ' * 80}\r")
            sys.stderr.flush()


# ─────────────────────────── summary box ────────────────────────────────────

def print_summary_box(
    target: str,
    stats: dict[str, int | str],
    elapsed: float,
    report_path: str | None = None,
) -> None:
    term_w = shutil.get_terminal_size((80, 20)).columns
    box_w  = min(term_w - 4, 68)

    top    = C.CYAN  + "┌" + "─" * (box_w - 2) + "┐" + C.RST
    mid    = C.CYAN  + "├" + "─" * (box_w - 2) + "┤" + C.RST
    bot    = C.CYAN  + "└" + "─" * (box_w - 2) + "┘" + C.RST

    def row(text: str) -> str:
        # strip ANSI for width calc
        import re
        plain = re.sub(r"\033\[[0-9;]*m", "", text)
        pad   = max(0, box_w - 4 - len(plain))
        return C.CYAN + "│ " + C.RST + text + " " * pad + C.CYAN + " │" + C.RST

    title = f"{C.BOLD}{C.WHITE}Scan Complete — {target}{C.RST}"
    time_s= f"{elapsed:.1f}s"

    print(f"\n{top}")
    print(row(title))
    print(mid)

    for k, v in stats.items():
        label = f"{C.GRAY}{k:<20}{C.RST}"
        val_c = C.BWHITE if isinstance(v, int) and v > 0 else C.GRAY
        value = f"{val_c}{v}{C.RST}"
        print(row(f"{label}  {value}"))

    print(mid)
    print(row(f"{C.GRAY}Elapsed{C.RST}            {C.YELLOW}{time_s}{C.RST}"))
    if report_path:
        print(row(f"{C.GRAY}Report{C.RST}             {C.CYAN}{report_path}{C.RST}"))
    print(bot)
    print()


# ─────────────────────────── dry-run plan table ─────────────────────────────

def print_plan(plan: list[tuple[str, str]]) -> None:
    section("Execution Plan (--dry-run)", Icon.INFO)
    for i, (stage, reason) in enumerate(plan, 1):
        bullet_c = C.CYAN
        print(
            f"  {bullet_c}{i:>2}.{C.RST}  "
            f"{C.BOLD}{stage:<18}{C.RST}  "
            f"{C.GRAY}{reason}{C.RST}"
        )
    print()


# ─────────────────────────── import summary ─────────────────────────────────

def print_import_summary(source: str, imported: int, errors: int, stats: dict) -> None:
    section(f"Import — {source}", Icon.ARROW)
    rows = [
        KV("imported", str(imported), C.BGREEN if imported > 0 else C.GRAY),
        KV("errors",   str(errors),   C.BRED   if errors   > 0 else C.GRAY),
    ]
    for k, v in sorted(stats.items()):
        rows.append(KV(k, str(v), C.WHITE))
    print_kv_table(rows)
    # machine-readable summary line (backward-compat for scripts & tests)
    parts = [f"imported={imported}"]
    if errors:
        parts.append(f"errors={errors}")
    parts += [f"{k}={v}" for k, v in sorted(stats.items())]
    print("  ".join(parts))


# ─────────────────────────── config hint ────────────────────────────────────

def print_config_hint(cfg) -> None:
    keys = cfg.keys
    has_vt = bool(keys.virustotal)
    has_st = bool(keys.securitytrails)
    if not has_vt or not has_st:
        lines = []
        if not has_vt:
            lines.append("STRATA_VIRUSTOTAL_KEY")
        if not has_st:
            lines.append("STRATA_SECURITYTRAILS_KEY")
        warn(
            f"Optional API keys not set: "
            f"{C.YELLOW}{', '.join(lines)}{C.RST} — "
            f"{C.GRAY}free sources only{C.RST}"
        )


__all__ = [
    "C", "Icon",
    "print_banner", "section", "ok", "fail", "warn", "info", "bullet", "err",
    "KV", "print_kv_table",
    "print_findings_table", "print_dns_finding",
    "print_passive_dns_results", "print_fingerprint_result",
    "stage_start", "stage_done", "stage_skip",
    "Spinner", "ProgressBar",
    "print_summary_box", "print_plan",
    "print_import_summary", "print_config_hint",
]

