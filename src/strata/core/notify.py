"""Run-completion notifications (Slack / Discord / generic webhooks).

A finished Strata run can post a compact summary to a webhook so teams see
surface changes without watching the terminal. Design rules:

* The webhook URL is a credential: it is never logged, never written to
  manifests, and never echoed in error messages.
* Notification failure must never fail the run — it is contained and logged.
* Payload is auto-detected from the URL: ``hooks.slack.com`` gets Slack
  ``text`` blocks, ``discord.com``/``discordapp.com`` get Discord embeds,
  everything else receives a plain JSON summary.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class RunSummary:
    target: str
    findings: int
    verified: int
    candidate: int
    dead: int
    new_findings: int
    vulns: int
    elapsed_seconds: float
    report_path: str | None

    def as_dict(self) -> dict:
        return {
            "event": "strata_run_completed",
            "target": self.target,
            "findings": self.findings,
            "verified": self.verified,
            "candidate": self.candidate,
            "candidate_label": "candidates",
            "dead": self.dead,
            "new_findings": self.new_findings,
            "vulns": self.vulns,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "report": self.report_path,
        }

    def text(self) -> str:
        lines = [
            f"*Strata run completed — {self.target}*",
            f"findings: {self.findings} "
            f"({self.verified} verified, {self.candidate} candidates, "
            f"{self.dead} dead)",
            f"new: {self.new_findings} • CVE/takeover findings: {self.vulns}",
        ]
        if self.report_path:
            lines.append(f"report: {self.report_path}")
        return "\n".join(lines)


def _slack_payload(summary: RunSummary) -> dict:
    risk = ":rotating_light:" if summary.vulns else ":white_check_mark:"
    return {
        "text": (
            f"{risk} *Strata run — {summary.target}*\n"
            f"findings {summary.findings} ({summary.verified} verified / "
            f"{summary.candidate} candidates / {summary.dead} dead)\n"
            f"new {summary.new_findings} • vuln findings {summary.vulns}\n"
            + (f"report: {summary.report_path}\n" if summary.report_path else "")
        ),
    }


def _discord_payload(summary: RunSummary) -> dict:
    color = 0xE74C3C if summary.vulns else 0x2ECC71
    return {
        "embeds": [
            {
                "title": f"Strata run — {summary.target}",
                "color": color,
                "fields": [
                    {"name": "findings", "value": str(summary.findings), "inline": True},
                    {"name": "verified", "value": str(summary.verified), "inline": True},
                    {"name": "candidates", "value": str(summary.candidate), "inline": True},
                    {"name": "dead", "value": str(summary.dead), "inline": True},
                    {"name": "new", "value": str(summary.new_findings), "inline": True},
                    {"name": "vuln findings", "value": str(summary.vulns), "inline": True},
                    *(
                        [{"name": "report", "value": summary.report_path}]
                        if summary.report_path
                        else []
                    ),
                ],
            }
        ]
    }


def _payload_for(url: str, summary: RunSummary) -> dict:
    lowered = url.lower()
    if "hooks.slack.com" in lowered:
        return _slack_payload(summary)
    if "discord.com" in lowered or "discordapp.com" in lowered:
        return _discord_payload(summary)
    return summary.as_dict()


def notify(
    url: str,
    summary: RunSummary,
    *,
    timeout: float = 10.0,
) -> bool:
    """POST the run summary. Returns True on delivery; never raises."""
    try:
        payload = json.dumps(_payload_for(url, summary)).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"content-type": "application/json", "user-agent": "strata/notify"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


__all__ = ["RunSummary", "notify"]
