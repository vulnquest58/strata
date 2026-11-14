import gzip
import json
import zlib
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import pytest

from strata.core.budget import RequestBudget
from strata.core.errors import (
    BudgetExceeded,
    ScopeViolation,
    classify_exception,
)
from strata.core.manifest import RunManifest, manifest_path_for
from strata.core.redact import redact_text, redact_url


def test_classify_exception_distinguishes_expected_from_unexpected() -> None:
    assert classify_exception(BudgetExceeded("limit")).code == "BUDGET_EXCEEDED"
    assert classify_exception(ScopeViolation("out of scope")).code == "SCOPE_VIOLATION"
    assert classify_exception(PermissionError("denied")).code == "SCOPE_VIOLATION"
    assert classify_exception(TimeoutError("slow")).code == "NETWORK_FAILURE"
    assert classify_exception(ValueError("bad")).code == "INVALID_INPUT"

    unexpected = classify_exception(ZeroDivisionError("boom"))
    assert unexpected.code == "UNEXPECTED"
    assert unexpected.expected is False


def test_request_budget_enforces_request_limit() -> None:
    budget = RequestBudget(max_requests=1)
    budget.before_request()
    with pytest.raises(BudgetExceeded):
        budget.before_request()
    assert budget.snapshot()["requests"] == 1


def test_request_budget_enforces_byte_limit() -> None:
    budget = RequestBudget(max_bytes=10)
    budget.before_request()
    budget.record_bytes(5)
    with pytest.raises(BudgetExceeded):
        budget.record_bytes(6)


def test_request_budget_enforces_time_limit() -> None:
    budget = RequestBudget(max_seconds=1.0)
    budget.started_at -= 2.0
    with pytest.raises(BudgetExceeded):
        budget.before_request()


async def test_transport_checks_budget_at_network_boundary(monkeypatch) -> None:
    from strata.core.content.fetch import FetchResponse, UrllibTransport

    budget = RequestBudget(max_requests=1)
    transport = UrllibTransport(budget=budget)
    monkeypatch.setattr(
        transport,
        "_get",
        lambda url, timeout, max_bytes: FetchResponse(url, 200, {}, b"ok"),
    )

    await transport.get("https://example.com/")
    with pytest.raises(BudgetExceeded):
        await transport.get("https://example.com/")
    assert budget.snapshot()["requests"] == 1
    assert budget.snapshot()["bytes_used"] == 2


@pytest.mark.parametrize(
    ("encoding", "compress"),
    [("gzip", gzip.compress), ("deflate", zlib.compress)],
)
async def test_transport_decodes_compressed_bodies(monkeypatch, encoding, compress) -> None:
    from strata.core.content.fetch import FetchResponse, UrllibTransport

    html = b"<html><a href='/login'>login</a></html>"
    wire = compress(html)
    budget = RequestBudget(max_requests=10, max_bytes=100_000)
    transport = UrllibTransport(budget=budget)
    monkeypatch.setattr(
        transport,
        "_get",
        lambda url, timeout, max_bytes: FetchResponse(
            url,
            200,
            {"content-type": "text/html", "content-encoding": encoding},
            wire,
        ),
    )

    response = await transport.get("https://example.com/")

    assert response.body == html
    assert "content-encoding" not in response.headers
    assert budget.snapshot()["bytes_used"] == len(wire)


def test_redact_url_strips_credentials_and_sensitive_query_values() -> None:
    url = (
        "https://user:pass@api.example.com/v1/users"
        "?token=supersecret&q=1#access_token=fragsecret"
    )
    redacted = redact_url(url)
    parsed = urlparse(redacted)
    assert parsed.username is None
    assert parsed.password is None
    assert parsed.hostname == "api.example.com"
    query = dict(parse_qsl(parsed.query))
    assert query["token"] == "***"
    assert query["q"] == "1"
    assert "fragsecret" not in redacted
    assert "supersecret" not in redacted


def test_redact_text_masks_sensitive_pairs() -> None:
    assert redact_text("password=hunter2 next=ok") == "password=*** next=ok"
    assert redact_text("api_key: abcdef123456") == "api_key: ***"


def test_manifest_fingerprint_is_stable_and_auditable(tmp_path: Path) -> None:
    manifest = RunManifest(
        target="example.com",
        scope="example.com",
        options={"no_passive": True, "max_requests": 100},
    )
    first = manifest.fingerprint()
    assert first == manifest.fingerprint()
    assert len(first) == 64

    manifest.finish(
        stats={"findings": 3},
        stages=[{"stage": "dns", "new_findings": 1}],
        report="reports/run.md",
        budget={"requests": 10},
    )
    payload = manifest.to_dict()
    assert payload["fingerprint"] == first
    assert payload["stats"] == {"findings": 3}

    path = manifest.write(tmp_path / "run.manifest.json")
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["fingerprint"] == first
    assert written["target"] == "example.com"

    assert manifest_path_for("reports/run.md") == Path("reports/run.manifest.json")
