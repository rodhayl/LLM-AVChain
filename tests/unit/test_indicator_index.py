from __future__ import annotations

from itertools import permutations
from pathlib import Path
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx
import pytest

from avchain.agent.worker import EndpointAgentWorker
from avchain.endpoint import scanner
from avchain.endpoint.indicators import ExactIndicatorIndex
from avchain.models.schemas import TelemetryEvent, ThreatEntry
from avchain.utils.helpers import compute_sha256


def legacy_match(path, entries):
    for entry_id, observables in entries.items():
        result = scanner.scan_artifact(path, observables)
        if result is not None:
            return entry_id, result
    return None


@pytest.mark.parametrize("kind", ["script", "package", "benign", "invalid_json"])
def test_indexed_scan_preserves_catalog_order_and_full_result(tmp_path, kind):
    path = tmp_path / ("script.ps1" if kind == "script" else "package.json")
    payloads = {
        "script": b"powershell https://example.invalid/ postinstall",
        "package": b'{"name":"demo","scripts":{"postinstall":"node install.js"}}',
        "benign": b'{"name":"benign"}',
        "invalid_json": b"not valid JSON, postinstall",
    }
    path.write_bytes(payloads[kind])
    (tmp_path / "install.js").write_text("curl https://example.invalid/")
    digest = compute_sha256(path.read_bytes())
    entries = [
        (uuid4(), {digest, "behavior:postinstall"}),
        (uuid4(), {"behavior:postinstall", "behavior:suspicious-network"}),
        (uuid4(), {"package:demo", "behavior:powershell-download"}),
        (uuid4(), {digest, "unrelated"}),
    ]
    for order in permutations(entries):
        catalog = dict(order)
        assert scanner.scan_indexed_artifact(
            path, ExactIndicatorIndex(catalog)
        ) == legacy_match(path, catalog)


@pytest.mark.parametrize("entry_count", [1, 10, 1000])
@pytest.mark.parametrize("result_kind", ["miss", "direct", "contextual"])
def test_catalog_size_does_not_multiply_reads_or_hashes(
    tmp_path, monkeypatch, entry_count, result_kind
):
    path = tmp_path / "sample.txt"
    path.write_bytes(b"postinstall")
    digest = compute_sha256(path.read_bytes())
    entries = {UUID(int=i + 1): {f"unrelated-{i}"} for i in range(entry_count)}
    if result_kind != "miss":
        entries[UUID(int=entry_count)] = {
            digest if result_kind == "direct" else "behavior:postinstall"
        }
    counts = {"reads": 0, "hashes": 0}
    read_bytes = Path.read_bytes
    hash_bytes = scanner.compute_sha256

    def counted_read(self):
        counts["reads"] += 1
        return read_bytes(self)

    def counted_hash(payload):
        counts["hashes"] += 1
        return hash_bytes(payload)

    monkeypatch.setattr(Path, "read_bytes", counted_read)
    monkeypatch.setattr(scanner, "compute_sha256", counted_hash)
    expected = legacy_match(path, entries)
    assert counts == {"reads": entry_count, "hashes": entry_count}
    counts.update(reads=0, hashes=0)
    assert scanner.scan_indexed_artifact(path, ExactIndicatorIndex(entries)) == expected
    assert counts == {"reads": 1, "hashes": 1}


def test_package_context_is_read_once_per_scan(tmp_path, monkeypatch):
    path = tmp_path / "package.json"
    path.write_text('{"name":"demo"}')
    sibling = tmp_path / "install.js"
    sibling.write_text("powershell")
    entries = {UUID(int=i + 1): {f"unrelated-{i}"} for i in range(100)}
    entries[UUID(int=100)] = {"behavior:powershell-download"}
    read_text = Path.read_text
    reads = []

    def counted_read(self, *args, **kwargs):
        reads.append(self)
        return read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counted_read)
    expected = legacy_match(path, entries)
    assert reads == [sibling] * 100
    reads.clear()
    assert scanner.scan_indexed_artifact(path, ExactIndicatorIndex(entries)) == expected
    assert reads == [sibling]


def test_direct_first_entry_still_skips_invalid_context(tmp_path):
    path = tmp_path / "package.json"
    path.write_bytes(b"\xff")
    entry_id = uuid4()
    digest = compute_sha256(path.read_bytes())
    entries = {entry_id: {digest}, uuid4(): {"irrelevant"}}
    assert scanner.scan_indexed_artifact(path, ExactIndicatorIndex(entries)) == (
        legacy_match(path, entries)
    )
    reversed_entries = dict(reversed(list(entries.items())))
    with pytest.raises(UnicodeDecodeError):
        legacy_match(path, reversed_entries)
    with pytest.raises(UnicodeDecodeError):
        scanner.scan_indexed_artifact(path, ExactIndicatorIndex(reversed_entries))


def test_empty_catalog_does_not_read_missing_file(tmp_path):
    assert (
        scanner.scan_indexed_artifact(tmp_path / "missing", ExactIndicatorIndex({}))
        is None
    )


@pytest.mark.parametrize("change", ["replace", "delete", "rewrite"])
def test_midscan_file_changes_raise_instead_of_using_old_digest(
    tmp_path, monkeypatch, change
):
    path = tmp_path / "sample.txt"
    path.write_bytes(b"original")
    index = ExactIndicatorIndex({uuid4(): {compute_sha256(path.read_bytes())}})
    read_bytes = Path.read_bytes

    def changed_read(self):
        result = read_bytes(self)
        if change == "delete":
            self.unlink()
        elif change == "replace":
            other = self.with_suffix(".new")
            other.write_bytes(b"modified")
            other.replace(self)
        else:
            self.write_bytes(b"modified")
        return result

    monkeypatch.setattr(Path, "read_bytes", changed_read)
    with pytest.raises(OSError):
        scanner.scan_indexed_artifact(path, index)


def test_no_file_or_sibling_content_is_cached_between_events(tmp_path):
    path = tmp_path / "sample.txt"
    path.write_bytes(b"original")
    index = ExactIndicatorIndex({uuid4(): {compute_sha256(path.read_bytes())}})
    assert scanner.scan_indexed_artifact(path, index) is not None
    path.write_bytes(b"modified")
    assert scanner.scan_indexed_artifact(path, index) is None
    path.unlink()
    with pytest.raises(FileNotFoundError):
        scanner.scan_indexed_artifact(path, index)

    package = tmp_path / "package.json"
    package.write_text('{"name":"demo"}')
    sibling = tmp_path / "install.js"
    sibling.write_text("powershell")
    index = ExactIndicatorIndex({uuid4(): {"behavior:powershell-download"}})
    assert scanner.scan_indexed_artifact(package, index) is not None
    sibling.write_text("benign")
    assert scanner.scan_indexed_artifact(package, index) is None


def test_exact_index_is_case_sensitive_and_immutable():
    first, second = uuid4(), uuid4()
    entries = {first: {"Same", "Å"}, second: {"Same", "same"}}
    index = ExactIndicatorIndex(entries)
    assert index.first("Same") == (0, first)
    assert index.first("same") == (1, second)
    assert index.first("SAME") is None
    assert index.first("A\u030a") is None
    entries[first].clear()
    entries.clear()
    assert index.first("Same") == (0, first)
    assert index.entries[first] == frozenset({"Same", "Å"})
    with pytest.raises(TypeError):
        index.entries[first] = frozenset()
    with pytest.raises(AttributeError):
        index.entries[first].add("changed")


@pytest.mark.parametrize("entry_count", [1, 10, 1000])
def test_exact_lookup_cost_does_not_depend_on_catalog_size(entry_count):
    counts = {"memberships": 0, "lookups": 0}

    class CountedSet(set):
        def __contains__(self, value):
            counts["memberships"] += 1
            return super().__contains__(value)

    class CountedDict(dict):
        def get(self, value, default=None):
            counts["lookups"] += 1
            return super().get(value, default)

    entries = {UUID(int=i + 1): CountedSet({f"ioc-{i}"}) for i in range(entry_count)}
    index = ExactIndicatorIndex(entries)
    index._first = CountedDict(index._first)
    for observable in (f"ioc-{entry_count - 1}", "absent"):
        counts.update(memberships=0, lookups=0)
        expected = next(
            (entry_id for entry_id, values in entries.items() if observable in values),
            None,
        )
        match = index.first(observable)
        assert (match[1] if match else None) == expected
        assert counts == {"memberships": entry_count, "lookups": 1}


@pytest.mark.asyncio
async def test_worker_refresh_replaces_index_and_preserves_feedback(
    test_environment, monkeypatch
):
    first = ThreatEntry(observables=["same"])
    second = ThreatEntry(observables=["same", "second"])
    entries = [first, second]

    def respond(request):
        assert request.url.params["state"] == "confirmed"
        return httpx.Response(200, json=[e.model_dump(mode="json") for e in entries])

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(respond), base_url="http://ledger"
    ) as client:
        worker = EndpointAgentWorker(ledger_client=client)
        submit = AsyncMock()
        monkeypatch.setattr(worker, "_submit_feedback", submit)
        await worker.refresh_confirmed_entries()
        event = TelemetryEvent(observable="same", metadata={"file_path": "/test"})
        result = await worker.process_event(event)
        assert result.entry_id == first.id
        assert result.action_taken == worker.remediation_action
        assert result.hashed_identifiers == {"file_path": compute_sha256(b"/test")}
        entries[:] = [second, first]
        await worker.refresh_confirmed_entries()
        assert (await worker.process_event(event)).entry_id == second.id
        entries.clear()
        await worker.refresh_confirmed_entries()
        assert await worker.process_event(event) is None
        assert worker.events_processed == 3
        assert worker.feedback_generated == 2
        assert submit.await_count == 2


@pytest.mark.asyncio
async def test_worker_failed_refresh_keeps_previous_snapshot(test_environment):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
        base_url="http://ledger",
    ) as client:
        worker = EndpointAgentWorker(ledger_client=client)
        entry_id = uuid4()
        worker.confirmed_entries = {entry_id: {"existing"}}
        with pytest.raises(httpx.HTTPStatusError):
            await worker.refresh_confirmed_entries()
        assert worker._indicator_index.first("existing") == (0, entry_id)


@pytest.mark.asyncio
async def test_worker_scan_failure_never_classifies_or_sends_feedback(
    test_environment, tmp_path, monkeypatch
):
    path = tmp_path / "sample.txt"
    path.write_bytes(b"original")
    worker = EndpointAgentWorker()
    worker.endpoint_scan_enabled = True
    worker.endpoint_watch_dir = tmp_path
    worker.confirmed_entries = {uuid4(): {compute_sha256(path.read_bytes())}}
    monkeypatch.setattr(
        "avchain.agent.worker.collect_artifacts", lambda *a, **kw: [path]
    )
    classify, submit = AsyncMock(), AsyncMock()
    monkeypatch.setattr(worker._artifact_classifier, "classify", classify)
    monkeypatch.setattr(worker, "_submit_feedback", submit)
    original = Path.read_bytes

    def changed_read(self):
        data = original(self)
        self.unlink()
        return data

    monkeypatch.setattr(Path, "read_bytes", changed_read)
    with pytest.raises(FileNotFoundError):
        await worker.process_local_artifacts()
    classify.assert_not_awaited()
    submit.assert_not_awaited()
    assert worker.feedback_generated == worker.artifact_detections == 0
