from __future__ import annotations

import asyncio
import base64
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI

from avchain.agent import worker as agent_worker_module
from avchain.consensus import service as consensus_service_module
from avchain.consensus.registry import ValidatorRegistry
from avchain.coverage import service as coverage_service_module
from avchain.coverage.service import HttpConsensusGateway, compute_metric
from avchain.crypto.keys import (
    canonicalize,
    generate_keypair,
    load_private_key,
    load_public_key,
    private_key_to_pem,
    verify_signature,
)
from avchain.database.core import (
    get_engine,
    get_session_factory,
    init_db,
    reset_database_state,
)
from avchain.evidence.storage import (
    EvidenceStorage,
    encode_evidence_payload,
    store_evidence_item,
)
from avchain.ledger import crud as ledger_crud_module
from avchain.ledger import service as ledger_service_module
from avchain.models.enums import LifecycleState, ProposalAction
from avchain.models.orm import Entry, EvidenceObject, Proposal
from avchain.models.schemas import (
    StateTransition,
    TelemetryEvent,
    ThreatEntryCreate,
)
from avchain.utils.helpers import current_timestamp
from avchain.validator import heuristics as heuristics_module
from avchain.validator import worker as validator_worker_module


class DummyResponse:
    def __init__(self, payload: dict[str, object], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.content = b"payload"

    def json(self) -> dict[str, object]:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "boom",
                request=httpx.Request("GET", "http://example"),
                response=httpx.Response(self.status_code),
            )


class DummyAsyncClient:
    def __init__(self, response: DummyResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, str, dict[str, object] | None]] = []

    async def __aenter__(self) -> DummyAsyncClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        _ = exc_type, exc, tb

    async def post(
        self,
        path: str,
        json: dict[str, object],
        headers: dict[str, str],
    ) -> DummyResponse:
        self.calls.append(("POST", path, {"json": json, "headers": headers}))
        return self.response

    async def get(
        self,
        path: str,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> DummyResponse:
        self.calls.append(
            ("GET", path, {"params": params or {}, "headers": headers or {}})
        )
        return self.response


@pytest.mark.asyncio
async def test_http_gateway_helpers_and_worker_client_contexts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transition = StateTransition(
        from_state=LifecycleState.SUSPECTED,
        to_state=LifecycleState.CONFIRMED,
        actor="consensus",
    )
    gateway_client = DummyAsyncClient(DummyResponse({"status": "ok"}))
    monkeypatch.setattr(
        consensus_service_module.httpx,
        "AsyncClient",
        lambda **_: gateway_client,
    )
    ledger_gateway = consensus_service_module.HttpLedgerGateway(
        base_url="http://ledger",
        api_key="k",
    )
    assert await ledger_gateway.transition_entry(str(uuid4()), transition) == {
        "status": "ok"
    }

    consensus_client = DummyAsyncClient(DummyResponse({"status": "queued"}))
    monkeypatch.setattr(
        coverage_service_module.httpx,
        "AsyncClient",
        lambda **_: consensus_client,
    )
    consensus_gateway = HttpConsensusGateway(base_url="http://consensus", api_key="k")
    assert await consensus_gateway.request_review(
        str(uuid4()),
        "coverage_threshold_exceeded",
    ) == {"status": "queued"}

    agent_client = DummyAsyncClient(DummyResponse([]))
    monkeypatch.setattr(
        agent_worker_module.httpx,
        "AsyncClient",
        lambda **_: agent_client,
    )
    agent = agent_worker_module.EndpointAgentWorker()
    async with agent._client(None, "http://ledger") as client:
        assert client is agent_client

    validator_client = DummyAsyncClient(DummyResponse([]))
    monkeypatch.setattr(
        validator_worker_module.httpx,
        "AsyncClient",
        lambda **_: validator_client,
    )
    private_key, _ = generate_keypair()
    key_path = tmp_path / "validator1_key.pem"
    key_path.write_text(private_key_to_pem(private_key), encoding="utf-8")
    validator = validator_worker_module.ValidatorWorker(
        validator_id="validator1",
        private_key_path=key_path,
    )
    async with validator._client(None, "http://ledger") as client:
        assert client is validator_client


def test_crypto_type_and_signature_failure_paths() -> None:
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public = rsa_private.public_key()
    private_pem = rsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = rsa_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    with pytest.raises(TypeError):
        load_private_key(private_pem)
    with pytest.raises(TypeError):
        load_public_key(public_pem)

    _, public_key = generate_keypair()
    assert verify_signature(public_key, canonicalize({"a": 1}), "!!!") is False
    encoded = base64.b64encode(b"wrong-size").decode("utf-8")
    assert verify_signature(public_key, canonicalize({"a": 1}), encoded) is False


def test_database_autoinit_and_evidence_storage_branches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = f"sqlite:///{(tmp_path / 'db' / 'ledger.db').as_posix()}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    reset_database_state()

    assert get_session_factory() is not None
    reset_database_state()
    assert get_engine() is not None

    storage = EvidenceStorage(tmp_path / "evidence")
    raw = encode_evidence_payload(b"raw-bytes", "application/octet-stream")
    text = encode_evidence_payload("plain-text", "text/plain")
    assert raw == b"raw-bytes"
    assert text == b"plain-text"

    init_db(database_url)
    with get_session_factory()() as session:
        entry = Entry(
            observables_json='["ioc-1"]',
            state="confirmed",
            tlp_label="TLP:CLEAR",
        )
        session.add(entry)
        session.commit()
        item = store_evidence_item(
            db=session,
            storage=storage,
            entry_id=entry.id,
            data=b"payload",
            content_type="application/octet-stream",
        )
        session.commit()
        assert storage.exists(item.digest)

    reset_database_state()


def test_heuristic_and_crud_edge_paths(
    db_session,
    storage,
) -> None:
    heuristic = heuristics_module.DeterministicHeuristic()
    assert heuristic.analyze([], [b"x"])[0] == ProposalAction.RETAIN
    assert (
        heuristic.analyze(["mid-signal-9"], [b"one", b"two"])[0]
        == ProposalAction.RETAIN
    )

    with pytest.raises(LookupError):
        ledger_crud_module.get_entry(db_session, uuid4())
    with pytest.raises(LookupError):
        ledger_crud_module.record_feedback(db_session, uuid4(), "deadbeef")

    entry = ledger_crud_module.create_entry(
        db_session,
        ThreatEntryCreate(observables=["ioc-2"], evidence=[], tlp_label="TLP:CLEAR"),
        storage=storage,
    )
    with pytest.raises(ValueError):
        ledger_crud_module.record_feedback(db_session, entry.id, "deadbeef")

    confirmed_entry = Entry(
        observables_json='["ioc-3"]',
        state=LifecycleState.CONFIRMED.value,
        tlp_label="TLP:CLEAR",
    )
    db_session.add(confirmed_entry)
    db_session.commit()

    with pytest.raises(ValueError, match="Feedback digest is unknown"):
        ledger_crud_module.record_feedback(db_session, confirmed_entry.id, "deadbeef")

    supporting_feedback = EvidenceObject(
        digest="f" * 64,
        entry_id=confirmed_entry.id,
        purpose="supporting",
        content_type="application/json",
        size=1,
    )
    db_session.add(supporting_feedback)
    db_session.commit()

    with pytest.raises(ValueError, match="uploaded as feedback"):
        ledger_crud_module.record_feedback(
            db_session, confirmed_entry.id, supporting_feedback.digest
        )

    fresh_changed = ledger_crud_module.run_timeout_transitions(
        db=db_session,
        suspected_timeout_hours=24.0,
        review_timeout_hours=24.0,
        now=current_timestamp(),
    )
    assert fresh_changed == []


@pytest.mark.asyncio
async def test_runtime_loops_and_main_wrappers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent_calls: list[str] = []

    async def fake_agent_sleep(_: float) -> None:
        raise RuntimeError("stop-loop")

    async def fake_agent_run_once(self) -> int:
        agent_calls.append("run-once")
        return 1

    monkeypatch.setattr(agent_worker_module.asyncio, "sleep", fake_agent_sleep)
    monkeypatch.setattr(
        agent_worker_module.EndpointAgentWorker,
        "run_once",
        fake_agent_run_once,
    )
    agent = agent_worker_module.EndpointAgentWorker()
    with pytest.raises(RuntimeError):
        await agent.run()
    assert agent_calls == ["run-once"]

    ran_main: list[str] = []

    class DummyAgentWorker:
        def __init__(self, *args, **kwargs) -> None:
            _ = args, kwargs

        async def run(self) -> None:
            ran_main.append("agent-main")

    monkeypatch.setattr(agent_worker_module, "EndpointAgentWorker", DummyAgentWorker)
    await agent_worker_module.main()
    assert "agent-main" in ran_main

    private_key, _ = generate_keypair()
    key_path = tmp_path / "validator1_key.pem"
    key_path.write_text(private_key_to_pem(private_key), encoding="utf-8")

    validator_calls: list[str] = []

    async def fake_validator_sleep(_: float) -> None:
        raise RuntimeError("stop-loop")

    async def fake_validator_run_once(self) -> int:
        validator_calls.append("run-once")
        return 1

    monkeypatch.setattr(validator_worker_module.asyncio, "sleep", fake_validator_sleep)
    monkeypatch.setattr(
        validator_worker_module.ValidatorWorker,
        "run_once",
        fake_validator_run_once,
    )
    validator = validator_worker_module.ValidatorWorker(
        validator_id="validator1",
        private_key_path=key_path,
    )
    with pytest.raises(RuntimeError):
        await validator.run()
    assert validator_calls == ["run-once"]

    validator_main_calls: list[tuple[str, str]] = []

    class DummyValidatorWorker:
        def __init__(
            self,
            validator_id: str,
            private_key_path: Path,
            status_name: str | None = None,
        ) -> None:
            _ = status_name
            validator_main_calls.append((validator_id, str(private_key_path)))

        async def run(self) -> None:
            validator_main_calls.append(("run", "called"))

    monkeypatch.setattr(
        validator_worker_module,
        "ValidatorWorker",
        DummyValidatorWorker,
    )
    monkeypatch.setattr(
        validator_worker_module.sys,
        "argv",
        ["worker", "validator9", str(key_path)],
    )
    await validator_worker_module.main()
    assert ("validator9", str(key_path)) in validator_main_calls

    module_entrypoints: list[str] = []

    def fake_asyncio_run(coro: object) -> None:
        code = getattr(coro, "cr_code", None)
        if code is not None:
            module_entrypoints.append(str(code.co_name))
        close = getattr(coro, "close", None)
        if callable(close):
            close()

    monkeypatch.setattr(asyncio, "run", fake_asyncio_run)

    agent_source = Path(agent_worker_module.__file__).read_text(encoding="utf-8")
    exec(
        compile(agent_source, str(agent_worker_module.__file__), "exec"),
        {"__name__": "__main__", "__file__": str(agent_worker_module.__file__)},
    )
    validator_source = Path(validator_worker_module.__file__).read_text(
        encoding="utf-8"
    )
    exec(
        compile(validator_source, str(validator_worker_module.__file__), "exec"),
        {
            "__name__": "__main__",
            "__file__": str(validator_worker_module.__file__),
        },
    )
    assert module_entrypoints == ["main", "main"]


@pytest.mark.asyncio
async def test_worker_run_loops_retry_after_http_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent_calls: list[str] = []

    async def failing_agent_run_once(self) -> int:
        _ = self
        agent_calls.append("run-once")
        raise httpx.ConnectError("agent unavailable")

    async def stop_agent_sleep(_: float) -> None:
        raise RuntimeError("stop-agent")

    monkeypatch.setattr(
        agent_worker_module.EndpointAgentWorker,
        "run_once",
        failing_agent_run_once,
    )
    monkeypatch.setattr(agent_worker_module.asyncio, "sleep", stop_agent_sleep)

    with pytest.raises(RuntimeError, match="stop-agent"):
        await agent_worker_module.EndpointAgentWorker().run()
    assert agent_calls == ["run-once"]

    private_key, _ = generate_keypair()
    key_path = tmp_path / "validator1_key.pem"
    key_path.write_text(private_key_to_pem(private_key), encoding="utf-8")
    validator_calls: list[str] = []

    async def failing_validator_run_once(self) -> int:
        _ = self
        validator_calls.append("run-once")
        raise httpx.ConnectError("validator unavailable")

    async def stop_validator_sleep(_: float) -> None:
        raise RuntimeError("stop-validator")

    monkeypatch.setattr(
        validator_worker_module.ValidatorWorker,
        "run_once",
        failing_validator_run_once,
    )
    monkeypatch.setattr(
        validator_worker_module.asyncio,
        "sleep",
        stop_validator_sleep,
    )

    with pytest.raises(RuntimeError, match="stop-validator"):
        await validator_worker_module.ValidatorWorker(
            validator_id="validator1",
            private_key_path=key_path,
        ).run()
    assert validator_calls == ["run-once"]


@pytest.mark.asyncio
async def test_agent_process_event_non_matching_cached_entry_branch() -> None:
    worker = agent_worker_module.EndpointAgentWorker()
    worker.confirmed_entries = {uuid4(): {"ioc-known"}}

    result = await worker.process_event(
        TelemetryEvent(observable="ioc-other", metadata={"file_path": "C:/Temp/other"})
    )

    assert result is None
    assert worker.events_processed == 1


@pytest.mark.asyncio
async def test_ledger_timeout_worker_and_lifespan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop_calls = {"sleep": 0, "transitions": 0}

    async def fake_sleep(_: float) -> None:
        loop_calls["sleep"] += 1
        if loop_calls["sleep"] > 1:
            raise RuntimeError("stop")

    @contextmanager
    def fake_session_scope():
        yield SimpleNamespace()

    monkeypatch.setattr(
        ledger_service_module,
        "get_settings",
        lambda: SimpleNamespace(
            poll_interval=1,
            suspected_timeout_hours=1.0,
            review_timeout_hours=1.0,
        ),
    )
    monkeypatch.setattr(ledger_service_module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(ledger_service_module, "session_scope", fake_session_scope)
    monkeypatch.setattr(
        ledger_service_module,
        "run_timeout_transitions",
        lambda **_: loop_calls.__setitem__(
            "transitions",
            loop_calls["transitions"] + 1,
        ),
    )

    with pytest.raises(RuntimeError):
        await ledger_service_module._timeout_worker()
    assert loop_calls["transitions"] == 1

    task_calls = {"cancelled": False, "awaited": False}

    async def fake_timeout_worker() -> None:
        return None

    class FakeTask:
        def cancel(self) -> None:
            task_calls["cancelled"] = True

        def __await__(self):
            async def _wait() -> None:
                task_calls["awaited"] = True
                raise asyncio.CancelledError

            return _wait().__await__()

    monkeypatch.setattr(ledger_service_module, "_timeout_worker", fake_timeout_worker)
    monkeypatch.setattr(ledger_service_module, "init_db", lambda: None)

    def fake_create_task(coro: object) -> FakeTask:
        close = getattr(coro, "close", None)
        if callable(close):
            close()
        return FakeTask()

    monkeypatch.setattr(
        ledger_service_module.asyncio,
        "create_task",
        fake_create_task,
    )
    async with ledger_service_module._lifespan(FastAPI()):
        pass
    assert task_calls == {"cancelled": True, "awaited": True}


def _build_registry() -> ValidatorRegistry:
    registry = ValidatorRegistry.__new__(ValidatorRegistry)
    registry.path = Path("unused")
    registry._validators = {
        "validator1": SimpleNamespace(
            validator_id="validator1",
            public_key="pk",
            weight=1.0,
        ),
        "validator2": SimpleNamespace(
            validator_id="validator2",
            public_key="pk",
            weight=1.0,
        ),
        "validator3": SimpleNamespace(
            validator_id="validator3",
            public_key="pk",
            weight=1.0,
        ),
    }
    return registry


def _add_proposal(
    db_session,
    *,
    entry_id: str,
    validator_id: str,
    action: ProposalAction,
    timestamp: datetime,
) -> None:
    db_session.add(
        Proposal(
            proposal_id=f"{validator_id}-{action.value}-{uuid4()}",
            entry_id=entry_id,
            validator_id=validator_id,
            action=action.value,
            confidence=0.9,
            explanation=action.value,
            timestamp=timestamp,
            signature="sig",
        )
    )


@pytest.mark.asyncio
async def test_consensus_decision_helpers_and_metric_empty_case(
    db_session,
) -> None:
    registry = ValidatorRegistry.__new__(ValidatorRegistry)
    registry.path = Path("unused")
    registry._validators = {}
    assert registry.count == 0

    assert (
        consensus_service_module._target_state_for_action(
            LifecycleState.CONFIRMED,
            ProposalAction.RETAIN,
        )
        is None
    )

    entry_id = str(uuid4())
    empty_metric = compute_metric(db_session, entry_id)
    assert empty_metric.vendors_total == 0
    assert empty_metric.coverage_ratio == 0.0

    assert (
        await consensus_service_module._evaluate_quorum(
            db=db_session,
            entry_id=entry_id,
            registry=registry,
            ledger_gateway=SimpleNamespace(
                transition_entry=lambda *_args, **_kwargs: None
            ),
        )
        is None
    )

    entry = Entry(
        id=entry_id,
        observables_json='["ioc-x"]',
        state=LifecycleState.CONFIRMED.value,
        tlp_label="TLP:CLEAR",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(entry)
    db_session.commit()

    assert (
        await consensus_service_module._evaluate_quorum(
            db=db_session,
            entry_id=entry_id,
            registry=registry,
            ledger_gateway=SimpleNamespace(
                transition_entry=lambda *_args, **_kwargs: None
            ),
        )
        is None
    )

    db_session.add(
        Proposal(
            proposal_id=f"proposal-review-{uuid4()}",
            entry_id=entry_id,
            validator_id="validator1",
            action=ProposalAction.REVIEW.value,
            confidence=0.9,
            explanation="review",
            timestamp=entry.updated_at,
            signature="sig",
        )
    )
    db_session.commit()

    review_registry = _build_registry()

    empty_entry_id = str(uuid4())
    empty_entry = Entry(
        id=empty_entry_id,
        observables_json='["ioc-empty"]',
        state=LifecycleState.SUSPECTED.value,
        tlp_label="TLP:CLEAR",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(empty_entry)
    db_session.commit()

    assert (
        await consensus_service_module._evaluate_quorum(
            db=db_session,
            entry_id=empty_entry_id,
            registry=review_registry,
            ledger_gateway=SimpleNamespace(
                transition_entry=lambda *_args, **_kwargs: None
            ),
        )
        is None
    )

    decision = await consensus_service_module._evaluate_quorum(
        db=db_session,
        entry_id=entry_id,
        registry=review_registry,
        ledger_gateway=SimpleNamespace(transition_entry=lambda *_args, **_kwargs: None),
    )
    assert decision is None


@pytest.mark.asyncio
async def test_consensus_quorum_covers_deprecate_review_target_none_and_gateway_error(
    db_session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _build_registry()

    deprecated_entry_id = str(uuid4())
    deprecated_entry = Entry(
        id=deprecated_entry_id,
        observables_json='["ioc-deprecate"]',
        state=LifecycleState.SUSPECTED.value,
        tlp_label="TLP:CLEAR",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(deprecated_entry)
    db_session.commit()

    _add_proposal(
        db_session,
        entry_id=deprecated_entry_id,
        validator_id="validator1",
        action=ProposalAction.DEPRECATE,
        timestamp=deprecated_entry.updated_at,
    )
    _add_proposal(
        db_session,
        entry_id=deprecated_entry_id,
        validator_id="validator2",
        action=ProposalAction.DEPRECATE,
        timestamp=deprecated_entry.updated_at,
    )
    db_session.commit()

    async def ok_transition(*_args, **_kwargs) -> None:
        return None

    deprecate_decision = await consensus_service_module._evaluate_quorum(
        db=db_session,
        entry_id=deprecated_entry_id,
        registry=registry,
        ledger_gateway=SimpleNamespace(transition_entry=ok_transition),
    )
    assert deprecate_decision is not None
    assert deprecate_decision.action == ProposalAction.DEPRECATE

    review_entry_id = str(uuid4())
    review_entry = Entry(
        id=review_entry_id,
        observables_json='["ioc-review"]',
        state=LifecycleState.CONFIRMED.value,
        tlp_label="TLP:CLEAR",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(review_entry)
    db_session.commit()

    _add_proposal(
        db_session,
        entry_id=review_entry_id,
        validator_id="validator1",
        action=ProposalAction.REVIEW,
        timestamp=review_entry.updated_at,
    )
    _add_proposal(
        db_session,
        entry_id=review_entry_id,
        validator_id="validator2",
        action=ProposalAction.REVIEW,
        timestamp=review_entry.updated_at,
    )
    db_session.commit()

    review_decision = await consensus_service_module._evaluate_quorum(
        db=db_session,
        entry_id=review_entry_id,
        registry=registry,
        ledger_gateway=SimpleNamespace(transition_entry=ok_transition),
    )
    assert review_decision is not None
    assert review_decision.action == ProposalAction.REVIEW

    targetless_entry_id = str(uuid4())
    targetless_entry = Entry(
        id=targetless_entry_id,
        observables_json='["ioc-targetless"]',
        state=LifecycleState.SUSPECTED.value,
        tlp_label="TLP:CLEAR",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(targetless_entry)
    db_session.commit()

    _add_proposal(
        db_session,
        entry_id=targetless_entry_id,
        validator_id="validator1",
        action=ProposalAction.PROMOTE,
        timestamp=targetless_entry.updated_at,
    )
    _add_proposal(
        db_session,
        entry_id=targetless_entry_id,
        validator_id="validator2",
        action=ProposalAction.PROMOTE,
        timestamp=targetless_entry.updated_at,
    )
    db_session.commit()

    monkeypatch.setattr(
        consensus_service_module,
        "_target_state_for_action",
        lambda *_args: None,
    )
    assert (
        await consensus_service_module._evaluate_quorum(
            db=db_session,
            entry_id=targetless_entry_id,
            registry=registry,
            ledger_gateway=SimpleNamespace(transition_entry=ok_transition),
        )
        is None
    )
    monkeypatch.undo()

    broken_entry_id = str(uuid4())
    broken_entry = Entry(
        id=broken_entry_id,
        observables_json='["ioc-broken"]',
        state=LifecycleState.SUSPECTED.value,
        tlp_label="TLP:CLEAR",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(broken_entry)
    db_session.commit()

    _add_proposal(
        db_session,
        entry_id=broken_entry_id,
        validator_id="validator1",
        action=ProposalAction.PROMOTE,
        timestamp=broken_entry.updated_at,
    )
    _add_proposal(
        db_session,
        entry_id=broken_entry_id,
        validator_id="validator2",
        action=ProposalAction.PROMOTE,
        timestamp=broken_entry.updated_at,
    )
    db_session.commit()

    async def failing_transition(*_args, **_kwargs) -> None:
        raise httpx.ConnectError("ledger unavailable")

    with pytest.raises(Exception) as exc_info:
        await consensus_service_module._evaluate_quorum(
            db=db_session,
            entry_id=broken_entry_id,
            registry=registry,
            ledger_gateway=SimpleNamespace(transition_entry=failing_transition),
        )

    assert getattr(exc_info.value, "status_code", None) == 502
