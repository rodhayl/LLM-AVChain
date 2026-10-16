from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

from avchain.consensus.registry import get_registry
from avchain.crypto.keys import canonicalize, load_private_key, sign_message
from avchain.evidence.storage import store_evidence_item
from avchain.incident.collector import IncidentCollector
from avchain.incident.executor import LocalApproval, ScopedExecutor, bindings_digest
from avchain.incident.knowledge import KnowledgeStore, package_digest
from avchain.incident.lab import create_lab_fixture, draft_lab_package
from avchain.incident.models import (
    ActionBinding,
    ActionTemplate,
    PackageRevocation,
    SignedPackage,
    SignedRevocation,
    SourceCase,
    TriageResult,
    ValidatorApproval,
)
from avchain.incident.node import IncidentNode, KnowledgeClient
from avchain.incident.triage import IncidentTriage, LocalIncidentModel, validate_triage
from avchain.ledger.crud import append_transition, create_entry
from avchain.llm.providers.lmstudio import LMStudioClient
from avchain.models.enums import LifecycleState
from avchain.models.schemas import EvidencePayload, ThreatEntryCreate
from avchain.utils.helpers import compute_sha256


def sign_payload(
    payload, validator_key_paths, *, domain="avchain-remediation-package-v1"
):
    message = canonicalize(
        {"domain": domain, "payload": payload.model_dump(mode="json")}
    )
    return [
        ValidatorApproval(
            validator_id=v,
            signature=sign_message(
                load_private_key(validator_key_paths[v].read_text()), message
            ),
        )
        for v in ("validator1", "validator2")
    ]


@pytest.fixture()
def package_setup(db_session, storage, validator_key_paths):
    entry = create_entry(
        db_session,
        ThreatEntryCreate(
            observables=["owned-lab"],
            evidence=[EvidencePayload(data={"source": "owned fixture"})],
        ),
        storage,
    )
    append_transition(
        db_session,
        entry.id,
        LifecycleState.SUSPECTED,
        LifecycleState.CONFIRMED,
        "test-fixture",
    )
    package = draft_lab_package(entry.id, entry.evidence_digests)
    signed = SignedPackage(
        package=package, approvals=sign_payload(package, validator_key_paths)
    )
    return KnowledgeStore(db_session, storage, get_registry()), signed


@pytest.fixture()
def local_fixture(tmp_path):
    root = tmp_path / "project"
    create_lab_fixture(root)
    collector = IncidentCollector(root)
    incident = collector.collect()
    return root, collector, incident


def approval_for(root, incident, package, analysis):
    return LocalApproval(
        incident.incident_id,
        package_digest(package),
        bindings_digest(analysis),
        compute_sha256(str(root.resolve()).encode()),
        datetime.now(UTC) + timedelta(minutes=1),
    )


def test_collector_investigates_without_ioc_and_grounds_content(local_fixture):
    root, collector, incident = local_fixture
    assert len(incident.artifacts) == 3
    script = next(a for a in incident.artifacts if "install_hook_target" in a.tags)
    assert {"canary_read", "loopback_egress"} <= set(script.tags)
    assert '"127.0.0.1"' in script.excerpt
    assert script.digest == compute_sha256(
        collector.paths[script.artifact_id].read_bytes()
    )
    assert str(root) not in incident.model_dump_json()


def test_collector_blocks_symlinks_bad_shapes_and_limits(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("private")
    root = tmp_path / "project"
    root.mkdir()
    (root / "link").symlink_to(outside)
    (root / "package.json").write_text("[]")
    result = IncidentCollector(root).collect()
    assert "non_regular_file_skipped" in result.limitations
    assert "invalid_manifest" in result.limitations
    assert not any(a.excerpt == "private" for a in result.artifacts)
    assert (
        "file_limit_reached"
        in IncidentCollector(root, max_files=1).collect().limitations
    )
    (root / "huge").write_text("x" * 10)
    assert (
        "oversized_file_skipped"
        in IncidentCollector(root, max_bytes=3).collect().limitations
    )
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="Symlink"):
        IncidentCollector(linked_root)


def test_contract_forbids_commands_unknown_ops_and_unversioned_schema():
    with pytest.raises(ValidationError):
        ActionTemplate(action_id="bad", operation="run_shell", required_tags=["file"])
    with pytest.raises(ValidationError):
        TriageResult(
            verdict="suspicious", explanation="x", evidence_ids=[], shell="rm -rf /"
        )
    draft = draft_lab_package(uuid4(), ["a" * 64])
    for changes in (
        {"schema_version": 99},
        {"expires_at": draft.issued_at},
        {"evidence_digests": ["../../secret"]},
        {"actions": draft.actions * 2},
    ):
        with pytest.raises(ValidationError):
            type(draft).model_validate({**draft.model_dump(), **changes})


def test_signed_publication_versions_and_separate_gate(
    package_setup, validator_key_paths
):
    store, signed = package_setup
    store.publish(signed)
    assert store.latest(signed.package.package_id) == signed
    with pytest.raises(ValueError, match="version"):
        store.publish(signed)
    version2 = signed.package.model_copy(update={"version": 2})
    next_signed = SignedPackage(
        package=version2, approvals=sign_payload(version2, validator_key_paths)
    )
    store.publish(next_signed)
    assert store.latest(version2.package_id).package.version == 2
    with pytest.raises(ValueError, match="rollback"):
        store.latest(version2.package_id, minimum_version=3)


@pytest.mark.parametrize(
    "mutation", ["tampered", "single", "duplicate", "unknown", "expired", "future"]
)
def test_reject_unsigned_invalid_or_stale_packages(package_setup, mutation):
    store, signed = package_setup
    if mutation == "tampered":
        signed = signed.model_copy(
            update={"package": signed.package.model_copy(update={"title": "changed"})}
        )
    elif mutation == "single":
        signed = signed.model_copy(update={"approvals": signed.approvals[:1]})
    elif mutation == "duplicate":
        signed = signed.model_copy(update={"approvals": signed.approvals[:1] * 2})
    elif mutation == "unknown":
        signed = signed.model_copy(
            update={
                "approvals": [
                    signed.approvals[0].model_copy(
                        update={"validator_id": "unregistered"}
                    ),
                    signed.approvals[1],
                ]
            }
        )
    else:
        stamp = datetime.now(UTC) + timedelta(hours=2 if mutation == "future" else -2)
        signed = signed.model_copy(
            update={
                "package": signed.package.model_copy(
                    update={
                        "issued_at": stamp,
                        "expires_at": stamp + timedelta(hours=1),
                    }
                )
            }
        )
    with pytest.raises(ValueError):
        store.publish(signed)


def test_evidence_integrity_gate(package_setup):
    store, signed = package_setup
    store.storage._path_for(signed.package.evidence_digests[0]).write_text("tampered")
    with pytest.raises(ValueError, match="tampered"):
        store.publish(signed)


def test_revocation_is_signed_exact_and_durable(package_setup, validator_key_paths):
    store, signed = package_setup
    store.publish(signed)
    revoke = PackageRevocation(
        package_id=signed.package.package_id,
        version=1,
        package_digest=package_digest(signed.package),
        reason="lab withdrawn",
        timestamp=datetime.now(UTC),
    )
    envelope = SignedRevocation(
        revocation=revoke,
        approvals=sign_payload(
            revoke, validator_key_paths, domain="avchain-remediation-revocation-v1"
        ),
    )
    with pytest.raises(ValueError):
        store.revoke(envelope.model_copy(update={"approvals": signed.approvals}))
    store.revoke(envelope)
    with pytest.raises(ValueError, match="revoked"):
        store.latest(signed.package.package_id)
    with pytest.raises(ValueError, match="already revoked"):
        store.revoke(envelope)


@pytest.mark.asyncio
async def test_rules_variant_and_benign_same_knowledge(tmp_path):
    package = draft_lab_package(uuid4(), ["a" * 64])
    for name, variant, benign in (
        ("a", False, False),
        ("b", True, False),
        ("c", False, True),
    ):
        root = tmp_path / name
        create_lab_fixture(root, variant=variant, benign=benign)
        result = await IncidentTriage().analyze(
            IncidentCollector(root).collect(), package
        )
        assert result.backend == "rules"
        assert len(result.output.actions) == (0 if benign else 2)
        assert result.model is None


@pytest.mark.asyncio
async def test_model_grounding_and_explicit_test_provenance(local_fixture):
    _, _, incident = local_fixture
    package = draft_lab_package(uuid4(), ["a" * 64])
    rules = await IncidentTriage().analyze(incident, package)

    class Model:
        async def analyze_incident(self, evidence):
            assert "AVCHAIN_CANARY" in evidence
            return rules.output

    with pytest.raises(ValueError, match="test_double"):
        IncidentTriage(Model())
    record = await IncidentTriage(Model(), test_double=True).analyze(incident, package)
    assert record.backend == "test_double"
    assert record.input_digest == rules.input_digest
    for bad in (
        rules.output.model_copy(update={"evidence_ids": ["fabricated"]}),
        rules.output.model_copy(update={"verdict": "benign"}),
        rules.output.model_copy(
            update={
                "actions": [
                    ActionBinding(
                        action_id="shell", artifact_id=incident.artifacts[0].artifact_id
                    )
                ]
            }
        ),
        rules.output.model_copy(update={"actions": rules.output.actions * 2}),
    ):
        with pytest.raises(ValueError):
            validate_triage(bad, incident, package)


@pytest.mark.asyncio
async def test_model_failure_is_not_reported_as_rules_success(local_fixture):
    _, _, incident = local_fixture

    class FailedModel:
        async def analyze_incident(self, evidence):
            raise RuntimeError("model offline")

    with pytest.raises(RuntimeError, match="offline"):
        await IncidentTriage(FailedModel(), test_double=True).analyze(
            incident, draft_lab_package(uuid4(), ["a" * 64])
        )
    for url in ("https://remote.invalid/v1", "http://127.0.0.1.evil.invalid/v1"):
        with pytest.raises(ValueError, match="loopback"):
            LocalIncidentModel(LMStudioClient(base_url=url))


@pytest.mark.asyncio
async def test_executor_quarantine_disable_and_persistent_restore(
    local_fixture, tmp_path
):
    root, collector, incident = local_fixture
    package = draft_lab_package(uuid4(), ["a" * 64])
    analysis = await IncidentTriage().analyze(incident, package)
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    executor = ScopedExecutor(root, tmp_path / "recovery")
    receipt = executor.apply(
        incident,
        package,
        analysis,
        collector.paths,
        approval_for(root, incident, package, analysis),
    )
    assert receipt.status == "applied"
    assert json.loads((root / "package.json").read_text())["scripts"] == {}
    assert not (root / "install_check.py").exists()
    assert str(root) not in receipt.model_dump_json()
    restored = ScopedExecutor(root, tmp_path / "recovery").restore(executor.last_run_id)
    assert restored.status == "rolled_back"
    assert before == {p.name: p.read_bytes() for p in root.iterdir()}


@pytest.mark.asyncio
async def test_executor_failed_postcheck_restores_exact_bytes(
    local_fixture, tmp_path, monkeypatch
):
    root, collector, incident = local_fixture
    package = draft_lab_package(uuid4(), ["a" * 64])
    analysis = await IncidentTriage().analyze(incident, package)
    executor = ScopedExecutor(root, tmp_path / "recovery")
    before = {p.name: p.read_bytes() for p in root.iterdir()}

    def fail(rows):
        raise ValueError("postcheck failure")

    monkeypatch.setattr(executor, "_postcheck", fail)
    result = executor.apply(
        incident,
        package,
        analysis,
        collector.paths,
        approval_for(root, incident, package, analysis),
    )
    assert result.status == "rolled_back"
    assert before == {p.name: p.read_bytes() for p in root.iterdir()}


@pytest.mark.asyncio
async def test_executor_refuses_stale_approval_and_artifact(local_fixture, tmp_path):
    root, collector, incident = local_fixture
    package = draft_lab_package(uuid4(), ["a" * 64])
    analysis = await IncidentTriage().analyze(incident, package)
    executor = ScopedExecutor(root, tmp_path / "recovery")
    approved = approval_for(root, incident, package, analysis)
    with pytest.raises(ValueError, match="approval"):
        executor.apply(
            incident,
            package,
            analysis,
            collector.paths,
            LocalApproval(
                "wrong",
                approved.package_digest,
                approved.bindings_digest,
                approved.root_hash,
                approved.expires_at,
            ),
        )
    (root / "install_check.py").write_text("changed")
    with pytest.raises(ValueError, match="changed"):
        executor.apply(incident, package, analysis, collector.paths, approved)


@pytest.mark.asyncio
async def test_recovery_refuses_concurrent_overwrite(local_fixture, tmp_path):
    root, collector, incident = local_fixture
    package = draft_lab_package(uuid4(), ["a" * 64])
    analysis = await IncidentTriage().analyze(incident, package)
    executor = ScopedExecutor(root, tmp_path / "recovery")
    executor.apply(
        incident,
        package,
        analysis,
        collector.paths,
        approval_for(root, incident, package, analysis),
    )
    (root / "package.json").write_text("new operator work")
    result = executor.restore(executor.last_run_id)
    assert result.status == "rollback_incomplete"
    assert (root / "package.json").read_text() == "new operator work"
    assert (root / "install_check.py").exists()
    with pytest.raises(ValueError, match="identifier"):
        executor.restore("../outside")


def test_executor_scope_guards(local_fixture, tmp_path):
    root, _, _ = local_fixture
    with pytest.raises(ValueError, match="outside"):
        ScopedExecutor(root, root / "state")
    executor = ScopedExecutor(root, tmp_path / "recovery")
    with pytest.raises(ValueError, match="escapes"):
        executor._safe_path("../outside")
    (root / "unsafe").symlink_to(tmp_path)
    with pytest.raises(ValueError, match="Symlink"):
        executor._safe_path("unsafe/secret", missing=True)


@pytest.mark.asyncio
async def test_api_requires_auth_and_majority(
    package_setup, ledger_client, auth_headers
):
    _, signed = package_setup
    response = await ledger_client.post(
        "/ledger/remediation/packages", json=signed.model_dump(mode="json")
    )
    assert response.status_code in (401, 403)
    invalid = signed.model_copy(update={"approvals": signed.approvals[:1]})
    response = await ledger_client.post(
        "/ledger/remediation/packages",
        headers=auth_headers("ledger"),
        json=invalid.model_dump(mode="json"),
    )
    assert response.status_code == 400
    response = await ledger_client.post(
        "/ledger/remediation/packages",
        headers=auth_headers("ledger"),
        json=signed.model_dump(mode="json"),
    )
    assert response.status_code == 201


@pytest.mark.asyncio
async def test_node_rechecks_revocation_before_write(
    package_setup,
    local_fixture,
    ledger_client,
    evidence_client,
    auth_headers,
    validator_key_paths,
    tmp_path,
):
    store, signed = package_setup
    root, _, incident = local_fixture
    observation = store_evidence_item(
        store.db,
        store.storage,
        str(signed.package.entry_id),
        canonicalize(incident.model_dump(mode="json")),
        "application/json",
    )
    draft = signed.package.model_copy(update={"evidence_digests": [observation.digest]})
    analysis = await IncidentTriage().analyze(incident, draft)
    case = SourceCase(
        incident_digest=observation.digest,
        knowledge=draft,
        analysis=analysis.model_copy(
            update={
                "output": analysis.output.model_copy(
                    update={"explanation": "", "inferences": []}
                )
            }
        ),
    )
    case_item = store_evidence_item(
        store.db,
        store.storage,
        str(draft.entry_id),
        canonicalize(case.model_dump(mode="json")),
        "application/json",
    )
    package = draft.model_copy(
        update={"evidence_digests": [observation.digest, case_item.digest]}
    )
    signed = SignedPackage(
        package=package, approvals=sign_payload(package, validator_key_paths)
    )
    store.publish(signed)
    client = KnowledgeClient(
        ledger_client,
        auth_headers("ledger")["Authorization"].split()[1],
        get_registry(),
        tmp_path / "checkpoint.json",
        evidence_client=evidence_client,
        evidence_api_key=auth_headers("evidence")["Authorization"].split()[1],
    )
    node = IncidentNode(root, tmp_path / "recovery", client, IncidentTriage())
    investigation = await node.investigate(signed.package.package_id)
    revoke = PackageRevocation(
        package_id=signed.package.package_id,
        version=1,
        package_digest=package_digest(signed.package),
        reason="withdrawn",
        timestamp=datetime.now(UTC),
    )
    store.revoke(
        SignedRevocation(
            revocation=revoke,
            approvals=sign_payload(
                revoke, validator_key_paths, domain="avchain-remediation-revocation-v1"
            ),
        )
    )
    with pytest.raises(httpx.HTTPStatusError):
        await node.remediate(
            investigation,
            approval_for(
                root, investigation.incident, signed.package, investigation.analysis
            ),
        )
    assert (root / "install_check.py").exists()


@pytest.mark.asyncio
async def test_live_client_transport_contract_is_not_real_inference(local_fixture):
    _, _, incident = local_fixture
    package = draft_lab_package(uuid4(), ["a" * 64])
    rules = await IncidentTriage().analyze(incident, package)

    def handler(request):
        body = json.loads(request.content)
        assert body["temperature"] == 0
        assert "UNTRUSTED DATA" in body["messages"][0]["content"]
        assert "AVCHAIN_CANARY" in body["messages"][1]["content"]
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": rules.output.model_dump_json()}}]
            },
        )

    model = LocalIncidentModel(LMStudioClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(ValueError, match="test_double"):
        IncidentTriage(model)
    result = await IncidentTriage(model, test_double=True).analyze(incident, package)
    assert result.backend == "test_double"
    assert model.responses_received == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("manifest_mode", [0o600, 0o640, 0o644])
async def test_executor_preserves_private_and_executable_modes(
    local_fixture, tmp_path, manifest_mode
):
    import stat

    root, collector, incident = local_fixture
    (root / "package.json").chmod(manifest_mode)
    (root / "install_check.py").chmod(0o755)
    # Windows chmod/stat expose the read-only attribute, not POSIX ACL privacy.
    observed_manifest = stat.S_IMODE((root / "package.json").stat().st_mode)
    observed_script = stat.S_IMODE((root / "install_check.py").stat().st_mode)
    if os.name != "nt":
        assert observed_manifest == manifest_mode
        assert observed_script == 0o755
    package = draft_lab_package(uuid4(), ["a" * 64])
    analysis = await IncidentTriage().analyze(incident, package)
    executor = ScopedExecutor(root, tmp_path / "recovery")
    applied = executor.apply(
        incident,
        package,
        analysis,
        collector.paths,
        approval_for(root, incident, package, analysis),
    )
    assert applied.status == "applied"
    assert stat.S_IMODE((root / "package.json").stat().st_mode) == observed_manifest
    restored = executor.restore(executor.last_run_id)
    assert restored.status == "rolled_back"
    assert stat.S_IMODE((root / "package.json").stat().st_mode) == observed_manifest
    assert stat.S_IMODE((root / "install_check.py").stat().st_mode) == observed_script


@pytest.mark.asyncio
async def test_local_model_transport_ignores_proxy_environment(monkeypatch):
    import avchain.llm.providers.lmstudio as provider

    observed = {}
    real_client = httpx.AsyncClient

    def client_factory(**kwargs):
        observed.update(kwargs)
        return real_client(**kwargs)

    monkeypatch.setenv("HTTP_PROXY", "http://untrusted-proxy.invalid:8080")
    monkeypatch.setattr(provider.httpx, "AsyncClient", client_factory)
    model = LocalIncidentModel(
        LMStudioClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    json={
                        "choices": [
                            {
                                "message": {
                                    "content": json.dumps(
                                        {
                                            "verdict": "uncertain",
                                            "explanation": "no observation",
                                            "evidence_ids": [],
                                        }
                                    )
                                }
                            }
                        ]
                    },
                )
            )
        )
    )
    await model.analyze_incident("owned fixture only")
    assert observed["trust_env"] is False


@pytest.mark.asyncio
async def test_recovery_refuses_fifo_without_reading(local_fixture, tmp_path):
    import os

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO available only on POSIX")
    root, collector, incident = local_fixture
    package = draft_lab_package(uuid4(), ["a" * 64])
    analysis = await IncidentTriage().analyze(incident, package)
    executor = ScopedExecutor(root, tmp_path / "recovery")
    executor.apply(
        incident,
        package,
        analysis,
        collector.paths,
        approval_for(root, incident, package, analysis),
    )
    os.mkfifo(root / "install_check.py")
    assert executor.restore(executor.last_run_id).status == "rollback_incomplete"
    assert not (root / "install_check.py").is_file()


@pytest.mark.asyncio
async def test_concurrent_delayed_feed_cannot_downgrade_checkpoint(
    package_setup, validator_key_paths, tmp_path
):
    import asyncio

    _, signed = package_setup
    v2 = signed.package.model_copy(update={"version": 2})
    newer = SignedPackage(package=v2, approvals=sign_payload(v2, validator_key_paths))
    old_started, release_old = asyncio.Event(), asyncio.Event()
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            old_started.set()
            await release_old.wait()
            return httpx.Response(200, json=signed.model_dump(mode="json"))
        return httpx.Response(200, json=newer.model_dump(mode="json"))

    checkpoint = tmp_path / "checkpoint.json"
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://ledger"
    ) as http:
        first = KnowledgeClient(http, "lab", get_registry(), checkpoint)
        second = KnowledgeClient(http, "lab", get_registry(), checkpoint)
        delayed = asyncio.create_task(first.fetch(signed.package.package_id))
        await old_started.wait()
        await second.fetch(signed.package.package_id)
        release_old.set()
        with pytest.raises(ValueError, match="Replayed"):
            await delayed
    assert json.loads(checkpoint.read_text())[signed.package.package_id]["version"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"choices": []},
        {"choices": [None]},
        {"choices": [{"message": None}]},
        {"choices": [{"message": {"content": {}}}]},
        {"choices": [{"finish_reason": "length", "message": {"content": "{}"}}]},
        [],
    ],
)
async def test_local_model_malformed_or_truncated_reply_fails_closed(payload):
    client = LMStudioClient(
        max_retries=0,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=payload)
        ),
    )
    with pytest.raises(RuntimeError, match="LM Studio request failed"):
        await LocalIncidentModel(client).analyze_incident("owned fixture")


@pytest.mark.asyncio
async def test_incident_model_sends_schema_and_bounded_output():
    def handler(request):
        body = json.loads(request.content)
        assert body["max_tokens"] == 2048
        schema = body["response_format"]
        assert schema["type"] == "json_schema"
        assert schema["json_schema"]["strict"] is True
        assert schema["json_schema"]["schema"]["additionalProperties"] is False
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps(
                                {
                                    "verdict": "uncertain",
                                    "explanation": "none",
                                    "evidence_ids": [],
                                }
                            )
                        },
                    }
                ]
            },
        )

    await LocalIncidentModel(
        LMStudioClient(transport=httpx.MockTransport(handler))
    ).analyze_incident("owned fixture")


@pytest.mark.asyncio
async def test_malformed_json_counts_http_response_but_not_valid_output():
    client = LMStudioClient(
        max_retries=0,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"choices": [{"message": {"content": "not json"}}]}
            )
        ),
    )
    model = LocalIncidentModel(client)
    with pytest.raises(RuntimeError):
        await model.analyze_incident("owned fixture")
    assert client.completion_responses_received == 1
    assert model.responses_received == 0


@pytest.mark.parametrize("max_tokens", [0, -1, 4097, True, 3072.5, "3072"])
def test_incident_model_rejects_invalid_output_budget(max_tokens):
    with pytest.raises(ValueError, match="between 1 and 4096"):
        LocalIncidentModel(LMStudioClient(), max_tokens=max_tokens)


@pytest.mark.asyncio
@pytest.mark.parametrize("max_tokens", [1, 2048, 3072, 4096])
async def test_incident_model_explicit_budget_preserves_transport_controls(max_tokens):
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        assert body["max_tokens"] == max_tokens
        assert body["temperature"] == 0
        assert body["response_format"]["json_schema"]["strict"] is True
        assert "reasoning_effort" not in body
        assert "reasoning" not in body
        return httpx.Response(
            200,
            json={
                "choices": [{"finish_reason": "length", "message": {"content": "{}"}}]
            },
        )

    client = LMStudioClient(max_retries=0, transport=httpx.MockTransport(handler))
    with pytest.raises(RuntimeError):
        await LocalIncidentModel(client, max_tokens=max_tokens).analyze_incident("data")
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_truncated_reply_retains_only_sanitized_diagnostics():
    body = {
        "id": "private-response-id",
        "choices": [
            {
                "finish_reason": "length",
                "message": {
                    "content": '{"secret": "unfinished',
                    "reasoning": "private reasoning",
                    "reasoning_content": "other private reasoning",
                },
            }
        ],
        "usage": {
            "prompt_tokens": 1200,
            "completion_tokens": 3072,
            "total_tokens": 4272,
            "unrecognized": "secret",
            "completion_tokens_details": {"reasoning_tokens": 3000, "secret": "hidden"},
        },
    }
    model = LocalIncidentModel(
        LMStudioClient(
            max_retries=0,
            timeout_seconds=300,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json=body)
            ),
        ),
        max_tokens=3072,
    )
    with pytest.raises(RuntimeError):
        await model.analyze_incident("private evidence")
    assert model.responses_received == 0
    assert model.client.completion_responses_received == 1
    diagnostics = model.request_diagnostics[0]
    assert diagnostics["max_tokens"] == 3072
    assert diagnostics["timeout_seconds"] == 300
    assert diagnostics["finish_reason"] == "length"
    assert diagnostics["http_status"] == 200
    assert diagnostics["structured_output_validated"] is False
    assert diagnostics["usage"] == {
        "prompt_tokens": 1200,
        "completion_tokens": 3072,
        "total_tokens": 4272,
        "reasoning_tokens": 3000,
    }
    assert diagnostics["content_utf8_bytes"] == len(
        body["choices"][0]["message"]["content"]
    )
    assert diagnostics["reasoning_utf8_bytes"] == {
        "reasoning": len("private reasoning"),
        "reasoning_content": len("other private reasoning"),
    }
    assert diagnostics["elapsed_seconds"] >= 0
    serialized = json.dumps(diagnostics)
    assert "private" not in serialized
    assert "secret" not in serialized
    assert "hidden" not in serialized


@pytest.mark.asyncio
async def test_invalid_usage_fields_are_not_copied_to_diagnostics():
    body = {
        "choices": [
            {"finish_reason": {"secret": "hidden"}, "message": {"content": "{}"}}
        ],
        "usage": {
            "prompt_tokens": True,
            "completion_tokens": -1,
            "total_tokens": "secret",
            "completion_tokens_details": {"reasoning_tokens": "private"},
        },
    }
    client = LMStudioClient(
        max_retries=0,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=body)),
    )
    with pytest.raises(ValueError):
        await LocalIncidentModel(client).analyze_incident("data")
    assert client.last_completion_diagnostics["usage"] == {}
    assert client.last_completion_diagnostics["finish_reason"] == "unrecognized"
    assert "secret" not in json.dumps(client.last_completion_diagnostics)


@pytest.mark.asyncio
async def test_incident_model_wall_deadline_fails_closed_without_retry():
    import asyncio

    calls = []

    async def handler(request):
        calls.append(request)
        await asyncio.sleep(1)
        return httpx.Response(200, json={})

    client = LMStudioClient(
        max_retries=0,
        timeout_seconds=0.01,
        transport=httpx.MockTransport(handler),
    )
    model = LocalIncidentModel(client, max_tokens=3072)
    with pytest.raises(RuntimeError) as error:
        await model.analyze_incident("data")
    assert isinstance(error.value.__cause__, TimeoutError)
    assert len(calls) == 1
    assert model.responses_received == 0
    assert client.completion_responses_received == 0
    assert model.request_diagnostics[0]["error_type"] == "TimeoutError"
    assert model.request_diagnostics[0]["structured_output_validated"] is False


@pytest.mark.parametrize("requested_mode", [0o400, 0o600])
def test_persist_bytes_preserves_observable_read_only_flag(tmp_path, requested_mode):
    import stat

    probe = tmp_path / "probe"
    probe.write_bytes(b"baseline")
    probe.chmod(requested_mode)
    observed = stat.S_IMODE(probe.stat().st_mode)
    output = tmp_path / "persisted"
    try:
        ScopedExecutor._persist_bytes(
            output, b"owned laboratory fixture", mode=observed
        )
        assert output.read_bytes() == b"owned laboratory fixture"
        assert stat.S_IMODE(output.stat().st_mode) == observed
        assert bool(output.stat().st_mode & stat.S_IWRITE) == bool(
            requested_mode & stat.S_IWRITE
        )
    finally:
        # Only temporary owned fixtures; allow normal Windows pytest cleanup.
        probe.chmod(0o600)
        if output.exists():
            output.chmod(0o600)
