"""Two-node safe lab. Real-model mode never silently substitutes rules.

Run: python -m avchain.scripts.run_incident_demo --mode rules --output report.json
Use --mode local_llm --model EXISTING_MODEL for an actual loopback model run.
All services, validator keys and fixture files are ephemeral, isolated lab data.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import sysconfig
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import httpx

from avchain.config.settings import get_settings, reset_settings_cache
from avchain.consensus.registry import get_registry, reset_registry_cache
from avchain.crypto.keys import canonicalize, load_private_key, sign_message
from avchain.database.core import init_db, reset_database_state
from avchain.evidence.storage import EvidenceStorage
from avchain.incident.collector import IncidentCollector
from avchain.incident.executor import LocalApproval, bindings_digest
from avchain.incident.knowledge import package_digest
from avchain.incident.lab import (
    CANARY,
    HOOK_BODY,
    create_lab_fixture,
    draft_lab_package,
    transfer_case,
)
from avchain.incident.models import (
    AnalysisRecord,
    ExecutionReceipt,
    Incident,
    SignedPackage,
    SourceCase,
    TransferCaseContext,
    TransferObservation,
    ValidatorApproval,
)
from avchain.incident.node import IncidentNode, KnowledgeClient
from avchain.incident.triage import IncidentTriage, LocalIncidentModel
from avchain.llm.providers.lmstudio import LMStudioClient
from avchain.models.enums import ProposalAction
from avchain.models.schemas import (
    AnalysisProvenance,
    FeedbackRecord,
    StateTransition,
    ThreatEntry,
)
from avchain.scripts.generate_keys import generate_validator_material
from avchain.utils.helpers import compute_sha256
from avchain.validator.worker import ValidatorWorker


def write_report(path: Path, report: dict[str, Any]) -> None:
    """Replace a checkpoint atomically; never expose a half-written JSON report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(report, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class LabProgress:
    """Only structured, redacted evidence survives an interrupted laboratory.

    Stage checkpoints precede the next operation, including the canary replay
    after a receipt. Model prose, excerpts, exception text and recovery journals
    are not copied into this report. A RUNNING stage is never a successful gate.
    """

    def __init__(self, output: Path | None = None):
        self.output = output
        self.report: dict[str, Any] = {
            "schema_version": 1,
            "status": "in_progress",
            "evidence_detail": "sanitized_checkpoints",
            "stages": dict.fromkeys(
                [
                    "setup",
                    "baseline",
                    "source.observation",
                    "source.analysis",
                    "package.publication",
                    *(
                        f"{node}.{stage}"
                        for node in ("node_a", "node_b")
                        for stage in (
                            "investigation",
                            "rules",
                            "containment",
                            "recovery",
                            "feedback",
                        )
                    ),
                    "benign.investigation",
                    "benign.rules",
                    "benign.unchanged",
                    "final",
                ],
                "NOT_RUN",
            ),
            "nodes": {name: {} for name in ("node_a", "node_b", "benign")},
            "rule_comparison": {},
            "before_egress": {},
            "two_nodes_same_package": None,
        }

    def save(self) -> None:
        if self.output is not None:
            write_report(self.output, self.report)

    def start(self, stage: str) -> None:
        self.report["current_stage"] = stage
        self.report["stages"][stage] = "RUNNING"
        self.save()

    def passed(self, *, exercised: bool = True) -> None:
        self.report["stages"][self.report["current_stage"]] = (
            "PASS" if exercised else "NOT_RUN"
        )
        self.save()

    def failed(self, exc: Exception) -> None:
        stage = self.report.get("current_stage", "setup")
        self.report["stages"][stage] = "FAIL"
        self.report["status"] = "blocked_or_inconclusive"
        self.report.setdefault("failure", {})["stage"] = stage
        # Validation, OS and transport exceptions can embed paths or raw output.
        self.report.update(
            error=self.report["failure"].get(
                "message", "Laboratory stage failed; see structured failure evidence"
            ),
            error_type=type(exc).__name__,
            cause=type(exc.__cause__).__name__ if exc.__cause__ else None,
        )


def incident_checkpoint(incident: Incident) -> dict[str, Any]:
    return incident.model_dump(
        mode="json", exclude={"artifacts": {"__all__": {"excerpt"}}}
    )


def analysis_checkpoint(analysis: AnalysisRecord) -> dict[str, Any]:
    return analysis.model_dump(
        mode="json", exclude={"output": {"explanation", "inferences"}}
    )


def receipt_checkpoint(receipt: ExecutionReceipt) -> dict[str, Any]:
    result = receipt.model_dump(mode="json", exclude={"explanation"})
    result["operations"] = [
        {
            key: value
            for key, value in row.items()
            if key in {"artifact_id", "operation", "before", "after"}
        }
        for row in receipt.operations
    ]
    return result


class LabGateway:
    def __init__(self, client: httpx.AsyncClient, key: str):
        self.client, self.key = client, key

    async def transition_entry(
        self, entry_id: str, transition: StateTransition
    ) -> dict[str, Any]:
        response = await self.client.post(
            f"/ledger/entries/{entry_id}/transitions",
            json=transition.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {self.key}"},
        )
        response.raise_for_status()
        return dict(response.json())


def _fixture_child_env(port: int) -> dict[str, str]:
    """Allow only fixture settings and the current interpreter's bootstrap."""
    child_env = {
        "AVCHAIN_DEMO_PORT": str(port),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for variable in ("SystemRoot", "WINDIR"):
        if value := os.environ.get(variable):
            child_env[variable] = value
    if sys.platform == "linux" and sysconfig.get_config_var("Py_ENABLE_SHARED") == 1:
        base = Path(sys.base_prefix).resolve()
        library_dir = (base / "lib").resolve()
        library_name = sysconfig.get_config_var("LDLIBRARY")
        if (
            isinstance(library_name, str)
            and library_name
            and Path(library_name).name == library_name
        ):
            library = (library_dir / library_name).resolve()
            if (
                library_dir.is_relative_to(base)
                and library.is_relative_to(base)
                and library.is_file()
            ):
                # Never inherit arbitrary loader paths, proxies or credentials.
                child_env["LD_LIBRARY_PATH"] = str(library_dir)
    return child_env


class LoopbackCanary:
    def __init__(self) -> None:
        self.hits: list[str] = []
        self.last_transfer: TransferObservation | None = None
        hits = self.hits

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = min(int(self.headers.get("Content-Length", "0")), 128)
                hits.append(self.rfile.read(length).decode())
                self.send_response(204)
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def replay_owned_fixture(self, root: Path) -> int:
        """Execute only the exact bundled lab script, never arbitrary project code."""
        self.last_transfer = None
        before = len(self.hits)
        manifest = json.loads((root / "package.json").read_text())
        scripts = manifest.get("scripts", {})
        if not scripts:
            return 0
        if len(scripts) != 1:
            raise ValueError("Only owned single-hook fixtures may execute")
        command = next(iter(scripts.values()))
        allowed = {"python3 install_check.py", "python3 setup_check.py"}
        if command not in allowed:
            raise ValueError("Refusing non-fixture command")
        path = root / command.split()[1]
        if not path.exists():
            return 0
        body = path.read_text()
        known = {
            HOOK_BODY,
            "# Held-out filename and lifecycle hook; same safe behavior.\n" + HOOK_BODY,
            "print('ordinary local build')\n",
        }
        if body not in known or path.is_symlink():
            raise ValueError("Refusing modified or non-owned fixture")
        actor_digest = compute_sha256(path.read_bytes())
        subprocess.run(
            [sys.executable, str(path)],
            cwd=root,
            env=_fixture_child_env(self.server.server_port),
            check=True,
            capture_output=True,
            timeout=10,
        )
        if compute_sha256(path.read_bytes()) != actor_digest:
            raise ValueError("Owned replay artifact changed during observation")
        received = self.hits[before:]
        if received:
            self.last_transfer = TransferObservation(
                actor_artifact_id=compute_sha256(str(path.relative_to(root)).encode()),
                actor_digest=actor_digest,
                actor_path_hash=compute_sha256(str(path.resolve()).encode()),
                received_payload_digests=[
                    compute_sha256(value.encode()) for value in received
                ],
            )
        return len(self.hits) - before


async def run_lab(
    workspace: Path,
    triage: IncidentTriage,
    *,
    replay: bool = True,
    progress: LabProgress | None = None,
) -> dict[str, Any]:
    """Run against an isolated database configured by the caller, never production."""
    # Defer service imports until main has isolated paths. Their legacy global
    # app constructors must not use an inherited real EVIDENCE_DIR on CLI import.
    from avchain.consensus.service import create_app as consensus_app
    from avchain.evidence.service import create_app as evidence_app
    from avchain.ledger.service import create_app as ledger_app

    progress = progress if progress is not None else LabProgress()
    progress.start("setup")
    settings = get_settings()
    source_root = Path(__file__).resolve().parents[1]

    def code_digest() -> str:
        return compute_sha256(
            b"".join(p.read_bytes() for p in sorted(source_root.rglob("*.py")))
        )

    before_code_digest = code_digest()
    progress.report["code_digest_before"] = before_code_digest
    storage = EvidenceStorage()
    root_a, root_b, benign = (workspace / n for n in ("node-a", "node-b", "benign"))
    create_lab_fixture(root_a)
    create_lab_fixture(root_b, variant=True)
    # Native control has identical read/POST code; only its concrete grant differs.
    # replay=False remains the historical static-only unit-test mode, not runtime proof.
    create_lab_fixture(benign, benign=not replay)
    benign_before = {p.name: compute_sha256(p.read_bytes()) for p in benign.iterdir()}
    canary = LoopbackCanary() if replay else None
    headers = {"Authorization": f"Bearer {settings.ledger_api_key}"}
    try:
        progress.passed()
        progress.start("baseline")
        before = progress.report["before_egress"]
        case_contexts: dict[str, TransferCaseContext] = {}
        for name, root in (("node_a", root_a), ("node_b", root_b), ("benign", benign)):
            before[name] = canary.replay_owned_fixture(root) if canary else None
            observation = getattr(canary, "last_transfer", None)
            if observation is not None:
                case_contexts[name] = transfer_case(
                    observation, grant_transfer=name == "benign"
                )
            progress.save()
        if canary and (
            before != {"node_a": 1, "node_b": 1, "benign": 1}
            or set(case_contexts) != {"node_a", "node_b", "benign"}
        ):
            progress.report["failure"] = {
                "message": "Owned canary baseline did not pass",
                "failed_checks": ["baseline_egress"],
            }
            raise ValueError("Owned canary baseline did not pass")
        progress.passed(exercised=canary is not None)
        async with httpx.AsyncClient(  # noqa: SIM117
            transport=httpx.ASGITransport(app=ledger_app(storage)),
            base_url="http://ledger",
        ) as ledger:  # Separate context depends on initialized ledger client.
            async with (
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(
                        app=consensus_app(
                            ledger_gateway=LabGateway(ledger, settings.ledger_api_key)
                        )
                    ),
                    base_url="http://consensus",
                ) as consensus,
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=evidence_app(storage)),
                    base_url="http://evidence",
                ) as evidence,
            ):
                progress.start("source.observation")
                observed = IncidentCollector(root_a).collect()
                progress.report["source_incident"] = incident_checkpoint(observed)
                response = await ledger.post(
                    "/ledger/entries",
                    headers=headers,
                    json={
                        "observables": [a.digest for a in observed.artifacts],
                        "evidence": [{"data": observed.model_dump(mode="json")}],
                        "tlp_label": "TLP:CLEAR",
                    },
                )
                response.raise_for_status()
                entry = ThreatEntry.model_validate(response.json())
                draft = draft_lab_package(entry.id, entry.evidence_digests)
                # Keep the exact bounded, prose-free lab draft before inference:
                # a source abstention/error can precede all signed publication.
                progress.report.update(
                    source_knowledge=draft.model_dump(mode="json"),
                    source_knowledge_digest=package_digest(draft),
                    source_knowledge_status="unsigned_draft",
                    source_context=(
                        case_contexts["node_a"].model_dump(mode="json")
                        if "node_a" in case_contexts
                        else None
                    ),
                )
                progress.passed()
                progress.start("source.analysis")
                first_analysis = await triage.analyze(
                    observed, draft, case_context=case_contexts.get("node_a")
                )
                progress.report["source_analysis"] = analysis_checkpoint(first_analysis)
                progress.save()
                if not first_analysis.output.actions:
                    progress.report["failure"] = {
                        "failed_checks": ["no_source_actions"]
                    }
                    raise ValueError(
                        "Node A proposed no applicable actions; inconclusive"
                    )
                progress.passed()
                progress.start("package.publication")
                # Explicit lab validation attests observed safe-fixture behavior.
                # These are deterministic validator votes, not model evaluations.
                keys = Path(settings.validator_registry_path).parent / "keys"
                for validator in ("validator1", "validator2"):
                    worker = ValidatorWorker(
                        validator,
                        keys / f"{validator}_key.pem",
                        ledger_client=ledger,
                        evidence_client=evidence,
                        consensus_client=consensus,
                    )
                    await worker.submit_proposal(
                        entry,
                        ProposalAction.PROMOTE,
                        1.0,
                        "Owned fixture verified by deterministic lab validation",
                    )
                # Preserve the exact analysis-time catalog and observation link.
                # Free model prose is unnecessary for transferring a prior decision.
                source_case = SourceCase(
                    incident_digest=entry.evidence_digests[0],
                    knowledge=draft,
                    analysis=first_analysis.model_copy(
                        update={
                            "output": first_analysis.output.model_copy(
                                update={"explanation": "", "inferences": []}
                            )
                        }
                    ),
                    case_context=case_contexts.get("node_a"),
                )
                progress.report["source_case"] = source_case.model_dump(mode="json")
                response = await evidence.post(
                    "/evidence",
                    headers={"Authorization": f"Bearer {settings.evidence_api_key}"},
                    json={
                        "entry_id": str(entry.id),
                        "data": source_case.model_dump(mode="json"),
                    },
                )
                response.raise_for_status()
                draft = draft.model_copy(
                    update={
                        "evidence_digests": [
                            *draft.evidence_digests,
                            response.json()["digest"],
                        ]
                    }
                )
                payload = canonicalize(
                    {
                        "domain": "avchain-remediation-package-v1",
                        "payload": draft.model_dump(mode="json"),
                    }
                )
                approvals = [
                    ValidatorApproval(
                        validator_id=v,
                        signature=sign_message(
                            load_private_key((keys / f"{v}_key.pem").read_text()),
                            payload,
                        ),
                    )
                    for v in ("validator1", "validator2")
                ]
                signed = SignedPackage(package=draft, approvals=approvals)
                progress.report.update(
                    package=signed.model_dump(mode="json"),
                    package_digest=package_digest(draft),
                    validator_public_keys={
                        v: record.public_key
                        for v in ("validator1", "validator2")
                        if (record := get_registry().get(v)) is not None
                    },
                )
                progress.save()
                response = await ledger.post(
                    "/ledger/remediation/packages",
                    headers=headers,
                    json=signed.model_dump(mode="json"),
                )
                response.raise_for_status()
                progress.passed()
                results = {}
                controls = {}
                for name, root in (
                    ("node_a", root_a),
                    ("node_b", root_b),
                    ("benign", benign),
                ):
                    node_result = progress.report["nodes"][name]
                    progress.start(f"{name}.investigation")
                    knowledge = KnowledgeClient(
                        ledger,
                        settings.ledger_api_key,
                        get_registry(),
                        workspace / "checkpoints" / f"{name}.json",
                        evidence_client=evidence,
                        evidence_api_key=settings.evidence_api_key,
                    )
                    node = IncidentNode(
                        root, workspace / f"recovery-{name}", knowledge, triage
                    )
                    investigation = await node.investigate(
                        draft.package_id, case_context=case_contexts.get(name)
                    )
                    node_result.update(
                        incident=incident_checkpoint(investigation.incident),
                        analysis=analysis_checkpoint(investigation.analysis),
                        package_digest=package_digest(investigation.envelope.package),
                        source_evidence=[
                            {
                                key: case[key]
                                for key in (
                                    "source_case_digest",
                                    "source_incident_digest",
                                )
                            }
                            for case in investigation.knowledge_evidence
                        ],
                        case_context=(
                            investigation.case_context.model_dump(mode="json")
                            if investigation.case_context is not None
                            else None
                        ),
                    )
                    if all(
                        "package_digest" in progress.report["nodes"][n]
                        for n in ("node_a", "node_b")
                    ):
                        progress.report["two_nodes_same_package"] = all(
                            progress.report["nodes"][n]["package_digest"]
                            == package_digest(draft)
                            for n in ("node_a", "node_b")
                        )
                    progress.passed()
                    progress.start(f"{name}.rules")
                    rules = await IncidentTriage().analyze(
                        investigation.incident,
                        investigation.envelope.package,
                        knowledge_evidence=investigation.knowledge_evidence,
                        case_context=investigation.case_context,
                    )
                    controls[name] = rules.model_dump(mode="json")
                    progress.report["rule_comparison"][name] = analysis_checkpoint(
                        rules
                    )
                    progress.passed()
                    if name == "benign":
                        progress.start("benign.unchanged")
                        if investigation.analysis.output.actions:
                            progress.report["failure"] = {
                                "failed_checks": ["authorized_control_actions_proposed"]
                            }
                            raise ValueError(
                                "Benign control received a remediation proposal"
                            )
                        unchanged = benign_before == {
                            p.name: compute_sha256(p.read_bytes())
                            for p in benign.iterdir()
                        }
                        node_result["unchanged"] = unchanged
                        if not unchanged:
                            progress.report["failure"] = {
                                "failed_checks": ["authorized_control_bytes_changed"]
                            }
                            raise ValueError("Authorized control bytes changed")
                        authorized_egress = (
                            canary.replay_owned_fixture(root) if canary else None
                        )
                        node_result["after_egress"] = authorized_egress
                        progress.save()
                        if canary is not None and authorized_egress != 1:
                            progress.report["failure"] = {
                                "failed_checks": ["authorized_control_transfer_not_one"]
                            }
                            raise ValueError("Authorized control transfer changed")
                        results[name] = {
                            "incident": investigation.incident.model_dump(mode="json"),
                            "analysis": investigation.analysis.model_dump(mode="json"),
                            "unchanged": unchanged,
                            "source_evidence": node_result["source_evidence"],
                            "case_context": node_result["case_context"],
                            "after_egress": authorized_egress,
                        }
                        progress.passed()
                        continue
                    approval = LocalApproval(
                        investigation.incident.incident_id,
                        package_digest(draft),
                        bindings_digest(investigation.analysis),
                        compute_sha256(str(root.resolve()).encode()),
                        datetime.now(UTC) + timedelta(minutes=5),
                    )
                    progress.start(f"{name}.containment")
                    receipt = await node.remediate(investigation, approval)
                    node_result["receipt"] = receipt_checkpoint(receipt)
                    progress.save()
                    after = canary.replay_owned_fixture(root) if canary else None
                    node_result["after_egress"] = after
                    failed_checks = []
                    if receipt.status != "applied":
                        failed_checks.append("receipt_not_applied")
                    if canary is not None and after != 0:
                        failed_checks.append("canary_egress_not_zero")
                    progress.save()
                    if failed_checks:
                        progress.report["failure"] = {
                            "message": "Containment did not pass",
                            "failed_checks": failed_checks,
                        }
                        raise ValueError("Containment did not pass")
                    progress.passed()
                    assert node.executor.last_run_id is not None
                    progress.start(f"{name}.recovery")
                    restored = node.executor.restore(node.executor.last_run_id)
                    node_result["recovery"] = receipt_checkpoint(restored)
                    progress.save()
                    after_restore = (
                        canary.replay_owned_fixture(root) if canary else None
                    )
                    node_result["restored_egress"] = after_restore
                    progress.save()
                    failed_checks = []
                    if restored.status != "rolled_back":
                        failed_checks.append("recovery_receipt_not_rolled_back")
                    if canary is not None and after_restore != 1:
                        failed_checks.append("restored_egress_not_one")
                    if failed_checks:
                        progress.report["failure"] = {
                            "message": "Recovery did not restore the owned fixture",
                            "failed_checks": failed_checks,
                        }
                        raise ValueError("Recovery did not restore the owned fixture")
                    progress.passed()
                    # Publish a redacted receipt and feedback using existing APIs.
                    progress.start(f"{name}.feedback")
                    response = await evidence.post(
                        "/evidence",
                        headers={
                            "Authorization": f"Bearer {settings.evidence_api_key}"
                        },
                        json={
                            "entry_id": str(entry.id),
                            "data": {
                                **FeedbackRecord(
                                    entry_id=entry.id,
                                    hashed_identifiers={
                                        "node": compute_sha256(name.encode())
                                    },
                                    action_taken="incident_contained_then_restored",
                                    provenance=AnalysisProvenance(
                                        analysis_backend=investigation.analysis.backend
                                    ),
                                ).model_dump(mode="json"),
                                "node_hash": compute_sha256(name.encode()),
                                "receipt": receipt.model_dump(mode="json"),
                                "recovery": restored.model_dump(mode="json"),
                            },
                        },
                    )
                    response.raise_for_status()
                    feedback_digest = response.json()["digest"]
                    node_result["receipt_evidence_digest"] = feedback_digest
                    progress.save()
                    feedback_response = await ledger.post(
                        f"/ledger/entries/{entry.id}/feedback",
                        headers=headers,
                        json={"digest": feedback_digest},
                    )
                    feedback_response.raise_for_status()
                    progress.passed()
                    results[name] = {
                        "incident": investigation.incident.model_dump(mode="json"),
                        "analysis": investigation.analysis.model_dump(mode="json"),
                        "receipt": receipt.model_dump(mode="json"),
                        "after_egress": after,
                        "recovery": restored.model_dump(mode="json"),
                        "restored_egress": after_restore,
                        "receipt_evidence_digest": response.json()["digest"],
                        "source_evidence": node_result["source_evidence"],
                        "case_context": node_result["case_context"],
                    }
                progress.start("final")
                final_entry = await ledger.get(
                    f"/ledger/entries/{entry.id}", headers=headers
                )
                final_entry.raise_for_status()
                progress.report["two_nodes_same_package"] = all(
                    progress.report["nodes"][name]["package_digest"]
                    == package_digest(draft)
                    for name in ("node_a", "node_b")
                )
                progress.passed()
                progress.report["status"] = "passed"
                progress.save()
                return {
                    "schema_version": 1,
                    "status": "passed",
                    "source_incident": observed.model_dump(mode="json"),
                    "source_analysis": first_analysis.model_dump(mode="json"),
                    "source_knowledge": progress.report["source_knowledge"],
                    "source_knowledge_digest": progress.report[
                        "source_knowledge_digest"
                    ],
                    "source_knowledge_status": "unsigned_draft",
                    "source_context": progress.report["source_context"],
                    "source_case": source_case.model_dump(mode="json"),
                    "ledger_final": final_entry.json(),
                    "validator_public_keys": {
                        v: record.public_key
                        for v in ("validator1", "validator2")
                        if (record := get_registry().get(v)) is not None
                    },
                    "mode": first_analysis.backend,
                    "real_model_executed": first_analysis.backend == "local_llm",
                    "package_digest": package_digest(draft),
                    "package": signed.model_dump(mode="json"),
                    "before_egress": before,
                    "nodes": results,
                    "rule_comparison": controls,
                    "two_nodes_same_package": progress.report["two_nodes_same_package"],
                    "stages": progress.report["stages"],
                    "node_b_code_changed": before_code_digest != code_digest(),
                    "code_digest_before": before_code_digest,
                    "code_digest_after": code_digest(),
                    "network": "owned canary to loopback only"
                    if canary
                    else "not exercised",
                    "canary_values_verified": all(h == CANARY for h in canary.hits)
                    if canary
                    else None,
                }
    except Exception as exc:
        progress.report["code_digest_after"] = code_digest()
        progress.report["node_b_code_changed"] = (
            before_code_digest != progress.report["code_digest_after"]
        )
        progress.failed(exc)
        progress.save()
        raise
    finally:
        if canary:
            canary.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["rules", "local_llm"], required=True)
    parser.add_argument("--model")
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument(
        "--reasoning", choices=["server_default", "off"], default="server_default"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:1234/v1")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 600:
        parser.error("--timeout-seconds must be between 1 and 600")
    if not 1 <= args.max_tokens <= 4096:
        parser.error("--max-tokens must be between 1 and 4096")
    if args.mode == "local_llm" and not args.model:
        parser.error("--model must name an already installed local model")
    if args.reasoning == "off" and args.mode != "local_llm":
        parser.error("--reasoning off requires --mode local_llm")
    with tempfile.TemporaryDirectory(prefix="avchain-owned-lab-") as temporary:
        root = Path(temporary)
        registry = generate_validator_material(root / "trust", num_validators=3)
        overrides = {
            "DATABASE_URL": f"sqlite:///{root / 'ledger.db'}",
            "EVIDENCE_DIR": str(root / "evidence"),
            "VALIDATOR_REGISTRY_PATH": str(registry),
            "LLM_PROVIDER": "disabled",
        }
        previous = {k: os.environ.get(k) for k in overrides}
        os.environ.update(overrides)
        reset_settings_cache()
        reset_registry_cache()
        init_db()
        progress = LabProgress(args.output)
        try:
            triage = IncidentTriage()
            if args.mode == "local_llm":
                client = LMStudioClient(
                    base_url=args.base_url,
                    endpoint_model=args.model,
                    max_retries=0,
                    timeout_seconds=args.timeout_seconds,
                )
                triage = IncidentTriage(
                    LocalIncidentModel(
                        client, max_tokens=args.max_tokens, reasoning=args.reasoning
                    ),
                    model_name=args.model,
                )
            report = asyncio.run(run_lab(root, triage, progress=progress))
            code = 0
        except (
            RuntimeError,
            ValueError,
            httpx.HTTPError,
            OSError,
            subprocess.SubprocessError,
            TimeoutError,
        ) as exc:
            progress.failed(exc)
            report = {
                **progress.report,
                "mode": args.mode,
                "model": args.model,
                "status": "blocked_or_inconclusive",
                "real_model_executed": (
                    True
                    if isinstance(triage.model, LocalIncidentModel)
                    and triage.model.responses_received > 0
                    else None
                    if isinstance(triage.model, LocalIncidentModel)
                    and triage.model.client.completion_responses_received > 0
                    else False
                ),
                "model_http_responses": (
                    triage.model.client.completion_responses_received
                    if isinstance(triage.model, LocalIncidentModel)
                    else 0
                ),
                "validated_model_outputs": (
                    triage.model.responses_received
                    if isinstance(triage.model, LocalIncidentModel)
                    else 0
                ),
                "fallback_used": False,
            }
            code = 2
        finally:
            reset_database_state()
            reset_registry_cache()
            reset_settings_cache()
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
    report["model_configuration"] = (
        {
            "model": args.model,
            "timeout_seconds": args.timeout_seconds,
            "timeout_scope": "per_request_wall_clock",
            "max_tokens": args.max_tokens,
            "response_format": "json_schema",
            "temperature": 0,
            "max_retries": 0,
            "reasoning": (
                "off_requested"
                if args.reasoning == "off"
                else "server_default_unchanged"
            ),
            **({"reasoning_effort": "none"} if args.reasoning == "off" else {}),
        }
        if args.mode == "local_llm"
        else None
    )
    report["model_request_diagnostics"] = (
        triage.model.request_diagnostics
        if isinstance(triage.model, LocalIncidentModel)
        else []
    )
    report["model_reasoning_capability"] = (
        triage.model.reasoning_capability
        if isinstance(triage.model, LocalIncidentModel)
        else None
    )
    write_report(args.output, report)
    print(
        json.dumps(
            {
                "status": "passed" if code == 0 else "blocked_or_inconclusive",
                "report": str(args.output),
            }
        )
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
