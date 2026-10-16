from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from avchain.consensus.registry import ValidatorRegistry
from avchain.incident.cases import source_context
from avchain.incident.collector import IncidentCollector
from avchain.incident.executor import LocalApproval, ScopedExecutor
from avchain.incident.knowledge import package_digest, verify_package
from avchain.incident.models import (
    AnalysisRecord,
    ExecutionReceipt,
    Incident,
    SignedPackage,
    TransferCaseContext,
)
from avchain.incident.triage import IncidentTriage
from avchain.utils.helpers import compute_sha256

MAX_EVIDENCE_BYTES = 65536
MAX_TOTAL_EVIDENCE_BYTES = 131072


class KnowledgeClient:
    """Validate signed packages and persist the highest seen version per node.

    An authenticated, trusted transport is still required for prompt revocation;
    signatures alone cannot prove the absence of a withheld newer/revoked version.
    Every execution refreshes online and fails closed on errors.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        api_key: str,
        registry: ValidatorRegistry,
        checkpoint: Path,
        *,
        evidence_client: httpx.AsyncClient | None = None,
        evidence_api_key: str | None = None,
    ):
        self.client, self.api_key, self.registry = client, api_key, registry
        self.checkpoint = checkpoint
        self.evidence_client, self.evidence_api_key = evidence_client, evidence_api_key

    async def fetch_evidence(self, envelope: SignedPackage) -> list[dict[str, Any]]:
        """Fetch only signed digests via the configured authenticated service.

        Stream bounds apply before JSON parsing. No redirects, URL references,
        new credentials, raw log retrieval or fallback to a context-free decision.
        """
        verify_package(envelope, self.registry)
        if self.evidence_client is None or not self.evidence_api_key:
            raise ValueError("Authenticated source evidence client is required")
        digests = envelope.package.evidence_digests
        if len(set(digests)) != len(digests):
            raise ValueError("Duplicate source evidence digests")
        payloads: dict[str, bytes] = {}
        total = 0
        async with asyncio.timeout(30):
            for digest in digests:
                async with self.evidence_client.stream(
                    "GET",
                    f"/evidence/{digest}",
                    headers={"Authorization": f"Bearer {self.evidence_api_key}"},
                    follow_redirects=False,
                    timeout=10,
                ) as response:
                    response.raise_for_status()
                    if response.headers.get("content-type", "").split(";")[0] != (
                        "application/json"
                    ):
                        raise ValueError("Unsupported source evidence content type")
                    length = response.headers.get("content-length")
                    if length and int(length) > min(
                        MAX_EVIDENCE_BYTES, MAX_TOTAL_EVIDENCE_BYTES - total
                    ):
                        raise ValueError("Source evidence size budget exceeded")
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if (
                            len(raw) + len(chunk) > MAX_EVIDENCE_BYTES
                            or total > MAX_TOTAL_EVIDENCE_BYTES
                        ):
                            raise ValueError("Source evidence size budget exceeded")
                        raw.extend(chunk)
                    if compute_sha256(bytes(raw)) != digest:
                        raise ValueError("Source evidence digest mismatch")
                    payloads[digest] = bytes(raw)
        return source_context(payloads, envelope.package)

    async def fetch(self, package_id: str) -> SignedPackage:
        checkpoints = (
            json.loads(self.checkpoint.read_text()) if self.checkpoint.exists() else {}
        )
        previous = checkpoints.get(package_id, {})
        response = await self.client.get(
            f"/ledger/remediation/packages/{package_id}",
            params={"minimum_version": previous.get("version", 1)},
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        response.raise_for_status()
        envelope = SignedPackage.model_validate(response.json())
        if envelope.package.package_id != package_id:
            raise ValueError("Feed returned a different package")
        verify_package(envelope, self.registry)
        # Re-read after the network await: another client in this event loop may
        # have accepted a newer package while this response was in flight.
        # Comparison + write below contain no await. One process owns a checkpoint.
        checkpoints = (
            json.loads(self.checkpoint.read_text()) if self.checkpoint.exists() else {}
        )
        previous = checkpoints.get(package_id, {})
        version, digest = envelope.package.version, package_digest(envelope.package)
        if version < previous.get("version", 1) or (
            version == previous.get("version") and digest != previous.get("digest")
        ):
            raise ValueError("Replayed or equivocated package version")
        checkpoints[package_id] = {"version": version, "digest": digest}
        self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.checkpoint.with_suffix(".tmp")
        temporary.write_text(json.dumps(checkpoints, sort_keys=True))
        temporary.replace(self.checkpoint)
        return envelope


@dataclass(frozen=True)
class Investigation:
    incident: Incident
    envelope: SignedPackage
    analysis: AnalysisRecord
    knowledge_evidence: list[dict[str, Any]]
    case_context: TransferCaseContext | None = None


class IncidentNode:
    def __init__(
        self,
        root: Path,
        state_dir: Path,
        knowledge: KnowledgeClient,
        triage: IncidentTriage,
    ):
        self.collector = IncidentCollector(root)
        self.executor = ScopedExecutor(root, state_dir)
        self.knowledge, self.triage = knowledge, triage

    async def investigate(
        self, package_id: str, *, case_context: TransferCaseContext | None = None
    ) -> Investigation:
        # Observation is independent of known indicators and precedes retrieval.
        incident = self.collector.collect()
        envelope = await self.knowledge.fetch(package_id)
        context = await self.knowledge.fetch_evidence(envelope)
        analysis = await self.triage.analyze(
            incident,
            envelope.package,
            knowledge_evidence=context,
            case_context=case_context,
        )
        return Investigation(incident, envelope, analysis, context, case_context)

    async def remediate(
        self, investigation: Investigation, approval: LocalApproval
    ) -> ExecutionReceipt:
        current = await self.knowledge.fetch(investigation.envelope.package.package_id)
        if package_digest(current.package) != package_digest(
            investigation.envelope.package
        ):
            raise ValueError("Knowledge changed; investigate and approve again")
        return self.executor.apply(
            investigation.incident,
            current.package,
            investigation.analysis,
            self.collector.paths,
            approval,
        )
