from __future__ import annotations

import asyncio
import inspect
import sys
import traceback
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from avchain.config.settings import get_settings
from avchain.crypto.keys import canonicalize, load_private_key, sign_message
from avchain.models.enums import LifecycleState, ProposalAction
from avchain.models.schemas import AnalysisProvenance, Proposal, ThreatEntry
from avchain.utils.helpers import compute_sha256, current_timestamp, derive_proposal_id
from avchain.utils.runtime_status import write_status
from avchain.validator.heuristics import (
    AnalysisStrategy,
    DeterministicHeuristic,
    LMStudioAnalysisStrategy,
)


class ValidatorWorker:
    def __init__(
        self,
        validator_id: str,
        private_key_path: str | Path,
        strategy: AnalysisStrategy | None = None,
        status_name: str | None = None,
        ledger_base_url: str | None = None,
        evidence_base_url: str | None = None,
        consensus_base_url: str | None = None,
        ledger_client: httpx.AsyncClient | None = None,
        evidence_client: httpx.AsyncClient | None = None,
        consensus_client: httpx.AsyncClient | None = None,
    ) -> None:
        settings = get_settings()
        self.validator_id = validator_id
        self.private_key = load_private_key(
            Path(private_key_path).read_text(encoding="utf-8")
        )
        if strategy is not None:
            self.strategy = strategy
        elif settings.llm_provider.lower() == "lmstudio":
            self.strategy = LMStudioAnalysisStrategy()
        else:
            self.strategy = DeterministicHeuristic()
        self.status_name = status_name
        self.poll_interval = settings.poll_interval
        self.ledger_base_url = ledger_base_url or settings.ledger_base_url
        self.evidence_base_url = evidence_base_url or settings.evidence_base_url
        self.consensus_base_url = consensus_base_url or settings.consensus_base_url
        self.ledger_api_key = settings.ledger_api_key
        self.evidence_api_key = settings.evidence_api_key
        self.consensus_api_key = settings.consensus_api_key
        self._ledger_client = ledger_client
        self._evidence_client = evidence_client
        self._consensus_client = consensus_client
        self._processed_states: set[tuple[str, str]] = set()
        self.integrity_failures = 0
        self.processed_entries = 0
        self.proposals_submitted = 0
        self.last_entry_id: str | None = None
        self.last_action: str | None = None
        self.last_error: str | None = None
        self.last_error_at: str | None = None
        self.last_status_error: str | None = None
        self.last_status_error_at: str | None = None
        self._write_status()

    @asynccontextmanager
    async def _client(
        self,
        existing_client: httpx.AsyncClient | None,
        base_url: str,
    ) -> Any:
        if existing_client is not None:
            yield existing_client
            return
        async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
            yield client

    async def poll_entries(self, state: LifecycleState) -> list[ThreatEntry]:
        async with self._client(self._ledger_client, self.ledger_base_url) as client:
            response = await client.get(
                "/ledger/entries",
                params={"state": state.value},
                headers={"Authorization": f"Bearer {self.ledger_api_key}"},
            )
        response.raise_for_status()
        return [ThreatEntry.model_validate(item) for item in response.json()]

    async def fetch_evidence(self, digest: str) -> bytes | None:
        async with self._client(
            self._evidence_client, self.evidence_base_url
        ) as client:
            response = await client.get(
                f"/evidence/{digest}",
                headers={"Authorization": f"Bearer {self.evidence_api_key}"},
            )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        payload = bytes(response.content)
        if compute_sha256(payload) != digest:
            self.integrity_failures += 1
            return None
        return payload

    async def submit_proposal(
        self,
        entry: ThreatEntry,
        action: ProposalAction,
        confidence: float,
        explanation: str,
        provenance: AnalysisProvenance | None = None,
    ) -> bool:
        proposal_timestamp = current_timestamp()
        proposal = Proposal(
            proposal_id=self.compute_proposal_id(
                entry_id=str(entry.id),
                timestamp=proposal_timestamp,
            ),
            entry_id=entry.id,
            validator_id=self.validator_id,
            action=action,
            confidence=confidence,
            explanation=explanation,
            timestamp=proposal_timestamp,
            signature="",
            provenance=provenance,
        )
        unsigned_payload = proposal.model_dump(
            mode="json",
            exclude={"signature"},
            exclude_none=True,
        )
        signature = sign_message(self.private_key, canonicalize(unsigned_payload))
        async with self._client(
            self._consensus_client, self.consensus_base_url
        ) as client:
            response = await client.post(
                "/consensus/proposals",
                json={**unsigned_payload, "signature": signature},
                headers={"Authorization": f"Bearer {self.consensus_api_key}"},
            )
        response.raise_for_status()
        self._processed_states.add((str(entry.id), entry.state.value))
        self.proposals_submitted += 1
        self.last_entry_id = str(entry.id)
        self.last_action = action.value
        self._write_status()
        return True

    async def process_entry(self, entry: ThreatEntry) -> bool:
        processed_key = (str(entry.id), entry.state.value)
        if processed_key in self._processed_states:
            return False
        evidence_payloads = []
        for digest in entry.evidence_digests:
            payload = await self.fetch_evidence(digest)
            if payload is not None:
                evidence_payloads.append(payload)
        analysis_result = self.strategy.analyze(
            observables=entry.observables,
            evidence_data=evidence_payloads,
        )
        if inspect.isawaitable(analysis_result):
            action, confidence, explanation = await analysis_result
        else:
            action, confidence, explanation = analysis_result
        submitted = await self.submit_proposal(
            entry,
            action,
            confidence,
            explanation,
            provenance=getattr(self.strategy, "last_provenance", None),
        )
        if submitted:
            self.processed_entries += 1
            self._write_status()
        return submitted

    async def run_once(self) -> int:
        processed = 0
        for state in (LifecycleState.SUSPECTED, LifecycleState.REVIEW):
            entries = await self.poll_entries(state)
            for entry in entries:
                if await self.process_entry(entry):
                    processed += 1
        self._write_status()
        return processed

    async def run(self) -> None:
        while True:
            try:
                await self.run_once()
                self.last_error = None
                self.last_error_at = None
                self._write_status()
            except httpx.HTTPError as exc:
                self._record_error(exc)
            except Exception as exc:
                self._record_error(exc)
                traceback.print_exc()
            await asyncio.sleep(self.poll_interval)

    def compute_proposal_id(self, entry_id: str, timestamp: datetime) -> str:
        return derive_proposal_id(entry_id, self.validator_id, timestamp)

    def status(self) -> dict[str, Any]:
        provenance = getattr(self.strategy, "last_provenance", None)
        return {
            "worker": "validator",
            "validator_id": self.validator_id,
            "analysis_backend": (
                provenance.analysis_backend if provenance is not None else ""
            ),
            "llm_provider": (
                (provenance.llm_provider or "") if provenance is not None else ""
            ),
            "llm_model": (
                (provenance.llm_model or "") if provenance is not None else ""
            ),
            "prompt_name": (
                (provenance.prompt_name or "") if provenance is not None else ""
            ),
            "prompt_version": (
                (provenance.prompt_version or "") if provenance is not None else ""
            ),
            "poll_interval": self.poll_interval,
            "processed_entries": self.processed_entries,
            "processed_states_cached": len(self._processed_states),
            "proposals_submitted": self.proposals_submitted,
            "integrity_failures": self.integrity_failures,
            "last_entry_id": self.last_entry_id,
            "last_action": self.last_action,
            "last_error": self.last_error or "",
            "last_error_at": self.last_error_at or "",
            "last_status_error": self.last_status_error or "",
            "last_status_error_at": self.last_status_error_at or "",
        }

    def _write_status(self) -> bool:
        if self.status_name is None:
            return False
        try:
            payload = self.status()
            payload.update(last_status_error="", last_status_error_at="")
            write_status(self.status_name, payload)
        except OSError as exc:
            self.last_status_error = f"{type(exc).__name__}: {exc}"
            self.last_status_error_at = current_timestamp().isoformat()
            print(
                f"{self.last_status_error_at} status publication failed "
                f"for {self.status_name}: {self.last_status_error}",
                file=sys.stderr,
                flush=True,
            )
            return False
        self.last_status_error = None
        self.last_status_error_at = None
        return True

    def _record_error(self, exc: Exception) -> None:
        self.last_error = f"{type(exc).__name__}: {exc}"
        self.last_error_at = current_timestamp().isoformat()
        self._write_status()


async def main() -> None:
    validator_id = sys.argv[1] if len(sys.argv) > 1 else "validator1"
    key_path = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else Path("keys") / f"{validator_id}_key.pem"
    )
    worker = ValidatorWorker(
        validator_id=validator_id,
        private_key_path=key_path,
        status_name=validator_id,
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
