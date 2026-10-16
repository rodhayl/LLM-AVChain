from __future__ import annotations

import asyncio
import random
import sys
import traceback
from collections.abc import Mapping, Set
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx

from avchain.config.settings import get_settings
from avchain.coverage.central import CentralCheck
from avchain.crypto.keys import canonicalize, load_private_key, sign_message
from avchain.endpoint import (
    EndpointArtifactClassifier,
    EndpointArtifactState,
    apply_remediation,
    build_feedback_record,
    collect_artifacts,
    collect_external_telemetry,
    collect_native_snapshot_telemetry,
    requires_manual_review,
)
from avchain.endpoint.indicators import ExactIndicatorIndex
from avchain.endpoint.scanner import scan_indexed_artifact
from avchain.llm.client import EndpointLLMClient
from avchain.llm.registry import get_endpoint_llm_client
from avchain.models.schemas import FeedbackRecord, TelemetryEvent, ThreatEntry
from avchain.utils.helpers import current_timestamp, hash_identifiers
from avchain.utils.runtime_status import write_status


class EndpointAgentWorker:
    def __init__(
        self,
        status_name: str | None = None,
        ledger_base_url: str | None = None,
        evidence_base_url: str | None = None,
        ledger_client: httpx.AsyncClient | None = None,
        evidence_client: httpx.AsyncClient | None = None,
        llm_client: EndpointLLMClient | None = None,
        central_demo: bool = False,
    ) -> None:
        settings = get_settings()
        self.central_demo = central_demo
        self._central_snapshot: list[CentralCheck] | None = None
        self.central_sync_error: str | None = None
        self.status_name = status_name
        self.ledger_base_url = ledger_base_url or settings.ledger_base_url
        self.evidence_base_url = evidence_base_url or settings.evidence_base_url
        self.ledger_api_key = settings.ledger_api_key
        self.evidence_api_key = settings.evidence_api_key
        self.poll_interval = settings.poll_interval
        self.telemetry_rate = settings.telemetry_rate
        self.remediation_action = settings.remediation_action
        self.endpoint_scan_enabled = settings.endpoint_scan_enabled
        self.endpoint_watch_dir = (
            Path(settings.endpoint_watch_dir) if settings.endpoint_watch_dir else None
        )
        self.endpoint_quarantine_dir = Path(settings.endpoint_quarantine_dir)
        self.endpoint_max_file_size_bytes = settings.endpoint_max_file_size_bytes
        self.endpoint_process_events_path = settings.endpoint_process_events_path
        self.endpoint_package_events_path = settings.endpoint_package_events_path
        self.endpoint_network_events_path = settings.endpoint_network_events_path
        self.endpoint_native_snapshot_enabled = (
            settings.endpoint_native_snapshot_enabled
        )
        self.endpoint_native_snapshot_limit = settings.endpoint_native_snapshot_limit
        self.endpoint_signing_enabled = settings.endpoint_signing_enabled
        self.endpoint_id = settings.endpoint_id
        self.endpoint_private_key_path = settings.endpoint_private_key_path
        self.confirmed_entries = {}
        self.events_processed = 0
        self.feedback_generated = 0
        self.artifact_detections = 0
        self._ledger_client = ledger_client
        self._evidence_client = evidence_client
        self._llm_client = (
            llm_client if llm_client is not None else get_endpoint_llm_client()
        )
        self._artifact_state = EndpointArtifactState()
        self._artifact_classifier = EndpointArtifactClassifier(
            default_action=self.remediation_action,
            llm_client=self._llm_client,
        )
        self.last_matched_entry_id: str | None = None
        self.last_detection_kind: str | None = None
        self.last_feedback_action: str | None = None
        self.last_error: str | None = None
        self.last_error_at: str | None = None
        self.last_status_error: str | None = None
        self.last_status_error_at: str | None = None
        self._signing_key = self._load_signing_key()
        self._write_status()

    @property
    def confirmed_entries(self) -> Mapping[UUID, frozenset[str]]:
        return self._indicator_index.entries

    @confirmed_entries.setter
    def confirmed_entries(self, entries: Mapping[UUID, Set[str]]) -> None:
        # Replace the catalog and index together; callers cannot mutate a
        # nested set behind the index and leave stale detection knowledge.
        self._indicator_index = ExactIndicatorIndex(entries)

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

    async def refresh_confirmed_entries(self) -> list[ThreatEntry]:
        if self.central_demo:
            return await self._refresh_central_checks()
        async with self._client(self._ledger_client, self.ledger_base_url) as client:
            response = await client.get(
                "/ledger/entries",
                params={"state": "confirmed"},
                headers={"Authorization": f"Bearer {self.ledger_api_key}"},
            )
        response.raise_for_status()
        entries = [ThreatEntry.model_validate(item) for item in response.json()]
        self.confirmed_entries = {entry.id: set(entry.observables) for entry in entries}
        self._write_status()
        return entries

    async def _refresh_central_checks(self) -> list[ThreatEntry]:
        try:
            async with self._client(
                self._ledger_client, self.ledger_base_url
            ) as client:
                response = await client.get(
                    "/ledger/checks",
                    headers={"Authorization": f"Bearer {self.ledger_api_key}"},
                )
            response.raise_for_status()
            snapshot = [CentralCheck.model_validate(item) for item in response.json()]
            self._central_snapshot = snapshot
            self.central_sync_error = None
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            self.central_sync_error = type(exc).__name__
            if self._central_snapshot is None:
                raise
            snapshot = self._central_snapshot
        # A stale disabled view must not outlive a failed synchronization.
        entries = [
            item.entry
            for item in snapshot
            if item.entry.state.value == "confirmed"
            and (item.active or self.central_sync_error)
        ]
        catalog = {entry.id: set(entry.observables) for entry in entries}
        if catalog != self.confirmed_entries:
            self._artifact_state = EndpointArtifactState()
        self.confirmed_entries = catalog
        self._write_status()
        return entries

    def generate_telemetry_event(self) -> TelemetryEvent:
        observable = f"benign-{random.randint(1000, 9999)}"
        return TelemetryEvent(
            observable=observable,
            metadata={
                "file_path": f"C:/Temp/{observable}.bin",
                "process_name": "telemetry-simulator.exe",
                "host": "demo-endpoint",
            },
        )

    async def process_event(self, event: TelemetryEvent) -> FeedbackRecord | None:
        self.events_processed += 1
        match = self._indicator_index.first(event.observable)
        if match is None:
            return None
        entry_id = match[1]
        feedback = FeedbackRecord(
            entry_id=entry_id,
            hashed_identifiers=hash_identifiers(event.metadata),
            action_taken=self.remediation_action,
        )
        await self._submit_feedback(feedback)
        self.feedback_generated += 1
        self.last_matched_entry_id = str(entry_id)
        self.last_feedback_action = feedback.action_taken
        self._write_status()
        return feedback

    async def run_once(self, events: list[TelemetryEvent] | None = None) -> int:
        await self.refresh_confirmed_entries()
        generated_feedback = 0
        generated_feedback += await self.process_local_artifacts()
        event_batch = events if events is not None else self._build_event_batch()
        for event in event_batch:
            if await self.process_event(event) is not None:
                generated_feedback += 1
        self._write_status()
        return generated_feedback

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

    def status(self) -> dict[str, int | str]:
        provenance = getattr(self._artifact_classifier, "last_provenance", None)
        llm_model = getattr(self._llm_client, "endpoint_model", "")
        return {
            "worker": "agent",
            "confirmed_entries_cached": len(self.confirmed_entries),
            "central_demo": int(self.central_demo),
            "central_sync_error": self.central_sync_error or "",
            "events_processed": self.events_processed,
            "feedback_generated": self.feedback_generated,
            "artifact_detections": self.artifact_detections,
            "poll_interval": self.poll_interval,
            "telemetry_rate": self.telemetry_rate,
            "endpoint_scan_enabled": int(self.endpoint_scan_enabled),
            "endpoint_watch_dir": str(self.endpoint_watch_dir or ""),
            "remediation_action": self.remediation_action,
            "external_process_events": int(bool(self.endpoint_process_events_path)),
            "external_package_events": int(bool(self.endpoint_package_events_path)),
            "external_network_events": int(bool(self.endpoint_network_events_path)),
            "native_snapshot_enabled": int(self.endpoint_native_snapshot_enabled),
            "native_snapshot_limit": self.endpoint_native_snapshot_limit,
            "endpoint_signing_enabled": int(self.endpoint_signing_enabled),
            "endpoint_id": self.endpoint_id,
            "llm_enabled": int(self._llm_client is not None),
            "analysis_backend": (
                provenance.analysis_backend if provenance is not None else ""
            ),
            "llm_provider": (
                (provenance.llm_provider or "") if provenance is not None else ""
            ),
            "llm_model": llm_model or "",
            "prompt_name": (
                (provenance.prompt_name or "") if provenance is not None else ""
            ),
            "prompt_version": (
                (provenance.prompt_version or "") if provenance is not None else ""
            ),
            "last_detection_kind": self.last_detection_kind or "",
            "last_feedback_action": self.last_feedback_action or "",
            "last_matched_entry_id": self.last_matched_entry_id or "",
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

    def _build_event_batch(self) -> list[TelemetryEvent]:
        event_batch = collect_external_telemetry(
            self.endpoint_process_events_path,
            self.endpoint_package_events_path,
            self.endpoint_network_events_path,
        )
        if event_batch:
            return event_batch
        if self.endpoint_native_snapshot_enabled:
            event_batch = collect_native_snapshot_telemetry(
                limit=self.endpoint_native_snapshot_limit
            )
            if event_batch:
                return event_batch
        event_batch = [
            self.generate_telemetry_event() for _ in range(self.telemetry_rate)
        ]
        matched_observable = self._matching_observable()
        if matched_observable is not None:
            event_batch.insert(
                0,
                TelemetryEvent(
                    observable=matched_observable,
                    metadata={
                        "file_path": f"C:/Temp/{matched_observable}.bin",
                        "process_name": "telemetry-simulator.exe",
                        "host": "demo-endpoint",
                    },
                ),
            )
        return event_batch

    def _matching_observable(self) -> str | None:
        candidate_observables = sorted(
            observable
            for observables in self.confirmed_entries.values()
            for observable in observables
            if not str(observable).startswith("demo-")
        )
        if not candidate_observables:
            return None
        return candidate_observables[0]

    async def process_local_artifacts(self) -> int:
        if not self.endpoint_scan_enabled or self.endpoint_watch_dir is None:
            return 0
        generated_feedback = 0
        artifacts = collect_artifacts(
            self.endpoint_watch_dir,
            max_file_size_bytes=self.endpoint_max_file_size_bytes,
        )
        for artifact_path in artifacts:
            fingerprint = self._artifact_fingerprint(artifact_path)
            if self._artifact_state.has_processed(fingerprint):
                continue
            match = scan_indexed_artifact(artifact_path, self._indicator_index)
            if match is not None:
                entry_id, scan = match
                decision = await self._artifact_classifier.classify(scan)
                remediation_action = decision.recommended_action
                if requires_manual_review(remediation_action):
                    await self._submit_review_record(
                        entry_id=entry_id,
                        reason=(
                            "Endpoint detection requires analyst approval for "
                            f"{remediation_action}: {decision.explanation}"
                        ),
                    )
                    remediation_action = "alert"
                remediation = apply_remediation(
                    artifact_path,
                    action=remediation_action,
                    quarantine_dir=self.endpoint_quarantine_dir,
                )
                feedback = build_feedback_record(
                    entry_id=entry_id,
                    scan=scan,
                    decision=decision,
                    remediation=remediation,
                    provenance=self._artifact_classifier.last_provenance,
                )
                await self._submit_feedback(feedback)
                self.feedback_generated += 1
                self.artifact_detections += 1
                self.last_matched_entry_id = str(entry_id)
                self.last_detection_kind = scan.detection_kind
                self.last_feedback_action = feedback.action_taken
                if scan.detection_kind == "contextual":
                    self._mark_context_bundle_processed(scan.path.parent, artifacts)
                else:
                    self._artifact_state.mark_processed(fingerprint)
                self._write_status()
                generated_feedback += 1
        return generated_feedback

    def _artifact_fingerprint(self, artifact_path: Path) -> str:
        return f"{artifact_path.resolve()}:{artifact_path.stat().st_mtime_ns}"

    def _mark_context_bundle_processed(
        self,
        bundle_root: Path,
        artifacts: list[Path],
    ) -> None:
        for artifact_path in artifacts:
            try:
                if artifact_path.parent.resolve() != bundle_root.resolve():
                    continue
            except FileNotFoundError:
                continue
            self._artifact_state.mark_processed(
                self._artifact_fingerprint(artifact_path)
            )

    async def _submit_feedback(self, feedback: FeedbackRecord) -> None:
        evidence_payload = feedback.model_dump(mode="json", exclude={"digest"})
        if self._signing_key is not None:
            evidence_payload = self._sign_feedback_payload(evidence_payload)
        async with self._client(
            self._evidence_client, self.evidence_base_url
        ) as client:
            evidence_response = await client.post(
                "/evidence",
                json={"entry_id": str(feedback.entry_id), "data": evidence_payload},
                headers={"Authorization": f"Bearer {self.evidence_api_key}"},
            )
        evidence_response.raise_for_status()
        feedback.digest = evidence_response.json()["digest"]

        async with self._client(self._ledger_client, self.ledger_base_url) as client:
            ledger_response = await client.post(
                f"/ledger/entries/{feedback.entry_id}/feedback",
                json={"digest": feedback.digest},
                headers={"Authorization": f"Bearer {self.ledger_api_key}"},
            )
        ledger_response.raise_for_status()

    async def _submit_review_record(self, *, entry_id: UUID, reason: str) -> None:
        async with self._client(self._ledger_client, self.ledger_base_url) as client:
            review_response = await client.post(
                "/review/records",
                json={
                    "entry_id": str(entry_id),
                    "reason": reason,
                    "requested_by": "endpoint-agent",
                },
                headers={"Authorization": f"Bearer {self.ledger_api_key}"},
            )
        review_response.raise_for_status()

    def _record_error(self, exc: Exception) -> None:
        self.last_error = f"{type(exc).__name__}: {exc}"
        self.last_error_at = current_timestamp().isoformat()
        self._write_status()

    def _load_signing_key(self) -> Any:
        if not self.endpoint_signing_enabled:
            return None
        return load_private_key(
            Path(self.endpoint_private_key_path).read_text(encoding="utf-8")
        )

    def _sign_feedback_payload(
        self,
        evidence_payload: dict[str, Any],
    ) -> dict[str, Any]:
        unsigned_payload = {
            **evidence_payload,
            "endpoint_id": self.endpoint_id,
        }
        signature = sign_message(self._signing_key, canonicalize(unsigned_payload))
        return {
            **unsigned_payload,
            "signature": signature,
        }


async def main() -> None:
    worker = EndpointAgentWorker(status_name="agent")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
