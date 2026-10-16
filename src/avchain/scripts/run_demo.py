from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import yaml

from avchain.agent.worker import EndpointAgentWorker
from avchain.config.settings import get_settings
from avchain.crypto.keys import load_private_key, public_key_to_pem
from avchain.models.enums import LifecycleState
from avchain.models.schemas import EvidencePayload, TelemetryEvent, ThreatEntryCreate
from avchain.scripts.generate_keys import generate_validator_material
from avchain.utils.helpers import current_timestamp
from avchain.validator.worker import ValidatorWorker


async def _get_entry(
    ledger_client: httpx.AsyncClient,
    api_key: str,
    entry_id: str,
) -> dict[str, object]:
    response = await ledger_client.get(
        f"/ledger/entries/{entry_id}",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    response.raise_for_status()
    return dict(response.json())


async def _wait_for_entry_state(
    ledger_client: httpx.AsyncClient,
    api_key: str,
    entry_id: str,
    target_state: LifecycleState,
    timeout: float = 20.0,
) -> dict[str, object]:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        entry = await _get_entry(ledger_client, api_key, entry_id)
        if entry["state"] == target_state.value:
            return entry
        await asyncio.sleep(0.5)
    raise TimeoutError(
        f"Timed out waiting for entry {entry_id} -> {target_state.value}"
    )


async def _drive_validators_until_state(
    workers: list[ValidatorWorker],
    ledger_client: httpx.AsyncClient,
    api_key: str,
    entry_id: str,
    target_state: LifecycleState,
    timeout: float = 20.0,
) -> dict[str, object]:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        for worker in workers:
            await worker.run_once()
        entry = await _get_entry(ledger_client, api_key, entry_id)
        if entry["state"] == target_state.value:
            return entry
        await asyncio.sleep(1.0)
    raise TimeoutError(
        f"Timed out driving validators for entry {entry_id} -> {target_state.value}"
    )


async def _wait_for_service_ready(
    client: httpx.AsyncClient,
    path: str = "/docs",
    timeout: float = 30.0,
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    last_error: Exception | None = None
    while asyncio.get_running_loop().time() < deadline:
        try:
            response = await client.get(path)
            response.raise_for_status()
            return
        except httpx.HTTPError as exc:
            last_error = exc
            await asyncio.sleep(0.5)
    raise TimeoutError(f"Timed out waiting for {client.base_url}{path}: {last_error}")


async def _wait_for_validator_material(
    registry_path: Path,
    validator_ids: tuple[str, ...] = ("validator1", "validator2"),
    timeout: float = 30.0,
) -> Path:
    deadline = asyncio.get_running_loop().time() + timeout
    keys_dir = registry_path.parent / "keys"

    while asyncio.get_running_loop().time() < deadline:
        try:
            if not registry_path.exists():
                await asyncio.sleep(0.5)
                continue
            registry = yaml.safe_load(registry_path.read_text(encoding="utf-8")) or {}
            validators = registry.get("validators", [])
            registry_keys = {
                item["validator_id"]: item["public_key"]
                for item in validators
                if isinstance(item, dict)
                and "validator_id" in item
                and "public_key" in item
            }
            for validator_id in validator_ids:
                key_path = keys_dir / f"{validator_id}_key.pem"
                if not key_path.exists():
                    raise FileNotFoundError(str(key_path))
                private_key = load_private_key(key_path.read_text(encoding="utf-8"))
                if registry_keys.get(validator_id) != public_key_to_pem(
                    private_key.public_key()
                ):
                    raise ValueError(
                        f"Validator material not yet stable for {validator_id}"
                    )
            return keys_dir
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            FileNotFoundError,
            yaml.YAMLError,
        ):
            await asyncio.sleep(0.5)

    raise TimeoutError(f"Timed out waiting for validator material at {registry_path}")


async def main() -> None:
    settings = get_settings()
    registry_path = Path(settings.validator_registry_path)
    registry_dir = (
        registry_path.parent if registry_path.parent != Path("") else Path(".")
    )
    if not registry_path.exists():
        generate_validator_material(registry_dir)
    keys_dir = await _wait_for_validator_material(registry_path)
    demo_observable = f"demo-{uuid4().hex}e"
    demo_timeout = max(45.0, float(getattr(settings, "poll_interval", 30)) * 2.0)

    async with (
        httpx.AsyncClient(
            base_url=settings.ledger_base_url,
            timeout=10.0,
        ) as ledger_client,
        httpx.AsyncClient(
            base_url=settings.evidence_base_url,
            timeout=10.0,
        ) as evidence_client,
        httpx.AsyncClient(
            base_url=settings.consensus_base_url,
            timeout=10.0,
        ) as consensus_client,
        httpx.AsyncClient(
            base_url=settings.coverage_base_url,
            timeout=10.0,
        ) as coverage_client,
    ):
        for client in (
            ledger_client,
            evidence_client,
            consensus_client,
            coverage_client,
        ):
            await _wait_for_service_ready(client)

        create_payload = ThreatEntryCreate(
            observables=[demo_observable],
            evidence=[
                EvidencePayload(
                    content_type="application/json",
                    data={"source": "demo", "label": "malicious"},
                )
            ],
            attack_techniques=["T1059"],
            tlp_label="TLP:AMBER",
        )
        response = await ledger_client.post(
            "/ledger/entries",
            json=create_payload.model_dump(mode="json"),
            headers={"Authorization": f"Bearer {settings.ledger_api_key}"},
        )
        response.raise_for_status()
        entry = response.json()
        entry_id = str(entry["id"])

        workers = [
            ValidatorWorker(
                validator_id="validator1",
                private_key_path=keys_dir / "validator1_key.pem",
                status_name=None,
                ledger_client=ledger_client,
                evidence_client=evidence_client,
                consensus_client=consensus_client,
            ),
            ValidatorWorker(
                validator_id="validator2",
                private_key_path=keys_dir / "validator2_key.pem",
                status_name=None,
                ledger_client=ledger_client,
                evidence_client=evidence_client,
                consensus_client=consensus_client,
            ),
        ]
        await _drive_validators_until_state(
            workers=workers,
            ledger_client=ledger_client,
            api_key=settings.ledger_api_key,
            entry_id=entry_id,
            target_state=LifecycleState.CONFIRMED,
            timeout=demo_timeout,
        )

        agent = EndpointAgentWorker(
            status_name=None,
            ledger_client=ledger_client,
            evidence_client=evidence_client,
        )
        feedback_generated = await agent.run_once(
            events=[
                TelemetryEvent(
                    observable=create_payload.observables[0],
                    metadata={
                        "file_path": "C:/Temp/demo-malware.bin",
                        "process_name": "demo-remediation.exe",
                        "host": "demo-endpoint",
                    },
                )
            ]
        )
        if feedback_generated == 0:
            raise RuntimeError("Demo feedback loop did not produce any feedback")
        feedback_entry = await _get_entry(
            ledger_client=ledger_client,
            api_key=settings.ledger_api_key,
            entry_id=entry_id,
        )
        feedback_digests = feedback_entry.get("evidence_digests")
        if not isinstance(feedback_digests, list) or len(feedback_digests) < 2:
            raise RuntimeError(
                "Demo feedback did not attach evidence to the created entry"
            )

        coverage_start = current_timestamp()
        for index, vendor in enumerate(("VendorA", "VendorB", "VendorC")):
            coverage_response = await coverage_client.post(
                "/coverage/reports",
                json={
                    "entry_id": entry_id,
                    "vendor": vendor,
                    "detected": True,
                    "timestamp": (coverage_start + timedelta(minutes=index))
                    .isoformat()
                    .replace("+00:00", "Z"),
                },
                headers={"Authorization": f"Bearer {settings.coverage_api_key}"},
            )
            coverage_response.raise_for_status()
        await _wait_for_entry_state(
            ledger_client=ledger_client,
            api_key=settings.ledger_api_key,
            entry_id=entry_id,
            target_state=LifecycleState.REVIEW,
            timeout=demo_timeout,
        )

        final_entry = await _drive_validators_until_state(
            workers=workers,
            ledger_client=ledger_client,
            api_key=settings.ledger_api_key,
            entry_id=entry_id,
            target_state=LifecycleState.CONFIRMED,
            timeout=demo_timeout,
        )

        print(f"Demo entry created: {entry_id}")
        print(f"Feedback generated: {feedback_generated}")
        print(f"Final state: {final_entry['state']}")


if __name__ == "__main__":
    asyncio.run(main())
