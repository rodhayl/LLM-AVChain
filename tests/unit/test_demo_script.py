from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from avchain.crypto.keys import generate_keypair, private_key_to_pem, public_key_to_pem
from avchain.scripts import run_demo as run_demo_module


class DummyResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def json(self) -> object:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class DummyAsyncClient:
    def __init__(self, base_url: str, timeout: float) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self.entry_id = "00000000-0000-0000-0000-000000000001"
        self.entry_state = "suspected"
        self.coverage_posts = 0
        self.feedback_posts = 0
        self.observable = "demo-observable"

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
        _ = headers
        if path == "/ledger/entries":
            observables = json.get("observables")
            if isinstance(observables, list) and observables:
                self.observable = str(observables[0])
            return DummyResponse({"id": self.entry_id})
        if path == "/evidence":
            return DummyResponse(
                {
                    "digest": f"feedback-{self.feedback_posts + 1}",
                    "size": 10,
                    "content_type": "application/json",
                }
            )
        if path.endswith("/feedback"):
            self.feedback_posts += 1
            return DummyResponse({"status": "accepted"})
        if path == "/coverage/reports":
            assert json["entry_id"] == self.entry_id
            self.coverage_posts += 1
            if self.coverage_posts >= 3:
                self.entry_state = "review"
        return DummyResponse({})

    async def get(
        self,
        path: str,
        params: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> DummyResponse:
        _ = headers
        if path == "/docs":
            return DummyResponse({"ok": True})
        if path == "/ledger/entries" and params == {"state": "confirmed"}:
            if self.entry_state == "confirmed":
                return DummyResponse(
                    [
                        {
                            "id": self.entry_id,
                            "observables": [self.observable],
                            "evidence_digests": ["initial"],
                            "state": "confirmed",
                            "attack_techniques": ["T1059"],
                            "tlp_label": "TLP:AMBER",
                            "created_at": "2026-04-09T00:00:00Z",
                            "updated_at": "2026-04-09T00:00:00Z",
                            "history": [],
                        }
                    ]
                )
            return DummyResponse([])
        if path == f"/ledger/entries/{self.entry_id}":
            return DummyResponse(
                {
                    "id": self.entry_id,
                    "observables": [self.observable],
                    "evidence_digests": ["initial", "feedback"],
                    "state": self.entry_state,
                    "attack_techniques": ["T1059"],
                    "tlp_label": "TLP:AMBER",
                    "created_at": "2026-04-09T00:00:00Z",
                    "updated_at": "2026-04-09T00:00:00Z",
                    "history": [],
                }
            )
        if path == f"/evidence/entries/{self.entry_id}":
            item_count = 2 if self.feedback_posts else 1
            return DummyResponse(
                [
                    {
                        "digest": f"digest-{index}",
                        "entry_id": self.entry_id,
                        "content_type": "application/json",
                        "size": 10,
                        "created_at": "2026-04-09T00:00:00Z",
                    }
                    for index in range(item_count)
                ]
            )
        return DummyResponse({})


@pytest.mark.asyncio
async def test_run_demo_uses_registry_relative_key_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_dir = tmp_path / "runtime"
    registry_path = runtime_dir / "validators.yaml"
    generated_in: list[Path] = []
    worker_key_paths: list[Path] = []

    monkeypatch.setattr(
        run_demo_module,
        "get_settings",
        lambda: SimpleNamespace(
            validator_registry_path=str(registry_path),
            ledger_base_url="http://ledger",
            evidence_base_url="http://evidence",
            consensus_base_url="http://consensus",
            coverage_base_url="http://coverage",
            ledger_api_key="ledger-key",
            evidence_api_key="evidence-key",
            consensus_api_key="consensus-key",
            coverage_api_key="coverage-key",
        ),
    )

    def fake_generate_validator_material(output_dir: str | Path) -> Path:
        output_path = Path(output_dir)
        generated_in.append(output_path)
        keys_dir = output_path / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        validators = []
        for validator_id in ("validator1", "validator2"):
            private_key, public_key = generate_keypair()
            (keys_dir / f"{validator_id}_key.pem").write_text(
                private_key_to_pem(private_key),
                encoding="utf-8",
            )
            validators.append(
                {
                    "validator_id": validator_id,
                    "public_key": public_key_to_pem(public_key),
                    "weight": 1.0,
                }
            )
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        registry_path.write_text(
            "validators:\n"
            + "".join(
                [
                    f"- validator_id: {item['validator_id']}\n"
                    f"  public_key: |\n"
                    + "".join(
                        f"    {line}\n" for line in item["public_key"].splitlines()
                    )
                    + f"  weight: {item['weight']}\n"
                    for item in validators
                ]
            ),
            encoding="utf-8",
        )
        return registry_path

    class DummyWorker:
        def __init__(
            self,
            validator_id: str,
            private_key_path: Path,
            **_: object,
        ) -> None:
            _ = validator_id
            worker_key_paths.append(Path(private_key_path))

        async def run_once(self) -> int:
            shared_client.entry_state = (
                "confirmed" if shared_client.entry_state != "review" else "confirmed"
            )
            return 1

    shared_client = DummyAsyncClient(base_url="http://ledger", timeout=10.0)

    monkeypatch.setattr(
        run_demo_module,
        "generate_validator_material",
        fake_generate_validator_material,
    )
    monkeypatch.setattr(run_demo_module, "ValidatorWorker", DummyWorker)
    monkeypatch.setattr(run_demo_module.httpx, "AsyncClient", lambda **_: shared_client)

    await run_demo_module.main()

    assert generated_in == [runtime_dir]
    assert worker_key_paths == [
        runtime_dir / "keys" / "validator1_key.pem",
        runtime_dir / "keys" / "validator2_key.pem",
    ]
    assert shared_client.feedback_posts == 1
    assert shared_client.coverage_posts == 3
    assert shared_client.entry_state == "confirmed"
