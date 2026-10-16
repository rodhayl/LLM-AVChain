from __future__ import annotations

import json
import sys
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from avchain.config.settings import get_settings, reset_settings_cache
from avchain.consensus.registry import reset_registry_cache
from avchain.consensus.service import (
    LedgerGateway,
)
from avchain.consensus.service import (
    create_app as create_consensus_app,
)
from avchain.coverage.service import (
    ConsensusGateway,
)
from avchain.coverage.service import (
    create_app as create_coverage_app,
)
from avchain.database.core import init_db, reset_database_state, session_scope
from avchain.evidence.service import create_app as create_evidence_app
from avchain.evidence.storage import EvidenceStorage
from avchain.ledger.service import create_app as create_ledger_app
from avchain.models.schemas import StateTransition
from avchain.scripts.generate_keys import generate_validator_material


class ASGILedgerGateway(LedgerGateway):
    def __init__(self, app: Any, api_key: str) -> None:
        self._app = app
        self._api_key = api_key

    async def transition_entry(
        self,
        entry_id: str,
        transition: StateTransition,
    ) -> dict[str, Any]:
        transport = httpx.ASGITransport(app=self._app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://ledger",
        ) as client:
            response = await client.post(
                f"/ledger/entries/{entry_id}/transitions",
                json=transition.model_dump(mode="json"),
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
        response.raise_for_status()
        return dict(response.json())


class ASGIConsensusGateway(ConsensusGateway):
    def __init__(self, app: Any, api_key: str) -> None:
        self._app = app
        self._api_key = api_key

    async def request_review(self, entry_id: str, reason: str) -> dict[str, Any]:
        transport = httpx.ASGITransport(app=self._app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://consensus",
        ) as client:
            response = await client.post(
                "/consensus/review_requests",
                json={"entry_id": entry_id, "reason": reason},
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
        response.raise_for_status()
        return dict(response.json())


@pytest.fixture()
def test_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[dict[str, str]]:
    registry_path = generate_validator_material(output_dir=tmp_path, num_validators=3)
    db_path = tmp_path / "ledger.db"
    evidence_dir = tmp_path / "evidence"
    environment = {
        "DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
        "EVIDENCE_DIR": evidence_dir.as_posix(),
        "VALIDATOR_REGISTRY_PATH": registry_path.as_posix(),
        "LEDGER_API_KEY": "test-ledger-key",
        "EVIDENCE_API_KEY": "test-evidence-key",
        "CONSENSUS_API_KEY": "test-consensus-key",
        "COVERAGE_API_KEY": "test-coverage-key",
        "AGENT_API_KEY": "test-agent-key",
        "LEDGER_BASE_URL": "http://ledger",
        "EVIDENCE_BASE_URL": "http://evidence",
        "CONSENSUS_BASE_URL": "http://consensus",
        "COVERAGE_BASE_URL": "http://coverage",
        "POLL_INTERVAL": "1",
        "TELEMETRY_RATE": "1",
        "SUSPECTED_TIMEOUT_HOURS": "0.001",
        "REVIEW_TIMEOUT_HOURS": "0.001",
    }

    for key, value in environment.items():
        monkeypatch.setenv(key, value)

    reset_settings_cache()
    reset_database_state()
    reset_registry_cache()
    init_db()

    yield environment

    reset_database_state()
    reset_settings_cache()
    reset_registry_cache()


@pytest.fixture()
def storage(test_environment: dict[str, str]) -> EvidenceStorage:
    return EvidenceStorage(test_environment["EVIDENCE_DIR"])


@pytest.fixture()
def app_bundle(
    test_environment: dict[str, str],
    storage: EvidenceStorage,
) -> dict[str, Any]:
    settings = get_settings()
    ledger_app = create_ledger_app(storage=storage)
    evidence_app = create_evidence_app(storage=storage)
    consensus_app = create_consensus_app(
        ledger_gateway=ASGILedgerGateway(ledger_app, settings.ledger_api_key)
    )
    coverage_app = create_coverage_app(
        consensus_gateway=ASGIConsensusGateway(
            consensus_app, settings.consensus_api_key
        )
    )
    return {
        "ledger": ledger_app,
        "evidence": evidence_app,
        "consensus": consensus_app,
        "coverage": coverage_app,
    }


@pytest_asyncio.fixture()
async def ledger_client(app_bundle: dict[str, Any]) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_bundle["ledger"]),
        base_url="http://ledger",
    ) as client:
        yield client


@pytest_asyncio.fixture()
async def evidence_client(
    app_bundle: dict[str, Any],
) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_bundle["evidence"]),
        base_url="http://evidence",
    ) as client:
        yield client


@pytest_asyncio.fixture()
async def consensus_client(
    app_bundle: dict[str, Any],
) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_bundle["consensus"]),
        base_url="http://consensus",
    ) as client:
        yield client


@pytest_asyncio.fixture()
async def coverage_client(
    app_bundle: dict[str, Any],
) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_bundle["coverage"]),
        base_url="http://coverage",
    ) as client:
        yield client


@pytest.fixture()
def auth_headers() -> Callable[[str], dict[str, str]]:
    settings = get_settings()
    mapping = {
        "ledger": settings.ledger_api_key,
        "evidence": settings.evidence_api_key,
        "consensus": settings.consensus_api_key,
        "coverage": settings.coverage_api_key,
    }

    def build(service_name: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {mapping[service_name]}"}

    return build


@pytest.fixture()
def entry_payload() -> dict[str, Any]:
    return _load_fixture("entry_simple.json")


@pytest.fixture()
def coverage_payloads() -> list[dict[str, Any]]:
    return _load_fixture("coverage_reports.json")


@pytest.fixture()
def telemetry_payloads() -> list[dict[str, Any]]:
    return _load_fixture("telemetry_events.json")


@pytest.fixture()
def invalid_proposal_payload() -> dict[str, Any]:
    return _load_fixture("invalid_proposal.json")


@pytest.fixture()
def validator_key_paths(test_environment: dict[str, str]) -> dict[str, Path]:
    keys_dir = Path(test_environment["VALIDATOR_REGISTRY_PATH"]).parent / "keys"
    return {
        "validator1": keys_dir / "validator1_key.pem",
        "validator2": keys_dir / "validator2_key.pem",
        "validator3": keys_dir / "validator3_key.pem",
    }


@pytest.fixture()
def db_session(test_environment: dict[str, str]) -> Iterator[Any]:
    _ = test_environment
    with session_scope() as session:
        yield session


def _load_fixture(filename: str) -> Any:
    fixture_path = Path(__file__).parent / "fixtures" / filename
    return json.loads(fixture_path.read_text(encoding="utf-8"))
