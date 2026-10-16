from __future__ import annotations

import json

import pytest

from avchain.scripts.evaluate_modes import main


@pytest.mark.asyncio
async def test_evaluate_modes_returns_validator_and_endpoint_results(tmp_path) -> None:
    output_path = tmp_path / "evaluation.json"

    results = await main(output_path.as_posix())

    assert "validator" in results
    assert "endpoint" in results
    assert "interoperability" in results
    assert results["interoperability"]["roundtrip"]["observables_match"] is True
    assert json.loads(output_path.read_text(encoding="utf-8")) == results
