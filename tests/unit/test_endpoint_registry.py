from __future__ import annotations

from pathlib import Path

from avchain.endpoint.registry import EndpointRegistry
from avchain.scripts.generate_keys import generate_endpoint_material


def test_generate_endpoint_material_creates_registry_and_keys(tmp_path: Path) -> None:
    registry_path = generate_endpoint_material(tmp_path, endpoint_id="endpoint-a")
    registry = EndpointRegistry(registry_path)

    assert registry_path.exists()
    assert (tmp_path / "keys" / "endpoint-a_key.pem").exists()
    assert (tmp_path / "keys" / "endpoint-a_pub.pem").exists()
    assert registry.is_registered("endpoint-a") is True
    record = registry.get("endpoint-a")
    assert record is not None
    assert record.enabled is True
    assert record.trust_tier == "standard"
    assert registry.list_records()[0].endpoint_id == "endpoint-a"


def test_endpoint_registry_reads_extended_metadata(tmp_path: Path) -> None:
    registry_path = tmp_path / "endpoints.yaml"
    registry_path.write_text(
        "\n".join(
            [
                "endpoints:",
                "  - endpoint_id: endpoint-a",
                "    public_key: demo-key",
                "    enabled: false",
                "    trust_tier: quarantined",
            ]
        ),
        encoding="utf-8",
    )

    registry = EndpointRegistry(registry_path)
    record = registry.get("endpoint-a")

    assert record is not None
    assert record.enabled is False
    assert record.trust_tier == "quarantined"
