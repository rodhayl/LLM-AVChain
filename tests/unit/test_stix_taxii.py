from __future__ import annotations

import httpx
import pytest

from avchain.models.enums import LifecycleState
from avchain.models.schemas import ThreatEntry
from avchain.stix_taxii import (
    TaxiiClient,
    build_stix_bundle,
    import_stix_bundle,
    preview_stix_bundle,
    validate_stix_bundle,
)


def test_build_stix_bundle_exports_indicator_and_attack_patterns() -> None:
    entry = ThreatEntry(
        observables=[
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbddc1c5d08201b19a24a",
            "behavior:powershell-download",
        ],
        evidence_digests=["abc123"],
        state=LifecycleState.CONFIRMED,
        attack_techniques=["T1059"],
        tlp_label="TLP:AMBER",
    )

    bundle = build_stix_bundle(entry)
    validate_stix_bundle(bundle)

    indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")
    attack_patterns = [
        obj for obj in bundle["objects"] if obj["type"] == "attack-pattern"
    ]

    assert "file:hashes.'SHA-256'" in indicator["pattern"]
    assert indicator["object_marking_refs"] == [
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    ]
    assert [item["name"] for item in attack_patterns] == ["T1059"]


@pytest.mark.asyncio
async def test_taxii_client_publishes_bundle_to_collection() -> None:
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("Authorization")
        captured["payload"] = request.read().decode("utf-8")
        return httpx.Response(202, json={"status": "complete"})

    entry = ThreatEntry(
        observables=["example.org"],
        state=LifecycleState.CONFIRMED,
    )
    bundle = build_stix_bundle(entry)
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(
        base_url="http://taxii.example",
        transport=transport,
    ) as client:
        response = await TaxiiClient(
            base_url="http://taxii.example",
            api_key="taxii-key",
            client=client,
        ).publish_bundle(collection_id="demo", bundle=bundle)

    assert response == {"status": "complete"}
    assert captured["url"] == "http://taxii.example/taxii2/collections/demo/objects/"
    assert captured["auth"] == "Bearer taxii-key"


@pytest.mark.asyncio
async def test_taxii_client_fetches_collection_objects() -> None:
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("Authorization")
        return httpx.Response(
            200,
            json={
                "type": "bundle",
                "id": "bundle--demo",
                "spec_version": "2.1",
                "objects": [
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": "indicator--demo",
                        "pattern_type": "stix",
                        "pattern": "[domain-name:value = 'example.org']",
                    }
                ],
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(
        base_url="http://taxii.example",
        transport=transport,
    ) as client:
        response = await TaxiiClient(
            base_url="http://taxii.example",
            api_key="taxii-key",
            client=client,
        ).fetch_collection_objects(collection_id="demo")

    assert response["type"] == "bundle"
    assert captured["url"] == "http://taxii.example/taxii2/collections/demo/objects/"
    assert captured["auth"] == "Bearer taxii-key"


def test_preview_stix_bundle_round_trips_exported_indicator() -> None:
    entry = ThreatEntry(
        observables=["example.org", "behavior:powershell-download"],
        state=LifecycleState.CONFIRMED,
        attack_techniques=["T1059"],
        tlp_label="TLP:AMBER",
    )

    preview = preview_stix_bundle(build_stix_bundle(entry))

    assert "example.org" in preview.observables
    assert preview.attack_techniques == ["T1059"]
    assert preview.tlp_label == "TLP:AMBER"


def test_import_stix_bundle_builds_entry_with_bundle_evidence() -> None:
    entry = ThreatEntry(
        observables=["import.example", "behavior:powershell-download"],
        state=LifecycleState.CONFIRMED,
        attack_techniques=["T1059"],
        tlp_label="TLP:AMBER",
    )

    imported = import_stix_bundle(build_stix_bundle(entry))

    assert "import.example" in imported.observables
    assert imported.attack_techniques == ["T1059"]
    assert imported.tlp_label == "TLP:AMBER"
    assert imported.evidence[0].content_type == "application/json"
    assert imported.evidence[0].data["source"] == "stix_import"
