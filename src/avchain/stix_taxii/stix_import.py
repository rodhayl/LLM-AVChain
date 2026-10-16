from __future__ import annotations

from typing import Any

from avchain.models.schemas import EvidencePayload, ThreatEntryCreate


def preview_stix_bundle(bundle: dict[str, Any]) -> ThreatEntryCreate:
    objects = bundle.get("objects", [])
    indicator = next(
        (
            obj
            for obj in objects
            if isinstance(obj, dict) and obj.get("type") == "indicator"
        ),
        None,
    )
    if indicator is None:
        raise ValueError("STIX bundle does not contain an indicator")
    observables = _observables_from_pattern(str(indicator.get("pattern", "")))
    techniques = [
        ref.get("external_id")
        for obj in objects
        if isinstance(obj, dict) and obj.get("type") == "attack-pattern"
        for ref in obj.get("external_references", [])
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack"
    ]
    tlp_label = _tlp_label_from_bundle(objects)
    return ThreatEntryCreate(
        observables=observables or ["stix-import-placeholder"],
        evidence=[],
        attack_techniques=(
            [item for item in techniques if isinstance(item, str)] or None
        ),
        tlp_label=tlp_label,
    )


def import_stix_bundle(bundle: dict[str, Any]) -> ThreatEntryCreate:
    preview = preview_stix_bundle(bundle)
    import_evidence = EvidencePayload(
        content_type="application/json",
        data={
            "source": "stix_import",
            "bundle_id": bundle.get("id", ""),
            "bundle": bundle,
        },
    )
    return ThreatEntryCreate(
        observables=preview.observables,
        evidence=[import_evidence],
        attack_techniques=preview.attack_techniques,
        tlp_label=preview.tlp_label,
    )


def _observables_from_pattern(pattern: str) -> list[str]:
    observables: list[str] = []
    for token in pattern.split("'"):
        if token and token not in {"SHA-256", " OR "} and "=" not in token:
            cleaned = token.strip(" []")
            if cleaned and ":" not in cleaned[:5]:
                observables.append(cleaned)
    return [item for item in observables if item]


def _tlp_label_from_bundle(objects: list[dict[str, Any]]) -> str:
    for obj in objects:
        if obj.get("type") != "marking-definition":
            continue
        definition = obj.get("definition", {})
        if isinstance(definition, dict):
            tlp_value = definition.get("tlp")
            if isinstance(tlp_value, str):
                return f"TLP:{tlp_value.upper()}"
    return "TLP:CLEAR"
