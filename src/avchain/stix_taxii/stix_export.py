from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from avchain.attack import derive_attack_techniques, merge_attack_techniques
from avchain.models.schemas import ThreatEntry
from avchain.stix_taxii.mappings import (
    attack_pattern_id,
    indicator_id_for_entry,
    marking_definition_for_label,
    pattern_from_observables,
    relationship_id,
)


def build_stix_bundle(
    entry: ThreatEntry,
    *,
    exported_at: datetime | None = None,
) -> dict[str, Any]:
    timestamp = _format_timestamp(exported_at or datetime.now(UTC))
    identity_id = f"identity--{uuid5(NAMESPACE_URL, 'LLM-AVChain')}"
    indicator_id = indicator_id_for_entry(entry)
    marking = marking_definition_for_label(entry.tlp_label)
    techniques = merge_attack_techniques(
        entry.attack_techniques,
        derive_attack_techniques(*entry.observables),
    )

    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": timestamp,
            "modified": timestamp,
            "name": "LLM-AVChain",
            "identity_class": "system",
        },
        marking,
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created_by_ref": identity_id,
            "created": _format_timestamp(entry.created_at),
            "modified": _format_timestamp(entry.updated_at),
            "name": f"AVChain threat entry {entry.id}",
            "description": (
                "Lifecycle-governed threat entry exported from LLM-AVChain"
            ),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern_from_observables(entry.observables),
            "pattern_type": "stix",
            "valid_from": _format_timestamp(entry.created_at),
            "labels": ["avchain", entry.state.value],
            "object_marking_refs": [marking["id"]],
            "external_references": [
                {
                    "source_name": "avchain-entry",
                    "external_id": str(entry.id),
                }
            ],
            "x_avchain_lifecycle_state": entry.state.value,
            "x_avchain_evidence_digests": entry.evidence_digests,
        },
    ]

    for technique_id in techniques:
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_pattern_id(technique_id),
                "created_by_ref": identity_id,
                "created": timestamp,
                "modified": timestamp,
                "name": technique_id,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                    }
                ],
                "object_marking_refs": [marking["id"]],
            }
        )
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": relationship_id(entry, technique_id),
                "created_by_ref": identity_id,
                "created": timestamp,
                "modified": timestamp,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": attack_pattern_id(technique_id),
                "object_marking_refs": [marking["id"]],
            }
        )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid5(NAMESPACE_URL, f'{entry.id}:{timestamp}')}",
        "spec_version": "2.1",
        "objects": objects,
    }


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
