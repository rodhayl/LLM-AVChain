from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

from avchain.models.schemas import ThreatEntry

TLP_DEFINITIONS = {
    "TLP:CLEAR": {
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "definition": {"tlp": "clear"},
    },
    "TLP:GREEN": {
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "definition": {"tlp": "green"},
    },
    "TLP:AMBER": {
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "definition": {"tlp": "amber"},
    },
    "TLP:RED": {
        "id": "marking-definition--5e57c739-391a-4eb3-b6a7-5f7b6f98d7b9",
        "definition": {"tlp": "red"},
    },
}


def marking_definition_for_label(tlp_label: str) -> dict[str, object]:
    definition = TLP_DEFINITIONS.get(tlp_label.upper(), TLP_DEFINITIONS["TLP:CLEAR"])
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": definition["id"],
        "definition_type": "tlp",
        "definition": definition["definition"],
    }


def pattern_from_observables(observables: list[str]) -> str:
    fragments = [_pattern_fragment(value) for value in observables]
    return "[" + " OR ".join(fragments) + "]"


def indicator_id_for_entry(entry: ThreatEntry) -> str:
    return _stix_id("indicator", str(entry.id))


def attack_pattern_id(technique_id: str) -> str:
    return _stix_id("attack-pattern", technique_id)


def relationship_id(entry: ThreatEntry, technique_id: str) -> str:
    return _stix_id("relationship", f"{entry.id}:{technique_id}")


def _pattern_fragment(observable: str) -> str:
    escaped = observable.replace("\\", "\\\\").replace("'", "\\'")
    lower_value = observable.lower()
    if len(observable) == 64 and all(
        char in "0123456789abcdef" for char in lower_value
    ):
        return f"file:hashes.'SHA-256' = '{lower_value}'"
    if lower_value.startswith(("http://", "https://")):
        return f"url:value = '{escaped}'"
    if "." in observable and "/" not in observable and ":" not in observable:
        return f"domain-name:value = '{escaped}'"
    return f"x-avchain-observable:value = '{escaped}'"


def _stix_id(prefix: str, seed: str) -> str:
    return f"{prefix}--{uuid5(NAMESPACE_URL, seed)}"
