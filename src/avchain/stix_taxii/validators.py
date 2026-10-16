from __future__ import annotations

from typing import Any


def validate_stix_bundle(bundle: dict[str, Any]) -> None:
    if bundle.get("type") != "bundle":
        raise ValueError("STIX export must be a bundle")
    if bundle.get("spec_version") != "2.1":
        raise ValueError("STIX bundle must declare spec_version 2.1")

    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise ValueError("STIX bundle must include objects")

    ids = set()
    relationship_objects: list[dict[str, Any]] = []
    indicator_found = False
    for obj in objects:
        object_type = obj.get("type")
        object_id = obj.get("id")
        if not isinstance(object_type, str) or not isinstance(object_id, str):
            raise ValueError("Each STIX object must include type and id")
        ids.add(object_id)
        if object_type == "indicator":
            indicator_found = True
            if obj.get("pattern_type") != "stix":
                raise ValueError("Indicator must use STIX pattern_type")
            pattern = obj.get("pattern")
            if not isinstance(pattern, str) or not pattern.startswith("["):
                raise ValueError("Indicator must include a STIX pattern")
        if object_type == "relationship":
            relationship_objects.append(obj)

    if not indicator_found:
        raise ValueError("STIX bundle must include an indicator object")

    for relationship in relationship_objects:
        if relationship.get("source_ref") not in ids:
            raise ValueError("Relationship source_ref must resolve to a bundle object")
        if relationship.get("target_ref") not in ids:
            raise ValueError("Relationship target_ref must resolve to a bundle object")
