"""Resolve explicitly signed source evidence into a bounded, untrusted context."""

from __future__ import annotations

import json
from typing import Any

from avchain.incident.models import Incident, RemediationPackage, SourceCase
from avchain.incident.observations import source_case_context, validate_case_context
from avchain.incident.triage import validate_triage
from avchain.utils.helpers import canonical_json_bytes, compute_sha256

MAX_SOURCE_CASES = 4
MAX_CONTEXT_BYTES = 16384


def source_context(
    payloads: dict[str, bytes], package: RemediationPackage
) -> list[dict[str, Any]]:
    """Only typed incidents/cases are supported; never follow source URLs.

    A case links the exact analysis-time catalog and observation. Its digest in
    the signed package attests provenance, not truth, success or local approval.
    """
    if set(payloads) != set(package.evidence_digests):
        raise ValueError("Source evidence differs from the signed allowlist")
    incidents: dict[str, Incident] = {}
    cases: dict[str, SourceCase] = {}
    for digest, raw in payloads.items():
        if compute_sha256(raw) != digest:
            raise ValueError("Source evidence digest mismatch")
        data = json.loads(raw)
        if isinstance(data, dict) and data.get("kind") == "avchain-source-case":
            cases[digest] = SourceCase.model_validate(data)
        else:
            incidents[digest] = Incident.model_validate(data)
    if not 1 <= len(cases) <= MAX_SOURCE_CASES:
        raise ValueError("Missing or excessive typed source cases")
    used: set[str] = set()
    contexts: list[dict[str, Any]] = []
    for digest, case in sorted(cases.items()):
        incident = incidents.get(case.incident_digest)
        if incident is None or case.incident_digest in used:
            raise ValueError("Missing or ambiguous source observation")
        used.add(case.incident_digest)
        if (
            case.knowledge.model_dump(exclude={"evidence_digests"})
            != package.model_dump(exclude={"evidence_digests"})
            or not set(case.knowledge.evidence_digests) <= set(incidents)
            or case.incident_digest not in case.knowledge.evidence_digests
        ):
            raise ValueError("Source case belongs to a different knowledge context")
        if compute_sha256(canonical_json_bytes(incident.model_dump(mode="json"))) != (
            case.incident_digest
        ):
            raise ValueError("Source observation is not the canonical incident")
        original_input: dict[str, Any] = {
            "incident": incident.model_dump(mode="json"),
            "knowledge": case.knowledge.model_dump(mode="json"),
        }
        if case.case_context is not None:
            validate_case_context(case.case_context, incident)
            original_input["case_context"] = case.case_context.model_dump(mode="json")
        expected = compute_sha256(canonical_json_bytes(original_input))
        if expected != case.analysis.input_digest:
            raise ValueError("Source analysis input provenance mismatch")
        if case.analysis.backend == "local_llm" and not case.analysis.model:
            raise ValueError("Source model provenance is missing")
        ids = {a.artifact_id for a in incident.artifacts}
        if len(ids) != len(incident.artifacts) or any(
            a.related_artifact_id is not None and a.related_artifact_id not in ids
            for a in incident.artifacts
        ):
            raise ValueError("Ambiguous or dangling source artifact reference")
        validate_triage(case.analysis.output, incident, case.knowledge)

        def source_id(artifact_id: str, case_digest: str = digest) -> str:
            return f"{case_digest}:{artifact_id}"

        # Transfer only cited evidence and its bounded structural relationships,
        # never unrelated files/telemetry merely present in the source scan.
        cited = set(case.analysis.output.evidence_ids)
        if case.case_context is not None:
            cited.add(case.case_context.resource_artifact_id)
            if case.case_context.observation is not None:
                cited.add(case.case_context.observation.actor_artifact_id)
            cited.update(g.actor_artifact_id for g in case.case_context.grants)
        while True:
            related = {
                a.related_artifact_id
                for a in incident.artifacts
                if a.artifact_id in cited and a.related_artifact_id is not None
            }
            if related <= cited:
                break
            cited |= related
        selected = [a for a in incident.artifacts if a.artifact_id in cited]

        contexts.append(
            {
                "source_case_digest": digest,
                "source_incident_digest": case.incident_digest,
                "source_artifacts": [
                    {
                        "source_artifact_id": source_id(a.artifact_id),
                        "digest": a.digest,
                        "excerpt": a.excerpt,
                        "tags": a.tags,
                        "hook": a.hook,
                        "related_source_artifact_id": (
                            source_id(a.related_artifact_id)
                            if a.related_artifact_id
                            else None
                        ),
                    }
                    for a in selected
                ],
                "limitations": incident.limitations,
                "source_analysis": {
                    "backend": case.analysis.backend,
                    "model": case.analysis.model,
                    "prompt_version": case.analysis.prompt_version,
                    "input_digest": case.analysis.input_digest,
                    "verdict": case.analysis.output.verdict,
                    "source_evidence_ids": [
                        source_id(i) for i in case.analysis.output.evidence_ids
                    ],
                    "actions": [
                        {
                            "action_id": a.action_id,
                            "source_artifact_id": source_id(a.artifact_id),
                        }
                        for a in case.analysis.output.actions
                    ],
                },
                **(
                    {
                        "source_case_context": source_case_context(
                            case.case_context, digest
                        )
                    }
                    if case.case_context is not None
                    else {}
                ),
            }
        )
    if used != set(incidents):
        raise ValueError("Unassociated source observations")
    if len(canonical_json_bytes(contexts)) > MAX_CONTEXT_BYTES:
        raise ValueError("Source context exceeds the bounded model budget")
    return contexts
