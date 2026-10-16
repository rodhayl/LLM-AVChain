"""Checks for the one owned canary-transfer case, not a general policy engine."""

from __future__ import annotations

from typing import Any

from avchain.incident.models import Incident, TransferCaseContext


def validate_case_context(context: TransferCaseContext, incident: Incident) -> None:
    artifacts = {a.artifact_id: a for a in incident.artifacts}
    if len(artifacts) != len(incident.artifacts):
        raise ValueError("Ambiguous case artifact references")
    resource = artifacts.get(context.resource_artifact_id)
    if resource is None:
        raise ValueError("Case resource is not in the collected incident")
    for grant in context.grants:
        if (
            grant.actor_artifact_id not in artifacts
            or grant.resource_artifact_id != context.resource_artifact_id
        ):
            raise ValueError("Grant references a different case scope")
    observation = context.observation
    if observation is None:
        return
    actor = artifacts.get(observation.actor_artifact_id)
    if actor is None or (
        actor.digest != observation.actor_digest
        or actor.path_hash != observation.actor_path_hash
    ):
        raise ValueError("Observed replay does not match this collected artifact")
    if any(d != resource.digest for d in observation.received_payload_digests):
        raise ValueError("Receiver evidence does not match the case resource")


def matching_transfer_grant(context: TransferCaseContext) -> bool | None:
    """Comparison baseline only; never supplies a model verdict or local plan."""
    if not context.grant_records_complete or context.observation is None:
        return None
    return any(
        g.actor_artifact_id == context.observation.actor_artifact_id
        and g.resource_artifact_id == context.resource_artifact_id
        and g.receiver == context.observation.receiver
        for g in context.grants
    )


def source_case_context(
    context: TransferCaseContext, case_digest: str
) -> dict[str, Any]:
    """Keep source facts separate from all local action identifiers."""
    result = context.model_dump(mode="json")
    result["source_resource_artifact_id"] = (
        case_digest + ":" + result.pop("resource_artifact_id")
    )
    for grant in result["grants"]:
        for key in ("actor_artifact_id", "resource_artifact_id"):
            grant["source_" + key] = case_digest + ":" + grant.pop(key)
    observation = result["observation"]
    if observation is not None:
        observation["source_actor_artifact_id"] = (
            case_digest + ":" + observation.pop("actor_artifact_id")
        )
        observation.pop("actor_path_hash")
    return result
