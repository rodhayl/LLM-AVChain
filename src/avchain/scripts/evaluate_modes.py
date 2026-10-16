from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from avchain.endpoint.classifier import EndpointArtifactClassifier
from avchain.endpoint.scanner import ArtifactScan
from avchain.llm.schemas import (
    EndpointClassificationOutput,
    ValidatorAnalysisOutput,
)
from avchain.models.enums import ProposalAction
from avchain.models.schemas import ThreatEntry
from avchain.sandbox import inspect_bundle
from avchain.stix_taxii import (
    build_stix_bundle,
    import_stix_bundle,
    preview_stix_bundle,
    validate_stix_bundle,
)
from avchain.validator.heuristics import (
    DeterministicHeuristic,
    LMStudioAnalysisStrategy,
)


class BenchmarkValidatorLLMClient:
    async def analyze_validator_evidence(
        self,
        *,
        observables: list[str],
        evidence_summaries: list[str],
    ) -> ValidatorAnalysisOutput:
        _ = observables, evidence_summaries
        return ValidatorAnalysisOutput(
            action=ProposalAction.PROMOTE,
            confidence=0.86,
            reasoning_summary="Benchmark local LLM promotion",
            attack_techniques=["T1059"],
            evidence_gaps=[],
        )


class BenchmarkEndpointLLMClient:
    async def classify_endpoint_artifact(
        self,
        *,
        matched_observables: list[str],
        artifact_summary: str,
    ) -> EndpointClassificationOutput:
        _ = artifact_summary
        return EndpointClassificationOutput(
            verdict="malicious_simulant",
            severity="high",
            recommended_action="simulate_quarantine",
            explanation="Benchmark local LLM classification",
            confidence=0.9,
            behavior_tags=matched_observables,
        )


async def evaluate_validator_modes() -> dict[str, Any]:
    heuristic = DeterministicHeuristic()
    heuristic_result = heuristic.analyze(
        ["validator-benchmark-a"],
        [b"malicious powershell observed"],
    )
    llm_strategy = LMStudioAnalysisStrategy(client=BenchmarkValidatorLLMClient())
    llm_result = await llm_strategy.analyze(
        ["validator-benchmark-a"],
        [b"malicious powershell observed"],
    )
    return {
        "heuristic": _strategy_result_to_dict(heuristic_result),
        "llm_assisted": _strategy_result_to_dict(llm_result),
    }


async def evaluate_endpoint_modes() -> dict[str, Any]:
    inspection = inspect_bundle(
        Path("tests") / "fixtures" / "threat_simulants" / "pkg_dropper_sim_001"
    )
    scan = ArtifactScan(
        path=Path("package.json"),
        digest="benchmark-digest",
        matched_observables=list(inspection.indicators),
        detection_kind="contextual",
        summary=inspection.summary,
        metadata={},
    )
    rule_classifier = EndpointArtifactClassifier(default_action="alert")
    llm_classifier = EndpointArtifactClassifier(
        default_action="alert",
        llm_client=BenchmarkEndpointLLMClient(),
    )
    rule_result = await rule_classifier.classify(scan)
    llm_result = await llm_classifier.classify(scan)
    return {
        "rule_only": {
            "verdict": rule_result.verdict,
            "action": rule_result.recommended_action,
            "confidence": rule_result.confidence,
        },
        "rule_plus_llm": {
            "verdict": llm_result.verdict,
            "action": llm_result.recommended_action,
            "confidence": llm_result.confidence,
        },
    }


async def evaluate_modes() -> dict[str, Any]:
    return {
        "validator": await evaluate_validator_modes(),
        "endpoint": await evaluate_endpoint_modes(),
        "interoperability": evaluate_interoperability_modes(),
    }


def evaluate_interoperability_modes() -> dict[str, Any]:
    entry = ThreatEntry(
        observables=["roundtrip.example", "behavior:powershell-download"],
        evidence_digests=["digest-a"],
        attack_techniques=["T1059"],
        tlp_label="TLP:AMBER",
    )
    bundle = build_stix_bundle(entry)
    validate_stix_bundle(bundle)
    preview = preview_stix_bundle(bundle)
    imported = import_stix_bundle(bundle)
    return {
        "bundle_object_count": len(bundle["objects"]),
        "preview_observable_count": len(preview.observables),
        "import_evidence_count": len(imported.evidence),
        "roundtrip": {
            "observables_match": preview.observables == entry.observables,
            "attack_techniques_match": (
                (preview.attack_techniques or []) == (entry.attack_techniques or [])
            ),
            "tlp_matches": preview.tlp_label == entry.tlp_label,
        },
    }


async def main(output_path: str | None = None) -> dict[str, Any]:
    results = await evaluate_modes()
    if output_path:
        Path(output_path).write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def _strategy_result_to_dict(
    result: tuple[ProposalAction, float, str],
) -> dict[str, Any]:
    action, confidence, explanation = result
    return {
        "action": action.value,
        "confidence": confidence,
        "explanation": explanation,
    }
