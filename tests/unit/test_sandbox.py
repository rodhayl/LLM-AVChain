from pathlib import Path

from avchain.sandbox import inspect_bundle, inspect_path


def test_inspect_bundle_extracts_expected_indicators() -> None:
    result = inspect_bundle(
        Path("tests") / "fixtures" / "threat_simulants" / "pkg_dropper_sim_001"
    )

    assert result.artifact_count >= 2
    assert "package:pkg-dropper-sim-001" in result.indicators
    assert "behavior:postinstall" in result.indicators
    assert "T1204" in result.attack_techniques


def test_inspect_path_handles_single_file() -> None:
    result = inspect_path(
        Path("tests") / "fixtures" / "threat_simulants" / "eicar_avchain_001.txt"
    )

    assert result.artifact_count == 1
    assert len(result.digests) == 1
