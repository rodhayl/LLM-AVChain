from avchain.attack import derive_attack_techniques, merge_attack_techniques


def test_attack_rules_derive_expected_techniques() -> None:
    derived = derive_attack_techniques(
        "package:pkg-dropper-sim-001",
        "behavior:postinstall",
        "behavior:powershell-download",
        "https://example.invalid/payload",
    )

    assert derived == ["T1204", "T1059", "T1071"]


def test_merge_attack_techniques_preserves_order_without_duplicates() -> None:
    merged = merge_attack_techniques(["T1059"], ["T1204", "T1059"])

    assert merged == ["T1059", "T1204"]
