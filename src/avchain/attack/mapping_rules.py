from __future__ import annotations

ATTACK_RULES = {
    "behavior:postinstall": "T1204",
    "behavior:powershell-download": "T1059",
    "behavior:suspicious-network": "T1071",
}


def derive_attack_techniques(*signals: str) -> list[str]:
    techniques: list[str] = []
    for signal in signals:
        normalized = signal.strip().lower()
        technique = ATTACK_RULES.get(normalized)
        if technique is not None and technique not in techniques:
            techniques.append(technique)
        if normalized.startswith("package:") and "T1204" not in techniques:
            techniques.append("T1204")
        if normalized.startswith(("http://", "https://")) and "T1071" not in techniques:
            techniques.append("T1071")
    return techniques


def merge_attack_techniques(
    existing: list[str] | None,
    derived: list[str],
) -> list[str]:
    merged: list[str] = []
    for technique in (existing or []) + derived:
        if technique not in merged:
            merged.append(technique)
    return merged
