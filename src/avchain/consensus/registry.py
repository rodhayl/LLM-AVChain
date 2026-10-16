from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from avchain.config.settings import get_settings


@dataclass(frozen=True)
class ValidatorRecord:
    validator_id: str
    public_key: str
    weight: float = 1.0


class ValidatorRegistry:
    def __init__(self, yaml_path: str | Path | None = None) -> None:
        configured_path = yaml_path or get_settings().validator_registry_path
        self.path = Path(configured_path)
        self._validators = self._load()

    def _load(self) -> dict[str, ValidatorRecord]:
        if not self.path.exists():
            return {}
        payload = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        validators: dict[str, ValidatorRecord] = {}
        for item in payload.get("validators", []):
            record = ValidatorRecord(
                validator_id=str(item["validator_id"]),
                public_key=str(item["public_key"]),
                weight=float(item.get("weight", 1.0)),
            )
            validators[record.validator_id] = record
        return validators

    @property
    def count(self) -> int:
        return len(self._validators)

    def get(self, validator_id: str) -> ValidatorRecord | None:
        return self._validators.get(validator_id)

    def is_registered(self, validator_id: str) -> bool:
        return validator_id in self._validators

    def majority_threshold(self) -> int:
        return (self.count // 2) + 1


_registry: ValidatorRegistry | None = None


def get_registry() -> ValidatorRegistry:
    global _registry
    if _registry is None:
        _registry = ValidatorRegistry()
    return _registry


def reset_registry_cache() -> None:
    global _registry
    _registry = None
