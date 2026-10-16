from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from avchain.config.settings import get_settings


@dataclass(frozen=True)
class EndpointRecord:
    endpoint_id: str
    public_key: str
    enabled: bool = True
    trust_tier: str = "standard"


class EndpointRegistry:
    def __init__(self, yaml_path: str | Path | None = None) -> None:
        configured_path = yaml_path or get_settings().endpoint_registry_path
        self.path = Path(configured_path)
        self._endpoints = self._load()

    def _load(self) -> dict[str, EndpointRecord]:
        if not self.path.exists():
            return {}
        payload = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        endpoints: dict[str, EndpointRecord] = {}
        for item in payload.get("endpoints", []):
            record = EndpointRecord(
                endpoint_id=str(item["endpoint_id"]),
                public_key=str(item["public_key"]),
                enabled=bool(item.get("enabled", True)),
                trust_tier=str(item.get("trust_tier", "standard")),
            )
            endpoints[record.endpoint_id] = record
        return endpoints

    def get(self, endpoint_id: str) -> EndpointRecord | None:
        return self._endpoints.get(endpoint_id)

    def is_registered(self, endpoint_id: str) -> bool:
        return endpoint_id in self._endpoints

    def list_records(self) -> list[EndpointRecord]:
        return list(self._endpoints.values())


_registry: EndpointRegistry | None = None


def get_endpoint_registry() -> EndpointRegistry:
    global _registry
    if _registry is None:
        _registry = EndpointRegistry()
    return _registry


def reset_endpoint_registry_cache() -> None:
    global _registry
    _registry = None
