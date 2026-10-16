from __future__ import annotations

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///./data/ledger.db"
    evidence_dir: str = "./data/evidence"
    validator_registry_path: str = "runtime/validators.yaml"
    endpoint_registry_path: str = "runtime/endpoints.yaml"
    llm_provider: str = "disabled"
    lmstudio_base_url: str = "http://127.0.0.1:1234/v1"
    lmstudio_model_validator: str = "validator-local-model"
    lmstudio_model_endpoint: str = "endpoint-local-model"
    lmstudio_timeout_seconds: float = Field(default=30.0, ge=1.0)
    lmstudio_max_retries: int = Field(default=1, ge=0)
    llm_json_mode: bool = True
    quorum_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    coverage_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    poll_interval: int = Field(default=30, ge=1)
    telemetry_rate: int = Field(default=1, ge=1)
    suspected_timeout_hours: float = Field(default=24.0, ge=0.0)
    review_timeout_hours: float = Field(default=24.0, ge=0.0)
    remediation_action: str = "log"
    endpoint_scan_enabled: bool = False
    endpoint_watch_dir: str = ""
    endpoint_quarantine_dir: str = "runtime/quarantine"
    endpoint_max_file_size_bytes: int = Field(default=262144, ge=1024)
    endpoint_process_events_path: str = ""
    endpoint_package_events_path: str = ""
    endpoint_network_events_path: str = ""
    endpoint_native_snapshot_enabled: bool = False
    endpoint_native_snapshot_limit: int = Field(default=25, ge=1, le=200)
    endpoint_signing_enabled: bool = False
    endpoint_id: str = "endpoint-agent"
    endpoint_private_key_path: str = "runtime/keys/endpoint-agent_key.pem"
    port_ledger: int = 8000
    port_evidence: int = 8001
    port_consensus: int = 8002
    port_coverage: int = 8003
    port_agent: int = 8004
    ledger_api_key: str = "dev-ledger-key"
    evidence_api_key: str = "dev-evidence-key"
    consensus_api_key: str = "dev-consensus-key"
    coverage_api_key: str = "dev-coverage-key"
    agent_api_key: str = "dev-agent-key"
    ledger_base_url: str = "http://localhost:8000"
    evidence_base_url: str = "http://localhost:8001"
    consensus_base_url: str = "http://localhost:8002"
    coverage_base_url: str = "http://localhost:8003"
    taxii_base_url: str = ""
    taxii_collection_id: str = "default"
    taxii_api_key: str = ""

    @field_validator(
        "ledger_base_url",
        "evidence_base_url",
        "consensus_base_url",
        "coverage_base_url",
        mode="before",
    )
    @classmethod
    def _normalize_loopback_urls(cls, value: str) -> str:
        return str(value).replace("://localhost", "://127.0.0.1")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings_cache() -> None:
    global _settings
    _settings = None
