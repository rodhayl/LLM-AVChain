# Agent guidance

## Read first

- [README](README.md) and [documentation guide](docs/README.md).
- [Scope and reproducibility](docs/PUBLICATION_AND_REPRODUCIBILITY.md).
- Relevant [data models](docs/mvp_references/04_DATA_MODELS_AND_SCHEMAS.md), [API contracts](docs/mvp_references/05_API_CONTRACTS.md), [ledger model](docs/mvp_references/06_EVENT_AND_LEDGER_MODEL.md) and [consensus rules](docs/mvp_references/07_CONSENSUS_RULES.md).
- [Incident response](docs/INCIDENT_RESPONSE.md) for incident/model/execution changes.

## Implementation

Use the `src/avchain/` layout, `pathlib.Path`, timezone-aware UTC timestamps and `pydantic_settings.BaseSettings`. Database-accessing endpoints are synchronous; use async endpoints where they await service HTTP calls. Keep business logic in this repository.

Do not silently rename lifecycle states (`suspected`, `confirmed`, `review`, `deprecated`), proposal actions (`promote`, `retain`, `review`, `deprecate`), endpoints or schema fields. Change contracts and tests together. Record unresolved ambiguity instead of inventing behavior.

## Safety and evidence

- Never commit secrets, private keys, `.env` files or generated runtime data.
- Keep authenticated API boundaries and hashed telemetry identifiers intact.
- Use benign laboratory fixtures; do not introduce real malware.
- Deterministic mode remains the default. Explicit `local_llm` mode may use an already available loopback LM Studio model. Do not download models, call hosted models, silently fall back to rules or label doubles as real inference.
- Preserve historical fixture bytes/paths listed in [reports/README](reports/README.md). They are executable test/research inputs, not disposable logs.
- Do not change repository visibility, security settings or workflow trust behavior as incidental cleanup.

## Validation

Install `python -m pip install -e ".[dev,test]"`. Use Ruff for lint/format, strict mypy for source types and pytest for tests. Target at least 80% aggregate coverage. Run focused checks for behavior-preserving documentation changes; run the appropriate broader suite for source changes. Build and inspect distributions whenever package inputs change. See [CONTRIBUTING](CONTRIBUTING.md) for commands.
