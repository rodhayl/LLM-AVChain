# LLM-AVChain

A research proof of concept for lifecycle-governed cyber threat intelligence. It combines digest-addressed evidence, signed validator proposals, consensus-driven transitions, coverage-based revalidation and privacy-minimized endpoint feedback.

This is a runnable paper companion, not a production antivirus or CTI platform. Live-model effectiveness, general malware detection and production security are not established by the deterministic tests.

## What it does

- Tracks threat entries through `suspected`, `confirmed`, `review` and `deprecated`.
- Stores evidence off-chain, linked by SHA-256 digests.
- Validates signed proposals and records consensus transitions.
- Reopens review from coverage signals and endpoint feedback.
- Provides a dashboard, reviewer packets, and bounded STIX/TAXII interfaces.
- Demonstrates scoped incident investigation and remediation with optional local LM Studio inference. Model proposals never replace validator approval or explicit local execution permission.

![Incident investigation and reusable validated knowledge](docs/diagrams/01_incident_learning_overview_es.svg)

## Quick start

Requires Python 3.12 or later. From the repository:

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell instead:
# .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,test]"
python -m avchain.scripts.run_central_demo --output artifacts/central-demo.json
```

The central demo is a standalone in-process simulation. For the multi-service laboratory, start the services with `start.bat` on Windows or `docker compose up --build`, then run `python -m avchain.scripts.run_demo` from the activated environment. That lifecycle demo requires the ledger, evidence, consensus and coverage services to be reachable. Stop the stack with `stop.bat` or `docker compose down`. Published Compose ports and the native launcher bind to 127.0.0.1. Default development keys and the unauthenticated dashboard are for an isolated laboratory; do not expose them publicly or override the loopback bindings.

Additional bounded demonstrations:

- [Central active/inactive checks](docs/CENTRAL_DEMO.md): simulated coverage and two logical workers.
- [Incident response](docs/INCIDENT_RESPONSE.md): owned benign fixtures, containment and restoration. Real-model mode requires an already installed local model; it fails closed without silent rule fallback.
- [Research continuation](docs/RESEARCH_CONTINUATION.md): byte-verified historical incident evidence joined to a fresh central simulation. It does not rerun the model or renew an expired remediation package.

## Develop and verify

```sh
ruff check src tests
ruff format --check src tests
mypy src
pytest -m "not e2e" --cov=src/avchain --cov-report=term-missing --cov-fail-under=80
python -m hatchling build
```

See [validation and evidence](reports/README.md) for the dated results and limitations. Live/native and end-to-end campaigns require their documented environment; a unit-test pass does not establish them.

## Repository guide

- [src/avchain](src/avchain/): services, workers and demo commands.
- [tests](tests/): unit/integration/E2E tests and benign simulants.
- [docs](docs/README.md): paper, contracts, diagrams and reproduction instructions.
- [reports](reports/README.md): small retained regression/research fixtures and validation references.
- [Contributing](CONTRIBUTING.md), [security policy](SECURITY.md) and [citation metadata](CITATION.cff).

This sanitized source snapshot omits superseded plans, audit transcripts and historical build archives. They are retained privately and are not public release inputs. The retained research fixtures have explicit provenance and scope limits.

## License

[Apache License 2.0](LICENSE).
