# Contributing

Start with the [project overview](README.md), [documentation guide](docs/README.md), [scope and reproducibility](docs/PUBLICATION_AND_REPRODUCIBILITY.md), and [agent guidance](AGENTS.md).

## Development

Use Python 3.12+ in a virtual environment and install `python -m pip install -e ".[dev,test]"`.

```sh
ruff check src tests
ruff format --check src tests
mypy src
pytest -m "not e2e" --cov=src/avchain --cov-report=term-missing --cov-fail-under=80
python -m hatchling build
```

Document any omitted environment-specific checks. The minimal CI workflow uses an ephemeral GitHub-hosted Ubuntu runner for one package build, essential static checks and short deterministic smoke tests. It does not run the full suite, publish artifacts or deploy the application. Complete the relevant local validation before publishing a change; CI is not a replacement for native Windows, Docker or live-model acceptance. Do not register a persistent self-hosted runner for this public repository.

## Changes

- Keep lifecycle states, proposal actions, API contracts and field names aligned with the [reference contracts](docs/mvp_references/).
- Add tests for behavior changes and update user-facing documentation.
- Use benign, clearly labeled simulants only. Never commit malware, credentials, `.env`, generated keys, model downloads or private runtime output.
- Preserve byte-pinned historical fixtures under `reports/`; changes require an explicit reviewed migration of their consumers.
- Keep generated build/test output out of version control. Retain compact reproducibility receipts and use immutable Git links for historical evidence.
- Explain the problem, design, checks and remaining limits in each pull request. Do not present mocks, simulations or one laboratory run as general detection effectiveness.

Report sensitive vulnerabilities using [SECURITY.md](SECURITY.md).
