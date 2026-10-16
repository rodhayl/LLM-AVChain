# System boundaries

Understanding what is inside the POC and what is considered external is essential for a clean implementation.  The system boundaries outlined here delineate the responsibilities of the LLM‑AVChain POC and identify external dependencies or out‑of‑scope elements.

## Included within the POC

The following components are part of the implementation and must be built as described:

1. **Ledger and lifecycle journal.**  A local append‑only database that stores threat entries, their current state, history of state transitions and references to evidence digests.  It exposes a REST API for reading and writing entries.
2. **Evidence store.**  A file‑based key‑value store that holds raw evidence objects and endpoint feedback records.  Evidence is addressed by SHA‑256 digest; only the digest appears in the ledger.
3. **Validator services.**  One or more services that analyse evidence and produce signed proposals.  In the POC, these use deterministic heuristics instead of full LLMs to remain offline.
4. **Consensus controller.**  A service that collects proposals, verifies signatures, applies quorum rules and writes state transitions to the ledger.  It also logs decisions and exposes history queries.
5. **Coverage oracle.**  A service that ingests simulated coverage reports from mock vendors, computes a diversity metric and triggers review requests when coverage is high.
6. **Endpoint agent.**  A local agent that polls confirmed entries, monitors synthetic telemetry, performs bounded remediation and submits sanitised feedback to the system.
7. **Shared Python package (`avchain`).**  Shared models, database abstractions, crypto utilities and configuration loaders used across services.
8. **Test suite.**  Unit, integration and end‑to‑end tests covering all services, their interactions and major edge cases.
9. **Repository scaffolding and automation.**  Project configuration (`pyproject.toml`), Dockerfiles, GitHub Actions workflows, Makefile targets and pre‑commit hooks are part of the POC.

## External dependencies / out of scope

The following are explicitly outside the scope of the POC:

1. **Production‑grade distributed ledger or blockchain.**  The working paper mentions an append‑only ledger; the POC uses SQLite and does not implement consensus across multiple physical nodes.
2. **Real LLM inference.**  Validators do not call OpenAI or other paid APIs.  Instead, they use deterministic rules or stub models.  The code should be structured to allow plug‑in modules for future LLM integration.
3. **Full CTI platform integration.**  STIX/TAXII integration, vendor APIs, ATT&CK mapping services and MISP/OpenCTI connectors are not implemented.  The POC uses simplified representations and local inputs.
4. **User interface.**  No web dashboard or GUI is provided.  Interaction occurs via REST APIs, command‑line scripts and logs.
5. **Enterprise‑grade security.**  The POC demonstrates authentication and signing but does not include comprehensive RBAC, secrets management, attestation, hardware security modules or multi‑factor authentication.
6. **Persistence beyond local file system.**  The evidence store uses the local file system.  Cloud object storage or distributed caches are left for future work.
7. **Cross‑site deployment.**  The POC runs on a single machine via multiple Docker containers.  Network encryption (TLS) is not configured; HTTP is used within localhost.  For any remote deployment, TLS and network hardening would be required.

By clarifying these boundaries, contributors can focus on implementing the core logic without accidental scope creep.  Features beyond the POC boundary may be added in future iterations after the core is validated.