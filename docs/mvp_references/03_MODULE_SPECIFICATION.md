# Module specification

This document defines the modules and submodules of the `avchain` Python package.  Each module encapsulates a distinct service or shared library.  Responsibilities, dependencies and exposed interfaces are described for clear separation of concerns.

## Package layout

```
avchain/
├── __init__.py
├── config/         # Configuration loading and environment management
├── crypto/         # Key generation, signing and verification utilities
├── models/         # Pydantic domain models and SQLAlchemy ORM models
├── database/       # Session management and schema creation
├── utils/          # Helper functions (hashing, timestamps, logging)
├── ledger/         # Ledger service implementation and API routes
├── evidence/       # Evidence store service implementation and API routes
├── validator/      # Validator service worker logic and API client
├── consensus/      # Consensus controller implementation and API routes
├── coverage/       # Coverage oracle implementation and API routes
└── agent/          # Endpoint agent implementation and API client
```

## Shared libraries

### `avchain.config`

* Loads configuration from environment variables and `.env` files using Pydantic's `BaseSettings`.
* Exposes a `Settings` class with fields for database URL, evidence directory, service ports, API keys, quorum threshold, coverage threshold and polling intervals.
* Provides a factory function to load settings with optional overrides.

### `avchain.crypto`

* Implements key generation for Ed25519 using the `cryptography` library.
* Provides functions `sign_message(private_key: bytes, data: bytes) -> bytes` and `verify_signature(public_key: bytes, data: bytes, signature: bytes) -> bool`.
* Contains utilities to load and save PEM‑encoded keys from disk.

### `avchain.models`

* Contains Pydantic models representing API schemas (see `04_DATA_MODELS_AND_SCHEMAS.md`).
* Defines SQLAlchemy ORM classes for threat entries, evidence references, lifecycle events, proposals and decisions.  The ORM models map to tables in the SQLite database and include relationships for history.
* Provides enumeration classes for lifecycle states and proposal actions.

### `avchain.database`

* Defines a `create_engine` function and `SessionLocal` context manager for interacting with the SQLite database.
* Implements a `Base` declarative class from SQLAlchemy and a `init_db()` function to create tables on startup.
* Handles transactional sessions and commit/rollback semantics.

### `avchain.utils`

* Provides helper functions:
  * `compute_sha256(data: bytes) -> str` – returns a hex digest.
  * `current_timestamp() -> datetime` – returns a timezone‑aware UTC timestamp.
  * `setup_logging()` – configures the Python logging library to emit JSON logs.
  * `paginate(query, limit, offset)` – generic pagination for database queries.

## Services

### `avchain.ledger`

* Implements a FastAPI application exposing ledger endpoints (see `05_API_CONTRACTS.md`):
  * `POST /ledger/entries` – create a new threat entry with observable and evidence digests.
  * `GET /ledger/entries/{entry_id}` – retrieve an entry and its history.
  * `GET /ledger/entries` – list entries by lifecycle state.
  * `POST /ledger/entries/{entry_id}/transitions` – append a state transition (used by the consensus controller).
  * `POST /ledger/entries/{entry_id}/feedback` – record an endpoint feedback digest.
* Implements business logic for creating entries, appending transitions, updating current state, enforcing timeouts and returning query results.
* Validates incoming requests against Pydantic models and authenticates API keys.

### `avchain.evidence`

* Implements a FastAPI application exposing evidence store endpoints:
  * `POST /evidence` – add evidence data; returns digest and metadata.
  * `GET /evidence/{digest}` – fetch evidence by digest.
  * `GET /evidence/entries/{entry_id}` – list evidence digests associated with a threat entry.
* Stores evidence files in a configurable directory named by digest.  Maintains a mapping table linking entry IDs to digests.
* Sanitises input to prevent path traversal and enforces size limits on evidence objects.

### `avchain.validator`

* Contains a worker class that polls the ledger via its REST API for entries in Suspected or Review states.
* Defines a `analyse_evidence()` function that normalises evidence and applies a heuristic to produce a `Proposal` with action and confidence.
* Implements logic to sign the proposal with the validator’s private key and post it to the consensus controller.
* Can be configured to run as multiple instances via environment variables (each instance uses its own keypair and validator ID).

### `avchain.consensus`

* Implements a FastAPI application exposing consensus endpoints:
  * `POST /consensus/proposals` – receive a signed `Proposal` from a validator.
  * `POST /consensus/review_requests` – receive a request to move an entry to Review from the coverage oracle.
  * `GET /consensus/decisions/{entry_id}` – retrieve decisions and proposals for an entry.
* Validates signatures against a registry of validator public keys.
* Maintains in‑memory or database records of proposals grouped by entry ID.
* Applies quorum rules: when the number of promote/deprecate votes reaches the threshold, calls the ledger service to append the corresponding transition.
* Logs all decisions for audit purposes.

### `avchain.coverage`

* Implements a FastAPI application exposing coverage endpoints:
  * `POST /coverage/reports` – submit a vendor coverage report for an entry.
  * `GET /coverage/metrics/{entry_id}` – retrieve current coverage metric and report counts for an entry.
* Aggregates reports in memory or database with timestamps.  Calculates the vendor‑diversity metric as the fraction of unique vendors reporting a detection within a sliding time window (e.g., last 24 hours).
* When the metric exceeds the threshold, issues a POST to `/consensus/review_requests`.

### `avchain.agent`

* Implements an asynchronous worker that runs on endpoints or a simulated host.  The agent:
  * Polls the ledger for confirmed entries at a configurable interval.
  * Monitors synthetic telemetry events produced by an internal generator; these events include hashes, URLs and other observables.
  * Checks if any event matches an observable in the cached entries; on a match, classifies the event as malicious and performs a bounded remediation (logging or simulated quarantine).
  * Creates a `FeedbackRecord`, stores it via the evidence store and submits the digest to the ledger.
* Exposes a minimal REST or CLI interface to trigger manual synchronisation and to view agent logs.

## Inter‑module dependencies

* The **ledger** and **consensus** services both depend on the **database** and **models** modules.
* The **validator**, **coverage** and **agent** modules depend on the **models**, **crypto** and **config** modules, and use HTTP clients (`httpx`) to call other services.
* The **evidence** service depends on **utils** for hash computation and on **database** for mapping entries to evidence digests.
* No module performs direct database writes on behalf of another service; state changes occur only through the ledger service to maintain auditability.

This modular separation enables independent development and testing of each component while ensuring that shared code remains consistent across the POC.