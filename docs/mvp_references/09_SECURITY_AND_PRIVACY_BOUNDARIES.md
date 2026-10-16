# Security and privacy boundaries

The POC implements a simplified yet meaningful set of security and privacy controls.  This document captures the assumptions, controls and boundaries that must be honoured during implementation.  It draws on the working paper’s discussion of risks (historical working paper (historical reference retained privately)) and aligns with least‑disclosure principles.

## Threat model

The POC assumes an honest‑but‑curious adversary.  Attackers may attempt to submit fabricated evidence, forge proposals, flood the system with low‑quality entries, collude among validators or compromise endpoint agents.  Attackers do not have arbitrary code execution on the host machine but may send malicious HTTP requests.  Network traffic is local and unencrypted; in production, TLS and network segmentation would be required.

## Authentication and authorisation

* **API keys:** All external calls to ledger, evidence, consensus and coverage services require a valid API key in the `Authorization` header.  Keys are provisioned for validators, agents and admin clients.  Keys are stored in the database with hashed values using bcrypt.  The key’s role determines allowed operations (e.g., a validator key cannot create new entries).
* **Signature verification:** Proposals are signed using Ed25519.  The consensus controller verifies each signature before accepting a proposal.  Signatures ensure authenticity and non‑repudiation of validator recommendations.
* **Minimal privileges:** Services only perform actions within their role.  For example, the coverage oracle cannot promote entries directly; it can only request review.  The endpoint agent cannot change states; it can only submit feedback.

## Input validation and sanitisation

* **Schema validation:** All incoming JSON payloads are validated against the Pydantic models.  Unknown fields are rejected.  Confidence values must be between 0 and 1.
* **Length and size limits:** Evidence uploads are limited to a configurable maximum size (e.g., 10 MiB) to prevent storage exhaustion.  Strings have maximum lengths enforced via Pydantic validators.
* **Path safety:** The evidence service sanitises filenames to prevent path traversal attacks.  Evidence files are stored under a dedicated directory with no ability to escape the sandbox.

## Key management

* **Key generation:** Validator and agent keypairs are generated using the `cryptography` library’s Ed25519 implementation.  Keys are created during the bootstrap phase via a CLI (see environment and configuration).  Keys must not be hard‑coded in the repository.
* **Key storage:** Private keys are stored locally on disk in PEM format with file permissions restricted to the service process (chmod 600).  Public keys are stored in the validator registry (`validators.yaml`) and loaded by the consensus controller.
* **Key rotation:** The POC includes scripts to regenerate keys and update the validator registry.  Rotation is manual in the POC.

## Privacy controls

* **Evidence separation:** Raw evidence is stored off‑chain.  The ledger contains only cryptographic digests and metadata, ensuring that sensitive data is not replicated across services.
* **Telemetry hashing:** Endpoint agents hash local identifiers (paths, process names) before storing them in feedback records (historical working paper (historical reference retained privately)).  Raw telemetry never leaves the endpoint.
* **TLP labels:** Threat entries include TLP labels indicating distribution restrictions.  Although the POC runs locally, the label is recorded and can be enforced in future integrations.
* **Access logs:** Each service logs requests with timestamps and API keys (hashed) for auditing.  Logs avoid storing sensitive payloads.

## Rate limiting and abuse prevention

* **Rate limits:** Services apply per‑API‑key rate limiting (e.g., 100 requests per minute).  Excess requests return HTTP 429.  This prevents DoS via flooding.
* **Input queuing:** The consensus controller processes proposals in the order received.  If the queue grows beyond a threshold, additional proposals are temporarily rejected with HTTP 503 to prevent resource exhaustion.
* **Timeout policies:** The ledger applies automatic downgrades for entries that do not receive sufficient proposals within a timeframe.  This prevents attackers from leaving entries in limbo.

## Logging and monitoring

* Services emit structured JSON logs via the Python `logging` module.  Logs include timestamps, request identifiers, actor IDs and error details.  Sensitive fields (API keys, private keys) are never logged.
* A separate module can be used to aggregate logs (e.g., via `docker-compose` with a `vector` container), but this is optional for the POC.

## Limitations and future work

* **No TLS:** All services communicate over HTTP on localhost.  For any network deployment, TLS must be enabled and certificates managed securely.
* **No RBAC UI:** Role management is hard‑coded via API keys and YAML files.  A management interface would be required in production.
* **No hardware root of trust:** Private keys are stored in files.  In production, hardware security modules or cloud KMS should be used.
* **Simplified privacy model:** The hashing and TLP mechanisms are illustrative.  Real deployments require thorough data minimisation, encryption at rest and fine‑grained access control.

Implementing the above controls provides a secure baseline for the POC and demonstrates how LLM‑AVChain can incorporate security best practices while remaining accessible for experimentation.