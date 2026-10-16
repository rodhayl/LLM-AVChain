# API contracts

This document specifies the RESTful endpoints exposed by each service in the LLM‑AVChain POC.  Each endpoint lists the HTTP method, path, required headers, request body, response body and possible error responses.  Authentication is enforced via an `Authorization: Bearer <api_key>` header for all endpoints unless otherwise noted.

## Common response fields

Successful responses return the endpoint-specific resource body described below.  For example, entry endpoints return `ThreatEntry` objects, list endpoints return JSON arrays, and evidence download returns raw binary content.

Request validation failures return an HTTP 400 body using:

* `status` – `"error"`
* `error` – `"invalid_request"`
* `message` – `"Request validation failed"`

Other error responses return the appropriate HTTP status code with FastAPI's default `{"detail": "..."}` payload unless a more specific body is documented for the endpoint.

## Ledger service (`/ledger`)

### Create threat entry

* **Method:** `POST /ledger/entries`
* **Headers:** `Authorization` (API key), `Content-Type: application/json`
* **Body:**

```json
{
  "observables": ["<string>", …],
  "evidence": [
    { "content_type": "application/json", "data": { … } },
    { "content_type": "application/json", "data": { … } }
  ],
  "attack_techniques": ["T1059"],
  "tlp_label": "TLP:AMBER"
}
```

* **Description:** Accepts one or more observables and inline evidence objects.  For each evidence object the service computes a digest and stores the raw content via the evidence store.  It creates a `ThreatEntry` in **Suspected** state with references to the digests.
* **Response 201:** Returns the created `ThreatEntry` JSON with assigned ID and initial history.
* **Errors:** 400 for invalid input, 401 if API key missing/invalid, 500 for internal errors.

### Get threat entry by ID

* **Method:** `GET /ledger/entries/{entry_id}`
* **Response 200:** Returns the `ThreatEntry` including lifecycle history.
* **Errors:** 404 if entry does not exist, 401 if unauthenticated.

### List entries by state

* **Method:** `GET /ledger/entries`
* **Query params:** `state` (optional) – one of `suspected`, `confirmed`, `review`, `deprecated`.
* **Response 200:** Returns a list of entries in the requested state.
* **Errors:** 400 if state parameter invalid.

### Append state transition

* **Method:** `POST /ledger/entries/{entry_id}/transitions`
* **Body:**

```json
{
  "from_state": "suspected",
  "to_state": "confirmed",
  "actor": "consensus",
  "proposal_ids": ["<proposalId>", …],
  "notes": "Promotion after majority quorum"
}
```

* **Description:** Appends a new `LifecycleEvent` to an entry’s history and updates the current state.  Only the consensus controller should call this endpoint.  The server verifies that the transition is valid (e.g., Suspected→Confirmed).  Timestamp is generated server‑side.
* **Response 200:** Returns the updated `ThreatEntry`.
* **Errors:** 400 for invalid transition, 404 for unknown entry.

### Submit feedback digest

* **Method:** `POST /ledger/entries/{entry_id}/feedback`
* **Body:**

```json
{
  "digest": "<sha256>"
}
```

* **Description:** Records that the entry received feedback from an endpoint agent.  The digest must correspond to evidence uploaded via the evidence service as feedback for that same entry.
* **Response 201:** Returns a confirmation with timestamp.
* **Errors:** 400 if digest unknown or entry is not in Confirmed/Review state.

## Evidence store service (`/evidence`)

### Add evidence

* **Method:** `POST /evidence`
* **Headers:** `Content-Type: multipart/form-data` or `Content-Type: application/json`
* **Body fields:**
  * `entry_id` – UUID of the threat entry to associate with.
  * `file` – the evidence object uploaded as a file; for JSON, encode as application/json.
* **JSON alternative:** `{ "entry_id": "<uuid>", "data": { ... } }`
* **Description:** Stores the uploaded object in the evidence directory, computes its SHA‑256 digest and records metadata in the database. For JSON uploads, the request body must match that exact envelope; broader ad hoc JSON bodies are rejected with HTTP 400.
* **Response 201:** Returns `{ "digest": "<sha256>", "size": <int>, "content_type": "…" }`.
* **Errors:** 400 for missing file or entry ID, 404 if entry not found.

### Fetch evidence

* **Method:** `GET /evidence/{digest}`
* **Description:** Streams the raw evidence file back to the caller.  Content type header is set to the recorded MIME type.
* **Response 200:** Returns binary content.  Includes `Content-Disposition: attachment; filename="{digest}"`.
* **Errors:** 404 if digest unknown.

### List evidence for an entry

* **Method:** `GET /evidence/entries/{entry_id}`
* **Response 200:** Returns a list of `EvidenceItem` metadata (without raw content) for the specified entry.

## Consensus controller (`/consensus`)

### Submit proposal

* **Method:** `POST /consensus/proposals`
* **Body:** `Proposal` JSON as defined in the data models.
* **Description:** Receives a signed proposal from a validator.  Signature is verified using the registered public key for the `validator_id`.  The service also recomputes `proposal_id` from `entry_id`, `validator_id`, and `timestamp`, and rejects mismatches. If valid, the proposal is stored and considered for quorum.  If quorum is met, the controller posts a transition to the ledger.
* **Response 201:** Returns `{ "status": "accepted", "decision": {…} }` if a new decision was made; otherwise `{ "status": "queued" }`.
* **Errors:** 400 if signature invalid, `proposal_id` mismatched, or validator unknown; 404 if entry not found.

### Request review

* **Method:** `POST /consensus/review_requests`
* **Body:**

```json
{
  "entry_id": "<uuid>",
  "reason": "coverage_threshold_exceeded"
}
```

* **Description:** Called by the coverage oracle when the coverage metric exceeds the threshold.  Places the entry into Review state if currently Confirmed.
* **Response 200:** Returns the updated entry or `{ "status": "ignored" }` if no state change occurred.
* **Errors:** 404 if entry not found.

### Get decisions

* **Method:** `GET /consensus/decisions/{entry_id}`
* **Response 200:** Returns a list of `Decision` objects for the specified entry.  Each decision includes `supporting_proposals`, the list of proposal IDs that backed the decision.

## Coverage oracle (`/coverage`)

### Submit coverage report

* **Method:** `POST /coverage/reports`
* **Body:**

```json
{
  "report_id": "<uuid-optional>",
  "entry_id": "<uuid>",
  "vendor": "VendorA",
  "detected": true,
  "timestamp": "2026-04-08T09:00:00Z"
}
```

* **Description:** Adds a coverage report to the oracle’s store. `report_id` may be supplied by the caller or generated server-side when omitted. The current POC keeps the latest report per vendor for the entry and computes `coverage_ratio = vendors_detected / vendors_total`.  To match the documented demo flow, review is triggered only when at least three vendors have reported and the coverage ratio exceeds the configured threshold.
* **Response 201:** Returns current `CoverageMetric` for the entry.
* **Errors:** 400 if input invalid, 404 if entry unknown.

### Get coverage metric

* **Method:** `GET /coverage/metrics/{entry_id}`
* **Response 200:** Returns the current `CoverageMetric` for the entry.
* **Errors:** 404 if entry unknown.

## Validator service (`/validator`)

The validator service does not expose a public API in the POC.  It runs a background worker that consumes ledger data and posts proposals to `/consensus/proposals`.  For debugging or demonstration, a minimal `GET /validator/status` endpoint may return the validator’s current key ID and processed entries.

## Endpoint agent (`/agent`)

The endpoint agent operates as a background worker.  A minimal `GET /agent/status` endpoint may be provided to expose statistics such as the number of telemetry events processed and feedback records generated.  Submitting feedback is handled via the ledger and evidence services.

These API definitions are intentionally explicit to remove guesswork for implementers.  All request and response payloads must conform to the data models defined in the previous section.

## Additive signed remediation knowledge API (2026-10-11)

See [the incident contract](../INCIDENT_RESPONSE.md#additive-http-contract) for
`POST /ledger/remediation/packages`,
`GET /ledger/remediation/packages/{package_id}` and
`POST /ledger/remediation/revocations`. These routes reuse ledger transport
authentication and additionally enforce exact majority-signed package/revocation
payloads. They do not change lifecycle states, proposal actions or older routes.


## Optional minimal central demo (2026-10-12)

Authenticated `GET /ledger/checks` returns central active/inactive checks;
`POST /ledger/checks/events` accepts idempotent simulated-coverage/reactivation
changes. Existing APIs are unchanged. See [CENTRAL_DEMO](../CENTRAL_DEMO.md).
