# Data models and schemas

This section defines the domain objects used throughout the POC.  All external API payloads are validated against these Pydantic models.  Fields are documented with types and descriptions, and example JSON objects are provided for clarity.

## Enumerations

### `LifecycleState`

Represents the current lifecycle stage of a threat entry.

```python
from enum import Enum

class LifecycleState(str, Enum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    REVIEW = "review"
    DEPRECATED = "deprecated"
```

### `ProposalAction`

Possible actions that a validator can propose.

```python
class ProposalAction(str, Enum):
    PROMOTE = "promote"      # promote Suspected→Confirmed or Review→Confirmed
    RETAIN = "retain"        # keep current state (no change)
    REVIEW = "review"        # move Confirmed→Review
    DEPRECATE = "deprecate"  # move Review→Deprecated
```

## Core models

### `ThreatEntry`

Represents a threat entry stored in the ledger.

| Field | Type | Description |
|------|------|-------------|
| `id` | `uuid.UUID` | Unique identifier for the entry, generated on creation. |
| `observables` | `List[str]` | One or more observables (hashes, URLs, domains, etc.). |
| `evidence_digests` | `List[str]` | List of SHA‑256 digests referencing evidence objects in the evidence store. |
| `state` | `LifecycleState` | Current lifecycle state. |
| `attack_techniques` | `Optional[List[str]]` | List of ATT&CK technique identifiers (e.g., `T1055`). Optional. |
| `tlp_label` | `Optional[str]` | Traffic Light Protocol label controlling dissemination. Optional (default `"TLP:CLEAR"`). |
| `created_at` | `datetime` | Timestamp when the entry was created. |
| `updated_at` | `datetime` | Timestamp of the last state change. |
| `history` | `List[LifecycleEvent]` | Ordered list of state transition events. |

Example:

```json
{
  "id": "b9c2a239-6d1b-4f38-95e7-f9dcee05a6c3",
  "observables": ["5e884898da28047151d0e56f8dc6292773603d0d6aabbddc1c5d08201b19a247"],
  "evidence_digests": ["a3f1…"],
  "state": "suspected",
  "attack_techniques": ["T1059"],
  "tlp_label": "TLP:AMBER",
  "created_at": "2026-04-08T09:00:00Z",
  "updated_at": "2026-04-08T09:00:00Z",
  "history": [
    {
      "timestamp": "2026-04-08T09:00:00Z",
      "from_state": null,
      "to_state": "suspected",
      "actor": "creator",
      "proposal_ids": [],
      "notes": "Entry created"
    }
  ]
}
```

### `LifecycleEvent`

Represents a state transition recorded in the ledger.

| Field | Type | Description |
|------|------|-------------|
| `timestamp` | `datetime` | Time when the event occurred. |
| `from_state` | `LifecycleState` | Previous lifecycle state. |
| `to_state` | `LifecycleState` | New lifecycle state. |
| `actor` | `str` | Identifier of the actor causing the change (e.g., `validator:validator1`, `oracle`, `timeout`). |
| `proposal_ids` | `List[str]` | List of proposal identifiers that supported this decision (may be empty for timeouts). |
| `notes` | `Optional[str]` | Additional context or justification. |

Example:

```json
{
  "timestamp": "2026-04-08T09:30:00Z",
  "from_state": "suspected",
  "to_state": "confirmed",
  "actor": "consensus",
  "proposal_ids": ["66b3…", "44d1…"],
  "notes": "Promoted after consensus quorum"
}
```

### `EvidenceItem`

Represents evidence stored off‑chain.

| Field | Type | Description |
|------|------|-------------|
| `digest` | `str` | SHA‑256 digest of the evidence content (hex string). |
| `entry_id` | `uuid.UUID` | ID of the threat entry to which this evidence belongs. |
| `content_type` | `str` | MIME type of the evidence (e.g., `"application/json"`). |
| `size` | `int` | Size of the evidence in bytes. |
| `created_at` | `datetime` | Timestamp when the evidence was stored. |

Note: The raw content is stored on disk in a file named by the digest and is not returned by the ledger.  To fetch raw content, clients call the evidence store service.

### `Proposal`

Recommendation from a validator for a specific threat entry.

| Field | Type | Description |
|------|------|-------------|
| `proposal_id` | `str` | Unique identifier for this proposal (hash of entry ID, validator ID and timestamp). The consensus API recomputes and validates this value on receipt. |
| `entry_id` | `uuid.UUID` | ID of the entry being evaluated. |
| `validator_id` | `str` | Identifier for the validator instance. |
| `action` | `ProposalAction` | Proposed action (promote, retain, review, deprecate). |
| `confidence` | `float` | Confidence score between 0 and 1. |
| `explanation` | `str` | Human‑readable justification for the recommendation. |
| `timestamp` | `datetime` | Time when the recommendation was generated. |
| `signature` | `str` | Base64‑encoded Ed25519 signature over the canonical JSON of the proposal without the `signature` field. |

Example:

```json
{
  "proposal_id": "6aefb628adc91af3",
  "entry_id": "b9c2a239-6d1b-4f38-95e7-f9dcee05a6c3",
  "validator_id": "validator1",
  "action": "promote",
  "confidence": 0.82,
  "explanation": "Hash suffix matches known malware pattern.",
  "timestamp": "2026-04-08T09:10:00Z",
  "signature": "MEUCIQDl…"
}
```

### `Decision`

Represents the outcome of consensus for a specific entry at a given time.

| Field | Type | Description |
|------|------|-------------|
| `decision_id` | `str` | Unique identifier for the decision (UUID). |
| `entry_id` | `uuid.UUID` | ID of the entry decided upon. |
| `action` | `ProposalAction` | Resulting action decided (promote, retain, review, deprecate). |
| `timestamp` | `datetime` | Time when the decision was reached. |
| `supporting_proposals` | `List[str]` | Proposal IDs that contributed to the decision. |
| `notes` | `Optional[str]` | Additional explanation. |

### `CoverageReport`

Represents a single vendor’s detection report for a threat entry.

| Field | Type | Description |
|------|------|-------------|
| `report_id` | `uuid.UUID` | Unique report identifier. Clients may supply it, or the service may generate it when omitted. |
| `entry_id` | `uuid.UUID` | ID of the entry for which coverage is reported. |
| `vendor` | `str` | Name of the vendor (e.g., `"VendorA"`). |
| `detected` | `bool` | Whether the vendor detected the threat. |
| `timestamp` | `datetime` | Time when the report was generated. |

### `CoverageMetric`

Represents the aggregated coverage status for an entry.

| Field | Type | Description |
|------|------|-------------|
| `entry_id` | `uuid.UUID` | ID of the entry. |
| `vendors_total` | `int` | Number of vendors considered. |
| `vendors_detected` | `int` | Number of vendors reporting detection in the time window. |
| `coverage_ratio` | `float` | `vendors_detected / vendors_total`. |
| `timestamp` | `datetime` | Time when the metric was computed. |

### `TelemetryEvent` (internal)

Synthetic event observed by endpoint agents.  Not exposed via API but used internally.

| Field | Type | Description |
|------|------|-------------|
| `observable` | `str` | A file hash, URL or domain seen in telemetry. |
| `metadata` | `Dict[str, Any]` | Additional synthetic details such as process name, user ID and timestamp. |

### `FeedbackRecord`

Sanitised feedback generated by an endpoint agent.

| Field | Type | Description |
|------|------|-------------|
| `feedback_id` | `uuid.UUID` | Unique identifier for this feedback. |
| `entry_id` | `uuid.UUID` | ID of the threat entry that triggered the feedback. |
| `hashed_identifiers` | `Dict[str, str]` | Dictionary of hashed values (e.g., file_path, process_name). |
| `action_taken` | `str` | Remediation performed (e.g., `"log"`, `"quarantine"`). |
| `timestamp` | `datetime` | Time when the feedback was generated. |
| `digest` | `str` | SHA‑256 digest of the full feedback payload stored in the evidence store. |

## JSON schema generation

Pydantic can export OpenAPI and JSON Schema definitions for all models.  The FastAPI services automatically expose these schemas via `/openapi.json`.  To ensure compatibility, maintain field order and types as specified above.  When adding new fields, update this document and the corresponding Pydantic models.

These models form the contract between services and provide the foundation for validation and type safety throughout the POC.

## Additive incident-response contracts (schema v1, 2026-10-11)

The existing lifecycle models remain unchanged. `avchain.incident.models` adds
`Incident`, `Artifact`, `ActionTemplate`, `RemediationPackage`, `ValidatorApproval`,
`SignedPackage`, `PackageRevocation`, `SignedRevocation`, `ActionBinding`,
`TriageResult`, `AnalysisRecord` and `ExecutionReceipt`. All reject extra fields.
The [incident contract](../INCIDENT_RESPONSE.md) documents exact semantics,
operator approval, validity, signature domains, local scope and recovery limits.
