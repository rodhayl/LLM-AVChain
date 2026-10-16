# Consensus rules

The consensus layer aggregates validator proposals to determine when a threat entry should transition between lifecycle states.  This document specifies the quorum policy, weighting and tie‑breaking logic for the POC.

## Validator registry

A configuration file (e.g., `validators.yaml`) lists all registered validators.  Each entry contains:

* `validator_id` – unique string identifying the validator.
* `public_key` – PEM‑encoded Ed25519 public key used to verify signatures.
* `weight` – floating‑point weight (default 1.0) reserved for future weighted voting experiments.  The current POC stores this field but does not use it in quorum evaluation.

Validators may be added or removed by editing this registry and restarting the consensus service.  The number of active validators determines the quorum threshold.

## Proposal verification

Upon receiving a `Proposal` via `POST /consensus/proposals`, the service:

1. Locates the validator record by `validator_id`.  If not found, returns HTTP 400.
2. Serialises the proposal fields (excluding `signature`) into canonical JSON and computes the Ed25519 signature verification using the registered `public_key`.  If invalid, returns HTTP 400.
3. Ensures the `entry_id` exists in the ledger.  If not, returns HTTP 404.
4. Recomputes `proposal_id` from `entry_id`, `validator_id`, and `timestamp`; mismatches are rejected with HTTP 400.
5. Stores the proposal in the `proposals` table.

## Quorum policy

The POC uses a **simple majority quorum** with equal weights:

* For an entry in **Suspected** or **Review**:
  * **Promote to Confirmed** if more than 50 % of proposals recommend `PROMOTE` and the average confidence of promote proposals ≥ 0.5.
  * **Deprecate** if more than 50 % recommend `DEPRECATE`.
  * **Retain** if the above conditions are not met.  The entry remains in its current state until further proposals arrive or a timeout triggers a downgrade.

* For an entry in **Confirmed**:
  * Only the coverage oracle or a validator `REVIEW` proposal can trigger a transition to **Review**.  In the shipped POC, the coverage trigger is evaluated only after at least three vendors have reported and the coverage ratio exceeds the configured threshold.  When that threshold is exceeded, the consensus controller calls `/ledger/entries/{id}/transitions` with `to_state = review` and actor `oracle`.

The majority threshold is computed as `floor(n/2) + 1`, where `n` is the number of registered validators.  For example, with three validators, at least two must agree on promotion or deprecation.

## Weighted voting (future work)

The current POC does **not** apply weighted voting in quorum evaluation.  Validator weights are stored in the registry so that future experiments can sum weights per action and compare them against a configurable threshold.

## Tie‑breaking

If the number of proposals for two actions is equal (e.g., one `PROMOTE` and one `RETAIN`), the consensus controller does not change the state.  It waits for additional proposals or falls back to the timeout policy defined in the ledger.  The controller does not arbitrarily resolve ties.

## Decision creation

When a quorum is met, the controller:

1. Creates a `Decision` record with a unique `decision_id`, the action decided, timestamp and optional notes.
2. Records references to supporting proposals in the `decision_proposals` table.
3. Calls `POST /ledger/entries/{id}/transitions` with the appropriate `from_state` and `to_state` and the list of proposal IDs.

## Coverage oracle interactions

The coverage oracle computes a coverage ratio for each entry.  In the shipped POC, it issues a review request only after at least three vendors have reported and the ratio exceeds the configured threshold (default 0.6).  The consensus controller then calls `POST /ledger/entries/{id}/transitions` to move the entry to **Review**.  No proposals are required for this transition, but the action is logged as being triggered by the oracle.

## Rationale

This simple majority approach aligns with the working paper’s emphasis on consensus over single‑model authority (historical working paper (historical reference retained privately)).  It demonstrates how validators can collectively decide while leaving room for future enhancements, such as weighting, stake‑based voting or advanced aggregation functions.
