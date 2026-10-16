# Minimal central-check demo

This demo adds one idea to the existing ledger: a confirmed entry's supplemental
check is **active or inactive**, with an explicit reason and evidence. There is no
local-antivirus requirement, device/version matrix or new remediation platform.

## Run

With the existing project interpreter and dependencies:

```
python -m avchain.scripts.run_central_demo --output reports/my-central-demo.json
```

The command uses a temporary SQLite ledger, the existing evidence service storage,
and two logical endpoint workers in one process. No external vendor, model,
malware, real antivirus, actual scan target or OS security setting is touched.
It emits JSON retaining the two central events and their hash-checkable evidence:

1. Two synthetic confirmed entries start active on both nodes.
2. `SimulatedExternalCoverage` reports one entry covered and deactivates its check.
3. Both nodes synchronize that same inactive state; the other entry remains active.
4. Replaying the event makes no duplicate and changes nothing.
5. A central reactivation enables the check on both nodes.
6. Replaying the old deactivation cannot undo the later reactivation.

`coverage_source=SIMULATED` and `real_vendor_integration=false` are explicit. The
confirmation at setup is synthetic bootstrap, not new validator/effectiveness
proof. This command tests central state synchronization; the existing
`run_incident_demo` remains the separate bounded local-model/containment demo.

## Small additive contract

- `GET /ledger/checks`: confirmed entries plus active flag, reason, source and
  evidence digest. No event means active by default.
- `POST /ledger/checks/events`: event_id, entry_id, active, reason and source.
  Sources are `SIMULATED_EXTERNAL_COVERAGE` or `CENTRAL_REACTIVATION`; the latter
  requires active=true. Both routes use the existing ledger Bearer authentication.
- Reuse the existing entries and evidence store. One append-only
  `central_check_events` table records changes; there is no duplicate IOC catalog.
  Current status comes from the last stored event's sequence. Existing database
  initialization creates this new table without rewriting historical entries.
- Same event ID and same content is idempotent. Conflicting reuse returns 409;
  a replay of an older event never becomes the latest event.
- `EndpointAgentWorker(central_demo=True)` opts into this catalog. The default
  legacy worker and original coverage oracle remain unchanged. This simulated
  adapter does not route through the old aggregate coverage-triggered review.
- Control is per entry, including **all observables in that entry**. The demo's
  unaffected check is a separate entry; it does not promise to preserve individual
  variants grouped inside a centrally disabled entry.
- Coverage withdrawal may arrive as a new simulated feed event with active=true;
  an operator can also explicitly reactivate centrally. There is no automatic
  coverage expiry or provider-validity certification in this minimal slice.
- If synchronization or evidence validation fails after a known snapshot, nodes
  reactivate their last-known confirmed checks and report `central_sync_error`.
  With no prior snapshot, failure remains a blocker. This cannot reveal a withheld
  remote deprecation. Nonconfirmed/deprecated entries in a response are never
  activated. A refreshed successful catalog restores the central decision.

The original lifecycle states retain their meanings. Central reactivation cannot
revive a deprecated/false-positive entry. No AV is disabled, and supplemental
active/inactive is not a claim that every endpoint is protected by a vendor.
Connecting a real external coverage source would require a separate documented
adapter and trustworthy evidence; the demo makes no such integration claim.
