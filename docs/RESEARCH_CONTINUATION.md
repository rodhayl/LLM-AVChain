# Historical incident → simulated central catalog

This bounded research continuation connects the **historical real incident-v4
run** to a **fresh deterministic central active/inactive simulation**. It is not a
new live end-to-end run, a vendor integration, or a multiplatform acceptance claim.
The original independent `run_central_demo` remains unchanged.

## Run

With the existing project interpreter and dependencies, from the repository:

```sh
python -m avchain.scripts.run_research_continuation \
  --evidence-dir reports/incident_response_local_permission_v4 \
  --output reports/my-research-continuation.json
```

The three files (`REPORT.md`, `incident-llm.json`, `verification.json`) must
match the public evidence hashes pinned in the command. The incident and
verification files retain their exact original bytes. `REPORT.md` is a declared
privacy-preserving derivative: external dependency-environment identifiers use
synthetic aliases, and its old source URL is represented only by a commit identifier.
The supporting `preflight.json` and `execution.json` use the same aliases; their
path-related observations describe the original run, not current alias resolution.

The original report hash is retained separately from the public derivative hash.
Original evidence came from historical commit
`f80ec63faa1ecf2f01aaf3f83eb5427032da68e8` and tested source
`0a05947e97aae5e8035ab47bbe20fdec845ab06b` on 2026-10-11. Those identifiers are
provenance, not promises that removed Git history remains publicly available.
The command does not fetch files or run a model.

Output preserves `historical_file_sha256` for the original evidence hashes and
adds `public_evidence_file_sha256` plus `report_sanitization` for the checked public
files. `historical_evidence_url` is null because the original historical archive
is retained privately; `historical_evidence_commit` records its identity.

## What this establishes

1. Hash-check the declared public evidence set, recompute the original signed package digest and
   intact canonical source-case/draft digests, check the signed source links and
   verify both distinct archived Ed25519 signatures. The original-byte incident/verification and declared report derivative
   describe the historical real-model claim. Sanitized excerpts cannot freshly
   reconstruct the original incident or model input; that remains archived evidence.
2. Import only the archived ledger identity, observables, lifecycle state and
   history into a **new temporary SQLite database**. This is a research snapshot
   import, not fresh consensus. No production import route is added. Missing raw
   evidence is not fabricated; original digest references remain in the output.
3. Distribute the same confirmed entry's catalog to two logical endpoint workers:
   `14dcc46f-6453-4897-b536-b3c86eea4a58`, associated in the historical evidence with
   package `3b46b9290de8ec2939a5d22dd386cea512e7dea7b24adb7ffadd736f3b619cd7`.
4. Use existing authenticated central APIs and `SimulatedExternalCoverage` to
   demonstrate **active → inactive → active** on both workers. A separate synthetic
   control entry stays unchanged. Identical replay is idempotent; replaying the old
   deactivation cannot reverse the later reactivation. Both new event payloads and
   their recomputable evidence hashes are retained in the output.

The original signed package **expired 2026-10-11 at 15:56:48.799519Z**. Its
signatures and validity during the recorded run are checked solely as historical
evidence. They never authorize execution now. The command neither installs nor
republishes a remediation package, alters its timestamps/signatures, invokes
`KnowledgeClient`/remediation, nor bypasses the live expiry gate. Catalog
reactivation enables supplemental checks; it does not renew remediation authority.

All new HTTP calls use in-process ASGI transport. There are no model calls, real
sockets, native-node runs, scans, security changes or vendor requests. The command
disables model/scanning/signing for its workers, cleans up its temporary ledger,
and writes only the requested report. Distribution means catalog synchronization
to two logical workers, not new package installation or real endpoint execution.

## Focused verification

```sh
pytest tests/integration/test_research_continuation.py tests/integration/test_central_demo.py
```

Tests cover the preserved identity/history, two-node transitions, unrelated entry,
duplicate/stale replay, event hashes, archive/identity/digest/signature/source-case
tampering, still-enforced package expiry, safe output, temporary cleanup, and a
sentinel database. Socket/process/model/remediation/publication calls are prohibited
in the data-only test. These are focused CPU checks, not a native acceptance campaign.
