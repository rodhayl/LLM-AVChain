# Bounded incident investigation and remediation knowledge

Historical narrative below is a dated summary. Retired audit reports and commit references are retained privately; they are not independently reproducible from this sanitized snapshot. Current retained JSON fixtures and tests are the reproducible evidence shipped here.

## Purpose and actual scope

Investigate an explicitly selected directory even when no confirmed indicator exists, keep observed evidence separate from a model's hypotheses, and reuse a validated remedy on another node. Incident and package contracts are general: the first adapter demonstrates an install-hook chain as one case, not the definition of all incidents.

The shipped demonstration recognizes a deliberately narrow conjunction: a directly referenced local install script, an owned canary read, and loopback egress. It is not a detector for arbitrary malware, shell syntax, remote downloads, SSH theft, IDE tasks or obfuscated code. Unmatched/incomplete incidents are uncertain and require further investigation. No package hook is executed by the collector or executor.

### Behavioral verdict contract (incident-v4)

The current local-model prompt defines `suspicious` as concrete, response-relevant
represented behavior supported by evidence and the local permission scope, without
asserting malicious intent or real compromise. `benign` includes ordinary or
explicitly permitted behavior without separate response-relevant evidence. A
matching action template alone does not establish a need for response. Incomplete,
conflicting or insufficient evidence remains `uncertain`.

Safe simulation construction neither establishes nor erases a behavior. Names,
lifecycle names, marker words, self-descriptions and signed-package availability
do not decide the verdict. Concrete evidence and its relationships still matter;
tags are eligibility constraints rather than independent proof of need. This
same instruction applies to every case and contains no node/file-name exceptions.

The schema and enforcement are unchanged: `benign`/`uncertain` must have no
actions, including when eligible templates exist. The system never replaces an
abstention with rules or supplies missing actions. Current local-model records
and request diagnostics identify `incident-v4`; diagnostics also retain the
system-prompt SHA-256, including failed completion requests. The legacy record
default stays `incident-v1`, and rules/arbitrary doubles are not relabeled as
having received the current system prompt.

The checkpointed native run (historical reference retained privately)
established B's actual `benign`/empty-plan decision and correctly blocked receipt.
Its final explanation was not retained, so the model's reason cannot be established.
The v2 repair report (historical reference retained privately) documents a task
ambiguity, the bounded clarification and unchanged safeguards. Offline contracts
and replayed decisions do not demonstrate that a real model will change its verdict.
The native v2 experiment (historical reference retained privately)
also failed at B's benign/empty-plan decision. It does not establish the model's
internal reason. Do not repeat a historical configuration.

### Authenticated source observation and decision transfer

`incident-v3` adds an actual data path, rather than another verdict-definition
rewrite. Previously the model received source evidence **digests only**. It now
receives a bounded projection of the referenced source observation and decision,
through the existing authenticated evidence API. This repairs missing context;
it does not guarantee a different local model decision.

The source publisher stores one typed `SourceCase` (schema 1,
`kind=avchain-source-case`) referencing the original `Incident` digest, exact
analysis-time `RemediationPackage`, and `AnalysisRecord` with explanation and
hypotheses removed. The signed final package commits both evidence digests.
Retrieval verifies signatures first, requests only those digests, checks raw
hashes and strict schemas, joins by digest, recomputes the original input digest,
and validates source action grounding. The source catalog must equal the current
catalog in every field except explicitly enriched evidence digests. Case identity,
entry, version, validity interval, rationale and action capabilities cannot drift.

Limits are 64 KiB per evidence object, 128 KiB aggregate, four cases, 16 KiB of
projected context, 10-second request I/O timeouts and a 30-second aggregate retrieval
deadline. Streaming bounds precede JSON parsing; no truncation, redirect following,
source-URL crawling or context-free fallback occurs. Unknown, missing, tampered,
oversized, unassociated or ambiguously linked evidence blocks investigation before
local inference. Legacy packages containing untyped standalone analysis evidence
remain readable by the package API but cannot enter this new node analysis path;
publish a newly validated typed case rather than silently adapting history.
This version supports original analyses over an incident, catalog and optional
strict owned-transfer case context, not recursively enriched case histories. A record originally analyzed with more
context has a different input digest and is rejected rather than reconstructed
from assumptions. No nested evidence/reference URL is fetched.

Only cited source artifacts, concrete case actor/resource references and their
linked artifacts reach the model. Source
references use separately namespaced `source_artifact_id` values; they are never
local action targets. Absolute/path hashes, unrelated files, free model prose and
hypotheses are omitted from this context. Source excerpts remain **untrusted data**,
not instructions, proof of truth or approval. Producers must still ensure published
excerpts are appropriate to share; this narrow owned-fixture demo is not a general
secret-redaction system. The prior backend/model/prompt/input provenance remains
visible. Both the model and rules comparison receive the same enriched input.
Sanitized checkpoints retain source-case/incident digests and the enriched input
digest without adding source excerpts or model prose.

This transfers a signed **pre-containment observation and decision**, not a proven
successful resolution: publication still precedes A containment, and later feedback
is not part of this package. Demonstrated outcome transfer would require a separate
signed case after verified source execution/recovery. No outcome is fabricated here.
The local LLM still decides; benign/uncertain output stays blocked even when source
actions exist. All signature, revocation, approval, executor and recovery gates stay
in place. See the retrieval repair (historical reference retained privately).

### Concrete transfer permission and receiver evidence

The replayed demonstration now distinguishes permission to run an innocent lab
from permission for the represented transfer. Every fixture contains only an
artificial canary and byte-allowlisted code using the owned loopback receiver.
Its `case_context` supplies one concrete actor/resource/receiver grant scope,
whether the grant list is complete, and actual payload digests received during
that actor's byte-verified replay. A/B have no matching grant; the benign control
has one. A and the control use identical script and manifest bytes and both
actually send the canary before analysis. The supplied difference is the grant,
not an expected verdict, action label or special fixture name.

The receiver establishes receipt of the canary bytes during the owned replay.
It does not instrument file reads: the read relationship comes from the collected
script. Actor digest and local path hash bind the observation to the collected
artifact; the payload digest must equal the collected resource digest. Unknown
references, mismatches, extra fields and more than eight receipts/grants are
rejected. Absent observation or an incomplete grant list remain unknown in the
explicit rules comparison. There is no general authorization engine or new
service. These trusted, operator-supplied lab facts are not endpoint attestation.

Source cases commit this optional context in the exact original input digest;
retrieval verifies it and namespaces its references before reuse. Older cases
without context retain their original digest interpretation. The current system
prompt is incident-v4: it explains how the local actor/resource/receiver grant
relates to the observed transfer. A complete matching grant covers only that
transfer; it grants neither remediation approval nor blanket harmlessness. A
complete list without a match supports absence of permission for that transfer.
Incomplete records or absent observations leave this comparison unresolved.
Absent case context does not itself establish permission or lack of permission.
File prose and historical source grants cannot supply current permission; other
concrete risks must be assessed separately. Local benign/uncertain results still
stop action. No grant-based output correction or filtering is performed.

The control gate checks **non-interference**, original bytes and a second actual
receipt, not a mandatory `benign` label. Its actual verdict is retained separately;
`uncertain` with no actions is not reported as a demonstrated benign classification.
A false-positive model plan fails the lab rather than being filtered out. The
no-replay helper retains a static print-only control for isolated tests and makes
no runtime or equivalent-transfer acceptance claim.

Before the first inference, the atomic checkpoint now retains the exact unsigned
catalog, catalog digest and case context alongside the sanitized incident. This
preserves dynamic package identifiers/timestamps even if source analysis abstains
or transport fails. It does not publish a package or claim a source resolution.

The native permission-case run (historical reference retained privately)
completed A/B containment and recovery but proposed both actions on the granted
control; its guard stopped before control execution or final byte/transfer checks.
Its exact reconstructed inputs contained the matching local grant. Incident-v3
never explained that context and defined benign in terms of the behavior's absence,
which was inconsistent with this equivalent authorized control. Incident-v4 repairs
that task contract; the model's internal reason remains unknown. Offline replay of
all four retained decisions still fails, proving no forced correction was added.

Control failures now identify `authorized_control_actions_proposed`,
`authorized_control_bytes_changed`, or `authorized_control_transfer_not_one` only
when that check actually runs. A rejected plan has no fabricated receipt, unchanged
result or final transfer count. See [the v4 repair](../reports/43_INCIDENT_PERMISSION_CONTRACT.md).

## Installed components

- `IncidentCollector`: bounded directory observation (128 files/directories; 64 KiB per file; 8 KiB excerpt). Local path map remains local; exported identifiers are SHA-256 hashes. Symlinks, oversized files and incomplete scans make automatic action binding unavailable. Actual file contents are untrusted evidence, not instructions.
- `IncidentTriage`: uses either explicit rules or `LocalIncidentModel`, reusing the LM Studio JSON transport. The model gets actual excerpts, structured tags and the existing action catalog. It returns cited evidence IDs, a verdict, hypotheses and action/artifact IDs. Unknown fields, new commands, unknown actions, fabricated IDs, duplicate bindings and actions on benign/uncertain outputs are rejected. This verifies references and action eligibility; it does not prove arbitrary prose conclusions true.
- `RemediationPackage`: schema version, immutable package ID/version, source entry and evidence digests, validity interval, rationale, typed action templates and sources. The operator/capability catalog constructs the draft; the model does not invent a remediation program or grant permissions.
- `KnowledgeStore`: uses the existing SQLAlchemy ledger, digest-addressed evidence store, validator registry and Ed25519 helpers. A confirmed entry plus a majority of distinct registered signing keys authorizes the exact package. Lifecycle votes do not authorize a package: signatures have separate domains. New versions advance by exactly one. Signed revocation, expiry, source-state changes and evidence-integrity failure block retrieval.
- `KnowledgeClient`: verifies package signatures and ID, maintains a per-node highest-version/digest checkpoint, rejects downgrade/equivocation, retrieves bounded typed source evidence with a separately supplied existing evidence client/key, and refreshes the package online immediately before execution.
- `IncidentNode`: observes, retrieves, analyzes, then waits for exact host-side `LocalApproval`. Approval binds incident ID, package digest, action bindings, root hash and expiry. It is constructed by a trusted caller after operator review; it is not a public approval API or an authenticated multi-user approval system.
- `ScopedExecutor`: implements only `disable_npm_hook` and `quarantine_file`. It rechecks original digests and path scope, prepares recovery bytes and a journal, removes the selected hook/moves the script, verifies postconditions, and restores original bytes on failure. Recovery refuses to overwrite concurrent changes and reports `rollback_incomplete` instead of claiming success. A fresh executor can restore from a recorded run ID.

The old endpoint `simulate_quarantine` and label-only `block_execution` are unchanged legacy behavior. The new incident path does not rely on them and does not claim to install OS execution blocking.

## Reproduce the safe two-node demonstration

Install using the existing project workflow:

```bash
python -m pip install -e '.[dev,test]'
python -m avchain.scripts.run_incident_demo --mode rules --output artifacts/incident-rules.json
```

The command creates an isolated temporary database, evidence store, three ephemeral lab validator keys and three owned fixture directories. It does not use or modify an existing ledger or trust registry. Temporary keys are deleted at exit; the report contains public verification keys only.

1. Replay only byte-exact bundled lab scripts. They read only an adjacent artificial token and send it to a loopback-only HTTP collector. No shell invocation, sample download, real credential access or external destination is used.
2. Investigate A before any IOC is known. Construct a draft from the installed action catalog, analyze the concrete evidence and store the observation plus its typed, prose-free source decision/context link.
3. Use the existing consensus API and two signed validator votes to confirm the lab entry. Two separately domain-signed package approvals authorize publication. These validators share one lab controller; the test does not establish independent real-world adjudication.
4. A and B each fetch the same signed package and its hash-verified source observation/decision. B has a held-out filename and lifecycle hook (`prepare` versus `postinstall`), not an unseen malware family. Its executable code is not modified to handle the variant. Source digests are recorded before and after.
5. The lab harness explicitly approves the exact local plan on its own disposable files. The rules baseline selects both hook disabling and script quarantine. A local model may select a smaller eligible set; the actual receipt governs the claim. In either case canary egress must go from one observation to zero. The benign hook remains untouched.
6. Restore each node and verify original bytes and one canary observation again. Store redacted containment/recovery receipts using the existing evidence and feedback APIs. Feedback is not claimed to be cryptographically endpoint-authenticated in this lab.

The successful report contains per-case input evidence, model/rules output, backend, prompt version, model name, temperature, input digest, signed package, public verification keys, ledger state, action receipts, postcheck observations and recovery results. Temporary raw service storage is removed, so the report is the retained proof artifact.

The harness now atomically checkpoints sanitized partial evidence to `--output`
before proceeding to the next operation. A completed receipt is saved before its
canary replay, so a replay exception cannot erase the receipt. Failure reports
retain completed A/B results, selected action IDs, verdicts, input/package digests,
signed package and public verification keys, rules comparison, and observed canary
counts. They omit artifact excerpts, model explanations/hypotheses, raw exception
text and local recovery paths. Each stage is `NOT_RUN`, `RUNNING`, `PASS` or `FAIL`;
an interrupted `RUNNING` stage is not a passed gate. Baseline replay must actually
observe A=1, B=1 and the authorized control=1. Containment reports `receipt_not_applied` separately
from `canary_egress_not_zero`, and either still fails the run with exit 2. No actions
are added when the model abstains. A no-replay test reports baseline `NOT_RUN` and
does not establish the full canary journey.

For an already installed local model:

```bash
python -m avchain.scripts.run_incident_demo --mode local_llm \
  --model YOUR_ALREADY_INSTALLED_MODEL \
  --timeout-seconds 180 \
  --base-url http://127.0.0.1:1234/v1 \
  --output artifacts/incident-llm.json
```

The model must already be served on loopback. Use its actual chat-model identifier; the model listing may include downloaded but unloaded models or embedding models. Nothing is downloaded or trained. Requests use LM Studio JSON Schema structured output, temperature 0 and no retries. The completion budget defaults to 2,048 tokens and can be explicitly set with `--max-tokens` (1–4,096). The per-request wall-clock deadline and HTTP I/O timeout default to 180 seconds and can be set with `--timeout-seconds` (1–600). The client deadline cancels its outstanding request; it does not prove that the server immediately stops generation. By default no request-side reasoning override is sent. Explicit `--reasoning off` requests `reasoning_effort="none"` without changing persistent server settings. It requires the exact already-loaded instance to advertise `off` in `/api/v1/models`, then requires each completion to report zero reasoning tokens and no nonempty reasoning fields. Missing usage remains unknown and stops that experiment; a requested setting alone is not proof it worked. Truncation, empty choices and malformed completion envelopes fail closed. An unavailable model, invalid structured result, incomplete evidence, no applicable A plan, or a benign-control mutation makes the run blocked/inconclusive; no silent rule fallback is allowed. On failure, the report distinguishes valid structured outputs from received HTTP responses. If a response arrived but no valid output did, `real_model_executed` is null (unknown), not a false claim that no model ran. Both successful and blocked reports retain the selected configuration and sanitized per-request diagnostics: elapsed time, HTTP status, finish reason, valid integer token usage (including reasoning tokens when supplied), prompt/content/reasoning byte lengths and whether structured validation passed. Raw completion and reasoning text are never copied into these diagnostics. A missing usage field is unknown, not zero. The report also runs the rules baseline on exactly the same evidence and package per node. It does not assume the model is better. MockTransport/test doubles are always labeled separately.

## Additive HTTP contract

All routes use the existing ledger Bearer key and strict Pydantic request schemas. That key permits transport access; it cannot substitute for package signatures.

| Method and route | Input / result | Failure |
|---|---|---|
| `POST /ledger/remediation/packages` | `SignedPackage`; returns the accepted envelope, 201 | 400 for invalid signature/quorum/version/source |
| `GET /ledger/remediation/packages/{package_id}?minimum_version=1` | Current signed envelope, 200 | 409 when unavailable, revoked, stale or invalid |
| `POST /ledger/remediation/revocations` | `SignedRevocation`; returns `{"status":"revoked"}`, 201 | 400 for invalid/existing revocation |

`RemediationPackageORM` and `RemediationRevocationORM` are new tables in the same database. Existing lifecycle states, proposal actions and routes are unchanged. The executable/action schema version is 1. Package signatures cover canonical JSON `{domain: "avchain-remediation-package-v1", payload: package}`; revocations use `avchain-remediation-revocation-v1`. The existing registry's majority threshold is reused, with distinct key material required.

## Threat model and limits

- Suspect files and model outputs are untrusted. An LLM cannot generate code, select arbitrary filesystem paths, sign approvals, choose a new capability or expand local scope.
- The root must be a quiescent operator-controlled lab directory. Path checks and digest rechecks do not provide OS-level isolation from a hostile process racing parent directories. Concurrent writes and true power-loss behavior are not validated. Recovery preserves bytes and ordinary permission bits, not all original platform metadata/ACLs. Windows and native GUI acceptance are not covered by this Linux lab.
- A trusted authenticated service transport is still required. Signatures detect modification; they cannot prove a newer version/revocation has not been withheld. The per-node checkpoint stops observed-version rollback, and online refresh/expiry limit stale use. No claim of distributed anti-replay under an active transport attacker is made.
- The configured registry, local approval caller, local checkpoint and recovery directory are trusted operator state. Each checkpoint has a single process owner; concurrent asynchronous fetches in that process re-read after the response and cannot downgrade it. Sharing one checkpoint across OS processes is unsupported. This is not production authorization, key rotation, device attestation or an authenticated remote command channel.
- Read-only collection may encounter secrets. Only the known synthetic lab shares full excerpts automatically. Real project investigations must review/redact evidence before any publication; hashed path metadata does not anonymize file contents.
- One positive case, one simple held-out variant and one benign control do not measure detection accuracy, false-positive rates, prompt-injection immunity or generalization to unknown attacks. Rule markers are transparent lab features; a comment can mimic them. Explicit local review is essential.

## Data-only attribution

The example uses the install-hook and benign-control family shapes from [VSCodeAntivir's npm inspection](https://github.com/rodhayl/VSCodeAntivir/blob/362e1f8de7ed0e9dec4ad5519f72d7418cc13362/extension/src/scanner/engines/npm-audit-engine.ts) and [synthetic portfolio corpus](https://github.com/rodhayl/VSCodeAntivir/blob/362e1f8de7ed0e9dec4ad5519f72d7418cc13362/extension/test/corpus/portfolio.json). The dangerous external-download shape is replaced with newly authored adjacent-canary/loopback-only code. No payload from `samples/` is imported, no extension implementation is merged, and no personal incident account is placed in prompts or fixtures.

## Local agent preflight (Windows PowerShell)

Respect the operator's checkout and installation instructions. For the current
local experiment, reuse the existing checkout and existing interpreter/dependency
paths established in the retained local report (historical reference retained privately).
Do not clone, create a worktree, reset/stash changes, install dependencies, download
models, or change LM Studio/global settings. If the checkout has conflicting local
changes or the confirmed interpreter/dependencies are unavailable, stop and report
that specific blocker. The project `.venv` was absent in that attempt; do not assume
it exists now.

Before running, verify the exact newly published candidate SHA, a clean source
checkout, Python >=3.12, the selected interpreter's import of this checkout's
`src/avchain`, and the existing dependencies. Use `GET /v1/models` and, where
supported, `GET /api/v1/models` with a 10-second timeout and `trust_env=False` to
check the already loaded text/chat instance. A model catalog entry alone does not
prove that it is loaded. A 401/403 is an authentication blocker, not permission to
weaken security. Preserve the earlier inconclusive report unchanged.

### Historical experiment: reasoning disabled per request (completed, failed B)

The execution below has already completed on
`9b12363180a1ae982f8d04ce08678909253d78ec` (historical reference retained privately).
See the retained failure report (historical reference retained privately).
All three returned structured outputs were valid and reported zero reasoning
tokens. The run stopped at B containment, before B recovery or final benign
analysis. Its old failure artifact discarded the partial receipts; B's selected
actions and exact failing subcheck cannot be reconstructed. Do not interpret the
historical command below as an instruction to repeat or overwrite that evidence.

The checkpoint repair report (historical reference retained privately)
documents the demonstrated reporting defect and deterministic action-subset tests.
It does not establish a successful real-model B run or change the inference policy.
Any subsequent local experiment requires the exact reviewed/published candidate,
separate execution authorization, the same approved model settings and a fresh
output directory (for example `reports/incident_response_local_checkpointed/`).
Preserve all three existing local evidence directories unchanged. No automatic
rerun, extra completion, alternative model or silent deterministic fallback is
introduced by this repair.

The completed 3,072-token experiment (historical reference retained privately)
finished with exit 2. Its first source-A response was valid; the second consumed
3,069 reported reasoning tokens inside 3,072 completion tokens and returned no JSON
content. No containment was applied. Preserve that evidence and the earlier local
report unchanged. Do not repeat either historical configuration.

The revised configuration keeps the same loaded `slm-production-evaluation`
instance (`gemma-4-12b-it-qat@q4_k_xl`, context 8,192), schema, temperature 0,
**3,072 output tokens, 300 seconds per request and zero retries**. The only inference
setting change is **`--reasoning off`**, sent as **`reasoning_effort: "none"`** to
`/v1/chat/completions`. Do not send the native API's literal `off` to this endpoint.
There is no prompt/template edit, server setting change, reload, download or
provider switch.

[LM Studio's 0.4.8 notes](https://lmstudio.ai/changelog/lmstudio/lmstudio-v0.4.8)
introduce this request parameter. The exact endpoint mapping is documented in
[LM Studio's support response](https://github.com/lmstudio-ai/lmstudio-bug-tracker/issues/2057#issuecomment-4745710461).
The installed application's exact version was not recorded in the retained reports;
this guide does not infer it. The existing model metadata explicitly advertises
`off` and `on`; the code rereads that capability for the exact loaded instance before
its first completion, with a 10-second maximum metadata deadline, no retry and no
proxy inheritance. A missing capability, missing loaded alias, malformed response,
401/403 or timeout blocks the experiment before inference. A metadata default of
`on` is expected to remain unchanged by a per-request override.

The report records `off_requested` separately from observed usage. A completion
with positive reported reasoning tokens or nonempty reasoning text is marked
`reasoning_observed`; missing/invalid reasoning usage is `unknown`. Either stops
this experiment before using that output for containment. Only an explicit zero
with no nonempty reasoning fields yields `zero_reasoning_reported`. This is server
telemetry, not proof of hidden model computation. Google documents
[Gemma's thinking control and empty thought-channel handling](https://ai.google.dev/gemma/docs/capabilities/thinking);
model-template documentation alone does not prove an installed server honored an
override. No reasoning text is retained or promoted to a final answer.

After the revised candidate has been published and execution authorized, reuse the
verified existing `$py` and process-local `PYTHONPATH` from the retained local report.
Check a clean checkout at the exact candidate SHA, source import, same loaded model
and context, and absence of another active lab process. Capture the app version if
readily exposed, without installing anything. Then execute exactly once:

```powershell
& $py -m avchain.scripts.run_incident_demo --mode local_llm --model "slm-production-evaluation" --base-url "http://127.0.0.1:1234/v1" --max-tokens 3072 --timeout-seconds 300 --reasoning off --output reports/incident_response_local_reasoning_off/incident-llm.json
$LASTEXITCODE
```

The integrated lab makes at most four completion calls, stops at the first failure,
and never retries. The maximum client request budget is 20 minutes plus one
10-second metadata lookup and bounded lab work. Client cancellation does not prove
that the server immediately stopped generating. Do not start another configuration
or increase the budget after a failure.

Retain stdout, stderr, elapsed time, exit code, before/after loaded metadata and the
JSON report even on exit 2. Preserve source and previous evidence hashes. Do not
substitute a separate rules run; the successful integrated path already compares
rules on the same observations. Accept the complete journey only if actual results
show valid real outputs, the same signed package used by A/B, verified canary
containment/recovery 1→0→1, restoration, unchanged benign control and unchanged
source. Otherwise report the exact blocked or unreached stage. A unit-test double,
HTTP 200, requested override or one valid answer is not real end-to-end acceptance.
