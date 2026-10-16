# Permission-aware incident-v4 contract

Historical narrative below is a dated summary. Retired audit reports and commit references are retained privately; they are not independently reproducible from this sanitized snapshot. Current retained JSON fixtures and tests are the reproducible evidence shipped here.

2026-10-11. Base: `3d28b02be1986660b118bf3e3dbcabdf358137d6`.

## Verified finding

The native transfer-permission run (historical reference retained privately)
tested `fb353953e113c253274ca439da64bf1a2afcfb19` once. All four outputs validated
with zero reported reasoning tokens. A/B completed containment, restoration and
feedback, but the granted control returned suspicious with both actions. Its guard
correctly stopped before execution or final preservation checks: overall **FAIL**.

The input audit (historical reference retained privately)
independently reconstructs all four inputs from known synthetic bytes (including
Windows CRLF). All input digests and wire lengths match. The control did receive
its exact matching local grant; retrieved history described the ungranted source.
There is no missing-context diagnosis here.

Incident-v3 never explained `case_context`/grants and defined benign as absence of
the relevant behavior. That is inconsistent with the new equivalent authorized
transfer. This demonstrable task-contract defect does not establish the model's
internal reason or prove that history contaminated its decision.

## Minimal repair and boundaries

- Incident-v4 defines benign to include explicitly permitted behavior without a
  separate response need. It explains exact actor/resource/receiver matching,
  complete versus unknown scope, and current facts versus historical decisions.
- A grant covers only that transfer, never unrelated risk, blanket harmlessness
  or remediation approval. File instructions/role claims and historical grants
  cannot provide current permission. Missing context does not imply permission
  or its absence. Conservative incomplete-record handling is unchanged.
- No new schema, computed verdict input, rules fallback, action filter, model
  setting, capability or executor change. Every raw valid model decision remains
  binding. The same prompt applies to all cases without filename/node exceptions.
- Control diagnostics now distinguish proposed actions, changed bytes and a
  failed final transfer. A rejected plan has no fabricated later results; changed
  bytes stop before replay. The original report's missing code is not rewritten.

Prompt SHA-256: `d4dd0ba222cdae3cb0aa277a94e7315add6525f042219f6965fefa4b3c832b50`.
Length: 2,539 UTF-8 bytes, versus v3's 2,597. Native v3 control used 4,858 prompt
tokens with context 8,192 and max output 3,072. Shorter bytes do not prove v4 token
headroom; its real tokenizer usage remains unmeasured.

## Offline verification

Ruff and strict mypy PASS. Full suite: **344 passed, 1 Windows-only skip**, 92.03%
coverage, 39.73 seconds. Only inherited test-process proxy variables were cleared
for loopback; no install or persistent configuration change. New tests cover scoped,
absent/incomplete and conflicting historical permission, hostile file-role claims,
unchanged wire/schema and unmodified suspicious/benign/uncertain outputs.

Replaying all four retained native decisions still **fails** the control guard,
with A/B recovery preserved. These transport doubles verify contracts and safety,
not actual model understanding. Native acceptance of v4: **NOT_RUN**.

See verification (historical reference retained privately) and
independent review (historical reference retained privately).
Earlier failures and their evidence remain intact. After reviewed publication,
the next check is one bounded native run on the same authorized model/settings;
continued false positives or abstentions remain FAIL, with no retry or correction.
