# Incident-v4 native permission experiment: PASS

Public privacy-preserving derivative prepared 2026-10-16. External dependency-environment identifiers have been replaced with synthetic aliases, and the original source link is retained as a commit identifier. These aliases are not local paths to reproduce. Path-related observations describe the original run. Recorded outcomes and signed evidence are unchanged. This report is not byte-identical to the original; its original SHA-256 is `040838bb4dbd3bc3db55b944aa2039a1d8e5c0ab666694681c4bf1ad9fca00e8`.

Date: 2026-10-11, Europe/Madrid (CEST, UTC+02:00). Tested SHA: `0a05947e97aae5e8035ab47bbe20fdec845ab06b`, branch `feat/incident-response-knowledge-20261011`, repository `rodhayl/LLM-AVChain`. Windows 11 build 26200 AMD64, CPython 3.13.15.

**PASS for this single bounded synthetic laboratory run.** Both A/B applied the same signed package, each contained and restored its canary **1→0→1**, and published feedback. The authorized control was actually **`benign`**, selected no actions, preserved its bytes, and continued transferring one canary. No failed checks or NOT_RUN stages remain.

## Candidate and fixed configuration

The existing checkout advanced by fast-forward from `3d28b02be1986660b118bf3e3dbcabdf358137d6` to the exact requested candidate. The existing untracked `incident_response_local_source_v3/` evidence was preserved. Read [the permission contract](../43_INCIDENT_PERMISSION_CONTRACT.md). Windows process inventory confirmed no active incident laboratory. No installations, offline test repetitions, clones, worktrees, model reloads, product edits or security changes.

Verified `sys.executable` as the existing `../dependency-env-1/.venv/Scripts/python.exe`, with documented process-local PYTHONPATH: checkout `src`, existing dependency-env-1 and dependency-env-2 site-packages. Import resolved to this checkout's `src/avchain/__init__.py`. [Before](preflight.json)/[after](model-after.json) metadata confirm unchanged loaded **`slm-production-evaluation` / `gemma-4-12b-it-qat@q4_k_xl`**, Gemma 4 12B Q4_K_XL, context **8192**. Model-list reads used httpx, `trust_env=False`, timeout 10 seconds.

Imported prompt and all four completion diagnostics match **`incident-v4`** and the required SHA-256:

`d4dd0ba222cdae3cb0aa277a94e7315add6525f042219f6965fefa4b3c832b50`

## Exactly one execution

```powershell
& $py -m avchain.scripts.run_incident_demo --mode local_llm --model "slm-production-evaluation" --base-url "http://127.0.0.1:1234/v1" --max-tokens 3072 --timeout-seconds 300 --reasoning off --output reports/incident_response_local_permission_v4/incident-llm.json
```

Start **16:56:47.229+02:00**, end **16:58:52.697+02:00**; **125.462 seconds**, exit **0**. Four real structured outputs validated, all `finish_reason=stop`, explicit **reasoning_tokens=0**, zero reasoning-field bytes, and `zero_reasoning_reported`. Usage (prompt/completion/total): source **2341/457/2798**, A **4107/516/4623**, B **4136/462/4598**, control **4239/342/4581**. The model remained fixed; JSON Schema, temperature 0, 3072-token cap, 300-second per-request deadline, `reasoning_effort="none"`, zero retries and no fallback were preserved.

| Case | Actual decision/actions | Retained result |
|---|---|---|
| Source | `suspicious`; quarantine-hook | Source case published and linked |
| A | `suspicious`; quarantine-hook | Actual operation **`quarantine_file` only**; receipt `applied`; recovery `rolled_back`; canary **1→0→1**; feedback PASS |
| B | `suspicious`; quarantine-hook | Actual operation **`quarantine_file` only**; receipt `applied`; recovery `rolled_back`; canary **1→0→1**; feedback PASS |
| Authorized control | **`benign`**, actions `[]` | Bytes unchanged; transfer **1→1**; no remediation executed |

The model did not select `disable-hook`; neither node's receipt claims hook disabling. All stage statuses, receipts, operation digests, feedback evidence digests and control checks are retained in [the complete sanitized result](incident-llm.json). `failed_checks=[]`, `NOT_RUN=[]` in the independent verification; the harness reports every stage PASS.

## Provenance and publication checks

Verified unsigned draft digest: `bfd5bd098f6493e51fe9f60560b730508c7ed1fc0be64e35041e4dd3e9bf5af0`. Two distinct Ed25519 package signatures verified; A/B receipt digests match common signed package **`3b46b9290de8ec2939a5d22dd386cea512e7dea7b24adb7ffadd736f3b619cd7`**.

All investigated nodes received source-case digest `a0597111c9f042577a7e47bbed35c067a52cc33e16b0df3226b75012af1713b5` linked to source-incident digest `ef1ffa4ae4435ff0f3c5ee1f3b1f88f20c622dbedcb64af5ce68a396ca0681a5`. Reconstructed known synthetic bytes in memory, verified artifact hashes, canonical source-case/incident hashes, signed allowlist, exact original draft/context input digest and every enriched node input digest. The same input digests were supplied to the separate rules comparisons; rules did not override model decisions.

[Verification](verification.json), [execution](execution.json), [stdout](stdout.txt), [stderr](stderr.txt) (empty), [source/prior-evidence hashes](integrity-before.json), and model metadata are retained. Source hashes and harness code digests match before/after. All **seven** previous local evidence directories remain byte-identical, including the untracked v3 directory. No remaining `avchain-owned-lab-*` directory was found after the run.

For small sanitized publication, the successful report's artifact excerpts, model explanations/hypotheses and receipt prose were omitted, while retaining all structured decisions, stages, counts and receipts. Canonical source-case bytes and their digest were unchanged; its prose fields were already empty. Stream encoding/newlines were normalized. No secrets, raw reasoning or full application logs are published. Publication is limited to this new directory via normal `[skip ci]` commit/push after checking concurrent remote advances; no merge or release.

This proves the requested synthetic A/B/control journey on this candidate and configuration once. It does not measure general detection accuracy, repeatability or production readiness. The signed case transfers source observation/decision before containment, rather than proof of an earlier successful remedy outcome.
