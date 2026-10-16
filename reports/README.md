# Validation and historical fixtures

## Sanitized snapshot validation

See [public_readiness_validation.json](public_readiness_validation.json) for the new source snapshot, actual local checks and unresolved platform/hosting gates. Earlier counts below are dated historical results.

## Historical source baseline (2026-10-15)

The 2026-10-15 dependency/license candidate passed **390 tests, 4 skips, 2 deselections; 92.56% coverage**, plus Ruff, format, strict mypy, dependency consistency and distribution checks. The integrated `b6280ef1` runtime/test/config inputs were byte-identical to that candidate; all 80 resolved installed dependency versions matched. These results do not cover the full dependency-minimum matrix or a new native/model campaign.

The dated compatibility receipt, dependency/license review and archive audit are
retained with the private pre-cleanup backup. They are historical evidence, not
public download targets or validation of every future candidate. Current public
fixtures are listed below.

The 2026-10-15 hygiene-only change removed superseded plans, bootstrap copies, drafts and generated audit output. That earlier change left source, tests, dependencies, license, operational configuration and workflow bytes unchanged. Its dated focused validation is recorded in [validation.json](validation.json).

## Required retained fixtures

These are intentional regression/research inputs, not active runtime output:

- [incident-v4 evidence](incident_response_local_permission_v4/): the research continuation pins the public `REPORT.md` derivative and the original-byte `incident-llm.json` and `verification.json`. External dependency-environment identifiers in the report, `preflight.json` and `execution.json` use synthetic aliases. Original and public report hashes are recorded separately; outcomes, signatures, expiry and verification bytes are unchanged. Linked supporting files keep the derivative navigable.
- `incident_response_local_checkpointed/incident-llm.json` and `incident_response_local_verdict_v2/incident-llm.json`: native-abstention regression inputs.
- `incident_response_local_transfer_permission/incident-llm.json`: native permission-failure regression input.
- [Permission-contract repair](43_INCIDENT_PERMISSION_CONTRACT.md): the dated pre-run rationale linked by the incident-v4 report derivative. Its then-`NOT_RUN` status was superseded by the later bounded [incident-v4 run](incident_response_local_permission_v4/REPORT.md).

The historical incident-v4 package is expired and is never authority to execute remediation now. The retained fixtures establish only their documented synthetic laboratory observations.

## Archived material

Superseded reports and build archives are retained only in the private
pre-cleanup backup, outside the intended public distribution. Historical
packages carry older dependencies and incomplete license notices; they must not
be installed or republished as current releases. The public source does not
require downloading them. A repository-history replacement cannot withdraw
copies that others already downloaded or independently retained.
