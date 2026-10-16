# Publication and reproducibility

LLM-AVChain is a lifecycle-governed CTI architecture with a runnable research prototype. Use the [final paper](02_LLM-AVChain_Final_Paper.md) for the research narrative, [CITATION.cff](../CITATION.cff) for attribution, and a commit SHA for the exact software version.

## Reproduce

Follow the [setup and verification commands](../README.md). For a standalone in-process simulation, run `python -m avchain.scripts.run_central_demo --output artifacts/central-demo.json`. The deterministic lifecycle demonstration, `python -m avchain.scripts.run_demo`, requires the running local service stack described in the setup guide. Source and tests cover digest-linked evidence, signed proposals, consensus transitions, coverage review, hashed endpoint feedback, bounded STIX/TAXII and reviewer interfaces.

Separate demonstrations document their own assumptions:

- [Central checks](CENTRAL_DEMO.md): simulated coverage, two logical workers.
- [Incident response](INCIDENT_RESPONSE.md): owned benign fixtures and optional local inference; model proposals, validator signatures and local execution permission are distinct.
- [Research continuation](RESEARCH_CONTINUATION.md): historical real-model evidence plus a fresh deterministic central simulation. Expired historical signatures do not grant current execution authority.

See [dated validation and fixture provenance](../reports/README.md). Historical test counts describe their recorded candidate/environment, not every future installation or the dependency-minimum matrix.

## Limits

Do not present this prototype as general malware detection, complete AV/EDR, full-stack live-model effectiveness, production TAXII interoperability, native acceptance on every platform, production authentication/observability/resilience, or completed paper-scale empirical evaluation. Mocked-model and rules tests are not live-model evidence. One synthetic native run does not establish repeatability or real-world accuracy.

The sdist and wheel deliberately package application source and metadata, not repository tests or research fixtures. Clone the repository at the cited commit to reproduce fixture-dependent experiments. Build a fresh distribution from current source; historical archives in Git history contain older dependencies and incomplete license notices and are not release artifacts.

## Sanitized publication snapshot

This snapshot starts a new public source history. Superseded drafts, development plans, logs, audits and obsolete distributions are retained privately rather than linked for public download. The current tree keeps contracts, reproduction instructions, source/tests and necessary research fixtures. A documented public derivative removes unrelated workspace identifiers from incident-v4 provenance; the signed incident data and verification result are unchanged.

Historical results describe only their recorded candidate and environment. They are not fresh acceptance evidence for this snapshot. See the current [validation record](../reports/validation.json). Replacing a Git branch cannot revoke copies already downloaded, remove GitHub-managed pull-request refs, clear external forks, or prove cached historical objects have been purged. Those surfaces require separate host-side verification before claiming complete historical removal.
