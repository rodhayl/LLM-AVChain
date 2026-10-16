# Security Policy

## Scope

LLM-AVChain is a research proof-of-concept repository, not a production security platform.

That means:

- some trust and hardening controls are intentionally partial
- the repository should not be treated as production-ready defense software
- security reports are still welcome and useful

## Reporting A Security Issue

Please do not open a public issue for sensitive vulnerabilities involving:

- secret handling
- signing and trust boundaries
- evidence integrity
- unsafe sample behavior
- launcher/runtime exposure

Use [GitHub private vulnerability reporting](https://github.com/rodhayl/LLM-AVChain/security/advisories) and select **Report a vulnerability**. This channel is enabled for this repository and sends the report privately to its maintainers. Sign in to GitHub if prompted.

Include the affected commit/version, impact, safe reproduction steps and relevant sanitized evidence. Do not include credentials, private keys, personal data or real malware. Keep exploitation details out of public issues until coordinated disclosure.

## Safety Rules For Contributions

- Do not add real malware, droppers, or exploit payloads.
- Do not add samples that execute destructive behavior.
- Keep all demo threats benign and clearly labeled as simulants.
- Do not commit secrets, keys, or `.env` files.

## Security Posture Today

Implemented:

- API-key protected service endpoints
- digest-addressed evidence linkage
- signed validator proposals
- optional signed endpoint feedback with simple trust metadata

Still partial:

- JWT or mTLS
- RBAC
- endpoint attestation
- stronger trust scoring
- production observability and incident-response workflows

See [scope and reproducibility](docs/PUBLICATION_AND_REPRODUCIBILITY.md) for the current honest status.
