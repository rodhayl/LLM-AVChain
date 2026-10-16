# LLM-AVChain: Lifecycle-Governed Cyber Threat Intelligence with LLM Validators, Consensus and Endpoint Feedback

**David Munoz Sanchez**

---

## Abstract

Traditional cyber threat intelligence (CTI) pipelines accumulate stale indicators, propagate weakly curated artifacts, and provide limited assurance that shared intelligence translates into actionable defense. This paper introduces LLM-AVChain, a standards-aligned architecture that governs threat intelligence as a living system. Each threat entry progresses through explicit lifecycle states -- Suspected, Confirmed, Review, and Deprecated -- rather than remaining indefinitely active. Large language models (LLMs) are a target validator modality in the architecture, while the current proof-of-concept uses deterministic heuristics that submit the same structured recommendations through the consensus path. Evidence is stored off-chain but integrity-bound to an append-only ledger, and dissemination is designed to align with established standards including STIX 2.1, TAXII 2.1, TLP 2.0, and ATT&CK. Endpoint agents consume confirmed entries, fuse them with local telemetry, apply bounded remediation, and submit sanitized feedback. The architecture is presented as a design proposal with a reproducible evaluation methodology grounded in public datasets. It contributes a lifecycle object model, a validator and consensus architecture, an endpoint feedback loop, a threat-trust-and-privacy analysis, and a proof-of-concept specification suitable for implementation and empirical study.

**Keywords:** cyber threat intelligence, large language models, consensus, threat lifecycle, endpoint security, indicator management

---

## 1 Introduction

Cyber threat intelligence is integral to incident response and threat-informed detection engineering, yet operational CTI pipelines exhibit persistent weaknesses. Indicators often remain active long after their utility fades. Retirement logic is ad hoc, and downstream consumers receive blocklists with little context or connection to local remediation. NIST guidance emphasizes that intelligence is most effective when it is actionable, contextualized, and integrated into continuous risk management [1]. The interoperability stack is mature: STIX 2.1 [2] encodes objects, TAXII 2.1 [3] transports them, TLP 2.0 [4] constrains dissemination, and ATT&CK [5] provides a behavioral vocabulary. However, these standards do not prescribe lifecycle governance.

Meanwhile, recent work shows that large language models can assist malware analysis, threat research, and CTI extraction [6, 7], but they require external grounding and human oversight. Studies on LLM-assisted vulnerability assessment and malware summarization highlight both promise and brittleness under distribution shift and adversarial manipulation [8, 9]. There remains no unified architecture that combines lifecycle governance, AI-assisted analysis, consensus-based decision-making, and endpoint feedback.

This paper proposes LLM-AVChain, a system in which threat entries progress through explicit states, validators analyze evidence using LLMs, consensus determines promotions and retirements, and endpoint agents close the loop by providing operational feedback. The goal is not to claim a finished production system but to present a coherent design accompanied by a proof-of-concept specification that others can build upon, evaluate, and extend.

The contributions of this paper are:
1. A lifecycle object model for threat intelligence with explicit state governance.
2. A validator and consensus architecture that bounds LLM authority.
3. An endpoint feedback loop connecting shared intelligence to local enforcement.
4. A security, privacy, and trust analysis of the proposed system.
5. A reproducible evaluation methodology grounded in public datasets and baselines.

---

## 2 Background

### 2.1 CTI Standards and Platforms

Structured CTI sharing is built upon specifications maintained by OASIS and other standards bodies. STIX 2.1 [2] defines a common language for representing cyber threat information using a graph-based data model of objects and relationships. TAXII 2.1 [3] specifies a transport protocol for exchanging STIX content through collections and channels. TLP 2.0 [4], maintained by the Forum of Incident Response and Security Teams (FIRST), provides distribution control labels ranging from TLP:RED (restricted) to TLP:CLEAR (unrestricted). MITRE ATT&CK [5], now at version 18.1, offers a comprehensive vocabulary of adversary tactics, techniques, and procedures (TTPs) organized by platform and domain.

Operational platforms implement these standards at scale. MISP [10] supports collection, correlation, enrichment, and sharing of indicators across communities. OpenCTI [11], developed by Filigran, provides a graph-based knowledge management platform built on STIX with native ATT&CK integration. These platforms handle ingestion and sharing effectively but do not enforce explicit retirement logic or multi-validator governance for individual indicators.

### 2.2 Large Language Models in Security Workflows

LLMs have demonstrated utility in malware summarization, code understanding, vulnerability explanation, and CTI extraction. Evaluations such as the CyberMetric benchmark [7] and LLM-based CTI extraction studies [6] show that LLMs can augment threat research by interpreting unstructured reports, mapping behaviors to ATT&CK techniques, and generating analyst-readable summaries. Research on LLM-assisted malware classification, including work using the EMBER2024 dataset [12], illustrates that model-based approaches can complement signature and heuristic methods for static analysis.

However, LLMs also exhibit brittleness under distribution shift, sensitivity to prompt design, and vulnerability to adversarial manipulation. Adversarial machine learning taxonomies [13] catalog data poisoning, evasion, and prompt injection attacks that can degrade LLM-based analysis. Consequently, LLMs are best treated as decision-support tools rather than autonomous authorities. Architecture design must bound their influence, require corroboration, and preserve human oversight.

### 2.3 AI Governance and Risk Management

The NIST AI Risk Management Framework (AI RMF 1.0) [14] provides a structured approach to trustworthy AI deployment, emphasizing validity, reliability, safety, fairness, and accountability. The NIST Generative AI profile (AI 600-1) [15] extends this framework to address risks specific to generative AI systems, including hallucination, data provenance, and content integrity. These frameworks support a design principle that AI components must operate within bounded, auditable, and policy-constrained workflows.

The combination of CTI standards maturity, growing LLM capabilities, and structured AI governance creates an opportunity: systems can use LLMs as analytical components while containing their authority within a governed lifecycle.

---

## 3 Design Goals and Scope

LLM-AVChain is designed around six goals:

1. **Prevent indicator rot.** Threat entries should expire or be revalidated instead of remaining active by default.
2. **Preserve interoperability.** The system should augment, not replace, standards such as STIX, TAXII, TLP, and ATT&CK.
3. **Bound AI authority.** LLMs provide recommendations, but consensus determines lifecycle transitions.
4. **Use verifiable governance.** State changes must be auditable, signed, and traceable to evidence and policies.
5. **Connect intelligence to enforcement.** Confirmed intelligence must inform endpoint detection and remediation.
6. **Minimize unnecessary disclosure.** Evidence and feedback should be shared using least-disclosure principles.

This paper outlines an architecture and evaluation methodology. It does not claim a production deployment or superiority over existing systems without empirical evidence.

---

## 4 Architecture

### 4.1 Threat Entry Model and Lifecycle

A **threat entry** is an atomic object representing a file hash, domain, URL, certificate, package, behavioral cluster, or campaign fragment. Each entry contains a unique identifier, observables, provenance and confidence metadata, ATT&CK mappings where applicable, links to supporting evidence, dissemination restrictions, and an auditable history of state transitions. The lifecycle comprises four states:

| State | Purpose | Typical entry condition | Typical exit condition |
|---|---|---|---|
| **Suspected** | Newly submitted intelligence pending analysis | Initial submission from telemetry, sandbox, or analyst | Promotion to Confirmed, or rejection/expiry |
| **Confirmed** | Actionable intelligence for distribution | Consensus-backed promotion with sufficient evidence | Review triggered by age, conflict, or coverage signal |
| **Review** | Revalidation of aging or conflicting entries | Scheduled review, contradictory evidence, or coverage signal | Reconfirmation or transition to Deprecated |
| **Deprecated** | Retained for audit, no longer active | Consensus-backed retirement | No further lifecycle transitions in the shipped POC |

This minimal lifecycle can be extended, but it suffices for the core design. Entries that remain in Suspected without validator attention are moved to Review via configurable timeout, and from Review to Deprecated if no further action is taken. This prevents orphaned indicators.

### 4.2 Evidence Pipeline and Standards Alignment

Evidence objects are stored off-chain in a controlled store -- such as object storage or content-addressable storage -- and are referenced on the ledger via cryptographic digests. This preserves integrity while avoiding ledger bloat. Evidence types include static file metadata, disassembly artifacts, sandbox traces, process and network telemetry, analyst notes, YARA matches, STIX objects, and endpoint behavioral summaries.

When distributing intelligence, entries can be serialized into STIX 2.1 objects and shared via TAXII 2.1 collections. ATT&CK mappings provide behavioral context, while TLP labels constrain redistribution. The current proof-of-concept models this interoperability boundary but does not ship a production STIX/TAXII export connector.

### 4.3 Validator Workflow

Validators are independent services that monitor entries in the Suspected and Review states. For each entry they:

1. Retrieve evidence and verify integrity via cryptographic digests.
2. Enrich with context where permitted and derive a normalized representation.
3. Map behaviors to ATT&CK techniques and related schemas.
4. Execute one or more LLM prompts, domain-specific models, or rule-based heuristics. The current proof-of-concept uses deterministic heuristics at this step.
5. Generate a structured recommendation (promote, retain, review, or deprecate) with a confidence score, explanation, and provenance.
6. Digitally sign the recommendation using Ed25519 and submit it to the consensus layer.

LLM outputs are treated as structured evidence analyses rather than ground truth. Validator diversity -- using different models, different prompts, or different analytical approaches -- mitigates model brittleness and correlated failures.

### 4.4 Consensus and State Transition Logic

The consensus layer aggregates validator recommendations and applies policy thresholds. A configurable quorum -- based on validator count, reputation, diversity, or stake -- must be met before a lifecycle transition occurs. Policies may require a minimum number of independent validators, confidence thresholds, and checks on evidence freshness.

For the baseline design, a simple majority quorum is used: if more than half of registered validators recommend promotion with average confidence at or above 0.5, the entry transitions from Suspected to Confirmed. Deprecation requires a similar majority. Ties leave the entry unchanged, deferring to timeout policies. This approach demonstrates consensus semantics while allowing future extension to weighted voting, reputation systems, or stake-based mechanisms.

Consensus reduces dependence on any single validator and provides an auditable mechanism for handling conflicting evidence and aging intelligence.

### 4.5 Endpoint Agents and Enforcement

Endpoint agents consume confirmed entries and act as bounded local decision layers. They:

- Synchronize confirmed, policy-eligible entries from the ledger.
- Inspect local telemetry for matching observables or behaviors.
- Fuse intelligence with local context and run a compact classifier or rule-assisted model.
- Select a bounded response -- alerting, quarantining, killing a process, blocking network communication, or isolating a package installation -- based on confidence thresholds and policy. The current proof-of-concept defaults this response to a logged remediation action.
- Generate privacy-minimized feedback (hashed paths, behavior IDs, remediation codes) and send it to the evidence layer.

This closed loop ensures that shared intelligence leads to local action, and that local outcomes inform global governance decisions during revalidation cycles.

### 4.6 Coverage Signal and Revalidation

To decide when a confirmed entry should be revalidated, LLM-AVChain introduces a coverage signal: when independent security engines report broad detection coverage for a threat, the entry transitions to Review rather than staying active indefinitely. The production-oriented design can consider the number of vendors detecting the threat, the diversity of those vendors, and the persistence of coverage within a sliding time window. The current proof-of-concept implements a simplified rule based on the latest report per vendor, with a minimum sample of three vendors before triggering review.

High coverage does not automatically imply obsolescence. It triggers structured revalidation, during which validators reassess whether the entry should remain active, be deprecated as redundant, or be refreshed with new evidence. This mechanism prevents indicator rot for well-known threats while preserving novel or niche intelligence that may not reach broad vendor coverage.

---

## 5 Security, Privacy, and Trust

### 5.1 Data Poisoning and Evidence Fraud

Adversaries may attempt to submit fabricated evidence or noise to force false promotions. Mitigations include multi-source corroboration, validator diversity, delayed promotion for low-confidence submissions, and rate limiting. Storing cryptographic digests of evidence supports post-hoc integrity verification.

### 5.2 Adversarial ML Risks

Validators inherit adversarial ML risks such as data poisoning, evasion, and prompt injection [13]. Inputs should be schema-constrained; prompts and models should be versioned; retrieval should be bounded to approved sources; and safety policies should prevent unsupported claims from directly affecting lifecycle state.

### 5.3 Collusion and Validator Capture

Consensus reduces but does not eliminate collusion risk. Validators should be operated by diverse organizations; voting rights can be separated from evidence access; and dissenting recommendations should be logged for review. Future work could formalize trust scoring and reduce the weight of consistently anomalous validators.

### 5.4 Endpoint Compromise

A compromised endpoint could send false feedback or suppress detections. Agents should authenticate to the platform, sign their telemetry, support attestation where feasible, and be treated as probabilistic sources rather than ground truth.

### 5.5 Privacy and Least-Disclosure Sharing

CTI systems mix public indicators with sensitive local context. LLM-AVChain uses a least-disclosure posture: raw payloads remain off-chain; telemetry identifiers are hashed, aggregated, or summarized before transmission; access is restricted by role and TLP label; and evidence and dissemination are separated to minimize unnecessary exposure. These measures align with established data minimization principles and accommodate regulatory constraints.

---

## 6 Evaluation Methodology

This paper proposes a reproducible evaluation methodology rather than reporting completed empirical results. The proof-of-concept specification accompanying this paper provides a concrete implementation plan using deterministic heuristics in place of live LLM inference, allowing controlled experimentation.

### 6.1 Research Questions

1. Does lifecycle governance reduce stale, low-value entries compared to a static feed?
2. Do multi-validator decisions improve precision over single-model decisions?
3. Does endpoint feedback improve revalidation quality?
4. What latency and resource costs are introduced by the governance workflow?
5. How well does the system preserve privacy and interoperability?

### 6.2 Datasets and Corpora

Three publicly available resources can support evaluation:

- **EMBER2024** [12] -- A large-scale benchmark for evaluating malware classifiers across multiple file types, providing labeled feature vectors for static analysis experiments.
- **AndroZoo** [16] -- A corpus of Android applications suitable for mobile malware and package-analysis experiments.
- **MalwareBazaar** [17] -- A community-driven repository of recent malware samples that can be used for enrichment and additional testing, subject to appropriate handling controls.

These datasets can be supplemented with synthetic telemetry, analyst reports, and sandbox traces generated by the proof-of-concept implementation.

### 6.3 Baselines

Relevant baselines include: (i) a static feed without retirement logic; (ii) a single-model LLM triage pipeline without consensus; (iii) a traditional machine-learning classifier using EMBER-style features; (iv) existing CTI workflows implemented through MISP or OpenCTI; and (v) human analyst review on a stratified sample. Comparative experiments should assess lifecycle improvements in addition to standard detection metrics.

### 6.4 Metrics

Evaluation metrics span multiple dimensions:

- **Governance quality:** active-entry half-life, stale-entry ratio, revalidation rate
- **Detection quality:** precision, recall, F1 on labeled datasets
- **Consensus quality:** agreement rate, disagreement entropy, time-to-decision
- **Operational cost:** promotion latency, validator inference latency, resource utilization
- **Endpoint efficacy:** time-to-alert, remediation success rate
- **Privacy and interoperability:** raw-versus-summarized evidence ratio, STIX/TAXII round-trip fidelity

### 6.5 Experimental Procedure

A staged procedure should begin with offline replay on labeled data, then simulate endpoint feedback, and finally run a controlled pilot. The first stage measures how lifecycle logic changes the active knowledge base over time. The second stage evaluates whether endpoint feedback improves revalidation accuracy. The third stage assesses operational feasibility under realistic conditions.

---

## 7 Illustrative Case Study: Contagious Interview Campaign

In early 2026, Microsoft documented the Contagious Interview campaign [18], in which state-affiliated attackers posed as recruiters and persuaded software developers to clone repositories containing malicious payloads. The campaign exploited trust relationships in professional networks and used layered obfuscation to evade initial detection.

In LLM-AVChain, such a scenario would unfold as follows. A local endpoint agent observes unusual patterns -- repository cloning followed by suspicious package execution and unexpected network egress -- and creates a privacy-minimized behavioral summary. A threat entry enters the Suspected state with the behavioral indicators as observables. Validators analyze the chain of events, map behaviors to ATT&CK techniques (such as T1204 User Execution, T1059 Command and Scripting Interpreter, and T1071 Application Layer Protocol), and, if consensus supports it, promote the entry to Confirmed and prepare it for distribution in STIX/TAXII format.

Endpoint agents at other organizations receive the confirmed entry, match incoming telemetry against the observables, and apply bounded remediation -- such as blocking execution of identified payloads and alerting security teams in the broader architecture. In the shipped proof-of-concept, this remediation step is represented by a logged action. Feedback from multiple endpoints strengthens the entry's evidence base. As coverage grows and commodity detections become reliable, the original entry moves to Review and may eventually be deprecated, with the behavioral patterns incorporated into broader detection rules.

This scenario illustrates how the architecture handles a real attack pattern without claiming to have detected that campaign in practice. The lifecycle governance ensures that the intelligence remains active only as long as it provides value, and the feedback loop connects organizational boundaries without requiring raw telemetry exchange.

---

## 8 Limitations and Future Work

LLM-AVChain has several limitations that scope the contribution accurately.

**No empirical results.** This paper presents an architecture and evaluation methodology. No completed experiments or benchmarks are reported. The proof-of-concept specification uses deterministic heuristics rather than live LLM inference.

**LLM brittleness.** LLM performance remains sensitive to prompt design, training data composition, and adversarial inputs. Novel malware families and obfuscation techniques may degrade validator accuracy. The architecture mitigates this through consensus and diversity, but does not eliminate the underlying model limitations.

**Operational complexity.** The governance model introduces operational overhead: validator management, evidence access control, consensus threshold configuration, coverage metric calibration, and review scheduling all require attention. Organizations must weigh this complexity against the benefits of structured lifecycle management.

**Coverage signal limitations.** The coverage signal can be misleading if naively interpreted. High vendor coverage may indicate widespread detection rather than obsolescence. The architecture addresses this by triggering revalidation rather than automatic retirement, but operators must configure thresholds carefully.

**Privacy guarantees.** Privacy protections depend on correct implementation of telemetry hashing, access control, and TLP enforcement. The design provides a framework, but guarantees require careful engineering and audit.

**Scalability.** The proof-of-concept uses SQLite for simplicity. Production deployments handling millions of entries and high-throughput telemetry would require distributed databases, message queues, and horizontal scaling.

Future work should focus on:
- Empirical validation using public datasets (EMBER2024, AndroZoo, MalwareBazaar) with the proof-of-concept implementation.
- Controlled pilots integrating with existing CTI platforms (MISP, OpenCTI) via standard connectors.
- Formalizing validator trust scoring and reputation-based weighting.
- Exploring local model inference (e.g., fine-tuned classifiers on ONNX runtime) as an alternative to hosted LLM APIs.
- Human-in-the-loop escalation protocols for ambiguous or high-impact entries.
- Extension of the lifecycle model to campaign-level and family-level objects.

---

## 9 Conclusion

LLM-AVChain treats cyber threat intelligence as a dynamic, auditable system rather than an append-only feed. By combining explicit lifecycle states, evidence-bound validator recommendations, consensus-based governance, endpoint enforcement, and structured revalidation, it addresses the gap between shared intelligence and operational defense. The design neither assumes that LLMs alone solve CTI governance nor claims a production-ready solution. Instead, it demonstrates that LLMs become more useful when placed within a bounded system that preserves provenance, interoperability, and auditability.

The architecture contributes a lifecycle object model, a validator and consensus framework, an endpoint feedback loop, and a reproducible evaluation methodology. With CTI standards and AI governance frameworks mature enough to support implementation, and with research caution guiding evaluation design, LLM-AVChain offers a credible path toward lifecycle-governed cyber threat intelligence and a bounded environment for evaluating validator modalities, including LLM-based ones.

---

## Declarations

**Funding:** No external funding was received for this work.

**Conflict of interest:** The author declares no conflict of interest.

**Data availability:** No new dataset is introduced. The paper references publicly available standards, platform documentation, and datasets suitable for future evaluation.

---

## References

See `03_LLM-AVChain_Final_Paper_References.md` for the complete references list.
