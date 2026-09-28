# Project Change Log

This file records changes to project scope, architecture, requirements,
or proof strategy.

The formal UBI Stage 9B brief must trigger a new blueprint/control version.

---

## 2026-09-14T12:05:46.8344008Z - Phase 3A

Created TraceSOC-native evidence contract.

Added:
- src/tracesoc/models.py
- src/tracesoc/evidence/identity.py
- tests/unit/test_evidence_contract.py
- docs/evidence-contract.md
- project-control/phase3a-contract-validation.json

Validation:
- compile PASS
- 8 unit tests PASS

Stage 9A production source copied: FALSE
---

## 2026-09-14T12:29:37.1757832Z - Phase 3B

Added TraceSOC-native four-source JSONL adapter slice.

Sources:
- Sysmon
- Windows Security
- PowerShell
- Zeek

Fixture accounting:
- 16 total
- 12 accepted
- 4 quarantined

Validation:
- Python compile PASS
- 18 full unit tests PASS
- adapter accounting PASS
- detector-facing fixture metadata leaks: 0

Detection logic added: FALSE
Correlation logic added: FALSE
Real evidence acquired: FALSE
---

## 2026-09-14T12:52:40.0263264Z - Phase 3C

Added first TraceSOC behavioral detector.

Detector:
TRC-DET-001 — PowerShell web-retrieval behavior

Input:
SemanticEvent only.

Validation:
- compile PASS
- 26 full unit tests PASS
- static anti-hardcoding PASS
- production detector count exactly 1

Correlation added:
FALSE

Real evidence acquired:
FALSE
---

## 2026-09-14T13:00:31.6716194Z - Phase 3D

Added one bounded cross-source correlation and one synthetic finding.

Correlation:
TRC-CORR-001

Finding:
FINDING-001

Validation:
- 36 unit tests PASS
- two-run finding identity PASS
- adjacency-only correlation rejected
- static anti-hardcoding PASS
- malicious intent claim FALSE

Second detector added:
FALSE

Real evidence acquired:
FALSE
---

## 2026-09-14T13:20:25.8872945Z - Phase 3D.1

Fixed platform-dependent FINDING-001 serialization discovered by the
Phase 3E independent integrity check.

Added:
- canonical finding JSON byte serializer;
- LF-only binary output contract;
- four serialization tests;
- machine-readable repair proof.

Historical finding hash:
c57f110ed7b3f27aed59f8e93f6908e39997aa30e91ba181c5030f0e093dc964

Canonical finding hash:
fbb56699bb3f1dd5f75f5ccf153d10f0956be3940ed55a9edf3c9667e89e3c90

Finding semantics changed:
FALSE

Detection/correlation logic changed:
FALSE
---

## 2026-09-14T13:24:52.6132607Z - Phase 3E

Added TraceSOC finding explanation and raw-evidence verification CLI.

Command:
python -m tracesoc explain FINDING-001

Serialization:
tracesoc-finding-json-v1

Canonical finding SHA-256:
fbb56699bb3f1dd5f75f5ccf153d10f0956be3940ed55a9edf3c9667e89e3c90

Validation:
- 48 unit tests PASS
- canonical finding hash verified
- 2/2 raw evidence hashes verified
- exact line/byte locator agreement PASS
- tamper detection PASS
- repository path escape rejection PASS
- deterministic explain output PASS

Production detectors:
1

Production correlations:
1

Real evidence acquired:
FALSE
---

## 2026-09-14T13:32:16.2798818Z - Phase 4A

Defined TraceSOC real-evidence acquisition control plane.

Added:
- acquisition plan;
- acquisition register;
- evidence role policy;
- evidence manifest schema;
- machine-readable Phase 4A proof.

Real evidence acquired:
FALSE

Evidence download authorized:
FALSE

Next:
Phase 4B source discovery and adjudication.
---

## 2026-09-14T13:37:47.1216829Z - Phase 4B

Completed current external evidence-source research and source-role
adjudication.

No evidence was downloaded.

Approved candidate count:
5

Deferred:
3

Rejected:
1

Holdout isolation established before acquisition.

Next:
Phase 4C controlled acquisition.
---

## 2026-09-14T13:49:10.1555380Z - Phase 4C.1

Performed first controlled real-evidence acquisition.

Acquired:
- one pinned Splunk PowerShell Operational log;
- IoT-23 Capture-34-1 publisher README;
- IoT-23 original PCAP;
- IoT-23 publisher-derived Zeek conn.log.

All four artifacts passed:
download hash
-> controlled storage
-> post-storage hash
-> final hash revalidation.

No analytical parsing or rule tuning occurred.
---

## 2026-09-14T13:55:20.4373699Z - Phase 4C.1A

Added permanent evidence provenance/citation catalogue, evidence coverage
matrix, and derived challenge-corpus plan.

Confirmed current evidence corpus is intentionally incomplete.

Real telemetry represented:
PowerShell, Zeek/network.

Missing core real telemetry:
Sysmon, Windows Security.

No evidence downloaded.
---

## 2026-09-14T14:09:10.0607670Z - Project-control consolidation

Established a reusable master machine-readable project record.

Preserved test-ledger.jsonl as the single consolidated machine-readable test
history required by the Stage 9A carry-forward feedback.

The master record now indexes and reconciles evidence integrity, coverage,
phase proofs, external manifests, citations, and core control records.
---

## 2026-09-14T14:12:36.9777160Z - Master lineage semantics repair

Corrected master-record Git lineage semantics.

Replaced ambiguous repository.head with repository.parent_head_at_build.

Added a post-commit validation rule:

git HEAD^ == master.repository.parent_head_at_build

No analytical or evidence content changed.
---

## 2026-09-14T14:20:44.4725852Z - Phase 4C.2

Completed real-format structural census and acquired real Sysmon and Windows
Security evidence from the pinned Splunk attack_data revision.

Core four-family real telemetry coverage is now satisfied.

All six registered raw evidence artifacts passed SHA-256 revalidation.

No parser or detector behavior was changed.

Master project-control record rebuilt as a mandatory phase-closure step.
---

## 2026-09-14T14:52:12.1396456Z - Phase 4C.3

Acquired two independent benign IoT network controls from the publisher's
IoT-23 v2 layout.

Recorded explicit source-version refinement from the Phase 4B logical
scenario approval.

Preserved immutable originals, provenance metadata, exact locators, hashes,
and human-readable source references.

No detector tuning or holdout inspection occurred.
---

## 2026-09-15T07:19:40.4080868Z - Phase 4C.4

Selected Nextron Systems evtx-baseline v0.8.4 win10-client.tgz as the
independent endpoint BENIGN_CONTROL source.

No archive was downloaded.

Recorded publisher-provided SHA-256 as the future acquisition integrity gate.

Added the defense-ready Evidence README as a mandatory evidence-corpus closure
requirement.
---

## 2026-09-15T07:49:17.2457541Z - Phase 4C.5 recovery and completion

Recorded red -> diagnosis -> repair -> green for the initial safe-extraction
directory collision.

The already downloaded archive matched the publisher SHA-256 before and after
the failed attempt and was reused without redownloading.

No raw evidence or project-control record had been modified before the initial
stop.

Completed immutable raw archive storage and three derived EVTX lineage paths.
---

## 2026-09-15T07:57:06.0365876Z - Phase 4C.6

Established sealed holdout isolation before acquiring CAND-005.

Defined integrity-only pre-freeze access, mandatory analytic freeze, explicit
holdout access logging, and one-way first-use evaluation.

Selected a lean initial acquisition scope of README plus publisher Zeek log.

Deferred the 472 MB PCAP because packet-level holdout replay is not currently
required.

Excluded labels.config before evaluation to reduce information leakage.
---

## 2026-09-15T08:01:42.6285509Z - Phase 4C.6A

Refined the planned CAND-005 holdout artifact before acquisition.

Replaced the planned publisher-labeled 947 MB Zeek file with the publisher's
plain 668 MB conn.log.

The labeled Zeek file and labels.config are now explicitly deferred until
post-prediction scoring.

No holdout payload or labels were accessed.
---

## 2026-09-15T08:59:11.8928883Z - Phase 4C.6B

Re-adjudicated the selected network holdout after safely aborting the oversized
Hajime transfer.

Recorded the aborted transfer explicitly in the holdout access history.

Approved CAND-011 Muhstik as the replacement sealed network holdout.

No semantic holdout payload or publisher labels have been accessed.
---

## 2026-09-15T09:23:10.2661046Z - Phase 4C.7

Acquired CAND-011 Muhstik as the sealed TraceSOC network holdout.

Only README provenance metadata and the publisher's plain Zeek conn.log were
acquired.

The conn.log received integrity-only access: transport, file size, SHA-256,
controlled copy, post-storage SHA-256 verification and read-only protection.

No rows, fields, labels or semantic payload were inspected.

No normalization, detector execution or correlation occurred.

The labeled connection log, labels.config and PCAP remain unacquired.

The same-IoT-23-corpus limitation is explicitly retained.
---

## 2026-09-15T09:26:04.3391886Z - Phase 4C.8

Adjudicated remaining corpus gaps after sealed holdout acquisition.

Confirmed three distinct suspicious development scenarios and broad publisher
diversity.

Determined that no additional external dataset acquisition is currently
justified.

Challenge corpus work will use derived artifacts with parent lineage.

Scale will first be tested against the current corpus after real-format
adapters exist.

No holdout semantic or label access occurred.
---

## 2026-09-15T09:35:56.9638102Z - Phase 4D.1

Converted the Phase 4D.0 real-format census into a formal compatibility
matrix.

Retained all four synthetic JSONL adapters as regression controls.

Classified six real-format paths as requiring additive adapter support.

Isolated the benign Sysmon EVTX readability issue as DIAGNOSIS_REQUIRED rather
than assuming corruption.

Explicitly prohibited publisher Zeek labels from becoming detection selectors.

No holdout semantic access and no analytic code change occurred.
---

## 2026-09-15T09:43:18.4057221Z - Phase 4D.2

Closed the benign Sysmon EVTX readability investigation.

Windows offline log metadata reports numberOfLogRecords=0 for the exact
hash-identical Sysmon EVTX.

Readable PowerShell and Security controls report 121 and 3448 records
respectively.

Corrected the current interpretation of the endpoint benign evidence:
populated benign Sysmon event data is not established by the Nextron artifact.

No corruption, extraction failure or TraceSOC parser failure is claimed.

No external evidence acquisition was reopened.
---

## 2026-09-15T10:07:37.2432847Z - Phase 4D.3B

Added exact-byte raw readers for concatenated Windows Event XML streams and
Zeek ASCII/TSV logs.

Validated the readers against the acquired DEVELOPMENT PowerShell, Sysmon and
Zeek sources.

All accepted real records matched an independent raw-record census.

All real-source RawLocator byte/hash checks passed.

Focused tests passed 5/5 and the full regression passed 53/53.

No existing JSONL adapter, canonical model, detector, correlation logic or
holdout state was changed.