# TraceSOC Finalist Defense Runbook

This runbook is the current live-defense guide for the TraceSOC finalist candidate.

It is grounded in the frozen finalist authorities and must not be replaced by historical Stage 9A case-specific answers.

## 1. Candidate and freeze binding

- Project: `SOC-A5`
- Public variant: `V3`
- Private assignment set: `D3`
- Candidate: `UBI-2026-0091`
- Evidence marker: `UBI-A9-4BC183701F3C`
- Frozen technical commit: `8751a679f36b4983cdd3d2b0b35f44e9a11c4f39`
- Frozen technical tree: `fc420ee3fd1988cf578c0cf309ee3aefcccf33b2`
- Technical candidate was frozen before semantic holdout access.
- Later submission work is documentation and packaging, not post-holdout product tuning.

Assigned pack:

- File: `soc-analysis-stage-9-shared-b1.tar.gz`
- SHA-256: `df8fb093a6a69ca885a0f22518f842cf6a470232a6df821fb759a507389f2022`
- Manifest signature: `a8d15c6e852e04741c0169e57dac3bc05b9a77a869a94bf16b5c9ed4fe267fbf`
- Verified before use: `True`

## 2. Ninety-second project explanation

TraceSOC is a provenance-first SOC/DFIR evidence-reconstruction engine.

The problem it addresses is that security investigations combine heterogeneous evidence, but downstream conclusions can become detached from the exact raw observations that support them. That weakens reproducibility, analyst handoff, auditability and later review.

TraceSOC normalizes supported evidence into canonical observations while preserving exact raw locators. It then performs bounded detection, correlation, hypothesis formation, findings, narratives and response records without discarding unsupported evidence or converting uncertainty into invented certainty.

The strongest proof is the controlled six-source reconstruction: 5,442 canonical observations, all 5,442 raw-located, 32,658 detector evaluations, 5 matched detections and 6 source-level findings. A complete consequential downstream chain is mechanically reversible to the original evidence SHA-256.

Generalization was tested separately on 23,145 rows of real external Zeek evidence and a sealed post-freeze 156,458-row holdout. The holdout closes the measured ingestion/provenance-generalization question, but detection accuracy remains UNADJUDICATED because there is no valid exact labeled comparator.

The candidate also passes 524 of 524 current regression tests and 4 of 4 public acceptance classes, reproduces its core outputs deterministically, and processed a measured 198,463-record workload within the frozen workstation memory ceiling.

## 3. Architecture to explain

Forward analytical path:

```text
raw evidence
-> representation extraction
-> canonical observation
-> evidence graph
-> detection
-> bounded relationship / correlation
-> hypothesis / finding
-> narrative
-> response
```

Reverse evidentiary requirement:

```text
downstream conclusion
-> finding
-> relationship / detection
-> canonical observation
-> exact raw locator
-> original artifact
-> SHA-256
```

Key design principle: provenance is part of the event contract, not optional metadata.

## 4. Recommended proof walkthrough

Use this order during a defense so the argument moves from architecture to measured evidence.

### A. Technical freeze

Show:

`project-control/finalist-candidate-freeze-v04.json`

Explain:

- candidate was frozen before semantic holdout access;
- no post-freeze product tuning was performed;
- packaging changes do not alter the technical candidate.

### B. Controlled six-source reconstruction

Show:

`evidence/reference-case/case-manifest.json`

Measured state:

- 6 evidence families;
- 5,442 canonical observations;
- 5,442 / 5,442 raw-located;
- 32,658 detector evaluations;
- 5 matched detections;
- 6 hypotheses;
- 6 findings;
- 6 narratives;
- 6 response records.

Boundary: this is controlled interoperability evidence, not malicious ground truth.

### C. Reverse trace

Show:

`evidence/final-proof/r3-end-to-end-reverse-trace-proof.json`

Explain that the proof mechanically walks:

```text
RESPONSE
-> NARRATIVE
-> FINDING
-> HYPOTHESIS
-> MATCHED DETECTION / RELATIONSHIP
-> MATCHED CORRELATION
-> CANONICAL OBSERVATION
-> RAW LOCATOR
-> EMBEDDED RAW ARTIFACT
-> ORIGINAL ARTIFACT SHA-256
```

Boundary: reverse trace proves lineage, not maliciousness or causality.

### D. Bounded correlation examples

Use these examples to demonstrate why TraceSOC does not equate adjacency with causality:

- `TRC-CORR-004`: Windows Security 4688 to Sysmon Event 1 using same host, PID and exact image, with time bounded but not used as the sole selector.
- `TRC-CORR-005`: EML attachment to Sysmon process image by exact SHA-256 byte identity.
- `TRC-CORR-006`: Sysmon Event 1 process to Sysmon Event 3 network activity by exact normalized ProcessGuid.

What these do not prove:

- email delivery caused execution;
- matching bytes prove user action;
- process attribution proves maliciousness;
- correlation proves causality.

### E. External real evidence

Measured external Zeek result:

```text
source rows              = 23,145
canonical observations   = 23,145
source-count difference  = 0
```

Boundary: detector matches on that publisher dataset are not treated as publisher ground truth or as an accuracy measurement.

### F. Sealed post-freeze holdout

Show:

`evidence/final-proof/holdout-final-adjudication.json`

Measured result:

```text
source rows              = 156,458
canonical observations   = 156,458
detector evaluations     = 938,748
matched detections       = 0
findings                 = 0
```

State explicitly:

`DETECTION_ACCURACY_STATUS=UNADJUDICATED`

Why: there is no valid exact labeled comparator for the sealed artifact.

Do not say zero detections prove success. Do not say zero detections prove failure.

**Never rerun the sealed holdout during normal defense or packaging.**

### G. Regression and anti-hardcoding

Show:

`results/acceptance/public-test-results.json`

Current state:

- 524 discovered;
- 524 run;
- 524 passed;
- 4 / 4 public acceptance classes PASS.

Show grader-closure proof if challenged:

`evidence/final-proof/final-grader-feedback-closure-audit.json`

Selected finalist anti-hardcoding literals had zero production hits.

Boundary: 524 / 524 regression is software validation, not a detector-accuracy percentage.

### H. Reproduction controls

Show:

Current finalist clean build/test proof:

`project-control/finalist-one-command-reproduction-validation.json`

Current one-command entry point:

`powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\finalist-reproduce.ps1`

Validated state:

- 524 / 524 current regression tests PASS;
- 4 / 4 public acceptance classes PASS;
- product source remained unchanged;
- test source remained unchanged;
- the sealed raw holdout was not accessed.

Normally show the recorded proof during a defense rather than rerunning the full clean build/test unless a reviewer explicitly asks for reproduction.

Separate deterministic supplied-evidence proof:

`evidence/final-proof/frozen-clean-reproduction-resource-validation.json`

Explain:

- two fresh frozen six-source reproductions;
- same eleven core output hashes across both runs;
- same eleven core output hashes as accepted R3;
- measured runtimes approximately 3.438 and 3.393 seconds.

### I. Resource measurement

Show:

`project-control/phase4j-cov011-benchmark-result-v1.json`

Measured workload:

```text
accepted records         = 198,463
quarantined              = 0
end-to-end runtime       = 15.9617856 s
peak working set         = 486,924,288 bytes
frozen memory ceiling    = 4,000,000,000 bytes
```

Boundary: this proves behavior on the measured workload and workstation. It is not a universal scalability benchmark.

## 5. Safe read-only commands for the defense

These commands inspect accepted proof. They do not rerun the holdout or mutate product source.

### Repository freeze

```powershell
git rev-parse HEAD
git rev-parse "HEAD^{tree}"
git status --short -- src tests
```

### Verify major proof identities

```powershell
Get-FileHash .\project-control\finalist-candidate-freeze-v04.json -Algorithm SHA256
Get-FileHash .\evidence\final-proof\r3-end-to-end-reverse-trace-proof.json -Algorithm SHA256
Get-FileHash .\evidence\final-proof\holdout-final-adjudication.json -Algorithm SHA256
Get-FileHash .\results\acceptance\public-test-results.json -Algorithm SHA256
Get-FileHash .\project-control\finalist-one-command-reproduction-validation.json -Algorithm SHA256
```

### Inspect R3 counts

```powershell
$R3 = Get-Content .\evidence\reference-case\case-manifest.json -Raw | ConvertFrom-Json
$R3.analysis_counts | Format-List
```

### Inspect holdout adjudication without touching raw holdout

```powershell
$H = Get-Content .\evidence\final-proof\holdout-final-adjudication.json -Raw | ConvertFrom-Json
$H | ConvertTo-Json -Depth 10
```

### Inspect current acceptance

```powershell
$A = Get-Content .\results\acceptance\public-test-results.json -Raw | ConvertFrom-Json
$A | ConvertTo-Json -Depth 10
```

### Inspect evidence-backed claims

```powershell
Import-Csv .\evidence-index.csv | Select-Object -First 5 | Format-List
```

Do not execute a command merely because it existed in Stage 9A. Current commands and proof authorities are defined by the finalist README and `assessment-manifest.json`.

## 6. High-probability panel questions

### Why provenance-first instead of alert-first?

Because the project is designed so that a downstream conclusion remains inspectable and reversible to the raw evidence. An alert without recoverable supporting evidence is weaker for handoff, audit, reproduction and later challenge.

### Why preserve unsupported evidence instead of dropping it?

Because unsupported does not mean irrelevant. Silent loss would create false completeness. TraceSOC accounts for unsupported or partial representations explicitly and preserves their evidence identity.

### Why are correlation rules deliberately narrow?

Because time adjacency or visual similarity alone can create unsupported causal stories. Each supported correlation is limited to relationships the evidence can actually establish.

### Why freeze before the holdout?

To separate development from evaluation. The frozen candidate cannot be adapted after seeing unseen semantic holdout evidence simply to improve the observed result.

### Why is holdout accuracy unadjudicated?

Because the available publisher-labeled artifact is not an exact comparator for the sealed input. Precision, recall, false-positive and false-negative counts would therefore be unsupported.

### Why are there zero confirmed-malicious IOC rows?

Because the controlled finalist reference evidence does not independently establish a confirmed malicious IOC. Adding controlled values to the IOC set would fabricate certainty.

### Why is the reference case not called a confirmed incident?

Because it is controlled interoperability evidence. The system reconstructs evidence relationships and provenance without promoting the controlled scenario into malicious ground truth.

### Did TraceSOC execute containment?

No. Response records preserve recommendations and validation logic, but finalist proof does not claim executed production containment.

### What was inherited from Stage 9A?

Reusable engineering lessons and contracts: provenance, observation-versus-inference separation, deterministic identity, bounded correlation, alternatives and falsifiers, clean reproduction, anti-hardcoding and holdout discipline.

Case-specific Stage 9A answers and its production runtime were not copied into TraceSOC.

### What is the business value?

The demonstrated value is investigation assurance: defensible analyst handoff, auditability, exact evidence recovery, repeatable review and explicit uncertainty on a modest workstation.

No monetary ROI, analyst-hours saved, breach-cost reduction or false-positive reduction percentage was measured.

## 7. Known weaknesses and future validation

State these before a reviewer has to extract them:

- cross-publisher network holdout diversity is not established;
- detection accuracy on the sealed holdout remains UNADJUDICATED;
- resource measurements are bounded to measured workloads;
- response records are not proof of live production containment;
- the supported representation boundary is explicit and not universal.

A future validation should add a genuinely independent network publisher/corpus while retaining the same pre-freeze and no-tuning discipline.

## 8. Things never to say

Do not claim:

- the controlled reference case is malicious;
- a confirmed phishing incident exists in the controlled case;
- controlled values are confirmed malicious IOCs;
- email caused execution;
- correlation proves causality;
- process-instance attribution proves maliciousness;
- external IoT-23 detector matches are publisher ground truth;
- zero holdout detections prove success or failure;
- universal detector accuracy;
- cross-publisher generalization;
- measured monetary ROI;
- executed live containment.

## 9. Reviewer evidence map

- Freeze: `project-control/finalist-candidate-freeze-v04.json`
- Current regression: `results/acceptance/public-test-results.json`
- Current one-command clean build/test proof: `project-control/finalist-one-command-reproduction-validation.json`
- Reference reconstruction: `evidence/reference-case/case-manifest.json`
- Reverse trace: `evidence/final-proof/r3-end-to-end-reverse-trace-proof.json`
- Holdout adjudication: `evidence/final-proof/holdout-final-adjudication.json`
- PCAP accounting: `evidence/final-proof/r3-pcap-processing-issue-final-adjudication.json`
- Reproduction/resource proof: `evidence/final-proof/frozen-clean-reproduction-resource-validation.json`
- Grader closure: `evidence/final-proof/final-grader-feedback-closure-audit.json`
- Business/defense source: `evidence/finalist-problem-impact-proof-defense.md`
- Finalist evidence ledger: `finalist-evidence-ledger.json`
- Claim index: `evidence-index.csv`
- Timeline: `timeline.csv`
- IOC set: `ioc-set.csv`
- Continuity: `continuity-record.md`

## 10. Defense-room hygiene

Before a live defense or recording:

- close unrelated applications and browser tabs;
- disable visible notifications;
- ensure no passwords, tokens, API keys or unrelated personal data are visible;
- open only the repository artifacts required for the walkthrough;
- make the candidate binding and evidence marker available when provenance is discussed;
- use the read-only commands above instead of improvising destructive commands;
- do not access or rerun the raw sealed holdout.

## 11. Closing statement

The defensible finalist claim is intentionally bounded: within the measured supported representation boundary, TraceSOC reconstructs heterogeneous evidence while preserving exact provenance, accounts for unsupported evidence instead of silently losing it, applies bounded analytical relationships, and keeps consequential downstream evidence mechanically traceable to original artifact identity.

Where the evidence does not establish maliciousness, causality, accuracy or business ROI, TraceSOC records that uncertainty instead of inventing the missing answer.

