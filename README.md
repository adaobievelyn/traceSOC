# TraceSOC

**Evidence-first SOC/DFIR reconstruction with mechanically preserved raw provenance.**

TraceSOC transforms heterogeneous security evidence into normalized observations, detections, correlations, findings, narratives and response records while preserving a reversible path back to the exact raw source.

## Finalist status

- Project: `SOC-A5`
- Variant: `V3`
- Candidate: `UBI-2026-0091`
- Evidence marker: `UBI-A9-4BC183701F3C`
- Repository: **https://github.com/adaobievelyn/traceSOC.git**
- Frozen technical commit: `8751a679f36b4983cdd3d2b0b35f44e9a11c4f39`
- Frozen technical tree: `fc420ee3fd1988cf578c0cf309ee3aefcccf33b2`
- Technical candidate: **READY / FROZEN**
- Submission machine-readable core: **READY**
- Final human-facing reports: **READY / VISUALLY VALIDATED**

The technical candidate was frozen before semantic holdout access. Later work is submission packaging, validation and documentation; it is not post-holdout product tuning.

## Problem

SOC and DFIR investigations often combine evidence from email, packet captures, network logs and endpoint telemetry. The difficult part is not only parsing those sources: analytical conclusions can become detached from the raw observations that support them.

TraceSOC is designed to keep consequential claims reproducible, auditable and defensible by preserving exact provenance and explicit uncertainty throughout the analytical chain.

## Evidence contract

```text
raw evidence
-> representation extraction
-> canonical observation
-> evidence graph
-> detection
-> relationship / correlation
-> hypothesis / finding
-> narrative
-> response
```

The reverse path is equally important:

```text
downstream conclusion
-> finding
-> relationship / detection
-> canonical observation
-> exact raw locator
-> original artifact identity
-> SHA-256
```

Correlation is evidence-supported corroboration within its defined contract. It does not independently establish causality or maliciousness.

## Supported representation boundary

- `EML_MIME`
- `PCAP`
- `PCAPNG`
- `ZEEK_ASCII_CONN_LOG`
- `ZEEK_JSON_JSONL`
- `SYSMON_WINDOWS_EVENT_XML`
- `SYSMON_RECOGNIZED_WINDOWS_EVENT_JSON_JSONL`
- `POWERSHELL_OPERATIONAL_WINDOWS_EVENT_XML`
- `POWERSHELL_RECOGNIZED_WINDOWS_EVENT_JSON_JSONL`
- `WINDOWS_SECURITY_WINDOWS_EVENT_XML`
- `WINDOWS_SECURITY_RECOGNIZED_WINDOWS_EVENT_JSON_JSONL`
- `WINDOWS_SECURITY_SUPPORTED_SPLUNK_STYLE_TEXT`

TraceSOC is not a universal parser or mini-SIEM. Unsupported or partial evidence must be retained and accounted rather than silently discarded or converted into invented semantics.

## Measured finalist proof

- Controlled evidence families: 6
- Canonical observations: 5442
- Raw-locator coverage: 5442/5442
- Detector evaluations: 32658
- Matched detections: 5
- Hypotheses: 6
- Findings: 6
- Narratives: 6
- Responses: 6
- Reference incident status: `NOT_ESTABLISHED`

External real Zeek validation reconciled **23145 / 23145** source rows to canonical observations with source difference **0**.

The sealed post-freeze holdout reconciled **156458 / 156458** rows and executed **938748** detector evaluations without post-freeze tuning.

Holdout detection accuracy remains **UNADJUDICATED**. Zero holdout matches are therefore not scored as detection success or failure.

Current regression: **524/524 PASS**.

Current public acceptance: **4/4 PASS**.

Clean reproduction: 2 fresh runs; 11 deterministic core outputs; byte-identical to reference = True.

Measured scale workload: 198463 accepted records, 0 quarantined records, 15.9617856 seconds end-to-end, peak working set 486924288 bytes against the frozen 4000000000-byte ceiling.

These are measured workloads, not universal scalability claims.

## Supported environment

- OS: Windows 11 10.0.26100
- CPU: Intel64 Family 6 Model 142 Stepping 9, GenuineIntel
- Memory: 7.85 GB
- git: git version 2.55.0.windows.3
- pip: 26.1.2
- powershell: 5.1.26100.9444
- python: 3.13.14
- setuptools: 84.0.0
- tracesoc: 0.1.0

## Reproduction

Run from the repository root on the supported Windows environment.

### One-command finalist clean build and test

The primary finalist build/test entry point is:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\finalist-reproduce.ps1
```

It runs the validated sequence `clean.ps1 -> provision.ps1 -> build.ps1 -> test.ps1` using the pinned finalist environment.

Validated result:

- `FINALIST_ONE_COMMAND_REPRODUCTION=PASS`
- `FULL_REGRESSION=524/524_PASS`
- `PUBLIC_ACCEPTANCE_CLASSES=4/4_PASS`
- product source changed: `false`
- test source changed: `false`
- sealed holdout accessed: `false`

Current proof:

`project-control/finalist-one-command-reproduction-validation.json`

### Deterministic reproduction on supplied evidence

TraceSOC also provides `reproduce.ps1` for deterministic analysis of a supplied evidence directory.

After the pinned finalist environment has been provisioned, use:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\reproduce.ps1 -EvidenceDirectory 'C:\path\to\evidence' -OutputDirectory 'C:\path\to\new-tracesoc-output' -PythonExecutable '.\.venv\Scripts\python.exe'
```

The evidence directory must exist. The output directory must not already exist, must be outside the repository, and must not be inside the evidence directory.

The reproduction driver performs two independent isolated builds/runs, executes regression and public-acceptance validation, compares deterministic derived outputs, and verifies that the supplied raw evidence remains unchanged.

Evidence must fall within the documented supported representation boundary for semantic interpretation. A successfully ingested input can legitimately produce zero detections or zero findings when its evidence does not satisfy the implemented detection or correlation semantics.

### Preconditions

- Run supported commands from the repository root on Windows.
- Supported Python is exactly 3.13.14 with the pinned repository environment.
- The six reference-case raw evidence files must remain byte-identical to their indexed hashes.
- Do not rerun or tune against the sealed post-freeze holdout during normal submission reproduction.
- The process-scoped PowerShell execution-policy bypass changes no machine-wide execution-policy setting.

### 1. Clean

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\clean.ps1
```

### 2. Provision

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\provision.ps1
```

### 3. Build

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

### 4. Test

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\test.ps1 -Commit 8751a679f36b4983cdd3d2b0b35f44e9a11c4f39 -Output results\acceptance\public-test-results.json
```

The accepted clean-reproduction authority is:

`evidence/final-proof/frozen-clean-reproduction-resource-validation.json`

The current regression authority is:

`results/acceptance/public-test-results.json`

## Reviewer navigation

- `executive-brief.pdf` — executive Problem / Impact / Proof / Defense summary
- `incident-report.pdf` — technical validation and evidence-reconstruction report
- `defense-runbook.md` — live-defense walkthrough and verification guide
- `assessment-manifest.json` — submission/environment/command contract
- `finalist-evidence-ledger.json` — machine-readable finalist claim ledger
- `evidence-index.csv` — evidence-backed claims and limitations
- `timeline.csv` — canonical finalist timeline surface
- `ioc-set.csv` — confirmed-malicious IOC submission surface
- `continuity-record.md` — prior-stage continuity and migration record
- `project-control/finalist-candidate-freeze-v04.json` — frozen technical candidate
- `evidence/reference-case/` — controlled six-source reconstruction
- `evidence/final-proof/` — finalist proof and adjudication records
- `evidence/finalist-problem-impact-proof-defense.md` — problem, impact, proof and defense source

## Known claim boundaries

- Controlled six-source reference activity is not malicious ground truth.
- Correlation does not independently establish causality or maliciousness.
- Post-freeze holdout detection accuracy is UNADJUDICATED.
- Cross-publisher network holdout diversity is not established.
- No confirmed malicious IOC is asserted from the finalist reference evidence.
- Response records do not claim live response execution.
- Resource measurements are measured-case evidence, not universal scalability claims.

The zero-row confirmed-malicious IOC result is intentional: the finalist reference evidence does not independently establish a malicious IOC.

## Packaging state

Completed:

- technical candidate freeze
- machine-readable finalist core
- controlled six-source reconstruction
- external real-evidence validation
- sealed post-freeze holdout adjudication
- end-to-end reverse-trace proof
- deterministic clean reproduction
- measured resource validation
- regression and acceptance validation
- continuity finalization
- business-impact source
- stale presentation cleanup
- rebuild-utility safeguards
- finalist living-control refresh
- README technical and reproduction content reconciliation

Remaining final submission gates:

- `manifest.sha256` generation only after the submission tree is frozen
- final manifest verification after upload

## Anti-drift rule

Do not treat historical test counts, development milestones, Stage 9A case-specific answers, provisional plans, or superseded report artifacts as current finalist truth.

When a summary conflicts with the current finalist authorities, the authenticated proof/control records govern.

