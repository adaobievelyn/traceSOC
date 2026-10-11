# TraceSOC

**Provenance-first SOC/DFIR evidence reconstruction with reversible raw-evidence traceability.**

TraceSOC is a security engineering project that reconstructs analytical findings from heterogeneous raw security evidence while preserving the path back to the exact source observations that support each conclusion.

Instead of treating normalization, detection and correlation as permission to discard source context, TraceSOC keeps provenance and uncertainty attached throughout the analytical chain.

```text
raw evidence
    ↓
representation extraction
    ↓
canonical observations
    ↓
evidence graph
    ↓
detections
    ↓
bounded correlations
    ↓
hypotheses / findings
    ↓
narratives
    ↓
response records
```

The reverse path is equally important:

```text
finding / response
    ↓
supporting relationship or detection
    ↓
canonical observation
    ↓
exact raw locator
    ↓
original artifact
    ↓
SHA-256
```

The design goal is simple:

> A consequential security conclusion should remain reproducible, challengeable and traceable to the evidence that actually supports it.

---

## Why I Built TraceSOC

SOC and DFIR investigations often involve several evidence sources at once:

- endpoint telemetry
- Windows event logs
- PowerShell activity
- email
- packet captures
- network telemetry

The difficult problem is not only parsing those sources.

As an investigation progresses through normalization, detection, correlation and reporting, conclusions can become detached from the raw observations that produced them.

That creates problems for:

- investigation reproducibility
- analyst handoff
- evidence review
- auditability
- false certainty
- later technical validation

TraceSOC was built around the idea that **provenance should be part of the analytical architecture rather than documentation added after an investigation is complete.**

---

## Core Design Principles

### Provenance first

Canonical observations preserve exact source locators and artifact identity so downstream findings can be traced back to raw evidence.

### Observation before inference

TraceSOC distinguishes what the evidence directly establishes from what a detector, correlation rule or analyst infers.

### No silent evidence loss

Unsupported, malformed or partially supported evidence is accounted for rather than silently disappearing or being converted into invented semantics.

### Bounded correlation

Correlation is only created when the implemented evidence relationship is satisfied.

Temporal proximity alone is not treated as causality.

### Deterministic identity and output

Event and analytical identities are generated from defined evidence contracts rather than fixture IDs, expected answers or case-specific verdicts.

### Explicit uncertainty

Findings can preserve alternatives, falsifiers, limitations and residual uncertainty instead of forcing every observation into a definitive incident narrative.

### Safe response semantics

Recommended or simulated response activity remains distinguishable from actions that were actually executed.

---

## Supported Evidence Boundary

TraceSOC currently supports six security-evidence families across twelve defined representations.

### Email

- EML / MIME

### Packet Evidence

- PCAP
- PCAPNG

### Zeek

- ASCII/header-aware `conn.log`
- JSON / JSONL

### Sysmon

- Windows Event XML
- recognized Windows Event JSON / JSONL

### PowerShell Operational

- Windows Event XML
- recognized Windows Event JSON / JSONL

### Windows Security

- Windows Event XML
- recognized Windows Event JSON / JSONL
- supported Splunk-style text export

TraceSOC is **not** intended to be a universal parser or a replacement SIEM.

Unknown or partially supported evidence remains explicitly accounted for rather than being silently discarded.

---

## Detection and Correlation

TraceSOC separates detection from correlation.

A detector establishes that a defined semantic condition matched.

A correlation establishes only the relationship supported by its selectors and evidence.

Implemented correlation families include relationships across:

- PowerShell and Zeek network telemetry
- PowerShell and Sysmon process telemetry
- Sysmon process and packet evidence
- Windows Security process creation and Sysmon Event 1
- email attachments and Sysmon process evidence
- Sysmon Event 1 and Event 3 process/network activity

Correlation selectors include evidence such as:

- exact SHA-256 identity
- host identity
- PID
- process image
- normalized `ProcessGuid`
- source/destination network attributes
- bounded temporal relationships

A correlation does **not** independently establish:

- malicious intent
- causality
- compromise
- incident membership
- threat-actor attribution

Those claims require additional evidence.

---

## Evidence Reconstruction

A TraceSOC case can preserve:

- raw artifact identity
- canonical observations
- reconstructed PowerShell ScriptBlocks
- detector evaluations
- correlation evaluations
- evidence relationships
- hypotheses
- findings
- narratives
- response records
- raw-evidence indexes
- case-level accounting

The controlled reference case included six evidence sources and produced a complete raw-to-result reconstruction.

### Reference-case measurements

| Measurement | Result |
| --- | ---: |
| Canonical observations | 5,442 |
| Observations with raw locators | 5,442 / 5,442 |
| Detector evaluations | 32,658 |
| Matched detections | 5 |
| Hypotheses | 6 |
| Findings | 6 |
| Narratives | 6 |
| Response records | 6 |

The reference case is controlled validation evidence.

It is **not malicious ground truth**, and TraceSOC does not convert the controlled activity into a confirmed compromise simply because detections or correlations exist.

---

## Reverse Traceability

TraceSOC mechanically validated a complete consequential chain from a downstream response record back to original evidence:

```text
response
→ narrative
→ finding
→ hypothesis
→ detection / relationship
→ correlation
→ canonical observation
→ exact raw locator
→ embedded raw artifact
→ original artifact SHA-256
```

This demonstrates that provenance survives the analytical pipeline rather than ending at the normalized-event layer.

---

## Validation Beyond the Reference Case

The project was also tested against evidence outside the controlled six-source reconstruction.

### External Zeek Validation

```text
23,145 source records
→ 23,145 canonical observations
→ source difference: 0
```

This tested real Zeek representation handling and source accounting outside the reference case.

### Post-Freeze Holdout

A semantically unseen holdout was evaluated only after the analytical implementation had been frozen.

```text
156,458 source records
→ 156,458 canonical observations
→ 938,748 detector evaluations
```

No production tuning was performed after holdout access.

The holdout produced zero matched detections.

That result is **not classified as detection success or failure**, because an exact valid observation-level scoring comparator was not established.

Detection accuracy therefore remains:

```text
UNADJUDICATED
```

This distinction is intentional.

---

## Software Validation

Current regression state:

```text
524 / 524 tests passed
```

Public acceptance:

```text
4 / 4 acceptance classes passed
```

The acceptance surface includes positive, negative, malformed-input and clean-state behavior.

TraceSOC also includes tests covering areas such as:

- provenance contracts
- evidence-directory intake
- malformed evidence handling
- deterministic case output
- source-native mapping
- PowerShell ScriptBlock reconstruction
- Sysmon semantics
- Windows Security semantics
- Zeek parsing
- behavioral detections
- bounded correlations
- evidence graphs
- hypotheses and findings
- response validation
- clock-state handling
- source contradiction
- multi-source scenarios

---

## Deterministic Reproduction

Two fresh controlled six-source runs reproduced the same **11 core output hashes** and matched the accepted reference outputs.

TraceSOC also provides a reproduction workflow for supplied evidence.

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\reproduce.ps1 `
  -EvidenceDirectory 'C:\path\to\evidence' `
  -OutputDirectory 'C:\path\to\tracesoc-output' `
  -PythonExecutable '.\.venv\Scripts\python.exe'
```

The reproduction process validates that the supplied evidence remains unchanged and compares independently generated analytical outputs.

A successfully processed evidence set may legitimately produce **zero detections or zero findings** if its contents do not satisfy the implemented analytical rules.

---

## Build and Test

The validated development environment uses:

- Windows
- Python 3.13.14
- PowerShell 5.1
- Git
- Wazuh-independent local processing
- approximately 8 GB host memory

Clean the local environment:

```powershell
.\clean.ps1
```

Provision the pinned Python environment:

```powershell
.\provision.ps1
```

Build and install TraceSOC:

```powershell
.\build.ps1
```

Run the regression and public acceptance suite:

```powershell
.\test.ps1
```

---

## Resource Validation

A larger real-format workload was used to measure processing behavior on the development workstation.

| Measurement | Result |
| --- | ---: |
| Input records | 198,463 |
| Accepted | 198,463 |
| Quarantined | 0 |
| Semantic events | 198,463 |
| End-to-end runtime | 15.96 seconds |
| Peak working set | ~487 MB |

These are measurements from the tested workload and machine.

They are **not universal scalability claims**.

---

## Repository Structure

```text
traceSOC/
├── src/
│   └── tracesoc/              # Product implementation
│
├── tests/
│   ├── unit/                  # Unit and contract validation
│   ├── integration/           # Multi-source integration testing
│   └── fixtures/              # Controlled and synthetic test evidence
│
├── docs/                      # Architecture and evidence-contract documentation
│
├── evidence/
│   ├── reference-case/        # Controlled six-source reconstruction
│   └── final-proof/           # Validation and traceability proof
│
├── results/                   # Acceptance and validation results
│
├── scripts/                   # Reproduction and validation utilities
│
├── project-control/           # Engineering history and validation records
│
├── build.ps1
├── clean.ps1
├── provision.ps1
├── reproduce.ps1
├── test.ps1
└── pyproject.toml
```

`project-control/` contains detailed development and validation records retained as engineering history. The product implementation itself lives under `src/tracesoc/`.

---

## Useful Technical Documentation

- [`docs/evidence-contract.md`](./docs/evidence-contract.md) — provenance, canonical-event and semantic-event contracts
- [`docs/first-behavioral-detection.md`](./docs/first-behavioral-detection.md) — behavioral detection boundary
- [`docs/first-bounded-correlation.md`](./docs/first-bounded-correlation.md) — correlation design and claim boundaries
- [`docs/explain-finding.md`](./docs/explain-finding.md) — raw-to-finding explanation path
- [`docs/finding-serialization-contract.md`](./docs/finding-serialization-contract.md) — deterministic finding serialization
- [`docs/four-source-adapter-slice.md`](./docs/four-source-adapter-slice.md) — early multi-source adapter architecture

---

## Known Limitations

TraceSOC deliberately records its current boundaries.

- It is not a universal log parser.
- Native EVTX ingestion is outside the current supported boundary.
- Correlation does not independently prove causality or malicious intent.
- Detection accuracy on the post-freeze holdout remains unadjudicated.
- Current network development and holdout evidence do not establish cross-publisher generalization.
- Response records distinguish planning/simulation from executed containment.
- Resource measurements apply only to the measured workloads and machine.
- A matched detection is not automatically a confirmed incident.

These limitations are part of the product's evidence model rather than hidden behind stronger claims.

---

## Project Origin

TraceSOC is my original security-engineering project, designed and implemented from scratch.

It was developed during the finalist phase of the Ubuntu Bridge Initiative Advanced SOC Analysis programme, where I used the project to bring together lessons from earlier work in:

- SOC investigation
- DFIR
- telemetry normalization
- detection engineering
- evidence provenance
- threat hunting
- adversarial testing
- deterministic validation

The architecture and implementation are TraceSOC-native rather than a repackaging of an earlier investigation.

---

## What TraceSOC Demonstrates

This project demonstrates hands-on work across:

- SOC and DFIR engineering
- multi-source security telemetry
- Python security tooling
- evidence normalization
- provenance preservation
- detection engineering
- cross-source correlation
- hypothesis and finding construction
- deterministic testing
- anti-hardcoding controls
- malformed-input handling
- holdout methodology
- reproducible security analysis
- resource-constrained engineering

The central design principle remains:

> **Preserve what the evidence proves, preserve what it does not prove, and make every consequential conclusion traceable back to source.**
