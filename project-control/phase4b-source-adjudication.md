# TraceSOC Phase 4B Evidence Source Adjudication

## Purpose

Phase 4B researches and adjudicates candidate evidence sources before any real
evidence is acquired.

No external evidence was downloaded during this phase.

## Research date

The source availability and terms recorded here were externally verified during
Phase 4B and must be rechecked if acquisition occurs materially later.

## Approved initial corpus

### CAND-001 — Splunk Attack Data

Decision: APPROVED

Role: DEVELOPMENT

Telemetry:

- Sysmon;
- Windows Security;
- PowerShell Operational.

Acquisition boundary:

Only specifically selected log files are authorized.

The complete repository must not be pulled merely for convenience.

Reasons:

- maintained public repository;
- curated attack datasets;
- Apache-2.0 terms;
- supports selective Git-LFS acquisition;
- Windows Sysmon and Security telemetry documented;
- PowerShell Operational attack-data files documented.

Labels, ATT&CK IDs, folder names, analytic stories, and expected detection
outcomes are contextual metadata only.

They must not become production detector selectors.

### CAND-002 — IoT-23 CTU-IoT-Malware-Capture-34-1

Decision: APPROVED

Role: DEVELOPMENT

Telemetry:

- PCAP;
- Zeek conn.log.

Acquisition boundary:

Only network evidence is authorized.

Do not acquire the malware binary or password-protected executable archive.

Purpose:

Develop and validate TraceSOC real-network ingestion using an independent
published capture.

IoT-specific context must not be generalized into unsupported Windows endpoint
claims.

### CAND-003 — IoT-23 Philips HUE benign capture

Decision: APPROVED

Role: BENIGN_CONTROL

Capture:

CTU-Honeypot-Capture-4-1.

Purpose:

Independent benign network control from a real uninfected device.

### CAND-004 — IoT-23 Amazon Echo benign capture

Decision: APPROVED

Role: BENIGN_CONTROL

Capture:

CTU-Honeypot-Capture-5-1.

Purpose:

Second independent benign network control from a real uninfected device.

### CAND-005 — IoT-23 Hajime capture

Decision: APPROVED

Role: HOLDOUT

Capture:

CTU-IoT-Malware-Capture-9-1.

Holdout restrictions:

- do not inspect flow labels while tuning production analytics;
- do not derive thresholds from this source;
- do not derive destination values from this source;
- do not derive token lists from this source;
- do not add source-specific exceptions based on this source;
- do not use the scenario's known answer as detector input.

The source identity and provenance may be recorded before use.

## Deferred candidates

### CAND-006 — CTU-13

Decision: DEFERRED.

Proposed role:

SCALE_TEST.

Positive attributes:

- CC-BY;
- thirteen botnet scenarios;
- normal/background/botnet traffic;
- individual scenario access;
- approximately 1.9 GB aggregate corpus.

Reason for deferral:

TraceSOC does not yet need scale evidence.

A safe network-only subset must be selected before any acquisition because
dataset packages may contain executable malware material that TraceSOC does not
need.

### CAND-007 — OTRF Security-Datasets APT29

Decision: DEFERRED.

Technical suitability:

HIGH.

The published Day 1 host dataset documents:

- substantial Sysmon telemetry;
- Windows Security telemetry;
- PowerShell Operational telemetry;
- network data.

Reason for deferral:

Current repository licensing metadata is internally inconsistent.

The repository LICENSE file states MIT while repository documentation states
GPL-3.0.

TraceSOC will not silently choose one interpretation.

This source may be reconsidered after terms are unambiguously adjudicated.

### CAND-009 — SOCBED ACSAC 2021 Evaluation Dataset

Decision: DEFERRED.

Positive attributes:

- MIT repository;
- published reproducibility dataset;
- Windows Event JSONL;
- repeated simulations.

Reason for deferral:

The evaluation combines benign activity and cyberattack simulation.

It cannot be treated as a benign control until clean segmentation and ground
truth boundaries are independently established.

It remains a possible future scale or robustness source.

## Rejected candidate

### CAND-008 — AMIDES SOCBED benign samples

Decision: REJECTED AS PRIMARY TRACESOC EVIDENCE.

Reason:

The published samples are already extracted or normalized representations such
as process command lines and PowerShell ScriptBlockText rather than full raw
event records.

They are useful research data but do not satisfy TraceSOC's primary
raw-to-result provenance standard strongly enough for the core evidence corpus.

## Initial corpus coverage

Approved DEVELOPMENT:

- Splunk Attack Data — Windows endpoint telemetry;
- IoT-23 malicious network scenario — network telemetry.

Approved BENIGN_CONTROL:

- IoT-23 Philips HUE;
- IoT-23 Amazon Echo.

Approved HOLDOUT:

- IoT-23 Hajime.

SCALE_TEST:

Selection deferred until scale testing is needed.

## Safety rule

TraceSOC is authorized to acquire only the evidence artifacts necessary for
analysis.

For IoT-23, authorization is limited to:

- PCAP;
- Zeek/conn.log material;
- associated README/provenance metadata.

Malware binaries and password-protected malware archives are explicitly outside
the acquisition scope.

## Download status

Real evidence acquired: FALSE.

Downloads performed in Phase 4B: ZERO.

## Next

Phase 4C — controlled acquisition of the approved DEVELOPMENT and
BENIGN_CONTROL evidence, plus provenance registration and integrity
verification.

The HOLDOUT may be acquired into the isolated holdout namespace but must not be
opened for tuning or analytical inspection.