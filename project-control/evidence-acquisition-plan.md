# TraceSOC Evidence Acquisition Plan

## Phase

4A.

## Purpose

This document defines the control boundary for acquiring real evidence into
TraceSOC.

No real evidence is authorized for acquisition merely because a dataset is
interesting or publicly available.

Every accepted evidence source must have an explicit role, provenance record,
integrity record, storage location, known limitations, and lawful-use basis.

## Governing principle

TraceSOC works from evidence to conclusion.

It must never select evidence because the evidence is expected to produce a
desired detection, correlation, ATT&CK technique, incident narrative, or
assessment answer.

## Source families in project scope

TraceSOC intends to validate four telemetry families:

1. Sysmon.
2. Windows Security.
3. PowerShell Operational.
4. Zeek or equivalent network telemetry derived from packet/network evidence.

Not every dataset must contain all four families.

The final corpus must provide sufficient coverage across the project as a
whole.

## Corpus objectives

The final evidence corpus should support:

- realistic endpoint activity;
- Windows authentication/account/process/security audit activity;
- PowerShell execution activity;
- network telemetry;
- suspicious or attack-style prerecorded scenarios;
- benign controls;
- holdout validation;
- larger-scale performance testing.

Target project-level validation remains:

- approximately 8 to 12 high-quality behavioral detections;
- at least 3 suspicious or attack-style scenarios;
- at least 2 benign controls;
- held-out variants not used for rule tuning;
- positive, negative, malformed, mutation, timing, and boundary tests.

These are project targets, not reasons to force unsupported conclusions from
a particular evidence source.

## Safety boundary

TraceSOC will not execute malware in order to create evidence.

Acceptable suspicious evidence includes:

- prerecorded telemetry;
- public defensive-security datasets;
- packet captures handled offline;
- safely generated inert telemetry;
- controlled synthetic mutations of already accepted records where the
  mutation purpose is documented.

## Mandatory source review before acquisition

Before any external evidence is downloaded or copied into controlled TraceSOC
storage, the candidate must be reviewed for:

- provenance;
- publisher or origin;
- availability and stability;
- telemetry type;
- raw-data fidelity;
- known ground truth;
- known limitations;
- license or usage terms;
- privacy or redistribution concerns;
- approximate size;
- acquisition method;
- safety;
- relevance to TraceSOC;
- intended dataset role;
- risk of hidden answer labels contaminating detector logic;
- resource suitability for the 8 GB workstation.

No source is approved solely because another SOC project commonly uses it.

## Mandatory acquisition fields

Every acquired source must record:

- source_id;
- role;
- status;
- telemetry_family;
- origin_type;
- publisher;
- source_title;
- source_url;
- license_or_terms;
- acquired_utc;
- original_filename;
- storage_path;
- byte_size;
- sha256;
- time_start_utc where determinable;
- time_end_utc where determinable;
- host_coverage where determinable;
- user_coverage where determinable;
- known_labels;
- known_limitations;
- acquisition_method;
- integrity_status;
- notes.

Unknown facts must be recorded as UNKNOWN rather than invented.

## Acquisition sequence

For each approved source:

1. Record the candidate and intended role.
2. Review source provenance and usage terms.
3. Approve or reject the candidate.
4. Download or copy the original artifact without analytical transformation.
5. Preserve the original filename where practical.
6. Compute SHA-256 immediately.
7. Record byte size.
8. Store the immutable original in controlled raw/archive storage.
9. Record its controlled storage path.
10. Recompute SHA-256 after storage.
11. Compare pre-storage and post-storage hashes.
12. Record integrity status.
13. Do not parse or normalize the source until acquisition accounting is
    complete.
14. Do not move HOLDOUT material into development/tuning workflows.

## Storage policy

Small reproduction-critical fixtures may remain inside the Git repository.

Large real evidence is not to be committed to Git by default.

Preferred optional bulk storage:

D:\TraceSOC-Evidence

Controlled namespaces already established include:

- archives
- raw
- holdout
- manifests
- scratch

The D: drive is optional storage, not a mandatory TraceSOC runtime dependency.

If D: is unavailable, acquisition must stop until a controlled alternative is
explicitly recorded. TraceSOC must not silently redirect bulk evidence to an
uncontrolled directory.

## Immutable-original rule

The acquired original is evidence.

It must not be edited in place.

Parsing, extraction, decompression, normalization, conversion, filtering, or
mutation must create derived artifacts separately.

Derived artifacts must retain linkage to the immutable original.

## Archive rule

If the source arrives as an archive:

- preserve the original archive;
- hash the original archive;
- extract into a separate controlled location;
- do not substitute extracted-file hashes for the archive hash;
- where material, create hashes for extracted evidence independently.

## Dataset role isolation

Every evidence source must be assigned exactly one primary role at acquisition
time:

- DEVELOPMENT
- BENIGN_CONTROL
- HOLDOUT
- SCALE_TEST

Role definitions are governed by:

project-control/evidence-role-policy.md

A source may not silently change roles.

Any role change requires an explicit project-control decision.

## Holdout isolation

HOLDOUT evidence must not influence:

- detector thresholds;
- correlation thresholds;
- regex design;
- field-selection logic;
- expected-answer logic;
- hard-coded identifiers;
- source-specific exceptions.

Holdout evaluation is intended to test generalization after a rule or analytic
has been frozen.

## Ground-truth discipline

Publisher labels and scenario descriptions are contextual evidence, not
detector inputs.

Where a dataset says that an action is malicious, TraceSOC may record that
label in acquisition metadata, but production detection logic must derive its
decision from semantic telemetry rather than from the label.

## Anti-hardcoding rule

The following must never serve as hidden production selectors:

- fixture IDs;
- expected answers;
- dataset row numbers chosen because they are known positives;
- candidate IDs;
- assessment IDs;
- participant IDs;
- known solution hashes;
- scenario labels;
- known malicious IP addresses used only because the dataset says they are
  malicious;
- hard-coded final answers.

Indicators may eventually be used in explicitly declared IOC matching logic,
but such logic must be identified as IOC matching rather than behavioral
detection.

## Evidence rejection conditions

A candidate should be rejected or quarantined when:

- provenance cannot be established sufficiently;
- source integrity cannot be established;
- usage terms prohibit the intended project use;
- evidence requires unsafe execution;
- telemetry is too transformed to support required provenance;
- raw records cannot be meaningfully located;
- scenario labels are inseparable from analytical inputs;
- the source would cause unacceptable workstation/resource pressure without
  adding material validation value;
- the evidence is duplicative without an explicit reason;
- acquisition would undermine holdout isolation.

## Evidence source selection

Phase 4A defines the control plane only.

It does not approve any external source.

Source discovery, comparison, and approval occur in Phase 4B.

No real evidence download is authorized until Phase 4B records approved source
candidates.

## Current state

Real evidence acquired: FALSE.

External source candidates approved: FALSE.

Evidence acquisition control plane defined: TRUE.

Next phase:

Phase 4B - evidence source discovery, comparison, and source-role adjudication.