# TraceSOC Phase 4C.8 — Remaining Corpus Gap Adjudication

## Purpose

Determine whether additional external evidence acquisition is justified before
real-format implementation begins.

## Decision

NO NEW EXTERNAL DATASET ACQUISITION IS AUTHORIZED AT THIS STAGE.

The current external corpus is sufficient to proceed to real-format adapter
compatibility work.

This is not the same as declaring the final validation corpus complete.

## Current external evidence

Registered external artifacts:

15

Integrity:

15/15 SHA-256 revalidated.

## Required telemetry families

Development evidence exists for all four required families:

- PowerShell;
- Sysmon;
- Windows Security;
- Zeek/network.

## Benign controls

Network benign controls:

CLOSED

Two independent IoT-23 benign-device scenarios are acquired.

Endpoint benign control:

CLOSED

Nextron evtx-baseline Windows 10 goodware evidence is acquired, with selected
Security, Sysmon Operational, and PowerShell Operational channels preserved as
derived artifacts with raw-archive lineage.

## Network holdout

CLOSED FOR ACQUISITION

CAND-011 / IoT-23 v2 Muhstik is sealed.

Semantic access:

FALSE

Label access:

FALSE

Detector execution:

FALSE

Analytic freeze remains required before semantic use.

## Three suspicious development scenarios

### Scenario 1

PowerShell Active Directory discovery.

Primary source:

TS-DEV-SPLUNK-PS-001

### Scenario 2

Windows Defender disabling.

Primary evidence:

TS-DEV-SPLUNK-SYSMON-001

TS-DEV-SPLUNK-SECURITY-001

These two telemetry families represent one scenario and are not double-counted.

### Scenario 3

IoT-23 Capture 34-1 / Mirai network activity.

Primary source:

TS-DEV-IOT23-034-ZEEK

Therefore three distinct suspicious development scenarios are present.

Important boundary:

This establishes evidence availability only.

TraceSOC has not yet demonstrated successful real-format parsing, detection or
correlation on all three.

## Source diversity

The external corpus includes evidence from:

- Splunk;
- Stratosphere Laboratory / CTU;
- Nextron Systems.

Therefore broad source/publisher diversity is established.

Known narrower limitation:

The network development source and network holdout are both from the IoT-23
corpus.

Cross-publisher network holdout diversity is NOT established.

## Remaining mandatory corpus work

### Challenge corpus

OPEN

This does not require another external download.

Challenge artifacts will be derived from immutable originals and must preserve:

- challenge ID;
- parent TraceSOC source ID;
- parent SHA-256;
- transformation operator;
- derived SHA-256;
- expected disposition;
- generation time/tool.

### Scale

OPEN

TraceSOC will first test whether the existing corpus is sufficient for the
planned 100k–250k event benchmark.

No additional scale dataset is authorized until real-format adapters exist and
the current corpus is measured.

Only if the existing corpus cannot provide a scientifically valid benchmark
may external scale acquisition be reopened.

## Desirable but non-mandatory

Independent endpoint holdout.

No new endpoint holdout is selected at this stage.

## Evidence README

Still mandatory and open:

docs/EVIDENCE-README.md

It will be written after evidence/corpus closure, once the derived challenge
corpus and scale decision are resolved.

## Next phase

PHASE 4D — REAL-FORMAT ADAPTER COMPATIBILITY

The next work is implementation/compatibility work against the evidence we
already possess, not further collection.