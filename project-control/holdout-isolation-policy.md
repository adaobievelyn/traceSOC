# TraceSOC Holdout Isolation Policy

## Purpose

The holdout corpus exists to measure generalization after development choices
have been frozen.

Holdout evidence must not become development evidence.

## Primary rule

HOLDOUT DATA MUST NOT BE USED TO:

- choose detection logic;
- choose thresholds;
- choose correlation windows;
- choose parsing shortcuts;
- choose allowlists;
- choose exclusions;
- select fields because they are known to produce the expected answer;
- repair false positives;
- repair false negatives;
- select scenario-specific identifiers;
- inspect publisher labels before the applicable evaluation run.

## Allowed before analytic freeze

The following operations are permitted before analytic freeze because they do
not inspect the semantic payload:

- retrieve an already-approved holdout artifact;
- record exact publisher URL;
- record filename;
- record publisher/version metadata;
- measure byte size;
- compute cryptographic hashes;
- copy to controlled sealed storage;
- set read-only attributes;
- verify file existence;
- verify cryptographic integrity;
- record acquisition metadata;
- inspect README/provenance metadata only.

For the sealed Zeek holdout payload, the following are prohibited before
analytic freeze:

- Get-Content;
- Select-String;
- grep;
- head/tail;
- parsing;
- row counts derived by reading records;
- field inspection;
- label inspection;
- semantic inspection;
- detector execution;
- normalization;
- correlation;
- manual browsing.

## Integrity access is not analytic access

Computing SHA-256 reads bytes but does not interpret semantic content.

Such activity is classified:

INTEGRITY_ONLY_ACCESS

and is permitted prior to analytic freeze.

## Initial holdout scope

Approved source:

CAND-005

Dataset:

IoT-23 v2

Scenario:

CTU-IoT-Malware-Capture-9-1

Publisher scenario name:

Linux.Hajime

Primary holdout role:

NETWORK HOLDOUT

Initial acquisition scope:

1. README.md
2. 2018-07-25-10-53-16-192.168.100.111-zeek-conn-log.labeled

The README may be read for provenance.

The Zeek payload must remain sealed from semantic inspection until analytic
freeze.

## Deliberately not acquired initially

PCAP:

2018-07-25-10-53-16-192.168.100.111.pcap

Reason:

The current holdout objective exercises the Zeek/network analytic path.

TraceSOC does not currently require packet-level holdout replay.

Downloading the PCAP would add approximately 472 MB of evidence that would
not yet be used.

If packet-level holdout replay becomes a requirement, the PCAP must undergo a
new explicit adjudication before acquisition.

labels.config:

2018-07-25-10-53-16-192.168.100.111-labels.config

Reason:

Labeling rules are unnecessary for pre-evaluation holdout operation and create
avoidable information-leakage risk.

## Publisher labels

The Zeek filename indicates that publisher labels are embedded.

Before analytic freeze:

DO NOT INSPECT THEM.

During eventual evaluation:

Labels may be used only after TraceSOC has independently produced its results,
for post-hoc evaluation/accounting.

Labels may never become detector selectors.

## Required analytic freeze

Before first semantic holdout access, TraceSOC must create a committed
analytic-freeze proof that records at minimum:

- Git commit;
- parser/adapter identities;
- normalization schema version;
- detector inventory;
- detector-rule hashes;
- correlation-rule inventory;
- correlation-rule hashes;
- thresholds/windows;
- consolidated test-ledger state;
- development and benign-control validation state;
- challenge-test state then available;
- known limitations.

The freeze commit must occur before any semantic holdout payload inspection.

## First-use rule

The first semantic holdout evaluation must be a one-way evaluation step:

frozen analytics
-> holdout run
-> result capture
-> comparison/evaluation

If the holdout reveals failure, the failure is evidence.

Any subsequent repair creates a new analytic version and the same holdout may
no longer be described as unseen for that repaired version.

## Access log

Every holdout-related access is recorded in:

project-control/holdout-access-log.jsonl

The log distinguishes:

- POLICY_EVENT
- INTEGRITY_ONLY_ACCESS
- PROVENANCE_METADATA_ACCESS
- SEMANTIC_EVALUATION_ACCESS

## Storage

Future sealed holdout root:

D:\TraceSOC-Evidence\holdout\sealed

Holdout artifacts must not be copied into development, benign-control, fixture,
or generated-data namespaces.

## Evidence integrity

Acquired holdout originals are immutable.

No in-place modifications are allowed.

Any derived evaluation output must live outside the sealed holdout directory
and preserve parent source ID and SHA-256.

## Current state

Policy created:
TRUE

Holdout acquired:
FALSE

Holdout payload semantically inspected:
FALSE

Analytic freeze completed:
FALSE
---

# Phase 4C.6A source refinement

Before acquisition, publisher directory evidence established a preferable
plain Zeek conn.log at:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-9-1/zeek-labeled/conn.log

This file supersedes the previously planned label-bearing Zeek file as the
initial holdout payload.

Initial sealed payload:

conn.log

Publisher-labeled conn.log:

DEFERRED UNTIL POST-PREDICTION SCORING

labels.config:

DEFERRED UNTIL POST-PREDICTION SCORING

PCAP:

DEFERRED UNTIL A PACKET-LEVEL HOLDOUT REQUIREMENT EXISTS

The plain conn.log remains subject to the same pre-freeze prohibition on
semantic inspection.

No holdout payload had been downloaded or semantically accessed when this
refinement was made.
---

# Phase 4C.6B holdout replacement

The selected network holdout is now:

CAND-011

IoT-23 v2 CTU-IoT-Malware-Capture-3-1 / Muhstik.

It supersedes CAND-005 Hajime as the selected holdout before any semantic
holdout access occurred.

Initial sealed artifacts:

- README.md
- plain zeek-labeled/conn.log

Plain conn.log publisher size:

approximately 17 MB.

The following remain excluded from initial acquisition:

- publisher-labeled conn.log;
- labels.config;
- PCAP.

All existing analytic-freeze, access-log, label-isolation, and one-way
first-use rules remain unchanged.

CAND-005 remains in historical project records and is not erased.