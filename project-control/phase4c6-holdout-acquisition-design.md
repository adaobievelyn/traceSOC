# TraceSOC Phase 4C.6 — Sealed Holdout Acquisition Design

## Candidate

CAND-005

Status:

APPROVED

Role:

HOLDOUT

## Scenario

Dataset:

IoT-23 v2

Scenario:

CTU-IoT-Malware-Capture-9-1

Publisher scenario name:

Linux.Hajime

Device:

Raspberry Pi

## Source-version refinement

Phase 4B approved the logical IoT-23 Capture 9-1 holdout scenario.

TraceSOC will use the publisher's current IoT-23 v2 layout for acquisition.

The publisher states that v2 contains the same traffic as v1 with improved
organization, labels, metadata and repaired capture issues.

The exact TraceSOC evidence identity will therefore be fixed by:

- exact URL;
- acquisition UTC;
- filename;
- byte size;
- SHA-256;
- local sealed path.

The dataset being described as work in progress makes these exact acquisition
identifiers mandatory.

## Initial acquisition scope

### Provenance metadata

Filename:

README.md

Exact URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-9-1/README.md

Permitted pre-freeze use:

PROVENANCE_METADATA_ACCESS

### Sealed holdout payload

Filename:

2018-07-25-10-53-16-192.168.100.111-zeek-conn-log.labeled

Exact URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-9-1/2018-07-25-10-53-16-192.168.100.111-zeek-conn-log.labeled

Permitted pre-freeze use:

INTEGRITY_ONLY_ACCESS

Semantic inspection before analytic freeze:

PROHIBITED

## Deferred artifact

PCAP:

2018-07-25-10-53-16-192.168.100.111.pcap

Exact current publisher URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-9-1/pcap/2018-07-25-10-53-16-192.168.100.111.pcap

Current acquisition decision:

DEFERRED_NOT_REQUIRED

Reason:

Current holdout evaluation targets the Zeek/network path.

Packet-level replay is not yet a holdout requirement.

Estimated publisher size:

approximately 472 MB.

## Excluded pre-evaluation artifact

Label rules:

2018-07-25-10-53-16-192.168.100.111-labels.config

Publisher URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-9-1/2018-07-25-10-53-16-192.168.100.111-labels.config

Decision:

DO_NOT_ACQUIRE_PRE_EVALUATION

Reason:

The labeling rules are not required to evaluate TraceSOC and create avoidable
holdout-information leakage.

## Expected initial download volume

README:

approximately a few KB.

Zeek connection log:

publisher directory currently reports approximately 947 MB.

No PCAP in initial acquisition.

No malware binary.

No label-config acquisition.

## Sealed storage target

D:\TraceSOC-Evidence\holdout\sealed\iot23-v2\CTU-IoT-Malware-Capture-9-1

## Acquisition rules

The next phase may:

- download README;
- download the exact Zeek file;
- hash both;
- copy them into sealed holdout storage;
- set read-only attributes;
- register the evidence;
- create acquisition manifests;
- record integrity-only access.

The next phase must not:

- parse the Zeek payload;
- count Zeek records;
- inspect fields;
- inspect labels;
- execute detectors;
- normalize records;
- correlate events;
- use holdout information for development.

## First semantic access prerequisite

Before any semantic access to the holdout Zeek file:

ANALYTIC FREEZE REQUIRED.

## Current state

Download performed:
FALSE

Holdout acquired:
FALSE

Semantic payload access:
FALSE

Labels accessed:
FALSE

Analytic freeze:
FALSE