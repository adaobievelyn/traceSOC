# TraceSOC Phase 4C.6B — Network Holdout Re-adjudication

## Purpose

Replace the planned Hajime holdout with a smaller, still meaningful network
holdout before any semantic holdout access occurs.

## Previous candidate

CAND-005

Scenario:

IoT-23 v2 CTU-IoT-Malware-Capture-9-1

Malware:

Linux.Hajime

Planned plain Zeek conn.log:

approximately 668 MB.

## Aborted transfer

A Phase 4C.7 download was started and manually interrupted after the temporary
conn.log reached:

47,871,986 bytes

README temporary bytes:

2,663

The partial transfer:

- remained in scratch;
- was never copied to sealed holdout storage;
- was never added to the evidence-acquisition register;
- was never semantically inspected;
- was never parsed;
- had no labels inspected;
- was deleted after the abort audit.

The authoritative repository remained unchanged.

## Reason for replacement

The Hajime plain conn.log is much larger than required for the holdout
objective.

The holdout requirement is to evaluate unseen network generalization, not to
maximize download volume.

## Replacement candidate

CAND-011

Scenario:

IoT-23 v2 CTU-IoT-Malware-Capture-3-1

Malware:

Muhstik

Device:

Raspberry Pi

Publisher metadata:

- capture duration: 36.12 hours;
- packet count: 496,959;
- original PCAP size: approximately 56 MB;
- plain Zeek conn.log size: approximately 17 MB.

Historical IoT-23 scenario accounting reports approximately 156,104 flows.

## Diversity rationale

TraceSOC development network evidence currently includes:

CTU-IoT-Malware-Capture-34-1 / Mirai.

The replacement holdout is:

CTU-IoT-Malware-Capture-3-1 / Muhstik.

Therefore the holdout differs in at least:

- malware family;
- capture date;
- capture host;
- source subnet;
- traffic realization.

## Known limitation

Both the development network evidence and this holdout originate from the
IoT-23 corpus.

Therefore:

cross-publisher network holdout diversity is NOT established.

This limitation must remain visible in the final evidence README and report.

## Initial acquisition scope

Acquire only:

1. README.md
2. zeek-labeled/conn.log

The selected conn.log is the plain Zeek log.

Do not initially acquire:

- publisher-labeled conn.log;
- labels.config;
- PCAP.

## Exact URLs

README:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/README.md

Plain conn.log:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/zeek-labeled/conn.log

Labeled conn.log deferred:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/2018-05-19-20-57-19-192.168.2.5-zeek-conn-log.labeled

labels.config deferred:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/2018-05-19-20-57-19-192.168.2.5-labels.config

PCAP deferred:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/pcap/2018-05-19-20-57-19-192.168.2.5.pcap

## Isolation

The existing TraceSOC holdout-isolation policy remains in force.

Before analytic freeze, the plain conn.log may receive only:

INTEGRITY_ONLY_ACCESS

No semantic payload access is authorized.

## Current state

Selected holdout:

CAND-011

CAND-005:

SUPERSEDED AS SELECTED HOLDOUT, RETAINED AS HISTORICAL APPROVED CANDIDATE

Holdout acquired:

FALSE

Semantic holdout access:

FALSE

Holdout label access:

FALSE