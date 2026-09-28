# TraceSOC Phase 4C.6A — Holdout Source Refinement

## Purpose

Refine the Phase 4C.6 acquisition scope before any holdout payload is
downloaded.

No holdout payload has been acquired or semantically inspected.

## Existing candidate

Candidate:

CAND-005

Role:

HOLDOUT

Dataset:

IoT-23 v2

Scenario:

CTU-IoT-Malware-Capture-9-1

Publisher scenario:

Linux.Hajime

## New publisher evidence

The current publisher scenario directory exposes:

1. a root publisher-labeled Zeek connection file:

2018-07-25-10-53-16-192.168.100.111-zeek-conn-log.labeled

approximately 947 MB;

2. an additional Zeek directory containing a plain:

conn.log

approximately 668 MB;

3. the original PCAP;

4. labels.config.

The publisher documentation describes conn.log.labeled as a normal Zeek
conn.log with two additional columns containing labels.

Therefore the plain conn.log is a better initial semantic holdout input.

## Refined initial acquisition scope

### Provenance metadata

README.md

URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-9-1/README.md

Pre-freeze access class:

PROVENANCE_METADATA_ACCESS

### Sealed holdout payload

Plain Zeek conn.log

URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-9-1/zeek-labeled/conn.log

Approximate publisher directory size:

668 MB

Pre-freeze access class:

INTEGRITY_ONLY_ACCESS

Semantic access before analytic freeze:

PROHIBITED

## Labeled artifact

Filename:

2018-07-25-10-53-16-192.168.100.111-zeek-conn-log.labeled

URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-9-1/2018-07-25-10-53-16-192.168.100.111-zeek-conn-log.labeled

Initial decision:

DEFER_UNTIL_POST_PREDICTION_SCORING

Reason:

The publisher-labeled variant adds answer-bearing label columns.

Keeping it out of the initial holdout acquisition further reduces accidental
label leakage.

After TraceSOC has produced frozen predictions on the plain conn.log, a
separate evaluation/scoring phase may explicitly authorize acquisition of the
labeled variant.

## labels.config

Filename:

2018-07-25-10-53-16-192.168.100.111-labels.config

URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-9-1/2018-07-25-10-53-16-192.168.100.111-labels.config

Decision:

DO_NOT_ACQUIRE_BEFORE_SCORING

Reason:

It contains labeling rules and is unnecessary for blind evaluation.

## PCAP

Filename:

2018-07-25-10-53-16-192.168.100.111.pcap

URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-9-1/pcap/2018-07-25-10-53-16-192.168.100.111.pcap

Decision:

DEFERRED_NOT_REQUIRED

Reason:

Packet-level holdout replay is not currently required.

## Benefit

The revised scope:

- avoids label-bearing input during first-pass holdout analysis;
- reduces initial holdout download volume;
- keeps the holdout closer to realistic unlabeled telemetry;
- preserves the labeled version only as future post-prediction scoring
  evidence;
- preserves the original PCAP as an optional future packet-level validation
  source.

## Historical Phase 4C.6 design

Phase 4C.6 remains a valid historical record of the initial isolation design.

This Phase 4C.6A record supersedes only its selected Zeek artifact locator.

The isolation principles themselves remain unchanged.

## Current state

Holdout downloaded:

FALSE

Holdout semantic payload accessed:

FALSE

Publisher labels accessed:

FALSE

Plain conn.log selected:

TRUE

Labeled conn.log deferred:

TRUE

labels.config deferred:

TRUE

PCAP deferred:

TRUE