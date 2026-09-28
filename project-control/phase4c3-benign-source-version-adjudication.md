# TraceSOC Phase 4C.3 Benign Source-Version Adjudication

## Historical approval

Phase 4B approved:

- CAND-003 — IoT-23 CTU-Honeypot-Capture-4-1, Philips Hue;
- CAND-004 — IoT-23 CTU-Honeypot-Capture-5-1, Amazon Echo.

Both were approved as BENIGN_CONTROL network evidence.

## Acquisition version

Phase 4C.3 uses the publisher's IoT-23 version 2 layout for these two
scenario identities.

## Evidence basis

The publisher states that IoT-23 v2 contains the same traffic as v1 but
provides improvements including:

- improved file organization;
- improved labels;
- corrected broken PCAP headers using pcapfix;
- corrected host IP metadata;
- corrected packet counts;
- corrected capture sizes;
- corrected start dates;
- clearer scenario names.

The publisher also states that v2 remains a work in progress.

## Adjudication

This is a SOURCE VERSION REFINEMENT, not a role change.

The underlying approved scenario identities remain:

CTU-Honeypot-Capture-4-1
CTU-Honeypot-Capture-5-1

Their primary TraceSOC role remains:

BENIGN_CONTROL

The exact v2 artifacts acquired by TraceSOC become fixed evidence identities
through:

- exact upstream acquisition locator;
- acquisition timestamp;
- byte size;
- SHA-256;
- controlled local path;
- immutable/read-only storage;
- external acquisition manifest.

Future changes to the publisher's v2 files do not change the identity of the
TraceSOC copies.

## Limitation

Because the publisher describes v2 as work in progress, TraceSOC must cite
the exact downloaded files and their hashes rather than merely saying
"IoT-23 v2".

## Label boundary

Publisher labels are ground-truth/context metadata only.

They must not enter production detector selectors or detector-facing semantic
fields.

## Safety

These are benign captures.

No malware binary or executable artifact is authorized or acquired.