# TraceSOC Storage Policy

## Decision

The external SSD mounted as D: is accepted as OPTIONAL bulk-evidence
storage.

It is not a mandatory TraceSOC runtime dependency.

## Controlled namespace

D:\TraceSOC-Evidence

TraceSOC project activity must not modify existing content outside this
directory.

## Approved uses

- immutable downloaded evidence archives;
- large PCAP collections;
- public telemetry datasets;
- holdout datasets;
- large raw evidence;
- large non-scored temporary processing files.

## Not approved as primary location

The following remain on the system drive and inside the Git-controlled
TraceSOC repository:

- production source code;
- project-control records;
- small fixtures;
- core tests;
- final machine-readable proof;
- final scored outputs;
- clean-build instructions.

## Rationale

The drive is a healthy NTFS USB SSD with 318.12 GB free at the time of
adoption.

A controlled 256 MB write/read/hash/delete smoke test completed
successfully.

Measured smoke-test values:

- Write MB/s: 195.57
- Read/hash MB/s: 121.62
- I/O class: SUITABLE

These figures are validation measurements, not claims of maximum hardware
performance.

## Reproducibility rule

TraceSOC's core acceptance suite must remain runnable without D: by using
small committed fixtures.

Large-dataset or scale tests may be explicitly skipped when optional bulk
evidence is unavailable.

## Safety rule

No malware is executed from D:.

Attack datasets are treated as inert evidence unless the formal Stage 9B
contract explicitly requires another safe method.