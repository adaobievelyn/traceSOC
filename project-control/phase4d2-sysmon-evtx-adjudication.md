# TraceSOC Phase 4D.2 — Benign Sysmon EVTX Adjudication

## Question

Why does the selected Nextron benign Sysmon EVTX contain approximately
799 MB of data while Windows event readers return no events?

## Artifact

Microsoft-Windows-Sysmon%4Operational.evtx

Byte size:

799,084,544

SHA-256:

efbc4d4cd450eddf7665f5965b0f6cfe30088f8f69225886e1d433329fb950cb

## Integrity observations

The derived EVTX:

- has the expected TraceSOC SHA-256;
- has the expected byte size;
- matches the original Nextron tar member byte size exactly;
- originates from a regular archive file member;
- is not a symbolic link;
- is not a hard link;
- contains the expected EVTX file signature;
- contains expected EVTX chunk signatures.

No evidence supports an extraction mismatch.

## Reader observations

Control PowerShell EVTX:

- Get-WinEvent: readable;
- .NET EventLogReader: readable;
- wevtutil query: readable;
- Windows offline metadata record count: 121.

Control Security EVTX:

- Get-WinEvent: readable;
- .NET EventLogReader: readable;
- wevtutil query: readable;
- Windows offline metadata record count: 3,448.

Sysmon EVTX:

- Get-WinEvent default: no matching events;
- Get-WinEvent oldest: no matching events;
- .NET EventLogReader: no event;
- wevtutil query oldest: no event;
- wevtutil query newest: no event;
- Windows offline metadata record count: 0.

## Adjudication

Status:

CONFIRMED_ZERO_RECORD_LOG

The Sysmon EVTX is recognized by the Windows Event Log subsystem and reports
zero log records.

The evidence does NOT support describing the artifact as corrupt.

The evidence does NOT support describing the extraction as failed.

The evidence does NOT support describing the result as a TraceSOC parser
failure.

The file's large byte size does not establish that event records are populated.

## Correction to earlier interpretation

Phase 4C.5 correctly established:

- archive integrity;
- exact extraction;
- EVTX magic;
- parent/derived lineage.

However, its summary wording `SYSMON_BENIGN=PASS` was broader than the later
event-readability evidence supports.

The corrected current interpretation is:

- endpoint benign control: ACQUIRED;
- benign Windows Security events: ESTABLISHED;
- benign PowerShell events: ESTABLISHED;
- benign Sysmon event data: NOT ESTABLISHED from this artifact.

The historical Phase 4C.5 proof is retained rather than rewritten.

This later adjudication supersedes only the interpretation of the Sysmon
channel's event-content availability.

## Coverage consequence

COV-006 remains ACQUIRED.

COV-006 is an endpoint benign-control requirement, not a requirement that
every endpoint telemetry family have populated benign events.

No new external dataset acquisition is authorized on the basis of this
finding.

If later detector validation demonstrates that an independent populated benign
Sysmon corpus is materially required, that need must be demonstrated by a
specific failed validation requirement before acquisition can be reopened.

## Adapter consequence

Generic EVTX ingestion must handle a Windows-recognized zero-record EVTX as a
valid empty input.

It must not:

- fabricate events;
- quarantine the entire file merely because it contains zero records;
- infer corruption from file size;
- count zero records as parser failure.

This particular artifact cannot validate the Sysmon EVTX-to-canonical mapping
because there are no event records to map.

Real Sysmon mapping will initially be validated using the populated development
XML event stream.

## Filesystem timestamps

The creation/access/write times reported by `wevtutil gli` on the extracted
files are local filesystem metadata.

They are not original telemetry event timestamps and must not be used as
evidence time.

## Holdout

No holdout semantic or label access occurred during this diagnosis.

## Next phase

PHASE 4D.3 — REAL-FORMAT INGESTION IMPLEMENTATION