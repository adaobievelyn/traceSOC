# TraceSOC Phase 4D.1 — Real-Format Compatibility Adjudication

## Objective

Translate the Phase 4D.0 read-only observations into explicit implementation
requirements before changing parser code.

No detector logic is changed in this phase.

No holdout semantic payload is accessed.

## Existing architecture

TraceSOC currently has four JSONL adapters:

- load_sysmon_jsonl
- load_windows_security_jsonl
- load_powershell_jsonl
- load_zeek_jsonl

These remain valid synthetic/regression adapters.

They must not be deleted merely because real evidence uses other formats.

## Compatibility decision

Synthetic JSONL fixtures:

COMPATIBLE

Real development PowerShell:

ADAPTATION_REQUIRED

Observed format:

XML_EVENT_STREAM

Real development Sysmon:

ADAPTATION_REQUIRED

Observed format:

XML_EVENT_STREAM

Real development Windows Security:

ADAPTATION_REQUIRED

Observed format:

TEXT_EVENT_EXPORT

Real development Zeek:

ADAPTATION_REQUIRED

Observed format:

ZEEK_TSV_CONN_LOG

Benign PowerShell EVTX:

ADAPTATION_REQUIRED

Bounded Get-WinEvent readability:

READABLE

Benign Windows Security EVTX:

ADAPTATION_REQUIRED

Bounded Get-WinEvent readability:

READABLE

Benign Sysmon EVTX:

DIAGNOSIS_REQUIRED

Observed Get-WinEvent result/error:

No events were found that match the specified selection criteria.

No corruption claim is made.

The file remains hash-valid and retains its parent-archive lineage.

## Required architecture

Real-format ingestion must preserve the existing evidence contract:

raw source record
-> parsed event
-> CanonicalEvent
-> SemanticEvent
-> detector
-> correlation
-> finding

Real-format support must be additive.

The existing JSONL paths remain regression controls.

## XML event streams

PowerShell and Sysmon development evidence are concatenated Windows Event XML
records.

The reader must identify individual Event records without rewriting the source.

Each accepted or quarantined raw record must retain:

- logical source;
- exact record index;
- exact byte offset;
- exact byte length;
- exact raw-record SHA-256;
- adapter ID;
- schema version.

The mapper must use observed Windows Event fields, not scenario-specific
answers.

## Windows Security text export

The Security development source is a multiline text event export.

Observed record structure includes:

- leading event timestamp;
- LogName;
- SourceName;
- EventCode;
- ComputerName;
- RecordNumber;
- Message;
- multiline event-specific sections.

A boundary-aware reader is required.

TraceSOC must not detect scenario behavior by matching the source filename,
T1562.001 directory, or expected attack description.

## Zeek

Development Zeek evidence uses standard Zeek ASCII/TSV headers including:

- #separator;
- #fields;
- #types.

The development file also contains publisher:

- label;
- det_label.

These columns are evidence metadata.

They may be retained in source_context for later evaluation/accounting.

They MUST NOT become detection selectors or semantic behavior fields used to
produce a detection verdict.

## EVTX

TraceSOC should not introduce a heavy binary-EVTX dependency before it is
necessary.

The current preferred lightweight architecture is:

EVTX
-> controlled Windows event extraction boundary
-> Windows Event XML
-> same family-specific XML mapper

That design reuses the real XML mapping path while retaining parent EVTX
identity and EventRecordID provenance.

This decision remains provisional for Sysmon until Phase 4D.2 resolves why the
selected benign Sysmon EVTX returns no event through bounded Get-WinEvent
access.

## Holdout

TS-HOLD-IOT23V2-003-ZEEK remains:

SEALED_NOT_ADJUDICATED

Its semantic compatibility is intentionally unknown.

It must not be opened merely to make development convenient.

## Hardcoding prohibition

Real-format adapters must not select records using:

- fixture IDs;
- candidate IDs;
- source hashes;
- expected verdicts;
- malware-family labels;
- known attack IP addresses;
- scenario folder names;
- expected command strings used only because they appear in the selected
  corpus.

Parsing may depend only on source format/schema semantics.

## Next phase

PHASE 4D.2 — SYSMON BENIGN EVTX READABILITY DIAGNOSIS

This is intentionally isolated before parser implementation.

After that diagnosis:

PHASE 4D.3 — REAL-FORMAT INGESTION IMPLEMENTATION