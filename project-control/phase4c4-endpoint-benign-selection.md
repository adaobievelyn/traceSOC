# TraceSOC Phase 4C.4 Endpoint Benign Evidence Selection

## Decision

APPROVED

Candidate ID:

CAND-010

Primary role:

BENIGN_CONTROL

## Source

Publisher:

Nextron Systems

Project:

evtx-baseline

Release:

v0.8.4

Selected release asset:

win10-client.tgz

Exact release asset locator:

https://github.com/NextronSystems/evtx-baseline/releases/download/v0.8.4/win10-client.tgz

Repository:

https://github.com/NextronSystems/evtx-baseline

Release page:

https://github.com/NextronSystems/evtx-baseline/releases/tag/v0.8.4

## Publisher-reported release identity

Displayed asset size:

67.6 MB

Publisher-provided SHA-256:

d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e

This publisher hash is an expected acquisition hash.

TraceSOC must independently compute SHA-256 after download and compare it
before the archive is accepted.

## License

Repository license:

Apache License 2.0.

TraceSOC must preserve the publisher/repository attribution and source
reference.

## Why this source is appropriate

The publisher explicitly describes evtx-baseline as example goodware EVTX
logs containing software installation and basic user interaction.

Documented example user activity includes ordinary operations such as:

- opening normal applications;
- installing and updating software;
- web browsing;
- downloading/opening documents;
- running developer utilities;
- using file-transfer clients;
- opening editors;
- archiving/extracting files;
- using common Windows desktop applications.

This is useful negative-pressure evidence because legitimate endpoint activity
must not automatically become a suspicious finding merely because tools such
as PowerShell, archive utilities, browsers, file-transfer software, or
administrative processes appear.

## Collection configuration documented by publisher

The evtx-baseline collection procedure documents:

- Sysmon installation;
- enlarged Sysmon logging;
- enlarged PowerShell logging;
- enlarged Windows Security logging;
- process-creation auditing;
- command-line process logging;
- PowerShell Script Block Logging;
- PowerShell Module Logging;
- export of Windows EVTX files.

Therefore the archive is a strong candidate for benign endpoint telemetry
across the same broad Windows evidence domains TraceSOC analyzes.

## Important evidence boundary

The selection phase does NOT assume that every desired EVTX channel is
actually present in the selected archive.

After acquisition, TraceSOC must inspect the archive contents and explicitly
verify the presence or absence of at least:

- Microsoft-Windows-Sysmon/Operational;
- Security;
- Microsoft-Windows-PowerShell/Operational.

Observed archive contents are authoritative.

Publisher documentation is context, not a substitute for inspecting the
actual acquired artifact.

## Acquisition design

The archive itself will be retained as the immutable external raw artifact.

The original downloaded archive will:

1. be downloaded into controlled scratch;
2. have SHA-256 computed;
3. be compared to the publisher-provided SHA-256;
4. be copied into controlled raw storage;
5. have SHA-256 recomputed after storage;
6. receive a read-only safety attribute;
7. be registered in the acquisition register;
8. receive an external acquisition manifest.

## Extraction design

The raw archive will never be modified.

Extraction will occur into a separate derived/extracted namespace.

Selected EVTX members required by TraceSOC will be individually hashed.

Each extracted EVTX must retain lineage to:

CAND-010
-> immutable win10-client.tgz
-> archive SHA-256
-> archive member path
-> extracted file SHA-256.

## Benign classification boundary

"Goodware" and "benign" are publisher/source context.

They are not production detector selectors.

If TraceSOC detects apparently suspicious behavior in this dataset, the result
must be investigated rather than automatically dismissed or automatically
relabeled.

Possible interpretations include:

- false positive;
- legitimate administrative behavior;
- ambiguous activity;
- source contamination;
- genuinely suspicious behavior in nominally benign telemetry.

## Rejection / partial-acceptance conditions

Acquisition must stop or be adjudicated if:

- downloaded archive SHA-256 differs from the publisher-provided hash;
- archive cannot be opened safely;
- archive structure is materially different from documentation;
- no relevant endpoint EVTX exists;
- source provenance cannot be maintained.

If only some target channels are present, TraceSOC must record the actual
coverage rather than fabricating missing telemetry.

## Safety

No executable content from the archive will be executed.

The evidence is for offline log analysis only.

## Current state

Selected:
TRUE

Approved:
TRUE

Downloaded:
FALSE

Acquired:
FALSE

Raw evidence modified:
FALSE

Detector tuning performed:
FALSE

Next:

PHASE_4C5_ENDPOINT_BENIGN_EVIDENCE_ACQUISITION