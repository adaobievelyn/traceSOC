# TraceSOC First Behavioral Detection

## Phase

3C.

## Detection

`TRC-DET-001`

PowerShell web-retrieval behavior.

## Purpose

The first detector exists only to prove the TraceSOC detection boundary.

It is not the final detection corpus.

## Detector input

`SemanticEvent` only.

The detector does not receive:

- RawLocator;
- source_context;
- fixture_id;
- expected_answer;
- original raw record;
- Stage 9A verdicts.

## Behavioral conditions

A match requires all of the following:

1. source family is PowerShell;
2. normalized event type is `script_execution`;
3. execution engine is `powershell.exe` or `pwsh.exe`;
4. script text contains a supported retrieval primitive:
   - `Invoke-WebRequest`; or
   - `Start-BitsTransfer`;
5. the same semantic event contains an explicit HTTP or HTTPS URI.

## Explicit non-input

`command_family` does not determine the match.

It exists in the synthetic fixture but the detector deliberately ignores it.

This proves that the architecture is not merely selecting the fixture's
pre-labelled answer.

## Claim boundary

A match establishes:

> PowerShell web-retrieval behavior was observed in this semantic event.

A match does not establish:

- malware;
- malicious intent;
- compromise;
- initial access;
- exfiltration;
- successful payload execution;
- campaign membership;
- business impact.

Those require additional evidence.

## Evidence contribution

A match records the exact semantic event ID that caused the detector to
fire.

Future findings must trace that event ID back through CanonicalEvent and
RawLocator to the original source record.

## Phase 3 limit

TraceSOC may implement exactly one synthetic behavioral detector before
real evidence acquisition.

The next phase is bounded correlation, not a second detector.

## Anti-drift rule

No second production detector before Phase 4 evidence acquisition and
provenance registration.