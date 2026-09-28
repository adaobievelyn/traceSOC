# TraceSOC Four-Source Adapter Slice

## Phase

3B.

## Purpose

Prove that four telemetry families can enter the TraceSOC native evidence
contract consistently before detection or correlation logic is written.

Supported architecture-validation fixture families:

1. Sysmon
2. Windows Security
3. PowerShell Operational-style telemetry
4. Zeek connection-style telemetry

## Fixture status

The files under `tests/fixtures/tiny/` are synthetic architecture fixtures.

They are not:

- the final TraceSOC evidence corpus;
- evidence of a real incident;
- evidence of malicious intent;
- detection validation datasets;
- holdout datasets;
- scale-test datasets.

Each fixture has four records:

- three accepted records;
- one deliberately invalid record.

Total:

- 16 raw records;
- 12 accepted;
- 4 quarantined.

## Provenance

Each JSONL record receives:

- logical source;
- zero-based record index;
- one-based line number;
- exact byte offset;
- exact record byte length;
- SHA-256 of the exact record bytes;
- adapter ID;
- input schema version.

Quarantined records retain this same provenance.

## Anti-hardcoding boundary

Synthetic fixtures deliberately contain `fixture_id` and `expected_answer`.

Adapters place these fields into `source_context`.

They are not promoted into `semantic_fields`.

`SemanticEvent.from_canonical()` therefore does not expose them to a
detector.

This is intentional structural separation.

## Current adapter scope

The current adapters implement only the narrow event shapes required to
prove the first vertical slice.

They are not claims of complete native parsers for every Sysmon, Windows
Security, PowerShell, or Zeek schema.

Real evidence acquisition will determine the next schema requirements.

## Anti-drift gate

No second production detection may be developed before Phase 4 real
evidence acquisition and provenance registration are complete.

Phase 3 may implement exactly one synthetic end-to-end detection and
correlation path to prove architecture.

## Not implemented in Phase 3B

- detection rules;
- correlation;
- findings;
- explain CLI;
- final evidence acquisition;
- holdout corpus;
- response validation.

## Next

Phase 3C:

Implement one behavioral detection against SemanticEvent only.