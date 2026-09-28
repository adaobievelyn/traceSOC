# TraceSOC Finding Serialization Contract

## Phase

3D.1.

## Defect discovered

Phase 3E introduced an independent integrity check against the finding hash
accepted in Phase 3D.

That check failed.

The JSON content was unchanged, but Phase 3D generated the finding using
Python text-mode file output on Windows. Newline translation therefore
produced CRLF bytes.

The Phase 3E in-memory serializer produced LF bytes.

Because SHA-256 operates on bytes, the two byte representations produced
different hashes even though they decoded to the same JSON object.

## Adjudication

The integrity check was correct to stop.

TraceSOC must not define deterministic evidence or finding hashes in terms
of host-specific text newline behavior.

The historical Phase 3D hash is preserved as evidence of the original
generated Windows text representation.

It is not deleted or rewritten.

## Canonical TraceSOC finding serialization

The canonical finding byte representation is now:

- JSON;
- keys sorted;
- indentation of two spaces;
- UTF-8;
- no BOM;
- LF newline characters only;
- exactly one final LF;
- binary file write.

Serialization contract ID:

tracesoc-finding-json-v1

## Authority

For FINDING-001 integrity checks after Phase 3D.1, the canonical hash
recorded in:

project-control/phase3d1-finding-serialization-repair.json

supersedes the historical Windows-text hash for reproducibility purposes.

The historical Phase 3D proof remains unchanged.

## Meaning

This repair changes byte serialization only.

It does not change:

- source evidence;
- CanonicalEvent values;
- SemanticEvent values;
- TRC-DET-001;
- TRC-CORR-001;
- FINDING-001 fields;
- observed facts;
- inference;
- alternative explanation;
- falsifier;
- residual risk;
- malicious-intent boundary.

## Reason

A deterministic proof artifact must have the same bytes on Windows, Linux,
or another environment that implements the same serialization contract.