# TraceSOC Finding Explanation

## Phase

3E.

## Command

Run from the TraceSOC repository using the project Python environment:

python -m tracesoc explain FINDING-001

Machine-readable form:

python -m tracesoc explain FINDING-001 --json

## Purpose

This command completes the first TraceSOC raw-to-result proof path.

It does not trust a stored finding merely because that file exists.

The command regenerates FINDING-001 from the controlled vertical slice,
serializes it under the canonical TraceSOC finding contract, and verifies
its SHA-256 against the accepted Phase 3D.1 canonical hash.

## Serialization authority

Serialization ID:

tracesoc-finding-json-v1

Contract:

- UTF-8;
- no BOM;
- sorted JSON keys;
- two-space indentation;
- LF only;
- one final LF;
- binary write semantics.

The historical Phase 3D Windows-text hash remains preserved in the Phase 3D
proof.

The canonical Phase 3D.1 hash governs post-repair reproducibility checks.

## Raw evidence verification

For every evidence reference, TraceSOC verifies:

- repository-bound logical source path;
- source file existence;
- byte offset;
- byte length;
- line number where available;
- SHA-256 of the exact raw record bytes;
- line locator and byte-range locator agreement.

A mismatch causes the explanation to fail.

## Demonstrated proof chain

raw JSONL record
-> RawLocator
-> CanonicalEvent
-> SemanticEvent
-> TRC-DET-001
-> TRC-CORR-001
-> FINDING-001
-> canonical finding hash
-> explain
-> exact raw-record re-verification.

## Explanation content

The human-readable explanation exposes:

- observed facts;
- inference;
- confidence and confidence scope;
- alternative explanation;
- falsifier;
- residual risk;
- business impact;
- decision required;
- recommended action;
- response-validation status;
- detection identifiers;
- correlation identifiers;
- correlation-edge identifiers;
- raw evidence locators and hashes.

## Claim boundary

FINDING-001 remains synthetic.

Malicious intent remains unestablished.

The finding demonstrates architectural behavior only.

## Anti-drift

Production detector count remains one.

Production correlation count remains one.

No second detector is allowed before Phase 4 real evidence acquisition and
provenance registration.

After Phase 3E, TraceSOC must stop for the mandatory pre-Phase-4 defense
readiness gate.