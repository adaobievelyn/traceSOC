# TraceSOC Derived Evidence Challenge Corpus Plan

## Purpose

TraceSOC must be tested against more than clean positive records.

The challenge corpus will test parser, normalization, correlation, evidence
accounting, and failure behavior using controlled derived variants.

## Core rule

Immutable acquired originals are never edited.

Every challenge artifact must be created as a separate derived artifact and
must record:

- challenge_id;
- base TraceSOC source_id;
- base raw SHA-256;
- mutation operator;
- mutation parameters;
- generated artifact SHA-256;
- purpose;
- expected structural effect;
- expected analytical boundary;
- creation timestamp;
- tool/script version.

## Required challenge classes

CHAL-DUP-001 — exact duplicate record.

Purpose:
Verify duplicate accounting and ensure repeated input is not silently lost.

CHAL-DUP-002 — semantically repeated event represented by a separate record.

Purpose:
Distinguish exact byte duplication from repeated real-world behavior.

CHAL-MAL-001 — truncated record.

Purpose:
Verify quarantine and source accounting.

CHAL-MAL-002 — malformed structured record.

Examples:
malformed XML or malformed JSON where appropriate.

Purpose:
Verify explicit parse failure rather than silent coercion.

CHAL-MISS-001 — missing timestamp.

Purpose:
Exercise UNTIMED or rejection behavior according to the evidence contract.

CHAL-MISS-002 — missing required semantic field.

Purpose:
Verify explicit rejection/quarantine and no fabricated value.

CHAL-TIME-001 — records reordered relative to timestamps.

Purpose:
Verify deterministic timeline handling independent of file order.

CHAL-TIME-002 — correlation exactly at allowed time boundary.

Purpose:
Test inclusive boundary behavior.

CHAL-TIME-003 — correlation immediately outside allowed boundary.

Purpose:
Prove the correlation does not silently expand its time window.

CHAL-CLOCK-001 — invalid or unresolved time value.

Purpose:
Verify clock-state handling and no fabricated UTC time.

CHAL-UNKNOWN-001 — unsupported provider/event code/log type.

Purpose:
Verify graceful unsupported-input accounting.

CHAL-LABEL-001 — publisher label present.

Purpose:
Prove that labels remain outside detector-facing semantics and cannot trigger
production behavior by themselves.

CHAL-MIX-001 — benign and suspicious records mixed in the same processing run.

Purpose:
Verify that file-level labels do not contaminate per-event decisions.

CHAL-CORR-001 — same destination but wrong host/source identity.

Purpose:
Prove that time/destination adjacency alone cannot create a correlation.

CHAL-CORR-002 — same host and destination but reversed directionality.

Purpose:
Prove directionality remains part of the bounded correlation contract.

## Provenance

Challenge artifacts are derivatives.

Their lineage must remain:

immutable external source
-> TraceSOC source_id
-> exact original raw SHA-256
-> declared mutation
-> derived challenge SHA-256
-> test result.

## Labels

A challenge identifier is test metadata.

It must not enter production SemanticEvent fields or production detector
selectors.

## Timing

Challenge generation begins only after real source formats are understood and
the corresponding production adapter behavior is defined.

This plan does not authorize mutations during Phase 4C.1A.