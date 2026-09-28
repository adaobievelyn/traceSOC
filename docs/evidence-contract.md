# TraceSOC Evidence Contract

## Purpose

TraceSOC must be able to explain every material analytical result back to
raw evidence without exposing fixture answers, expected outcomes, or
investigation labels to detection logic.

The initial contract is:

raw record
-> RawLocator
-> CanonicalEvent
-> SemanticEvent
-> detector/correlation layers

## RawLocator

A RawLocator is the stable evidence pointer.

It contains:

- logical source path;
- record index;
- optional line number;
- optional byte offset;
- optional byte length;
- raw SHA-256;
- adapter identity;
- input schema version.

The path is logical and evidence-relative. Absolute workstation paths are
not accepted because they would make event identity machine-dependent.

## CanonicalEvent

CanonicalEvent is provenance-rich.

It contains:

- deterministic event ID;
- source family;
- normalized event type;
- clock state;
- raw locator;
- raw timestamp when present;
- normalized UTC timestamp when justified;
- host;
- principal;
- semantic fields;
- source context.

CanonicalEvent is evidence representation, not an incident conclusion.

## SemanticEvent

SemanticEvent is detector-facing.

It deliberately excludes:

- RawLocator;
- source_context;
- fixture identifiers;
- expected outcomes stored in source context;
- raw assessment metadata.

Only fields explicitly promoted into semantic_fields reach the semantic
event.

This creates a structural anti-hardcoding boundary.

## Clock states

OBSERVED:
A valid timestamp is directly supported and normalized to UTC.

CORRECTED:
A timestamp has an evidence-supported correction and is normalized to UTC.

UNTIMED:
The source record does not provide a usable time.

UNRESOLVED:
Time information exists but cannot currently be normalized defensibly.

UNTIMED and UNRESOLVED events must not claim a normalized UTC timestamp.

## Deterministic identity

Event identity is derived from:

- identity contract version;
- source type;
- event type;
- logical source;
- raw record index;
- line number;
- byte offset;
- raw SHA-256;
- adapter identity;
- input schema version.

It does not use:

- fixture IDs;
- expected answers;
- technique labels;
- verdicts;
- campaign answers;
- case-specific hashes as selectors.

## Evidence doctrine

A CanonicalEvent may support later reasoning, but it does not itself prove:

- malicious intent;
- causality;
- campaign membership;
- credential compromise;
- privilege escalation;
- lateral movement;
- business impact.

Those conclusions require explicit higher-layer evidence.

## Phase 3A scope

This phase defines only the evidence contract.

It does not yet implement:

- source adapters;
- detections;
- correlation;
- findings;
- CLI explanation;
- response validation.

Those capabilities must build on this contract rather than bypass it.