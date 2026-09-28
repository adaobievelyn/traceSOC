# TraceSOC Continuity Decision Freeze

## Phase

2D - Stage 7 -> Stage 8 -> Stage 9A -> TraceSOC continuity.

## Authority

The submitted Stage 9A package is the authoritative continuity source.

Archive:

UBI-2026-0091-STAGE_9-20260911T160346Z-1-001.zip

SHA-256:

83ae8b71ead89033f9ae0aa58eee96b8af437860d6f270202664c27c551da0b6

The earlier developmental Stage 9 repository is retained only as historical
discovery evidence.

If the developmental repository and submitted package conflict, the
submitted package governs.

## Confirmed lineage

### Stage 7

Carry forward the capability, not the old case:

- exact raw provenance;
- source file;
- line number;
- byte offset;
- byte length;
- raw SHA-256;
- adapter identity;
- input schema identity.

Disposition: ADAPT.

### Stage 8

Carry forward:

- provenance-rich normalized events;
- semantic detector-facing events;
- structural separation of fixture/expected metadata from detector input;
- source accounting;
- behavior-based detection interfaces;
- bounded correlation;
- mutation testing;
- positive and negative tests;
- malformed-input tests;
- holdouts;
- regression testing;
- anti-hardcoding validation;
- machine-readable test evidence.

Disposition: ADAPT.

The Stage 8 ATT&CK rule corpus and replay fixtures are reference material,
not TraceSOC production content.

Disposition: RETIRE_AS_PRODUCTION_REFERENCE_ONLY.

### Stage 9A

Carry forward:

- deterministic event identity;
- multi-source ingestion patterns;
- accepted/quarantined accounting;
- explicit clock state;
- apply-clock-once behavior;
- preservation of untimed evidence;
- deterministic timeline construction;
- duplicate-candidate discipline;
- clean reproduction;
- machine-readable testing;
- evidence-index claim structure;
- observed/inferred/unresolved separation;
- alternative hypotheses;
- explicit confidence;
- falsifiers;
- SEARCH_NOT_CLOSED reasoning.

Disposition: ADAPT.

Final-case adjudicators, case-specific identities, hashes, host assumptions,
network/archive reconstruction logic, and final-case answers must not drive
TraceSOC runtime decisions.

Disposition: CASE_SPECIFIC.

Submitted Stage 9A Sigma, YARA, Zeek, report-generation, and final-case rule
artifacts may be consulted as references but are not TraceSOC production
deliverables.

Disposition: RETIRE_AS_PRODUCTION_REFERENCE_ONLY.

## Response-system improvement

Stage 9A response handling was safe-by-default but did not fully prove:

pre-state
-> controlled apply
-> post-state verification
-> rollback
-> rollback verification

TraceSOC must implement this as a controlled sandbox validation chain.

## Originality boundary

No Stage 9A production source has been copied into TraceSOC during Phase 2.

TraceSOC will implement its core vertical slice natively.

Historical code may be inspected and adapted only when:

1. the capability is demonstrably generic;
2. case-specific selectors are removed;
3. a new TraceSOC-native contract exists;
4. new tests establish the behavior independently;
5. the user can explain the component's input, transformation, output and
   failure modes.

## Next phase

Phase 3 - TraceSOC-native vertical slice.

Raw fixture
-> source adapter
-> canonical event + provenance
-> semantic detection event
-> one behavioral detection
-> one bounded correlation
-> one finding
-> one evidence/claim record
-> tracesoc explain FINDING-001
-> safe response plan
-> machine-readable test record