# TraceSOC — Authoritative Stage 9A Submission Review

## Authority

This review treats the submitted assessment package as the authoritative Stage 9A source:

- Archive: `UBI-2026-0091-STAGE_9-20260911T160346Z-1-001.zip`
- Archive SHA-256: `83ae8b71ead89033f9ae0aa58eee96b8af437860d6f270202664c27c551da0b6`
- Submission package root: `UBI-2026-0091-STAGE_9/`
- Technical forensic freeze recorded by the submission: `d4d156abc5798d189171743ddac555b33c6ede13`
- Later developmental repository HEAD supplied separately: `88522176181b0249c545e60c30f878510de8465f`

The developmental ZIP is retained only as lineage/history. Carry-forward decisions are governed by what survived into the submitted package and by the submitted machine-readable evidence.

## Package integrity

The submission contains 255 files including `manifest.sha256`.

`manifest.sha256` contains 254 entries and exactly covers every other file in the package:

- manifest entries: 254
- non-manifest package files: 254
- missing files: 0
- hash mismatches: 0
- unlisted files: 0
- phantom manifest paths: 0

Result: **submission package integrity verified**.

## Developmental repository vs submitted package

The final developmental Git tree contains 229 tracked files. The submitted package contains 255 files.

Relative-path comparison:

- overlapping files: 223
- semantically identical overlapping files: 221
- byte-identical overlapping files: 32
- line-ending-only differences: 189
- material text differences: 2
- submission-only files: 32
- developmental-only files: 6

The only material overlapping-file differences are packaging/defense state:

1. `evidence/defense-readiness.md`
   - submitted package marks the recording hygiene check complete.
2. `evidence/final-document-generation.json`
   - submitted package has the later generation timestamp and no pending `video-url.txt` / `manifest.sha256` artifacts.

No material Stage 9 analytical source-code difference was identified between the final developmental Git tree and the submitted package.

The submission-only set primarily adds:

- the sealed original Stage 9 evidence package;
- raw evidence files;
- regenerated parser/timeline products;
- `manifest.sha256`;
- `video-url.txt`;
- packaging artifacts.

The developmental-only set consists of six internal `project-control/` contract/traceability files not included in the assessed submission.

## Assessed result state

The submitted `assessment-manifest.json` records:

- public tests: 12 passed / 0 failed;
- peak memory: about 148.6 MB;
- runtime: about 13.2 seconds;
- frozen hashes for timeline, evidence index, IOC set, recovered archive, incident report and executive brief.

The submitted `evidence/final-test-summary.json` records:

- tests run: 62
- passed: 62
- failed: 0
- errors: 0
- skipped: 0
- holdout acceptance tests present: true
- holdout fixtures: 12
- expected answers drive decisions: false
- fixture IDs drive decisions: false

An independent Linux execution of the submitted test suite during this review produced:

- tests run: 62
- passed: 61
- failed: 0
- errors: 0
- skipped: 1
- process exit code: 0

The single skip is the PowerShell dry-run execution test because PowerShell is unavailable in the review environment. All other submitted tests passed unchanged. This does not replace the authoritative Windows result; it provides an additional portability check.

## Clean reproduction

The submitted `evidence/clean-reproduction.json` records:

- raw inputs verified before use: true
- raw inputs provisioned from external package: true
- investigation outputs regenerated: true
- recovered tree regenerated: true
- scored outputs rebuilt byte-identically: true
- repository clean after reproduction: true
- tests: 62 passed / 0 failed / 0 errors
- timeline rows: 100,053
- source types: 4

The three scored machine-readable outputs were reproduced identically:

- `timeline.csv`
- `ioc-set.csv`
- `evidence-index.csv`

The recovered archive tree was also identity-verified.

## Stage 7 -> Stage 8 -> Stage 9 continuity actually present in the submission

### Stage 7

The submitted continuity verification records exactly two selected Stage 7 imports:

1. `timeline-builder/continuity/stage7/network-range/continuity_adapter.py`
2. `timeline-builder/continuity/stage7/detections/stage7-continuity-handoff.json`

Both match the preserved expected SHA-256 values.

Stage 7 contract tests in Stage 9:

- tests: 4
- failures: 0
- errors: 0
- skipped: 0

The important inherited contract is byte-level provenance:

`raw record -> source file + line + byte offset + byte length + raw SHA-256 + adapter/schema identity -> NormalizedEvent`

Stage 9 explicitly rejects transfer of Stage 7 case conclusions, topology, historical IPs, test identifiers and prior detection metadata into Stage 9 semantic decisions.

### Stage 8

The submission verifies an exact Stage 8 continuity snapshot:

- continuity source commit: `952a3543378cdbf6a91bbda933963f85178f8ab3`
- assessed lineage commit: `fb2cc79bf0db2af62a8c1f5e4f5caedf5dbf7ed0`
- imported rows/artifacts: 105
- imported historical raw-event extracts: 9
- regression tests: 171
- failures: 0
- errors: 0
- skipped: 0

The Stage 8 snapshot includes the functional detection framework, rules, fixtures, tests, evidence records, decision records, source accounting, normalization verification and raw-event provenance extracts.

Stage 8's most important generic engineering contribution is the separation of:

1. provenance-rich `NormalizedEvent`; and
2. detector-facing `DetectionEvent`.

The detector projection deliberately excludes source-custody metadata, fixture/assertion metadata and raw provenance. This creates a structural anti-hardcoding boundary rather than relying only on developer discipline.

Stage 8 also supplies:

- accepted-source accounting;
- semantic rules;
- bounded sequence/time-window correlation;
- explicit diagnostic no-alert states;
- mutation testing;
- holdout testing;
- deterministic regression;
- anti-hardcoding tests;
- source-to-decision navigation.

Verified Stage 8 anti-hardcoding evidence records:

- production rule files reviewed: 13
- private/case literal hits: 0
- forbidden metadata identifier hits: 0
- transfer-safe attack mutations alerted: 48/48
- benign mutations alerted: 0/144

### Stage 9

The submitted Stage 9 production pipeline does **not** import `stage8_pipeline` at runtime outside the frozen continuity snapshot. A static Python import scan found zero direct Stage 7/8 continuity imports from Stage 9 production modules.

Therefore Stage 9's architecture is best described as:

`verified continuity contracts + frozen prior-stage proof -> independently implemented Stage 9 interfaces`

rather than "Stage 8 package used as the Stage 9 runtime engine."

Stage 9 independently implements:

- multi-source ingestion;
- deterministic normalized event IDs;
- semantic fingerprints;
- malformed-record quarantine;
- exact locators;
- clock model derivation and explicit zero offsets;
- apply-clock-once enforcement;
- preservation of untimed events;
- semantic duplicate candidates;
- deterministic timeline generation;
- bounded public interface tests;
- post-freeze holdout tests;
- detection validation;
- clean reproduction;
- final claim/evidence generation;
- incident investigation/adjudication.

## Submitted normalized-event contract

The submitted parser-generated normalized stream contains 100,053 records:

- Sysmon: 100,000
- PCAP: 51
- PowerShell: 1
- EML: 1

Common Stage 9 normalized fields include:

- `normalized_event_id`
- `semantic_fingerprint`
- `schema_version`
- `source_id`
- `source_type`
- `adapter_id`
- `artifact_path`
- `artifact_sha256`
- `exact_locator`
- `parser_status`
- `original_time`
- `observed_time_utc`
- `clock_status`
- `clock_offset_seconds`
- `utc_time`
- `event_type`
- `activity`
- `host`
- `user`
- `src_ip`
- `dst_ip`
- `details`

Important behavior:

- ingestion does not silently assume clocks;
- malformed JSON is quarantined;
- untimed evidence survives the timeline;
- clock corrections are explicit and applied once;
- zero offset is a real verified value, not treated as absence.

## Submitted claim/evidence contract

`evidence-index.csv` contains 30 claims with these fields:

- `claim_id`
- `report_section`
- `claim`
- `artifact_path`
- `exact_locator`
- `collection_time_utc`
- `sha256`
- `proves`
- `does_not_prove`
- `confidence`
- `alternative_considered`
- `disposition`

This is one of the strongest reusable Stage 9A ideas. It prevents a report claim from existing without an evidence locator and forces explicit separation between what evidence proves and what it does not prove.

For TraceSOC, this contract should be **extended**, not copied unchanged, with:

- finding ID;
- detection IDs;
- correlation-edge IDs;
- hypothesis state;
- falsifier;
- residual risk;
- business impact;
- decision required;
- response-validation state.

## What the assessed incident report proves about methodology

The 15-page submitted incident report consistently uses a bounded structure:

- raw proof;
- what the evidence proves;
- what it does not prove;
- alternative explanation;
- disposition;
- next collection action.

The one-page executive brief preserves the same boundary at business level.

This directly supports carrying forward the reasoning discipline while leaving the Stage 9 case answers behind.

## Why the 14/15 response score occurred

The submitted response workflow is safe by default:

- `Contain`, `Recover`, `Verify` modes;
- modifying actions require explicit `-Apply`;
- scheduled-task disable/remove;
- outbound firewall blocking;
- archive removal;
- identity containment remains manual rather than blindly disabling an account.

The response tests verify:

- script existence;
- safe dry-run default;
- required response cmdlets;
- no blind `Disable-ADAccount` behavior;
- dry-run execution where PowerShell is available.

They do **not** validate a complete controlled lifecycle of:

`pre-state -> apply -> post-state verification -> rollback -> rollback verification`

There is also no rollback mode in the submitted script.

This precisely matches the external feedback that one point was lost for practical validation limits of containment/recovery controls.

TraceSOC should deliberately convert this weakness into a design feature.

# Authoritative TraceSOC carry-forward decisions

The safest interpretation for an original Stage 9B project is: **carry contracts and methods forward aggressively; carry case-specific implementations forward minimally.**

Until the formal Stage 9B reuse rules arrive, no Stage 9A code should be copied into TraceSOC production source.

| Prior component | Decision | TraceSOC treatment |
|---|---|---|
| Stage 7 byte-level provenance contract | ADAPT | Make raw locators and record hashes first-class TraceSOC evidence fields. |
| Stage 7 Zeek continuity adapter | ADAPT | Use as a design reference for the TraceSOC Zeek adapter; implement TraceSOC-native schema. |
| Stage 7 historical handoff/case metadata | CASE_SPECIFIC | Preserve only as lineage evidence; never use as runtime semantics. |
| Stage 8 `NormalizedEvent` model | ADAPT | Build a TraceSOC canonical event contract supporting Sysmon, Security, PowerShell and Zeek. |
| Stage 8 `DetectionEvent` semantic projection | ADAPT | Preserve the strict separation between provenance metadata and detector-visible fields. |
| Stage 8 source accounting | ADAPT | Build accepted/quarantined/duplicate accounting with balance assertions. |
| Stage 8 detection engine/rule registry | ADAPT | Create a smaller TraceSOC detector API with contributing-event evidence IDs. |
| Stage 8 mutation framework | ADAPT | Build TraceSOC mutations for identifiers, field loss/rename, ordering, timing boundary and benign changes. |
| Stage 8 holdout methodology | ADAPT | Require genuinely separate post-rule holdouts. |
| Stage 8 anti-hardcoding tests | ADAPT | Make fixture-ID / expected-answer / case-marker independence a permanent TraceSOC acceptance gate. |
| Stage 8 ATT&CK rule implementations | RETIRE | Do not make the old Stage 8 rules the TraceSOC rule library; use only as design references. |
| Stage 8 replay fixtures/raw events | RETIRE | Do not use as TraceSOC product evidence. |
| Stage 8 monolithic regression runner | ADAPT | Preserve deterministic two-run proof but create a TraceSOC-native modular runner/test ledger. |
| Stage 8/9 machine test-report runner | ADAPT | Build one consolidated TraceSOC machine-readable test ledger/report. |
| Stage 9 ingestion | ADAPT | Reuse design ideas: deterministic IDs, semantic fingerprints, quarantine, exact locators; write new source adapters. |
| Stage 9 clock integrity | ADAPT | Preserve explicit clock state, zero offset, unresolved state and apply-once behavior. |
| Stage 9 timeline builder | ADAPT | Preserve untimed events, deterministic sorting and semantic duplicate-candidate logic; remove case annotations. |
| Stage 9 public-interface/holdout pattern | ADAPT | Use it to prove semantic behavior independent of fixture IDs and expected answers. |
| Stage 9 clean reproduction | ADAPT | Make clean rebuild and hash identity a TraceSOC definition-of-done requirement. |
| Stage 9 evidence-index schema | ADAPT | Extend into TraceSOC proof/claim records with falsifier, residual risk and business decision fields. |
| Stage 9 neutral evidence graph implementation | CASE_SPECIFIC | Do not copy the large case graph builder; design a smaller generic TraceSOC correlation graph. |
| Stage 9 competing-hypothesis methodology | ADAPT | Carry hypothesis, confidence, alternative, falsifier and `SEARCH_NOT_CLOSED` semantics into findings. |
| Stage 9 credential/privilege/host-movement adjudicators | CASE_SPECIFIC | Keep as historical investigation code only. |
| Stage 9 network archive recovery | CASE_SPECIFIC | Keep outside the core product; only generalize later if a new dataset creates a real requirement. |
| Stage 9 Sigma/YARA/Zeek rules | RETIRE | Do not present these as TraceSOC's original rule set. Build new behavioral detections against TraceSOC's schema. |
| Stage 9 response workflow | ADAPT | Redesign around safe sandbox apply, state verification, rollback and rollback verification. |
| Stage 9 report/document generator | RETIRE | TraceSOC reporting should be generated from its own generic finding/claim model. |

## Phase 2 closure conclusion

The submitted package validates the continuity thesis:

**TraceSOC does need Stage 7/8/9 continuity, but primarily as a proven engineering contract, not as a repository to copy.**

The strongest inherited principles are:

1. exact raw provenance;
2. semantic/provenance separation;
3. complete source accounting;
4. anti-hardcoding boundaries;
5. mutation and holdout testing;
6. explicit clock state;
7. deterministic clean reproduction;
8. evidence-bounded claims;
9. competing hypotheses and residual uncertainty;
10. response safety.

TraceSOC's originality should come from combining those principles into a reusable SOC finding/correlation/response-validation product with a generic multi-source schema, a smaller explainable correlation model, business-decision fields and materially stronger response validation.

## Recommended next step

Do not acquire large datasets and do not copy Stage 9 source yet.

Freeze this continuity decision into TraceSOC project control, then build a **TraceSOC-native vertical slice from scratch**:

`raw fixture -> adapter -> canonical event/provenance -> semantic detection event -> one behavioral detection -> one bounded correlation -> one finding/claim -> explain command -> dry-run response plan -> machine test record`

Minimum vertical-slice fixture should contain:

- Sysmon event(s);
- Windows Security event(s);
- PowerShell Operational event(s);
- Zeek event(s);
- one correlated suspicious sequence;
- one benign control;
- one malformed input;
- one untimed/clock case;
- one mutation demonstrating IDs/expected answers do not drive decisions.

The response part of this slice should initially remain non-destructive, but its state model should already include:

`planned -> applied_in_sandbox -> verified -> rolled_back -> rollback_verified`

That directly addresses the only Stage 9A scoring weakness while preserving the evidence methodology that earned 89/90.
