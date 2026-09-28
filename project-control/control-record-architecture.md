# TraceSOC Finalist Control Record Architecture

## Purpose

TraceSOC separates technical evidence, submission-contract artifacts, finalist
control records and historical development records so that old development
state cannot silently become current finalist truth.

## Tier 1 — technical and submission authorities

The following are current finalist authorities:

- `project-control/finalist-candidate-freeze-v04.json`
- `results/acceptance/public-test-results.json`
- `project-control/finalist-one-command-reproduction-validation.json`
- `evidence/reference-case/`
- `evidence/final-proof/`
- `finalist-evidence-ledger.json`
- `evidence-index.csv`
- `timeline.csv`
- `ioc-set.csv`
- `assessment-manifest.json`
- `continuity-record.md`
- `evidence/finalist-problem-impact-proof-defense.md`

When a historical control record conflicts with one of these current
authorities, the current authenticated finalist authority governs the finalist
claim.

## Tier 2 — living finalist control records

These files summarize current project state:

- `project-control/tracesoc-master-record.json`
- `project-control/requirements-matrix.csv`
- `project-control/risk-register.csv`
- `project-control/evidence-ledger.csv`
- `project-control/defense-readiness-checklist.md`
- `project-control/control-record-architecture.md`
- `project-control/defense-notes.md`

They are navigational/control artifacts. They do not replace the underlying
proof.

## Tier 3 — historical development evidence

Historical phase proofs, point-in-time refresh records, the consolidated development test ledger and prior
acceptance states remain useful for continuity and engineering history.

`project-control/finalist-living-control-refresh.json` is a historical
point-in-time packaging refresh record. Its recorded hashes and remaining-work
list describe the state when that record was created and must not override
newer authenticated living controls or current submission artifacts.

They must not be presented as the current finalist regression denominator when
they conflict with:

`results/acceptance/public-test-results.json`

Current frozen-candidate regression:

`524 / 524 PASS`

Current public acceptance:

`4 / 4 PASS`

## Rebuild utility boundary

Legacy utilities:

- `scripts/rebuild_root_indexes.py`
- `scripts/rebuild_master_control_record.py`

were retained for historical engineering reproducibility but safeguarded during
finalist packaging.

They must not overwrite the authenticated finalist root indexes or current
finalist master/control surfaces.

The template-compliant finalist generator is:

`scripts/build_finalist_package.py`

Required UBI schemas remain governed by the locked templates under:

`evidence/submission-templates/`

## Claim authority rule

A reviewer-facing claim should resolve through:

`report / brief`
`-> finalist evidence index or ledger`
`-> proof record`
`-> canonical observation / relationship`
`-> exact raw locator`
`-> original artifact identity`

Historical counts, fixture state or development milestones are context only
unless explicitly identified as historical.

## Current freeze boundary

Technical candidate:

`8751a679f36b4983cdd3d2b0b35f44e9a11c4f39`

Tree:

`fc420ee3fd1988cf578c0cf309ee3aefcccf33b2`

Packaging changes after that freeze must not be represented as post-holdout
product tuning.
