# TraceSOC Evidence Role Policy

## Purpose

Every real evidence source entering TraceSOC must have exactly one primary
dataset role.

Roles prevent tuning data, benign controls, holdouts, and performance data from
being silently mixed.

## DEVELOPMENT

Purpose:

Evidence that may be inspected while implementing or refining parsers,
normalization, detections, correlations, and investigation logic.

Allowed uses include:

- parser development;
- schema understanding;
- rule development;
- correlation development;
- debugging;
- mutation design;
- exploratory analysis.

Because DEVELOPMENT evidence may influence implementation, successful results
on it do not by themselves demonstrate generalization.

## BENIGN_CONTROL

Purpose:

Evidence representing legitimate or expected activity used to challenge
detections and correlations.

Allowed uses include:

- negative tests;
- false-positive analysis;
- behavioral contrast;
- specificity testing;
- business-context reasoning.

A benign-control source must not be relabelled as suspicious simply because a
detector fires.

Unexpected matches require investigation and may reveal either:

- a false positive;
- ambiguous ground truth;
- contamination;
- genuinely suspicious behavior inside nominally benign material.

## HOLDOUT

Purpose:

Evidence intentionally withheld from tuning and implementation decisions until
the relevant analytic is frozen.

HOLDOUT evidence must not be used to choose:

- detector tokens;
- regexes;
- thresholds;
- time windows;
- destination identifiers;
- event identifiers;
- field combinations;
- expected outcomes.

A holdout result may expose weakness.

A failed holdout must be recorded honestly.

If a holdout is later used to repair a detector, that evidence is no longer a
valid holdout for the repaired version and must be reclassified through an
explicit project-control decision.

## SCALE_TEST

Purpose:

Evidence used primarily to measure processing behavior, resource consumption,
runtime, storage behavior, and larger-volume accounting.

A scale-test source does not automatically validate analytical accuracy.

Scale results and analytical correctness are separate claims.

## Role assignment rule

Each source receives exactly one primary role when approved for acquisition.

The acquisition register records that role.

## Role-change rule

Role changes are not silent edits.

Any role change must document:

- old role;
- new role;
- reason;
- date;
- analytical implications;
- whether prior validation claims remain valid.

## Holdout contamination rule

If a holdout source influences production logic, the holdout is contaminated.

Contamination must be recorded.

The project must not continue calling that source an independent holdout for
the affected analytic version.

## Labels

Ground-truth or scenario labels may be retained in metadata.

They must remain outside the detector-facing SemanticEvent unless an explicit,
documented analytic requires them for a non-production evaluation purpose.

## Current state

No real evidence has been assigned a role yet.

Role policy defined: TRUE.