# TraceSOC Grounding Record

## Stable project thesis

TraceSOC is an evidence-accountable SOC investigation and response-validation
engine.

Its purpose is not merely to generate alerts.

Its purpose is to let another analyst reproduce how raw telemetry became a
security conclusion, understand what is observed versus inferred, see what
remains uncertain, identify what would falsify the conclusion, understand
the business consequence, and verify the proposed response.

## Authority order

1. Formal UBI Stage 9B brief and contracts.
2. Raw evidence and source semantics.
3. Fresh accepted machine proof.
4. Requirements matrix and this grounding record.
5. Production code and tests.
6. Generated outputs and reports.
7. Historical notes and brainstorming.

## Session-start ground check

Before material work, state:

- Current objective
- Governing requirement IDs
- Evidence basis
- What we are NOT assuming
- Expected artifact
- Closure condition
- Stop/escalation triggers

## Permanent analytical doctrine

Never force evidence to satisfy an expected narrative.

Never convert temporal adjacency into causality without a supported relationship.

Never convert a finite negative test into a universal absence claim.

Never convert suspicious behavior into malicious intent without evidence.

Never use fixture IDs, expected answers, candidate identifiers, or assignment
markers as runtime decision inputs.

Separate visibly:

OBSERVED FACT
INFERENCE
RESIDUAL RISK
BUSINESS IMPACT
DECISION REQUIRED

Every material conclusion must state what evidence would change it.