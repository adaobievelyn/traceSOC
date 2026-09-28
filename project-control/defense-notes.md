# TraceSOC Finalist Defense Notes

## 1. What is TraceSOC?

TraceSOC is a provenance-first SOC/DFIR evidence-reconstruction engine.

Its central requirement is that consequential downstream claims remain
traceable back to exact raw evidence.

Proof source:

`evidence/final-proof/r3-end-to-end-reverse-trace-proof.json`

Limitation:

Traceability does not independently prove maliciousness or causality.

## 2. What did the controlled six-source case prove?

It demonstrated one coherent supported workflow across email, packet, Zeek,
Sysmon, PowerShell and Windows Security evidence.

Measured state:

- 5,442 canonical observations;
- 5,442 / 5,442 raw-located;
- 32,658 detector evaluations;
- 5 matched detections;
- 6 findings after source-level aggregation.

Limitation:

The controlled case is not malicious ground truth.

## 3. How do you know the product was not built only for that case?

Four controls matter:

1. anti-hardcoding verification;
2. external real Zeek evidence with 23,145 / 23,145 rows reconciled;
3. a sealed post-freeze holdout with 156,458 / 156,458 rows reconciled;
4. a current one-command clean build/test path that reproduces the accepted 524/524 regression and 4/4 public acceptance from the frozen candidate.

Limitation:

Cross-publisher network holdout diversity is not established.

## 4. Why did the holdout produce zero detections?

The measured fact is simply zero matched detections on that sealed input.

It is not scored as success or failure because no exact valid labeled
comparator exists for the sealed artifact.

Therefore:

`DETECTION_ACCURACY_STATUS=UNADJUDICATED`

## 5. Why are there zero confirmed malicious IOC rows?

Because the finalist reference evidence does not independently establish a
malicious IOC.

Populating the IOC file anyway would fabricate analytical certainty.

The correct result is a valid zero-row IOC set.

## 6. What is the business value?

The demonstrated value is investigation assurance:

- defensible analyst handoff;
- auditability;
- exact evidence recovery;
- reproducibility;
- explicit uncertainty;
- reduced dependence on narrative-only conclusions.

No monetary savings, analyst-hours saved or false-positive reduction percentage
was measured.

## 7. Why trust the resource claim?

A real-format benchmark processed 198,463 accepted records with peak working
set 486,924,288 bytes under the frozen 4,000,000,000-byte ceiling.

Two fresh six-source reproductions also completed in approximately 3.4 seconds
each.

Limitation:

These are measured workloads, not universal scalability guarantees.

## 8. Did TraceSOC execute containment?

No finalist proof claims executed production response.

Response records preserve the distinction between recommendation/simulation
and executed action.

## 9. What was carried forward from Stage 9A?

Verified contracts and lessons were carried forward:

- provenance;
- separation of observation and inference;
- deterministic identity;
- bounded correlation;
- alternatives/falsifiers;
- clean reproduction;
- anti-hardcoding and holdout discipline.

Case-specific Stage 9A answers and production runtime were not copied into
TraceSOC.

See:

`continuity-record.md`

## 10. What remains before submission?

The technical product, current one-command clean build/test path and both final reports are complete.

Remaining packaging gates are:

- generate `manifest.sha256` last;
- verify the integrity manifest again after final upload.

Technical candidate remains frozen while these packaging tasks are completed.
