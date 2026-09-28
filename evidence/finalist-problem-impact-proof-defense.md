# TraceSOC Finalist — Problem / Impact / Proof / Defense Source

**Purpose:** authoritative narrative source for the finalist executive brief,
technical validation report and live defense.

**Technical candidate:**  
`8751a679f36b4983cdd3d2b0b35f44e9a11c4f39`

This document distinguishes measured technical proof from business significance.
It does not invent monetary savings, analyst-hours saved, false-positive
reduction percentages or detection-accuracy figures that were not measured.

---

# 1. Executive thesis

TraceSOC is a provenance-first SOC/DFIR evidence-reconstruction engine.

Its purpose is not simply to generate alerts.

Its purpose is to preserve the connection between a consequential analytical
statement and the exact raw evidence from which that statement was derived.

The product processes heterogeneous evidence through the following chain:

`raw evidence -> representation extraction -> canonical observation -> detection -> relationship/correlation -> hypothesis -> finding -> narrative -> response`

The corresponding reverse requirement is:

`downstream conclusion -> finding -> relationship/detection -> canonical observation -> exact raw locator -> original artifact -> SHA-256`

The finalist evidence demonstrates that this reverse path is mechanically
possible within the measured TraceSOC scope.

---

# 2. PROBLEM

## 2.1 The operational problem

SOC and DFIR investigations commonly combine evidence from different
representations:

- email;
- endpoint process/event telemetry;
- PowerShell activity;
- Windows Security events;
- packet captures;
- Zeek network logs.

These sources do not naturally share one schema, one clock representation,
one identifier model or one level of evidentiary certainty.

The engineering problem is therefore not merely:

> Can a tool parse the files?

The harder problem is:

> Can the system combine those files without losing the provenance required to
> defend the resulting conclusion?

A reconstruction pipeline can fail even when it produces attractive output.

Examples include:

- silently dropping unsupported records;
- losing source byte/record identity during normalization;
- treating timing proximity as identity;
- converting correlation into unsupported causality;
- inflating repeated packet representations into independent findings;
- treating a controlled or benign observable as malicious;
- reporting a detector result without preserving the exact source evidence;
- producing a narrative that cannot be mechanically traced back to raw bytes.

TraceSOC was built around those failure modes.

## 2.2 Why this matters to an organization

An investigation result may be consumed by:

- another analyst;
- an incident responder;
- a SOC lead;
- an engineering reviewer;
- an auditor;
- management;
- a future investigator revisiting the case.

Those people should not have to trust a narrative because the original analyst
said it was correct.

They should be able to answer:

1. What source produced this claim?
2. Where exactly in that source is the evidence?
3. Was any evidence discarded?
4. What interpretation was made?
5. What does the evidence actually prove?
6. What does it not prove?
7. Can the result be reproduced?
8. Would the same product operate on evidence that was not used to design it?

TraceSOC makes those questions first-class product requirements.

---

# 3. IMPACT

## 3.1 Operational significance

TraceSOC addresses four operational risks.

### A. Evidence-to-conclusion detachment

A conclusion that has lost its raw provenance is difficult to independently
verify.

TraceSOC preserves exact source location and artifact identity through the
canonical observation layer and into downstream analytical records.

### B. Silent evidence loss

Unsupported or partially supported evidence can disappear in conventional
normalization pipelines.

TraceSOC instead accounts for it explicitly.

In the controlled reference PCAPNG evidence, all 9,672 packet locators are
accounted:

- 5,412 normalized supported IPv4 TCP/UDP events;
- 4,260 supported-partial processing-issue records;
- zero recorded parser errors.

The 4,260 issue records were not silently discarded.

### C. Unsupported certainty

SOC output can become more certain than the underlying evidence.

TraceSOC explicitly separates:

- observation;
- correlation;
- hypothesis;
- finding;
- narrative;
- response.

The system therefore supports statements such as:

- corroborates;
- byte-identical;
- process-instance attribution;
- observed;
- unresolved;
- unadjudicated;

without automatically converting them into:

- malicious;
- causal;
- compromised;
- incident confirmed.

### D. Reproduction and handoff

An analytical result that cannot be regenerated is weak evidence for later
review.

The frozen six-source TraceSOC candidate was reproduced twice from a fresh
state, producing the same 11 deterministic core output hashes as the accepted
R3 case.

## 3.2 Business significance

The business value demonstrated here is **capability-based**, not
ROI-quantified.

TraceSOC provides mechanisms that support:

- defensible analyst handoff;
- auditability of consequential findings;
- evidence-preserving investigation workflows;
- repeatable technical review;
- explicit treatment of uncertainty;
- verification without relying solely on analyst narrative;
- operation on a modest workstation rather than requiring a heavyweight SIEM
  stack for the demonstrated workflow.

This project did **not** measure:

- monetary savings;
- analyst-hours saved;
- mean-time-to-detect reduction;
- mean-time-to-respond reduction;
- breach-cost reduction;
- false-positive reduction percentage;
- universal precision or recall.

Those must not appear as accomplished business outcomes in the finalist
submission.

---

# 4. PRODUCT RESPONSE

TraceSOC implements the following engineering response to the problem.

## 4.1 Provenance-first canonical observations

Each canonical observation retains a raw locator that can include:

- logical source;
- record index;
- line number;
- byte offset;
- byte length;
- raw SHA-256;
- adapter identity;
- input-schema identity.

The canonical layer is therefore not merely a simplified event stream.

It is an evidence-preserving analytical boundary.

## 4.2 Representation-specific adapters, product-wide contract

The frozen finalist boundary supports:

- EML/MIME email;
- PCAP;
- PCAPNG;
- standard/header-aware Zeek ASCII `conn.log`;
- native Zeek JSON/JSONL;
- Sysmon Windows Event XML;
- recognized native Windows Event JSON/JSONL;
- PowerShell Operational Windows Event XML;
- recognized native Windows Event JSON/JSONL;
- Windows Security Windows Event XML;
- recognized native Windows Event JSON/JSONL;
- the existing supported Splunk-style Windows Security text export.

TraceSOC does not claim arbitrary log-format support.

Unknown representations are preserved/accounted rather than fabricated into
known semantics.

## 4.3 Bounded evidence relationships

Cross-source correlations use evidence-supported selectors.

Examples established in the finalist product include:

- PowerShell web retrieval corroborated by Zeek;
- PowerShell process activity corroborated by Sysmon;
- Sysmon network activity corroborated by packet evidence;
- Windows Security 4688 process creation corroborated by Sysmon Event 1;
- EML attachment bytes linked to a Sysmon process image by exact SHA-256;
- Sysmon Event 1 and Event 3 attributed to the same process instance by exact
  ProcessGuid.

These relationships do not automatically establish maliciousness or causality.

## 4.4 Findings derived after evidence aggregation

TraceSOC preserves raw multiplicity while controlling downstream analytical
inflation.

In the R2/R3 packet correlation case, 66 evidence relationships were retained
because they represented real raw packet multiplicity.

The analytical layer then aggregated them into three source-level hypotheses
with relationship groups of:

- 6;
- 18;
- 42.

That prevented raw representation multiplicity from becoming 66 independent
findings.

---

# 5. PROOF

## 5.1 Controlled six-source reference reconstruction

Reference case:

`case_6bfc43f87590a1f654df3473d9d15c08e17304ed5030d191b4248ee3f4ee2348`

Measured results:

- six evidence families;
- 5,442 canonical observations;
- 5,442 / 5,442 canonical observations with exact raw locators;
- 32,658 detector evaluations;
- 5 matched detections;
- 6 source-level hypotheses;
- 6 findings;
- 6 narratives;
- 6 response records;
- embedded raw evidence preserved;
- case seal verified.

The reference activity is a controlled interoperability/provenance
demonstration.

It is not presented as malicious ground truth.

## 5.2 End-to-end reverse traceability

The final reverse-trace proof mechanically verifies:

`response`
`-> narrative`
`-> finding`
`-> hypothesis`
`-> unique matched detection + relationship`
`-> matched correlation`
`-> canonical observation`
`-> exact raw locator`
`-> embedded raw artifact`
`-> original artifact SHA-256`

This is the central proof of the TraceSOC product claim.

## 5.3 External real-evidence validation

A real external IoT-23 Zeek ASCII file was selected without tuning TraceSOC to
its contents.

Measured result:

`23,145 source rows -> 23,145 canonical observations`

with:

- zero source-count difference;
- exact raw locators;
- source hash unchanged;
- embedded raw evidence preserved.

The 1,641 matched detector results observed in that run are not treated as
publisher ground truth.

## 5.4 Post-freeze unseen holdout

The product was frozen before semantic access to the sealed holdout.

Measured holdout result:

- source rows: 156,458;
- canonical observations: 156,458;
- detector evaluations: 938,748;
- matched detections: 0;
- findings: 0;
- raw evidence embedded: true;
- seal verification: true;
- product tuning after freeze: false.

This closes the holdout for:

`INGESTION_PROVENANCE_GENERALIZATION`

Detection accuracy remains:

`UNADJUDICATED`

because the available later labeled artifact was not an exact valid comparator.

Zero matched detections are therefore neither declared a success nor a failure.

## 5.5 Combined validation volume

Across the three separate R3, external-real-evidence and post-freeze holdout
runs, TraceSOC produced:

`185,045 canonical observations`

calculated as:

`5,442 + 23,145 + 156,458`

This number describes observations across separate validation runs.

It is not represented as 185,045 unique incident events or one single case.

## 5.6 Regression

Current frozen-candidate regression:

`524 / 524 PASS`

Public acceptance classes:

`4 / 4 PASS`

## 5.7 Deterministic clean reproduction

Two fresh frozen six-source executions reproduced the same 11 core artifact
hashes as:

- each other; and
- the accepted R3 outputs.

Measured runtimes:

- run 1: 3.438 seconds;
- run 2: 3.393 seconds.

The approximately 4.5 MiB child-process working-set observation from these
small runs is not claimed as total system consumption.

## 5.8 Scale/resource benchmark

A separate real-format resource/accounting benchmark processed:

- 198,463 expected records;
- 198,463 accepted records;
- 0 quarantined records;
- 198,463 semantic events.

Measured end-to-end runtime:

`15.9617856 seconds`

Measured peak working set:

`486,924,288 bytes`

The frozen resource ceiling was:

`4,000,000,000 bytes`

This benchmark is evidence for parser/accounting/semantic-conversion resource
behavior.

It is not a detector-accuracy benchmark and did not execute real cross-source
correlation.

---

# 6. DEFENSE

## 6.1 Why provenance-first instead of alert-first?

An alert can be regenerated or changed.

The original evidence must remain independently inspectable.

TraceSOC therefore makes raw evidence identity and raw location part of the
analytical contract rather than treating provenance as optional metadata.

## 6.2 Why not discard unsupported evidence?

Because inability to normalize an observation is not evidence that the raw
observation did not exist.

TraceSOC preserves and accounts for unsupported/partial input rather than
silently deleting it.

## 6.3 Why are correlation rules intentionally bounded?

Because temporal proximity and semantic similarity do not necessarily prove
identity or causality.

TraceSOC therefore uses strong selectors where available and treats weaker
attributes as corroboration.

Examples:

- attachment/process linkage uses exact byte SHA-256;
- Sysmon process/network linkage uses exact ProcessGuid;
- time may constrain or corroborate but does not become an unsupported sole
  identity selector.

## 6.4 Why freeze before the holdout?

To distinguish product generalization from product tuning.

The frozen candidate was established before semantic access to the holdout.

When the holdout later produced zero matched detections, the product was not
changed to manufacture a preferred result.

## 6.5 Why is holdout detector accuracy still unadjudicated?

Because a valid scoring claim requires a valid comparator.

The later publisher-labeled artifact was not byte-equivalent to the sealed
holdout and did not provide an exact observation-level comparator.

Using it anyway would create a number that looked scientific but was not
evidence-grounded.

TraceSOC records the accuracy question as:

`UNADJUDICATED`

rather than inventing precision, recall, false-positive or false-negative
rates.

## 6.6 Why are there zero confirmed malicious IOC rows?

Because the controlled finalist reference evidence does not independently
establish a malicious IOC.

The correct evidence-preserving output is therefore a template-compliant
zero-row confirmed-malicious IOC set.

Inventing malicious classification merely to make the file look populated
would contradict the product's provenance and evidentiary principles.

## 6.7 Why not claim a confirmed incident?

Because the finalist reference case demonstrates reconstruction,
interoperability, provenance and bounded analytical relationships.

The measured state does not establish a malicious incident.

The report filename `incident-report.pdf` is retained for submission
compatibility.

Its document title/content must make clear that the finalist artifact is a:

**TraceSOC Technical Validation and Evidence Reconstruction Report**

rather than falsely representing a confirmed security incident.

## 6.8 Why does this matter beyond the reference case?

The product was also exercised on:

- external real Zeek evidence; and
- a separately sealed post-freeze holdout.

Those runs demonstrate evidence handling outside the controlled six-source
reference case without modifying the frozen product.

Cross-publisher network holdout diversity is still not established because the
development and sealed network corpora both originate from IoT-23.

That remains an explicit limitation.

---

# 7. BUSINESS VALUE WITHOUT INVENTED ROI

TraceSOC's demonstrated business case is based on assurance and investigation
quality.

## Analyst value

An analyst can move from a downstream finding back to the source evidence
without relying solely on memory or manually maintained notes.

## Reviewer value

A reviewer can inspect:

- the claim;
- the evidence;
- the exact locator;
- what the evidence proves;
- what it does not prove;
- the alternative interpretation;
- the resulting disposition.

## SOC leadership value

The system distinguishes evidence-backed certainty from unresolved questions.

That makes it harder for uncertainty to disappear as findings move upward into
management-facing narratives.

## Audit and handoff value

Deterministic evidence identities and reproducible outputs provide a stronger
basis for technical review and later handoff than narrative-only analysis.

## Small-team / constrained-environment value

The measured candidate operates on the finalist workstation with approximately
7.85 GiB of physical RAM.

The separate 198,463-record benchmark remained below the frozen 4 GB
working-set ceiling.

This supports the claim that the demonstrated workflow does not require a
heavyweight SIEM/VM stack on this workstation.

It does not establish universal scalability.

---

# 8. WHAT IS NOT CLAIMED

The finalist package must not claim any of the following as measured results:

- universal log-format support;
- universal detection accuracy;
- a confirmed malicious incident from the controlled reference case;
- a confirmed malicious IOC from the controlled values;
- malicious causality from correlation alone;
- that email delivery caused process execution;
- that process-instance attribution establishes maliciousness;
- that external IoT-23 detector matches are ground truth;
- that zero holdout matches prove success;
- cross-publisher network holdout generalization;
- monetary savings;
- analyst-hours saved;
- false-positive reduction percentage;
- breach-cost reduction;
- executed containment or response actions.

These boundaries are part of the product proof rather than weaknesses to hide.

---

# 9. FUTURE BUSINESS MEASUREMENT

A production deployment could measure business outcomes that the finalist
project did not attempt to fabricate.

Candidate future KPIs include:

- analyst time from finding to exact raw source;
- investigation handoff time;
- percentage of consequential claims with complete raw provenance;
- unsupported-evidence accounting rate;
- review/rework frequency;
- reproduction success rate across analyst workstations;
- time required to reproduce a finding during audit or defense;
- precision/recall only when a valid labeled comparator exists.

These are future measurements.

They are not finalist results.

---

# 10. REPORT FRAMING

## Executive brief

The executive brief should answer, on one page:

1. What problem does TraceSOC solve?
2. Why does that problem matter operationally?
3. What did the finalist product actually prove?
4. What did it deliberately not claim?
5. Why should a reviewer believe the result?
6. What should be tested next?

It should lead with business/operational meaning and use technical counts only
as proof.

## Technical report

The required `incident-report.pdf` filename should contain a report titled:

**TraceSOC Technical Validation and Evidence Reconstruction Report**

The report should document:

- problem and architecture;
- supported evidence boundary;
- reference reconstruction;
- evidence relationships;
- raw-to-result traceability;
- external validation;
- post-freeze holdout;
- regression;
- reproduction;
- resource behavior;
- business significance;
- design defense;
- limitations;
- future work.

It must not convert the controlled reference case into a fabricated malicious
incident.

---

# 11. FINALIST STORY

## Problem

Security evidence is fragmented across representations, and analytical
conclusions can become detached from the exact source material that supports
them.

## Impact

That weakens reproducibility, handoff, auditability and the ability to
distinguish evidence from inference.

## Proof

TraceSOC has demonstrated:

- six supported evidence families in one controlled reconstruction;
- 5,442 / 5,442 reference canonical observations with raw locators;
- a mechanical downstream-to-original-SHA reverse trace;
- 23,145 / 23,145 external Zeek observations reconciled;
- 156,458 / 156,458 post-freeze holdout observations reconciled;
- 524 / 524 regression tests passing;
- deterministic clean reproduction;
- explicit packet/unsupported evidence accounting;
- measured operation on the finalist workstation.

## Defense

The product deliberately:

- preserves evidence rather than silently dropping it;
- bounds correlation rather than inventing causality;
- separates observation from interpretation;
- freezes before holdout;
- avoids label/fixture-driven product logic;
- refuses unsupported detector-accuracy and maliciousness claims.

That combination is the central finalist argument for TraceSOC.
