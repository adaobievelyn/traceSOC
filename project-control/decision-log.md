# Decision Log

Every material technical decision must record:

- Decision ID
- Date
- Question
- Decision
- Reason
- Alternatives considered
- Evidence / benchmark
- Trade-off
- What would change this decision
- Affected requirement IDs

---

## DEC-001 - Lightweight workstation architecture

Date UTC: 2026-09-14T10:47:10.1232497Z

Question:
What execution architecture should TraceSOC use?

Decision:
Use the Windows host with a project-local Python virtual environment and
SQLite as the core architecture.

Treat WSL, Docker, Zeek, and external bulk storage as optional adapters or
supporting facilities rather than mandatory runtime dependencies.

Evidence:
The Phase 0 machine audit establishes:

- RAM: 7.85 GB
- Free system-disk capacity: 43.63 GB
- Python: 3.13.14
- SQLite: 3.50.4
- Git: available
- TShark: 4.6.8
- WSL: available
- Docker: available
- Native Zeek: not currently available
- Hardware virtualization: reported unavailable

Reason:
The observed environment supports a lightweight host-first architecture.
The evidence does not justify making a full VM architecture mandatory.

Alternatives considered:
- Full Windows VM lab
- Elasticsearch-based stack
- Docker-first architecture
- WSL-first architecture

Trade-off:
The chosen architecture prioritizes reproducibility, explainability, and
low resource use over enterprise-scale streaming infrastructure.

What would change this decision:
- A formal Stage 9B requirement requiring another runtime; or
- Measured evidence that the host-first architecture cannot satisfy an
  accepted requirement.

Affected provisional requirements:
PRE-006 and future performance, reproducibility, and environment
requirements.
---

## DEC-002 - Adopt external SSD as optional bulk-evidence storage

Date UTC: 2026-09-14T11:00:13.8448145Z

Decision:
Adopt D:\TraceSOC-Evidence as optional bulk-evidence storage.

Do not make the external drive a mandatory runtime dependency.

Evidence:
- USB SSD
- NTFS
- Healthy
- 476.13 GB total
- 318.12 GB free at Phase 1.2
- 256 MB controlled write/read/hash/delete smoke test passed
- Write: 195.57 MB/s
- Read/hash: 121.62 MB/s
- I/O classification: SUITABLE

Reason:
The drive provides substantial capacity for public telemetry, PCAPs,
holdouts, and scale testing without consuming the system disk.

Trade-off:
External-drive availability cannot be assumed on another assessor's
machine.

Therefore core TraceSOC tests and reproducibility must use small local
fixtures, while large-dataset testing remains optional.

What would change this decision:
- storage health degradation;
- repeated I/O corruption;
- formal Stage 9B prohibition;
- evidence that the external-drive dependency has leaked into the core
  acceptance path.
---

## DEC-003 - Freeze Stage 7/8/9A continuity boundary

Date UTC: 2026-09-14T12:00:01.0210052Z

Decision:
Use the submitted Stage 9A package as the authoritative continuity source.

The developmental Stage 9 repository remains historical discovery evidence
only.

Carry generic Stage 7/8/9A engineering contracts forward through explicit
TraceSOC-native adaptation.

Do not copy the Stage 9A repository wholesale and do not allow final-case
identifiers, expected answers, known hashes, fixture metadata, or case
outcomes to drive TraceSOC runtime decisions.

Response validation must improve on Stage 9A by proving controlled apply,
post-state verification, rollback, and rollback verification.

Evidence:
- project-control/stage9a-authoritative-submission-review.md
- project-control/stage9a-carry-forward-matrix.csv
- project-control/stage9a-authoritative-source.json

Submitted archive SHA-256:
83ae8b71ead89033f9ae0aa58eee96b8af437860d6f270202664c27c551da0b6

What would change this decision:
A formal Stage 9B rule that explicitly requires, prohibits, or constrains
reuse differently.