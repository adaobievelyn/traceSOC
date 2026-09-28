from __future__ import annotations

from tracesoc.cli.case import (
    ARTIFACT_INDEX_FILE,
    DETECTIONS_FILE,
    EVENTS_FILE,
    FINDINGS_FILE,
    HYPOTHESES_FILE,
    RAW_EVIDENCE_DIRECTORY,
    RAW_EVIDENCE_INDEX_FILE,
    RELATIONSHIPS_FILE,
    CaseAnalysisError,
    analyze_case,
    verify_case_seal,
)

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from tracesoc.findings.models import EvidenceReference
from tracesoc.findings.serialization import (
    SERIALIZATION_ID,
    finding_sha256,
)
from tracesoc.vertical_slice import build_fixture_finding_001


SUPPORTED_FINDING_ID = "FINDING-001"
EXPECTED_SERIALIZATION_ID = "tracesoc-finding-json-v1"


class EvidenceIntegrityError(RuntimeError):
    pass


class FindingIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedEvidence:
    reference: EvidenceReference
    raw_text: str
    raw_sha256_verified: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.reference.to_dict(),
            "raw_sha256_verified": self.raw_sha256_verified,
            "raw_text": self.raw_text,
        }


def discover_repo(
    start: Path | None = None,
) -> Path:
    candidate = (
        Path.cwd()
        if start is None
        else start
    ).resolve()

    for root in (
        candidate,
        *candidate.parents,
    ):
        if (
            (
                root
                / "project-control"
                / "phase3d1-finding-serialization-repair.json"
            ).is_file()
            and (
                root
                / "src"
                / "tracesoc"
            ).is_dir()
        ):
            return root

    raise FileNotFoundError(
        "TraceSOC repository root could not be discovered"
    )


def accepted_finding_contract(
    repo: Path,
) -> tuple[str, str]:
    proof_path = (
        repo
        / "project-control"
        / "phase3d1-finding-serialization-repair.json"
    )

    proof = json.loads(
        proof_path.read_text(
            encoding="utf-8",
        )
    )

    serialization_id = (
        proof
        .get("serialization_contract", {})
        .get("serialization_id")
    )

    canonical_hash = (
        proof
        .get("canonical_finding", {})
        .get("sha256")
    )

    if serialization_id != EXPECTED_SERIALIZATION_ID:
        raise FindingIntegrityError(
            "Accepted serialization contract is not tracesoc-finding-json-v1"
        )

    if SERIALIZATION_ID != EXPECTED_SERIALIZATION_ID:
        raise FindingIntegrityError(
            "Runtime serialization implementation identity mismatch"
        )

    if (
        not isinstance(canonical_hash, str)
        or len(canonical_hash) != 64
    ):
        raise FindingIntegrityError(
            "Repair proof does not contain a valid canonical finding SHA-256"
        )

    return (
        serialization_id,
        canonical_hash.lower(),
    )


def resolve_evidence_reference(
    *,
    repo: Path,
    reference: EvidenceReference,
) -> VerifiedEvidence:
    repo = repo.resolve()

    candidate = (
        repo
        / reference.logical_source
    ).resolve()

    try:
        candidate.relative_to(repo)
    except ValueError as exc:
        raise EvidenceIntegrityError(
            "Evidence logical path escapes the repository boundary"
        ) from exc

    if not candidate.is_file():
        raise EvidenceIntegrityError(
            f"Evidence source does not exist: {reference.logical_source}"
        )

    if (
        reference.byte_offset is None
        or reference.byte_length is None
    ):
        raise EvidenceIntegrityError(
            "Evidence reference lacks byte offset/length"
        )

    raw_file = candidate.read_bytes()

    start = reference.byte_offset
    end = start + reference.byte_length

    if start < 0 or end > len(raw_file):
        raise EvidenceIntegrityError(
            "Evidence byte range falls outside source file"
        )

    record_bytes = raw_file[
        start:end
    ]

    observed_sha256 = hashlib.sha256(
        record_bytes
    ).hexdigest()

    if observed_sha256 != reference.raw_sha256:
        raise EvidenceIntegrityError(
            "Raw evidence SHA-256 does not match the finding reference"
        )

    if reference.line_number is not None:
        lines = raw_file.splitlines(
            keepends=True
        )

        line_index = (
            reference.line_number - 1
        )

        if (
            line_index < 0
            or line_index >= len(lines)
        ):
            raise EvidenceIntegrityError(
                "Referenced line number is outside source file"
            )

        line_bytes = lines[
            line_index
        ].rstrip(
            b"\r\n"
        )

        if line_bytes != record_bytes:
            raise EvidenceIntegrityError(
                "Line-number and byte-range locators resolve to different raw evidence"
            )

    try:
        raw_text = record_bytes.decode(
            "utf-8"
        )
    except UnicodeDecodeError as exc:
        raise EvidenceIntegrityError(
            "Current FINDING-001 evidence is expected to be UTF-8 JSONL"
        ) from exc

    return VerifiedEvidence(
        reference=reference,
        raw_text=raw_text,
        raw_sha256_verified=True,
    )


def explain_finding(
    *,
    repo: Path,
    finding_id: str,
) -> dict[str, Any]:
    if finding_id != SUPPORTED_FINDING_ID:
        raise ValueError(
            f"Unsupported finding ID: {finding_id}"
        )

    serialization_id, expected_hash = (
        accepted_finding_contract(
            repo
        )
    )

    finding = build_fixture_finding_001(
        repo
    )

    if finding.finding_id != finding_id:
        raise FindingIntegrityError(
            "Regenerated finding identity does not match request"
        )

    actual_hash = finding_sha256(
        finding
    )

    if actual_hash != expected_hash:
        raise FindingIntegrityError(
            "Regenerated finding does not match the accepted canonical finding hash"
        )

    verified_evidence = tuple(
        resolve_evidence_reference(
            repo=repo,
            reference=reference,
        )
        for reference in finding.evidence
    )

    if not verified_evidence:
        raise EvidenceIntegrityError(
            "Finding contains no evidence references"
        )

    if not all(
        item.raw_sha256_verified
        for item in verified_evidence
    ):
        raise EvidenceIntegrityError(
            "One or more evidence references failed integrity verification"
        )

    return {
        "finding": finding.to_dict(),
        "serialization_id": serialization_id,
        "finding_sha256": actual_hash,
        "expected_finding_sha256": expected_hash,
        "finding_hash_verified": True,
        "raw_evidence_reference_count": len(
            verified_evidence
        ),
        "raw_evidence_hashes_verified": len(
            verified_evidence
        ),
        "evidence": [
            item.to_dict()
            for item in verified_evidence
        ],
        "claim_boundary": {
            "malicious_intent_established": (
                finding.malicious_intent_established
            ),
            "synthetic_fixture": (
                finding.synthetic_fixture
            ),
        },
    }


def render_text(
    explanation: dict[str, Any],
) -> str:
    finding = explanation[
        "finding"
    ]

    lines: list[str] = []

    lines.append(
        f"FINDING: {finding['finding_id']}"
    )

    lines.append(
        f"TITLE: {finding['title']}"
    )

    lines.append(
        f"STATE: {finding['state']}"
    )

    lines.append(
        f"CONFIDENCE: {finding['confidence']}"
    )

    lines.append(
        f"CONFIDENCE SCOPE: {finding['confidence_scope']}"
    )

    lines.append(
        f"SERIALIZATION: {explanation['serialization_id']}"
    )

    lines.append("")

    lines.append(
        "OBSERVED FACTS"
    )

    for index, fact in enumerate(
        finding["observed_facts"],
        start=1,
    ):
        lines.append(
            f"  {index}. {fact}"
        )

    lines.append("")

    lines.append(
        f"INFERENCE: {finding['inference']}"
    )

    lines.append(
        "ALTERNATIVE EXPLANATION: "
        f"{finding['alternative_explanation']}"
    )

    lines.append(
        f"FALSIFIER: {finding['falsifier']}"
    )

    lines.append(
        f"RESIDUAL RISK: {finding['residual_risk']}"
    )

    lines.append(
        f"BUSINESS IMPACT: {finding['business_impact']}"
    )

    lines.append(
        f"DECISION REQUIRED: {finding['decision_required']}"
    )

    lines.append(
        f"RECOMMENDED ACTION: {finding['recommended_action']}"
    )

    lines.append(
        "RESPONSE VALIDATION STATUS: "
        f"{finding['response_validation_status']}"
    )

    lines.append("")

    lines.append(
        "DETECTIONS: "
        + ", ".join(
            finding["detection_ids"]
        )
    )

    lines.append(
        "CORRELATIONS: "
        + ", ".join(
            finding["correlation_ids"]
        )
    )

    lines.append(
        "CORRELATION EDGES: "
        + ", ".join(
            finding["correlation_edge_ids"]
        )
    )

    lines.append("")

    lines.append(
        "FINDING_HASH_VERIFIED=PASS"
    )

    lines.append(
        "FINDING_SHA256="
        f"{explanation['finding_sha256']}"
    )

    lines.append(
        "MALICIOUS_INTENT_ESTABLISHED="
        f"{str(finding['malicious_intent_established']).upper()}"
    )

    lines.append(
        "SYNTHETIC_FIXTURE="
        f"{str(finding['synthetic_fixture']).upper()}"
    )

    lines.append("")
    lines.append(
        "RAW EVIDENCE"
    )

    for index, evidence in enumerate(
        explanation["evidence"],
        start=1,
    ):
        lines.append("")
        lines.append(
            f"  EVIDENCE {index}"
        )

        lines.append(
            f"  EVENT_ID={evidence['event_id']}"
        )

        lines.append(
            f"  SOURCE_TYPE={evidence['source_type']}"
        )

        lines.append(
            f"  LOGICAL_SOURCE={evidence['logical_source']}"
        )

        lines.append(
            f"  RECORD_INDEX={evidence['record_index']}"
        )

        lines.append(
            f"  LINE_NUMBER={evidence['line_number']}"
        )

        lines.append(
            f"  BYTE_OFFSET={evidence['byte_offset']}"
        )

        lines.append(
            f"  BYTE_LENGTH={evidence['byte_length']}"
        )

        lines.append(
            f"  RAW_SHA256={evidence['raw_sha256']}"
        )

        lines.append(
            "  RAW_HASH_VERIFIED=PASS"
        )

        lines.append(
            f"  RAW_RECORD={evidence['raw_text']}"
        )

    lines.append("")

    lines.append(
        "RAW_EVIDENCE_HASHES_VERIFIED="
        f"{explanation['raw_evidence_hashes_verified']}/"
        f"{explanation['raw_evidence_reference_count']}"
    )

    return "\n".join(
        lines
    )


class CaseExplainIntegrityError(
    ValueError
):
    pass


def _case_load_payload(
    *,
    case_directory: Path,
    filename: str,
    expected_case_id: str,
) -> dict[
    str,
    Any,
]:
    path = (
        case_directory
        / filename
    )

    if not path.is_file():
        raise CaseExplainIntegrityError(
            "sealed case file is missing: "
            + filename
        )

    try:
        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except json.JSONDecodeError as exc:
        raise CaseExplainIntegrityError(
            "sealed case file is not valid JSON: "
            + filename
        ) from exc

    if not isinstance(
        payload,
        dict,
    ):
        raise CaseExplainIntegrityError(
            "sealed case payload must be an object: "
            + filename
        )

    if (
        payload.get(
            "case_id"
        )
        != expected_case_id
    ):
        raise CaseExplainIntegrityError(
            "case ID mismatch in "
            + filename
        )

    return payload


def _case_record_list(
    payload: dict[
        str,
        Any,
    ],
    field: str,
) -> list[
    dict[
        str,
        Any,
    ],
]:
    value = payload.get(
        field
    )

    if not isinstance(
        value,
        list,
    ):
        raise CaseExplainIntegrityError(
            field
            + " must be a list"
        )

    records: list[
        dict[
            str,
            Any,
        ]
    ] = []

    for item in value:
        if not isinstance(
            item,
            dict,
        ):
            raise CaseExplainIntegrityError(
                field
                + " contains a non-object record"
            )

        records.append(
            item
        )

    return records


def _case_unique_record(
    records: list[
        dict[
            str,
            Any,
        ],
    ],
    *,
    field: str,
    value: str,
    label: str,
) -> dict[
    str,
    Any,
]:
    matches = [
        record
        for record
        in records
        if record.get(
            field
        )
        == value
    ]

    if len(matches) != 1:
        raise CaseExplainIntegrityError(
            label
            + " must resolve exactly once: "
            + value
        )

    return matches[0]


def _case_string_ids(
    record: dict[
        str,
        Any,
    ],
    field: str,
) -> tuple[
    str,
    ...,
]:
    value = record.get(
        field
    )

    if not isinstance(
        value,
        list,
    ):
        raise CaseExplainIntegrityError(
            field
            + " must be a list"
        )

    result: list[
        str
    ] = []

    for item in value:
        if (
            not isinstance(
                item,
                str,
            )
            or not item
        ):
            raise CaseExplainIntegrityError(
                field
                + " contains an invalid identifier"
            )

        result.append(
            item
        )

    if len(
        result
    ) != len(
        set(
            result
        )
    ):
        raise CaseExplainIntegrityError(
            field
            + " contains duplicate identifiers"
        )

    return tuple(
        result
    )


def _case_sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as handle:
        while True:
            block = handle.read(
                1024
                * 1024
            )

            if not block:
                break

            digest.update(
                block
            )

    return digest.hexdigest()


def _case_safe_embedded_path(
    value: str,
) -> tuple[
    str,
    ...,
]:
    if (
        not isinstance(
            value,
            str,
        )
        or not value
        or "\\" in value
    ):
        raise CaseExplainIntegrityError(
            "embedded raw-evidence path is invalid"
        )

    candidate = PurePosixPath(
        value
    )

    if candidate.is_absolute():
        raise CaseExplainIntegrityError(
            "absolute embedded raw-evidence path "
            "is forbidden"
        )

    if any(
        part in {
            "",
            ".",
            "..",
        }
        for part
        in candidate.parts
    ):
        raise CaseExplainIntegrityError(
            "embedded raw-evidence path escapes case"
        )

    if (
        len(
            candidate.parts
        )
        < 2
        or candidate.parts[0]
        != RAW_EVIDENCE_DIRECTORY
    ):
        raise CaseExplainIntegrityError(
            "embedded raw-evidence path is outside "
            "the raw-evidence directory"
        )

    return tuple(
        candidate.parts
    )


def _case_raw_evidence_for_event(
    *,
    case_directory: Path,
    event: dict[
        str,
        Any,
    ],
    artifacts: list[
        dict[
            str,
            Any,
        ],
    ],
    raw_records: list[
        dict[
            str,
            Any,
        ],
    ],
) -> dict[
    str,
    Any,
]:
    event_id = event.get(
        "event_id"
    )

    if (
        not isinstance(
            event_id,
            str,
        )
        or not event_id
    ):
        raise CaseExplainIntegrityError(
            "event has no valid event_id"
        )

    locator = event.get(
        "raw_locator"
    )

    if not isinstance(
        locator,
        dict,
    ):
        raise CaseExplainIntegrityError(
            "event has no raw locator: "
            + event_id
        )

    logical_source = locator.get(
        "logical_source"
    )

    if (
        not isinstance(
            logical_source,
            str,
        )
        or not logical_source
    ):
        raise CaseExplainIntegrityError(
            "event raw locator has no logical source: "
            + event_id
        )

    matching_artifacts = [
        artifact
        for artifact
        in artifacts
        if artifact.get(
            "source_path_display"
        )
        == logical_source
    ]

    if len(
        matching_artifacts
    ) != 1:
        raise CaseExplainIntegrityError(
            "event logical source does not resolve "
            "to exactly one input artifact: "
            + logical_source
        )

    artifact = (
        matching_artifacts[0]
    )

    artifact_id = artifact.get(
        "artifact_id"
    )

    artifact_sha256 = artifact.get(
        "sha256"
    )

    artifact_bytes = artifact.get(
        "bytes"
    )

    if (
        not isinstance(
            artifact_id,
            str,
        )
        or not artifact_id
        or not isinstance(
            artifact_sha256,
            str,
        )
        or not artifact_sha256
        or isinstance(
            artifact_bytes,
            bool,
        )
        or not isinstance(
            artifact_bytes,
            int,
        )
        or artifact_bytes < 0
    ):
        raise CaseExplainIntegrityError(
            "artifact identity is invalid for "
            + logical_source
        )

    matching_raw = [
        record
        for record
        in raw_records
        if (
            record.get(
                "artifact_id"
            )
            == artifact_id
            and record.get(
                "source_path_display"
            )
            == logical_source
        )
    ]

    if len(
        matching_raw
    ) != 1:
        raise CaseExplainIntegrityError(
            "artifact does not resolve exactly once "
            "in raw-evidence index: "
            + artifact_id
        )

    raw_record = (
        matching_raw[0]
    )

    case_relative_path = (
        raw_record.get(
            "case_relative_path"
        )
    )

    raw_sha256 = (
        raw_record.get(
            "sha256"
        )
    )

    raw_bytes = (
        raw_record.get(
            "bytes"
        )
    )

    if (
        not isinstance(
            case_relative_path,
            str,
        )
        or raw_sha256
        != artifact_sha256
        or raw_bytes
        != artifact_bytes
    ):
        raise CaseExplainIntegrityError(
            "raw-evidence index does not match artifact: "
            + artifact_id
        )

    parts = (
        _case_safe_embedded_path(
            case_relative_path
        )
    )

    embedded = (
        case_directory.joinpath(
            *parts
        )
    )

    if not embedded.is_file():
        raise CaseExplainIntegrityError(
            "embedded raw evidence is missing: "
            + case_relative_path
        )

    actual_bytes = (
        embedded.stat().st_size
    )

    actual_sha256 = (
        _case_sha256_file(
            embedded
        )
    )

    if (
        actual_bytes
        != artifact_bytes
    ):
        raise CaseExplainIntegrityError(
            "embedded raw evidence byte count "
            "does not match artifact: "
            + case_relative_path
        )

    if (
        actual_sha256
        != artifact_sha256
    ):
        raise CaseExplainIntegrityError(
            "embedded raw evidence SHA-256 "
            "does not match artifact: "
            + case_relative_path
        )

    locator_raw_sha256 = (
        locator.get(
            "raw_sha256"
        )
    )

    if (
        locator_raw_sha256
        is not None
        and not isinstance(
            locator_raw_sha256,
            str,
        )
    ):
        raise CaseExplainIntegrityError(
            "raw locator SHA-256 is invalid: "
            + event_id
        )

    locator_scope = (
        "LOCATOR_RETAINED_FILE_HASH_VERIFIED"
    )

    locator_content_hash_verified = (
        None
    )

    if (
        isinstance(
            locator_raw_sha256,
            str,
        )
        and locator_raw_sha256
        == artifact_sha256
    ):
        locator_scope = (
            "WHOLE_FILE_LOCATOR_HASH_VERIFIED"
        )

        locator_content_hash_verified = (
            True
        )

    return {
        "event_id":
            event_id,

        "artifact_id":
            artifact_id,

        "source_path_display":
            logical_source,

        "case_relative_path":
            case_relative_path,

        "artifact_sha256":
            artifact_sha256,

        "artifact_bytes":
            artifact_bytes,

        "embedded_raw_sha256":
            actual_sha256,

        "embedded_raw_bytes":
            actual_bytes,

        "embedded_raw_hash_verified":
            True,

        "raw_locator":
            dict(
                locator
            ),

        "raw_locator_reached":
            True,

        "locator_verification_scope":
            locator_scope,

        "locator_content_hash_verified":
            locator_content_hash_verified,
    }


def explain_case_finding(
    *,
    case_directory: Path,
    finding_id: str,
) -> dict[
    str,
    Any,
]:
    if not isinstance(
        case_directory,
        Path,
    ):
        raise TypeError(
            "case_directory must be pathlib.Path"
        )

    if not isinstance(
        finding_id,
        str,
    ) or not finding_id:
        raise ValueError(
            "finding_id must be non-empty text"
        )

    if not case_directory.is_dir():
        raise NotADirectoryError(
            str(
                case_directory
            )
        )

    verification = verify_case_seal(
        case_directory
    )

    if (
        verification.get(
            "seal_verified"
        )
        is not True
    ):
        raise CaseExplainIntegrityError(
            "case seal verification failed"
        )

    case_id = verification.get(
        "case_id"
    )

    if (
        not isinstance(
            case_id,
            str,
        )
        or not case_id
    ):
        raise CaseExplainIntegrityError(
            "verified case has no valid case ID"
        )

    finding_payload = (
        _case_load_payload(
            case_directory=(
                case_directory
            ),
            filename=(
                FINDINGS_FILE
            ),
            expected_case_id=(
                case_id
            ),
        )
    )

    hypothesis_payload = (
        _case_load_payload(
            case_directory=(
                case_directory
            ),
            filename=(
                HYPOTHESES_FILE
            ),
            expected_case_id=(
                case_id
            ),
        )
    )

    detection_payload = (
        _case_load_payload(
            case_directory=(
                case_directory
            ),
            filename=(
                DETECTIONS_FILE
            ),
            expected_case_id=(
                case_id
            ),
        )
    )

    relationship_payload = (
        _case_load_payload(
            case_directory=(
                case_directory
            ),
            filename=(
                RELATIONSHIPS_FILE
            ),
            expected_case_id=(
                case_id
            ),
        )
    )

    event_payload = (
        _case_load_payload(
            case_directory=(
                case_directory
            ),
            filename=(
                EVENTS_FILE
            ),
            expected_case_id=(
                case_id
            ),
        )
    )

    artifact_payload = (
        _case_load_payload(
            case_directory=(
                case_directory
            ),
            filename=(
                ARTIFACT_INDEX_FILE
            ),
            expected_case_id=(
                case_id
            ),
        )
    )

    raw_payload = (
        _case_load_payload(
            case_directory=(
                case_directory
            ),
            filename=(
                RAW_EVIDENCE_INDEX_FILE
            ),
            expected_case_id=(
                case_id
            ),
        )
    )

    findings = _case_record_list(
        finding_payload,
        "findings",
    )

    hypotheses = _case_record_list(
        hypothesis_payload,
        "hypotheses",
    )

    detections = _case_record_list(
        detection_payload,
        "detections",
    )

    relationships = _case_record_list(
        relationship_payload,
        "relationships",
    )

    events = _case_record_list(
        event_payload,
        "events",
    )

    artifacts = _case_record_list(
        artifact_payload,
        "artifacts",
    )

    raw_records = _case_record_list(
        raw_payload,
        "raw_evidence_files",
    )

    finding = _case_unique_record(
        findings,
        field="finding_id",
        value=finding_id,
        label="finding",
    )

    if (
        finding.get(
            "evidence_state"
        )
        != "CORROBORATED"
    ):
        raise CaseExplainIntegrityError(
            "case finding is not CORROBORATED"
        )

    if (
        finding.get(
            "incident_status"
        )
        != "NOT_ESTABLISHED"
    ):
        raise CaseExplainIntegrityError(
            "case finding unexpectedly declares "
            "incident status"
        )

    if (
        finding.get(
            "malicious_intent_status"
        )
        != "NOT_ESTABLISHED"
    ):
        raise CaseExplainIntegrityError(
            "case finding unexpectedly declares "
            "malicious intent"
        )

    hypothesis_id = finding.get(
        "hypothesis_id"
    )

    if (
        not isinstance(
            hypothesis_id,
            str,
        )
        or not hypothesis_id
    ):
        raise CaseExplainIntegrityError(
            "finding has no valid hypothesis ID"
        )

    hypothesis = _case_unique_record(
        hypotheses,
        field="hypothesis_id",
        value=hypothesis_id,
        label="hypothesis",
    )

    if (
        hypothesis.get(
            "evidence_state"
        )
        != "CORROBORATED"
    ):
        raise CaseExplainIntegrityError(
            "supporting hypothesis is not CORROBORATED"
        )

    if (
        finding.get(
            "statement"
        )
        != hypothesis.get(
            "statement"
        )
    ):
        raise CaseExplainIntegrityError(
            "finding statement no longer matches "
            "its source hypothesis"
        )

    if (
        finding.get(
            "rationale"
        )
        != hypothesis.get(
            "rationale"
        )
    ):
        raise CaseExplainIntegrityError(
            "finding rationale no longer matches "
            "its source hypothesis"
        )

    if (
        finding.get(
            "alternative_or_falsifier"
        )
        != hypothesis.get(
            "alternative_or_falsifier"
        )
    ):
        raise CaseExplainIntegrityError(
            "finding falsifier no longer matches "
            "its source hypothesis"
        )

    support_fields = (
        "detection_result_ids",
        "supporting_relationship_ids",
        "contradicting_relationship_ids",
        "observation_ids",
    )

    support_ids: dict[
        str,
        tuple[
            str,
            ...,
        ],
    ] = {}

    for field in support_fields:
        finding_ids = (
            _case_string_ids(
                finding,
                field,
            )
        )

        hypothesis_ids = (
            _case_string_ids(
                hypothesis,
                field,
            )
        )

        if (
            finding_ids
            != hypothesis_ids
        ):
            raise CaseExplainIntegrityError(
                "finding/hypothesis lineage mismatch: "
                + field
            )

        support_ids[
            field
        ] = finding_ids

    detection_ids = support_ids[
        "detection_result_ids"
    ]

    relationship_ids = support_ids[
        "supporting_relationship_ids"
    ]

    contradiction_ids = support_ids[
        "contradicting_relationship_ids"
    ]

    observation_ids = support_ids[
        "observation_ids"
    ]

    if not detection_ids:
        raise CaseExplainIntegrityError(
            "finding contains no detection result"
        )

    if not relationship_ids:
        raise CaseExplainIntegrityError(
            "finding contains no supporting relationship"
        )

    if not observation_ids:
        raise CaseExplainIntegrityError(
            "finding contains no observations"
        )

    resolved_detections: list[
        dict[
            str,
            Any,
        ]
    ] = []

    observation_id_set = set(
        observation_ids
    )

    for detection_id in detection_ids:
        detection = _case_unique_record(
            detections,
            field=(
                "detection_result_id"
            ),
            value=detection_id,
            label="detection result",
        )

        if (
            detection.get(
                "matched"
            )
            is not True
        ):
            raise CaseExplainIntegrityError(
                "finding references an unmatched "
                "detection result: "
                + detection_id
            )

        contributing = (
            _case_string_ids(
                detection,
                "contributing_event_ids",
            )
        )

        if not contributing:
            raise CaseExplainIntegrityError(
                "matched detection has no "
                "contributing events: "
                + detection_id
            )

        if not set(
            contributing
        ).issubset(
            observation_id_set
        ):
            raise CaseExplainIntegrityError(
                "detection contributing events are "
                "outside finding observation lineage: "
                + detection_id
            )

        resolved_detections.append(
            detection
        )

    resolved_relationships = [
        _case_unique_record(
            relationships,
            field=(
                "relationship_id"
            ),
            value=relationship_id,
            label="supporting relationship",
        )
        for relationship_id
        in relationship_ids
    ]

    resolved_contradictions = [
        _case_unique_record(
            relationships,
            field=(
                "relationship_id"
            ),
            value=relationship_id,
            label="contradicting relationship",
        )
        for relationship_id
        in contradiction_ids
    ]

    resolved_events = [
        _case_unique_record(
            events,
            field="event_id",
            value=event_id,
            label="observation",
        )
        for event_id
        in observation_ids
    ]

    raw_evidence = [
        _case_raw_evidence_for_event(
            case_directory=(
                case_directory
            ),
            event=event,
            artifacts=artifacts,
            raw_records=raw_records,
        )
        for event
        in resolved_events
    ]

    if len(
        raw_evidence
    ) != len(
        resolved_events
    ):
        raise CaseExplainIntegrityError(
            "not every observation reached raw evidence"
        )

    if not all(
        item[
            "embedded_raw_hash_verified"
        ]
        for item
        in raw_evidence
    ):
        raise CaseExplainIntegrityError(
            "one or more embedded raw artifacts "
            "failed verification"
        )

    if not all(
        item[
            "raw_locator_reached"
        ]
        for item
        in raw_evidence
    ):
        raise CaseExplainIntegrityError(
            "one or more observations lacks "
            "raw-locator provenance"
        )

    unique_artifacts = {
        item[
            "artifact_id"
        ]
        for item
        in raw_evidence
    }

    directly_verified_locators = sum(
        item[
            "locator_content_hash_verified"
        ]
        is True
        for item
        in raw_evidence
    )

    return {
        "case_id":
            case_id,

        "case_seal_verified":
            True,

        "finding":
            finding,

        "hypothesis":
            hypothesis,

        "detection_results":
            resolved_detections,

        "supporting_relationships":
            resolved_relationships,

        "contradicting_relationships":
            resolved_contradictions,

        "observations":
            resolved_events,

        "raw_evidence":
            raw_evidence,

        "reverse_proof": {
            "finding_to_hypothesis_verified":
                True,

            "finding_to_detection_results_verified":
                True,

            "finding_to_relationships_verified":
                True,

            "finding_to_observations_verified":
                True,

            "observation_to_raw_locator_verified":
                True,

            "observation_to_embedded_artifact_verified":
                True,

            "embedded_raw_hashes_verified":
                len(
                    raw_evidence
                ),

            "unique_embedded_artifacts":
                len(
                    unique_artifacts
                ),

            "direct_locator_content_hashes_verified":
                directly_verified_locators,

            "raw_locator_count":
                len(
                    raw_evidence
                ),

            "reverse_chain_complete":
                True,
        },

        "claim_boundary": {
            "evidence_state":
                finding.get(
                    "evidence_state"
                ),

            "incident_status":
                finding.get(
                    "incident_status"
                ),

            "malicious_intent_status":
                finding.get(
                    "malicious_intent_status"
                ),

            "numeric_confidence_used":
                False,
        },
    }


def render_case_text(
    explanation: dict[
        str,
        Any,
    ],
) -> str:
    finding = explanation[
        "finding"
    ]

    hypothesis = explanation[
        "hypothesis"
    ]

    proof = explanation[
        "reverse_proof"
    ]

    lines = [
        (
            "TraceSOC Case Finding "
            + str(
                finding[
                    "finding_id"
                ]
            )
        ),
        "",
        (
            "State: "
            + str(
                finding[
                    "evidence_state"
                ]
            )
        ),
        (
            "Statement: "
            + str(
                finding[
                    "statement"
                ]
            )
        ),
        (
            "Hypothesis: "
            + str(
                hypothesis[
                    "hypothesis_id"
                ]
            )
        ),
        (
            "Incident status: "
            + str(
                finding[
                    "incident_status"
                ]
            )
        ),
        (
            "Malicious intent: "
            + str(
                finding[
                    "malicious_intent_status"
                ]
            )
        ),
        "",
        (
            "Detection results: "
            + str(
                len(
                    explanation[
                        "detection_results"
                    ]
                )
            )
        ),
        (
            "Supporting relationships: "
            + str(
                len(
                    explanation[
                        "supporting_relationships"
                    ]
                )
            )
        ),
        (
            "Observations: "
            + str(
                len(
                    explanation[
                        "observations"
                    ]
                )
            )
        ),
        (
            "Raw evidence references: "
            + str(
                len(
                    explanation[
                        "raw_evidence"
                    ]
                )
            )
        ),
        (
            "Embedded raw hashes verified: "
            + str(
                proof[
                    "embedded_raw_hashes_verified"
                ]
            )
        ),
        (
            "Reverse chain complete: "
            + (
                "YES"
                if proof[
                    "reverse_chain_complete"
                ]
                else "NO"
            )
        ),
        "",
        (
            "Rationale: "
            + str(
                finding[
                    "rationale"
                ]
            )
        ),
        (
            "Alternative / falsifier: "
            + str(
                finding[
                    "alternative_or_falsifier"
                ]
            )
        ),
    ]

    return "\n".join(
        lines
    )


def main(
    argv: list[str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="tracesoc"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    explain_parser = subparsers.add_parser(
        "explain",
        help="Explain one TraceSOC finding and verify its raw evidence.",
    )

    explain_parser.add_argument(
        "finding_id",
    )

    explain_parser.add_argument(
        "--case",
        dest="case_directory",
        help=(
            "Resolve a v0.4 case finding from a "
            "sealed case directory."
        ),
    )

    explain_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit machine-readable JSON.",
    )

    case_parser = subparsers.add_parser(
        "case",
        help=(
            "Analyze heterogeneous raw evidence "
            "into a sealed TraceSOC case."
        ),
    )

    case_subparsers = (
        case_parser.add_subparsers(
            dest="case_command",
            required=True,
        )
    )

    analyze_parser = (
        case_subparsers.add_parser(
            "analyze",
            help=(
                "Analyze one evidence directory."
            ),
        )
    )

    analyze_parser.add_argument(
        "evidence_directory",
    )

    analyze_parser.add_argument(
        "--output",
        required=True,
        dest="output_directory",
    )

    args = parser.parse_args(
        argv
    )

    try:
        if args.command == "explain":
            if (
                args.case_directory
                is not None
            ):
                explanation = (
                    explain_case_finding(
                        case_directory=Path(
                            args.case_directory
                        ),
                        finding_id=(
                            args.finding_id
                        ),
                    )
                )

                renderer = (
                    render_case_text
                )

            else:
                repo = discover_repo()

                explanation = (
                    explain_finding(
                        repo=repo,
                        finding_id=(
                            args.finding_id
                        ),
                    )
                )

                renderer = (
                    render_text
                )

            if args.as_json:
                print(
                    json.dumps(
                        explanation,
                        sort_keys=True,
                        indent=2,
                    )
                )
            else:
                print(
                    renderer(
                        explanation
                    )
                )

            return 0

        if (
            args.command == "case"
            and args.case_command
            == "analyze"
        ):
            result = analyze_case(
                evidence_directory=Path(
                    args.evidence_directory
                ),
                output_directory=Path(
                    args.output_directory
                ),
            )

            print(
                "CASE_ID="
                + result[
                    "case_id"
                ]
            )

            print(
                "ARTIFACT_COUNT="
                + str(
                    result[
                        "artifact_count"
                    ]
                )
            )

            print(
                "CANONICAL_EVENT_COUNT="
                + str(
                    result[
                        "canonical_event_count"
                    ]
                )
            )

            print(
                "DETECTION_EVALUATION_COUNT="
                + str(
                    result[
                        "detection_evaluation_count"
                    ]
                )
            )

            print(
                "MATCHED_DETECTION_COUNT="
                + str(
                    result[
                        "matched_detection_count"
                    ]
                )
            )

            print(
                "EVENT_DETECTOR_COUNT="
                + str(
                    result[
                        "event_detector_count"
                    ]
                )
            )

            print(
                "DEFERRED_SCRIPTBLOCK_DETECTOR_COUNT="
                + str(
                    result[
                        "deferred_scriptblock_detector_count"
                    ]
                )
            )

            print(
                "FINDING_COUNT="
                + str(
                    result[
                        "finding_count"
                    ]
                )
            )

            print(
                "RAW_EVIDENCE_EMBEDDED="
                + (
                    "TRUE"
                    if result[
                        "raw_evidence_embedded"
                    ]
                    else "FALSE"
                )
            )

            print(
                "SEAL_SHA256="
                + result[
                    "seal_sha256"
                ]
            )

            print(
                "SEAL_VERIFIED=TRUE"
            )

            print(
                "OUTPUT_DIRECTORY="
                + result[
                    "output_directory"
                ]
            )

            return 0

    except (
        CaseAnalysisError,
        CaseExplainIntegrityError,
        EvidenceIntegrityError,
        FindingIntegrityError,
        FileExistsError,
        FileNotFoundError,
        NotADirectoryError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return 2

    return 2
