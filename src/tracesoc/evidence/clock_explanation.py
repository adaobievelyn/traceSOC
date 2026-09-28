from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from tracesoc.findings.models import EvidenceReference
from tracesoc.models import CanonicalEvent
from tracesoc.normalization.clock_evidence import ClockEvidence


SERIALIZATION_ID = "tracesoc-clock-evidence-explanation-v1"


class ClockEvidenceExplanationError(ValueError):
    """Raised when clock-evidence drilldown integrity cannot be verified."""


def verify_registered_evidence_reference(
    *,
    master_record_path: Path,
    reference: EvidenceReference,
) -> dict[str, Any]:
    registry = _load_artifact_registry(
        master_record_path
    )

    file_hash_cache: dict[Path, str] = {}
    raw_cache: dict[Path, bytes] = {}

    return _verify_reference(
        reference=reference,
        registry=registry,
        file_hash_cache=file_hash_cache,
        raw_cache=raw_cache,
    )


def explain_clock_evidence(
    *,
    evidence: ClockEvidence,
    canonical_events: Iterable[CanonicalEvent],
    master_record_path: Path,
) -> dict[str, Any]:
    event_by_id: dict[str, CanonicalEvent] = {}

    for event in canonical_events:
        if event.event_id in event_by_id:
            raise ClockEvidenceExplanationError(
                f"duplicate canonical event ID: {event.event_id}"
            )

        event_by_id[
            event.event_id
        ] = event

    target_event = event_by_id.get(
        evidence.target_event_id
    )

    if target_event is None:
        raise ClockEvidenceExplanationError(
            "ClockEvidence target event is unavailable"
        )

    supporting_events = []

    for event_id in evidence.supporting_event_ids:
        event = event_by_id.get(
            event_id
        )

        if event is None:
            raise ClockEvidenceExplanationError(
                f"ClockEvidence supporting event is unavailable: {event_id}"
            )

        supporting_events.append(
            event
        )

    registry = _load_artifact_registry(
        master_record_path
    )

    file_hash_cache: dict[Path, str] = {}
    raw_cache: dict[Path, bytes] = {}

    target_verified = _verify_reference(
        reference=EvidenceReference.from_canonical(
            target_event
        ),
        registry=registry,
        file_hash_cache=file_hash_cache,
        raw_cache=raw_cache,
    )

    supporting_verified = [
        _verify_reference(
            reference=EvidenceReference.from_canonical(
                event
            ),
            registry=registry,
            file_hash_cache=file_hash_cache,
            raw_cache=raw_cache,
        )
        for event
        in supporting_events
    ]

    return {
        "serialization_id":
            SERIALIZATION_ID,

        "clock_evidence":
            _clock_evidence_dict(
                evidence
            ),

        "target_evidence":
            target_verified,

        "supporting_evidence":
            supporting_verified,

        "raw_evidence_reference_count":
            1
            +
            len(
                supporting_verified
            ),

        "raw_evidence_hashes_verified":
            1
            +
            sum(
                1
                for item
                in supporting_verified
                if item[
                    "raw_sha256_verified"
                ]
            ),

        "analytic_boundary": {
            "detection_created":
                False,

            "correlation_created":
                False,

            "finding_created":
                False,

            "malicious_intent_established":
                False,

            "security_clock_mutated":
                False,
        },
    }


def clock_evidence_explanation_json_bytes(
    explanation: Mapping[str, Any],
) -> bytes:
    return (
        json.dumps(
            dict(
                explanation
            ),
            ensure_ascii=True,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
        )
        +
        "\n"
    ).encode(
        "utf-8"
    )


def _clock_evidence_dict(
    evidence: ClockEvidence,
) -> dict[str, Any]:
    return {
        "evidence_id":
            evidence.evidence_id,

        "state":
            evidence.state.value,

        "method":
            evidence.method,

        "target_event_id":
            evidence.target_event_id,

        "supporting_event_ids":
            list(
                evidence.supporting_event_ids
            ),

        "host":
            evidence.host,

        "target_event_time_raw":
            evidence.target_event_time_raw,

        "utc_interval_start":
            evidence.utc_interval_start.isoformat(),

        "utc_interval_end_exclusive":
            evidence.utc_interval_end_exclusive.isoformat(),

        "coordinate_offset_seconds":
            evidence.coordinate_offset_seconds,

        "resolution_seconds":
            evidence.resolution_seconds,

        "identity_dimensions":
            list(
                evidence.identity_dimensions
            ),
    }


def _load_artifact_registry(
    master_record_path: Path,
) -> dict[str, dict[str, Any]]:
    path = Path(
        master_record_path
    )

    if not path.is_file():
        raise ClockEvidenceExplanationError(
            "master control record does not exist"
        )

    try:
        master = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ClockEvidenceExplanationError(
            "master control record cannot be read"
        ) from exc

    evidence_state = master.get(
        "evidence_state"
    )

    if not isinstance(
        evidence_state,
        dict,
    ):
        raise ClockEvidenceExplanationError(
            "master evidence_state is unavailable"
        )

    artifacts = evidence_state.get(
        "artifacts"
    )

    if not isinstance(
        artifacts,
        list,
    ):
        raise ClockEvidenceExplanationError(
            "master evidence artifact registry is unavailable"
        )

    registry: dict[str, dict[str, Any]] = {}

    for artifact in artifacts:
        if not isinstance(
            artifact,
            dict,
        ):
            raise ClockEvidenceExplanationError(
                "master evidence artifact entry is not an object"
            )

        source_id = artifact.get(
            "source_id"
        )

        if not isinstance(
            source_id,
            str,
        ) or not source_id.strip():
            continue

        if source_id in registry:
            raise ClockEvidenceExplanationError(
                f"duplicate master evidence source ID: {source_id}"
            )

        registry[
            source_id
        ] = artifact

    return registry


def _verify_reference(
    *,
    reference: EvidenceReference,
    registry: Mapping[str, Mapping[str, Any]],
    file_hash_cache: dict[Path, str],
    raw_cache: dict[Path, bytes],
) -> dict[str, Any]:
    artifact = registry.get(
        reference.logical_source
    )

    if artifact is None:
        raise ClockEvidenceExplanationError(
            f"logical source is not registered: {reference.logical_source}"
        )

    if artifact.get(
        "hash_verified"
    ) is not True:
        raise ClockEvidenceExplanationError(
            "registered artifact is not hash verified"
        )

    if artifact.get(
        "integrity_status"
    ) != "VERIFIED":
        raise ClockEvidenceExplanationError(
            "registered artifact integrity status is not VERIFIED"
        )

    expected_sha = artifact.get(
        "expected_sha256"
    )

    observed_sha = artifact.get(
        "observed_sha256"
    )

    if (
        not isinstance(
            expected_sha,
            str,
        )
        or
        not isinstance(
            observed_sha,
            str,
        )
    ):
        raise ClockEvidenceExplanationError(
            "registered artifact lacks SHA-256 identity"
        )

    expected_sha = expected_sha.casefold()
    observed_sha = observed_sha.casefold()

    if expected_sha != observed_sha:
        raise ClockEvidenceExplanationError(
            "registered expected and observed artifact SHA-256 disagree"
        )

    storage_path = artifact.get(
        "storage_path"
    )

    if not isinstance(
        storage_path,
        str,
    ) or not storage_path.strip():
        raise ClockEvidenceExplanationError(
            "registered artifact lacks storage_path"
        )

    path = Path(
        storage_path
    )

    if not path.is_file():
        raise ClockEvidenceExplanationError(
            "registered artifact storage_path does not exist"
        )

    actual_artifact_sha = _sha256_file(
        path,
        file_hash_cache,
    )

    if actual_artifact_sha != expected_sha:
        raise ClockEvidenceExplanationError(
            "current artifact SHA-256 differs from master registration"
        )

    if (
        reference.byte_offset is None
        or
        reference.byte_length is None
    ):
        raise ClockEvidenceExplanationError(
            "evidence reference lacks byte offset/length"
        )

    if reference.byte_offset < 0:
        raise ClockEvidenceExplanationError(
            "evidence reference byte offset is negative"
        )

    if reference.byte_length <= 0:
        raise ClockEvidenceExplanationError(
            "evidence reference byte length must be positive"
        )

    payload = _read_raw(
        path,
        raw_cache,
    )

    start = reference.byte_offset
    end = (
        start
        +
        reference.byte_length
    )

    if end > len(
        payload
    ):
        raise ClockEvidenceExplanationError(
            "evidence reference byte range leaves registered artifact"
        )

    record_bytes = payload[
        start:end
    ]

    observed_record_sha = hashlib.sha256(
        record_bytes
    ).hexdigest()

    if (
        observed_record_sha
        !=
        reference.raw_sha256.casefold()
    ):
        raise ClockEvidenceExplanationError(
            "raw evidence record SHA-256 verification failed"
        )

    line_start_verified: bool | None = None

    if reference.line_number is not None:
        if reference.line_number <= 0:
            raise ClockEvidenceExplanationError(
                "evidence line number must be positive"
            )

        starts = _line_start_offsets(
            payload
        )

        line_index = (
            reference.line_number
            -
            1
        )

        if line_index >= len(
            starts
        ):
            raise ClockEvidenceExplanationError(
                "evidence line number leaves registered artifact"
            )

        if starts[
            line_index
        ] != start:
            raise ClockEvidenceExplanationError(
                "evidence line number does not identify record start byte"
            )

        line_start_verified = True

    try:
        raw_text = record_bytes.decode(
            "utf-8"
        )
    except UnicodeDecodeError as exc:
        raise ClockEvidenceExplanationError(
            "clock-evidence raw record is not UTF-8 text"
        ) from exc

    return {
        "reference":
            reference.to_dict(),

        "registered_source_id":
            reference.logical_source,

        "registered_artifact_sha256":
            expected_sha,

        "artifact_sha256_verified":
            True,

        "raw_sha256_verified":
            True,

        "line_start_verified":
            line_start_verified,

        "raw_text":
            raw_text,
    }


def _sha256_file(
    path: Path,
    cache: dict[Path, str],
) -> str:
    resolved = path.resolve()

    cached = cache.get(
        resolved
    )

    if cached is not None:
        return cached

    digest = hashlib.sha256()

    with resolved.open(
        "rb"
    ) as handle:
        while True:
            chunk = handle.read(
                1024
                *
                1024
            )

            if not chunk:
                break

            digest.update(
                chunk
            )

    value = digest.hexdigest()

    cache[
        resolved
    ] = value

    return value


def _read_raw(
    path: Path,
    cache: dict[Path, bytes],
) -> bytes:
    resolved = path.resolve()

    cached = cache.get(
        resolved
    )

    if cached is not None:
        return cached

    value = resolved.read_bytes()

    cache[
        resolved
    ] = value

    return value


def _line_start_offsets(
    payload: bytes,
) -> tuple[int, ...]:
    lines = payload.splitlines(
        keepends=True
    )

    starts = []
    offset = 0

    for line in lines:
        starts.append(
            offset
        )

        offset += len(
            line
        )

    return tuple(
        starts
    )