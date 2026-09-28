from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

from tracesoc.correlation.powershell_process import (
    correlate_powershell_detection_with_sysmon_process,
)
from tracesoc.correlation.sysmon_pcap_network import (
    correlate_sysmon_network_with_pcap,
)
from tracesoc.correlation.security_sysmon_process import (
    correlate_windows_security_process_with_sysmon,
    normalize_windows_process_id,
    normalize_windows_process_path,
)
from tracesoc.correlation.email_sysmon_artifact import (
    correlate_email_attachment_with_sysmon_process_image,
    extract_sysmon_sha256,
    normalize_sha256,
)
from tracesoc.correlation.sysmon_process_network import (
    correlate_sysmon_process_with_network_activity,
    normalize_sysmon_process_guid,
)
from tracesoc.correlation.web_retrieval_network import (
    correlate_web_retrieval_with_zeek,
)
from tracesoc.detection.registry import (
    POWERSHELL_SCRIPT_BLOCK_DETECTORS,
    SEMANTIC_EVENT_DETECTORS,
    evaluate_powershell_script_block,
    evaluate_semantic_event,
    get_detector_spec,
)
from tracesoc.evidence.correlation_bridge import (
    bridge_powershell_process_correlation,
    bridge_security_sysmon_process_correlation,
    bridge_email_sysmon_artifact_correlation,
    bridge_sysmon_process_network_correlation,
    bridge_sysmon_pcap_network_correlation,
    bridge_web_retrieval_correlation,
)
from tracesoc.evidence.findings_v04 import (
    CaseFinding,
    create_case_findings,
)
from tracesoc.evidence.case_narrative import (
    CaseNarrativeRecord,
    create_case_narratives,
)
from tracesoc.response.case_response import (
    CaseResponseRecord,
    create_case_response_records,
)
from tracesoc.evidence.hypotheses import (
    Hypothesis,
    detection_result_reference,
)
from tracesoc.evidence.states import (
    EvidenceState,
)
from tracesoc.evidence.intake import (
    EvidenceDirectoryIntake,
    EvidenceFileIntake,
    ingest_evidence_directory,
)
from tracesoc.evidence.native_canonical import (
    canonicalize_native_observations,
)
from tracesoc.models import (
    CanonicalEvent,
    SemanticEvent,
    SourceType,
)
from tracesoc.normalization.powershell_scriptblock import (
    RECONSTRUCTION_IDENTITY_VERSION,
    PowerShellScriptBlock,
    ScriptBlockState,
    reconstruct_powershell_scriptblocks,
)


CASE_SCHEMA_ID = (
    "tracesoc-case-v0.4.5a"
)

CASE_SEAL_SCHEMA_ID = (
    "tracesoc-case-seal-v1"
)

ARTIFACT_INDEX_FILE = (
    "artifact-index.json"
)

EVENTS_FILE = (
    "normalized-events.json"
)

SCRIPTBLOCKS_FILE = (
    "powershell-scriptblocks.json"
)

DETECTIONS_FILE = (
    "detections.json"
)

CORRELATIONS_FILE = (
    "correlations.json"
)

RELATIONSHIPS_FILE = (
    "relationships.json"
)

HYPOTHESES_FILE = (
    "hypotheses.json"
)

FINDINGS_FILE = (
    "findings.json"
)

RESPONSES_FILE = (
    "response-register.json"
)

NARRATIVES_FILE = (
    "narrative-register.json"
)

RAW_EVIDENCE_INDEX_FILE = (
    "raw-evidence-index.json"
)

RAW_EVIDENCE_DIRECTORY = (
    "raw-evidence"
)

MANIFEST_FILE = (
    "case-manifest.json"
)

SEAL_FILE = (
    "case-seal.json"
)

SEALED_DATA_FILES = (
    ARTIFACT_INDEX_FILE,
    EVENTS_FILE,
    SCRIPTBLOCKS_FILE,
    DETECTIONS_FILE,
    CORRELATIONS_FILE,
    RELATIONSHIPS_FILE,
    HYPOTHESES_FILE,
    FINDINGS_FILE,
    RESPONSES_FILE,
    NARRATIVES_FILE,
    RAW_EVIDENCE_INDEX_FILE,
    MANIFEST_FILE,
)


class CaseAnalysisError(
    RuntimeError
):
    pass


def _jsonable(
    value: object,
) -> object:
    if isinstance(
        value,
        Enum,
    ):
        return value.value

    if isinstance(
        value,
        datetime,
    ):
        return _utc_text(
            value
        )

    if is_dataclass(
        value
    ):
        return {
            field.name:
                _jsonable(
                    getattr(
                        value,
                        field.name,
                    )
                )
            for field
            in fields(
                value
            )
        }

    if isinstance(
        value,
        dict,
    ):
        return {
            str(key):
                _jsonable(
                    item
                )
            for key, item
            in value.items()
        }

    if isinstance(
        value,
        (
            tuple,
            list,
        ),
    ):
        return [
            _jsonable(
                item
            )
            for item
            in value
        ]

    if (
        value is None
        or isinstance(
            value,
            (
                str,
                int,
                float,
                bool,
            ),
        )
    ):
        return value

    raise CaseAnalysisError(
        "unsupported case serialization value: "
        + type(
            value
        ).__name__
    )


def _safe_case_relative_path(
    value: str,
) -> PurePosixPath:
    if not isinstance(
        value,
        str,
    ):
        raise CaseAnalysisError(
            "case-relative path must be text"
        )

    if (
        not value
        or "\\" in value
    ):
        raise CaseAnalysisError(
            "case-relative path is not canonical POSIX"
        )

    candidate = PurePosixPath(
        value
    )

    if candidate.is_absolute():
        raise CaseAnalysisError(
            "absolute path is forbidden in case bundle"
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
        raise CaseAnalysisError(
            "unsafe case-relative path"
        )

    return candidate


def _discover_source_files(
    evidence_root: Path,
) -> tuple[
    Path,
    ...,
]:
    discovered: list[
        Path
    ] = []

    for path in evidence_root.rglob(
        "*"
    ):
        if path.is_symlink():
            raise CaseAnalysisError(
                "symbolic-link evidence appeared "
                "after intake: "
                + path.relative_to(
                    evidence_root
                ).as_posix()
            )

        if path.is_file():
            discovered.append(
                path
            )

    discovered.sort(
        key=lambda path: (
            path.relative_to(
                evidence_root
            ).as_posix()
        )
    )

    return tuple(
        discovered
    )


def _preserve_raw_evidence(
    *,
    evidence_root: Path,
    intake: EvidenceDirectoryIntake,
    staging_directory: Path,
) -> tuple[
    dict[
        str,
        object,
    ],
    ...,
]:
    source_files = (
        _discover_source_files(
            evidence_root
        )
    )

    if (
        len(
            source_files
        )
        != len(
            intake.items
        )
    ):
        raise CaseAnalysisError(
            "evidence directory changed after intake: "
            "source-file count no longer matches "
            "artifact accounting"
        )

    raw_root = (
        staging_directory
        / RAW_EVIDENCE_DIRECTORY
    )

    raw_root.mkdir(
        parents=True,
        exist_ok=False,
    )

    records: list[
        dict[
            str,
            object,
        ]
    ] = []

    seen_paths: set[
        str
    ] = set()

    for source_path, item in zip(
        source_files,
        intake.items,
        strict=True,
    ):
        relative_text = (
            source_path.relative_to(
                evidence_root
            ).as_posix()
        )

        artifact = item.artifact

        if (
            artifact.source_path_display
            != relative_text
        ):
            raise CaseAnalysisError(
                "intake artifact/source ordering or "
                "path identity changed: "
                + relative_text
            )

        relative = (
            _safe_case_relative_path(
                relative_text
            )
        )

        if relative_text in seen_paths:
            raise CaseAnalysisError(
                "duplicate evidence source path: "
                + relative_text
            )

        seen_paths.add(
            relative_text
        )

        source_size_before = (
            source_path.stat().st_size
        )

        source_hash_before = (
            _sha256_file(
                source_path
            )
        )

        if (
            source_size_before
            != artifact.bytes
        ):
            raise CaseAnalysisError(
                "source evidence byte length changed "
                "after intake: "
                + relative_text
            )

        if (
            source_hash_before
            != artifact.sha256
        ):
            raise CaseAnalysisError(
                "source evidence SHA-256 changed "
                "after intake: "
                + relative_text
            )

        destination = (
            raw_root.joinpath(
                *relative.parts
            )
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if destination.exists():
            raise CaseAnalysisError(
                "raw-evidence destination collision: "
                + relative_text
            )

        shutil.copyfile(
            source_path,
            destination,
        )

        source_size_after = (
            source_path.stat().st_size
        )

        source_hash_after = (
            _sha256_file(
                source_path
            )
        )

        if (
            source_size_after
            != artifact.bytes
            or source_hash_after
            != artifact.sha256
        ):
            raise CaseAnalysisError(
                "source evidence changed while being "
                "preserved: "
                + relative_text
            )

        destination_size = (
            destination.stat().st_size
        )

        destination_hash = (
            _sha256_file(
                destination
            )
        )

        if (
            destination_size
            != artifact.bytes
            or destination_hash
            != artifact.sha256
        ):
            raise CaseAnalysisError(
                "preserved raw-evidence copy failed "
                "byte/hash verification: "
                + relative_text
            )

        case_relative_path = (
            RAW_EVIDENCE_DIRECTORY
            + "/"
            + relative_text
        )

        _safe_case_relative_path(
            case_relative_path
        )

        records.append(
            {
                "artifact_id":
                    artifact.artifact_id,

                "source_path_display":
                    relative_text,

                "case_relative_path":
                    case_relative_path,

                "sha256":
                    artifact.sha256,

                "bytes":
                    artifact.bytes,
            }
        )

    return tuple(
        records
    )


def _canonical_json_bytes(
    value: object,
) -> bytes:
    text = (
        json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )

    return (
        text.replace(
            "\r\n",
            "\n",
        )
        .replace(
            "\r",
            "\n",
        )
        .encode(
            "utf-8"
        )
    )


def _sha256_bytes(
    value: bytes,
) -> str:
    return hashlib.sha256(
        value
    ).hexdigest()


def _sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as handle:
        while True:
            chunk = handle.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(
                chunk
            )

    return digest.hexdigest()


def _utc_text(
    value: datetime | None,
) -> str | None:
    if value is None:
        return None

    if (
        value.tzinfo is None
        or value.utcoffset()
        is None
    ):
        raise CaseAnalysisError(
            "case serialization received "
            "a timezone-naive datetime"
        )

    return (
        value.astimezone(
            timezone.utc
        )
        .isoformat()
        .replace(
            "+00:00",
            "Z",
        )
    )


def _write_json_exclusive(
    path: Path,
    value: object,
) -> str:
    payload = _canonical_json_bytes(
        value
    )

    with path.open(
        "xb"
    ) as handle:
        handle.write(
            payload
        )

    return _sha256_bytes(
        payload
    )


def _case_id(
    intake: EvidenceDirectoryIntake,
) -> str:
    material = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "artifact_ids":
            sorted(
                item.artifact.artifact_id
                for item
                in intake.items
            ),
    }

    return (
        "case_"
        + _sha256_bytes(
            json.dumps(
                material,
                sort_keys=True,
                separators=(
                    ",",
                    ":",
                ),
            ).encode(
                "utf-8"
            )
        )
    )


def _artifact_record(
    item: EvidenceFileIntake,
) -> dict[
    str,
    Any,
]:
    artifact = item.artifact

    lineage = {
        "parent_artifact_id":
            getattr(
                artifact,
                "parent_artifact_id",
                None,
            ),

        "derivation_tool":
            getattr(
                artifact,
                "derivation_tool",
                None,
            ),

        "derivation_version":
            getattr(
                artifact,
                "derivation_version",
                None,
            ),

        "derivation_method":
            getattr(
                artifact,
                "derivation_method",
                None,
            ),
    }

    if not any(
        value is not None
        for value
        in lineage.values()
    ):
        lineage = {}

    return {
        "artifact_id":
            artifact.artifact_id,

        "artifact_type":
            artifact.artifact_type,

        "source_path_display":
            artifact.source_path_display,

        "sha256":
            artifact.sha256,

        "bytes":
            artifact.bytes,

        "acquired_or_observed_utc":
            None,

        "acquired_or_observed_time_status":
            "NOT_ESTABLISHED",

        "runtime_intake_time_in_sealed_truth":
            False,

        "immutability_state":
            artifact.immutability_state.value,

        "processing_state":
            artifact.processing_state.value,

        "adapter_family":
            item.adapter_family.value,

        "canonical_event_count":
            len(
                item.canonical_events
            ),

        "native_observation_count":
            len(
                item.native_observations
            ),

        "evidence_locator_count":
            len(
                item.evidence_locators
            ),

        "derived_artifact_count":
            len(
                item.derived_artifacts
            ),

        "issue_count":
            item.issue_count,

        "errors":
            list(
                item.errors
            ),

        "lineage":
            lineage,
    }


def _raw_locator_record(
    event: CanonicalEvent,
) -> dict[
    str,
    Any,
]:
    locator = event.provenance

    return {
        "logical_source":
            locator.logical_source,

        "record_index":
            locator.record_index,

        "line_number":
            locator.line_number,

        "byte_offset":
            locator.byte_offset,

        "byte_length":
            locator.byte_length,

        "raw_sha256":
            locator.raw_sha256,

        "adapter_id":
            locator.adapter_id,

        "input_schema_version":
            locator.input_schema_version,
    }


def _event_record(
    event: CanonicalEvent,
) -> dict[
    str,
    Any,
]:
    return {
        "event_id":
            event.event_id,

        "source_type":
            event.source_type.value,

        "event_type":
            event.event_type,

        "clock_state":
            event.clock_state.value,

        "event_time_raw":
            event.event_time_raw,

        "event_time_utc":
            _utc_text(
                event.event_time_utc
            ),

        "host":
            event.host,

        "principal":
            event.principal,

        "semantic_fields":
            dict(
                event.semantic_fields
            ),

        "source_context":
            dict(
                event.source_context
            ),

        "raw_locator":
            _raw_locator_record(
                event
            ),
    }


def _scriptblock_record(
    block: PowerShellScriptBlock,
) -> dict[
    str,
    Any,
]:
    return {
        "reconstruction_id":
            block.reconstruction_id,

        "script_block_id":
            block.script_block_id,

        "state":
            block.state.value,

        "host":
            block.host,

        "process_id":
            block.process_id,

        "thread_id":
            block.thread_id,

        "security_user_id":
            block.security_user_id,

        "path":
            block.path,

        "expected_message_total":
            block.expected_message_total,

        "observed_message_numbers":
            list(
                block.observed_message_numbers
            ),

        "missing_message_numbers":
            list(
                block.missing_message_numbers
            ),

        "parent_event_ids":
            list(
                block.parent_event_ids
            ),

        "first_event_time_utc":
            _utc_text(
                block.first_event_time_utc
            ),

        "last_event_time_utc":
            _utc_text(
                block.last_event_time_utc
            ),

        "script_text":
            block.script_text,

        "script_text_sha256":
            block.script_text_sha256,

        "fragments": [
            {
                "source_event_id":
                    fragment.source_event_id,

                "message_number":
                    fragment.message_number,

                "event_time_utc":
                    _utc_text(
                        fragment.event_time_utc
                    ),
            }
            for fragment
            in block.fragments
        ],
    }


def _detection_record(
    result: object,
    *,
    evaluated_input_kind: str,
    evaluated_input_id: str,
) -> dict[
    str,
    Any,
]:
    if evaluated_input_kind not in {
        "semantic_event",
        "powershell_script_block",
    }:
        raise CaseAnalysisError(
            "unsupported detection input kind"
        )

    record = {
        "detection_result_id":
            detection_result_reference(
                result
            ),

        "detection_id":
            result.detection_id,

        "detection_version":
            result.detection_version,

        "title":
            result.title,

        "state":
            result.state.value,

        "matched":
            result.matched,

        "reason_code":
            result.reason_code,

        "rationale":
            result.rationale,

        "contributing_event_ids":
            list(
                result.contributing_event_ids
            ),

        "evaluated_input_kind":
            evaluated_input_kind,

        "evaluated_input_id":
            evaluated_input_id,

        "evaluated_event_id":
            None,

        "evaluated_scriptblock_id":
            None,
    }

    if (
        evaluated_input_kind
        == "semantic_event"
    ):
        record[
            "evaluated_event_id"
        ] = evaluated_input_id

    else:
        record[
            "evaluated_scriptblock_id"
        ] = evaluated_input_id

    return record




def _correlation_record(
    *,
    result: object,
    candidate_event_id: str,
    candidate_kind: str,
    powershell_event_id: str | None = None,
    source_event_id: str | None = None,
    source_kind: str | None = None,
) -> dict[
    str,
    Any,
]:
    if candidate_kind not in {
        "zeek_network",
        "sysmon_process",
        "pcap_packet",
        "sysmon_hashed_process",
        "sysmon_network_activity",
    }:
        raise CaseAnalysisError(
            "unsupported correlation candidate kind"
        )

    if powershell_event_id is not None:
        if source_event_id is not None:
            raise CaseAnalysisError(
                "correlation record has two source event IDs"
            )

        source_event_id = (
            powershell_event_id
        )

        source_kind = (
            "powershell_behavior"
        )

    else:
        if source_event_id is None:
            raise CaseAnalysisError(
                "correlation source event ID is missing"
            )

        if source_kind not in {
            "sysmon_network",
            "windows_security_process",
            "email_attachment",
            "sysmon_process",
        }:
            raise CaseAnalysisError(
                "unsupported correlation source kind"
            )

    return {
        "correlation_id":
            result.correlation_id,

        "correlation_version":
            result.correlation_version,

        "state":
            result.state.value,

        "matched":
            result.matched,

        "reason_code":
            result.reason_code,

        "rationale":
            result.rationale,

        "source_event_id":
            source_event_id,

        "source_kind":
            source_kind,

        "powershell_event_id":
            powershell_event_id,

        "candidate_event_id":
            candidate_event_id,

        "candidate_kind":
            candidate_kind,

        "edge":
            (
                None
                if result.edge is None
                else _jsonable(
                    result.edge
                )
            ),
    }


def _collect_canonical_events(
    intake: EvidenceDirectoryIntake,
) -> tuple[
    CanonicalEvent,
    ...,
]:
    existing_events = tuple(
        event
        for item
        in intake.items
        for event
        in item.canonical_events
    )

    native_events = (
        canonicalize_native_observations(
            intake
        )
    )

    events = (
        existing_events
        + native_events
    )

    event_ids = tuple(
        event.event_id
        for event
        in events
    )

    if (
        len(
            event_ids
        )
        != len(
            set(
                event_ids
            )
        )
    ):
        raise CaseAnalysisError(
            "duplicate canonical event ID "
            "encountered across case intake"
        )

    return tuple(
        sorted(
            events,
            key=lambda event: (
                event.event_id
            ),
        )
    )


def _evaluate_event_detectors(
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ],
) -> tuple[
    dict[
        str,
        Any,
    ],
    ...,
]:
    records: list[
        dict[
            str,
            Any,
        ]
    ] = []

    for canonical in canonical_events:
        semantic = (
            SemanticEvent.from_canonical(
                canonical
            )
        )

        results = (
            evaluate_semantic_event(
                semantic
            )
        )

        expected_ids = tuple(
            spec.detection_id
            for spec
            in SEMANTIC_EVENT_DETECTORS
        )

        observed_ids = tuple(
            result.detection_id
            for result
            in results
        )

        if (
            observed_ids
            != expected_ids
        ):
            raise CaseAnalysisError(
                "detector registry returned "
                "unexpected event-detector ordering"
            )

        for result in results:
            records.append(
                _detection_record(
                    result,
                    evaluated_input_kind=(
                        "semantic_event"
                    ),
                    evaluated_input_id=(
                        canonical.event_id
                    ),
                )
            )

    return tuple(
        sorted(
            records,
            key=lambda record: (
                str(
                    record[
                        "evaluated_input_id"
                    ]
                ),
                str(
                    record[
                        "detection_id"
                    ]
                ),
            ),
        )
    )



def _evaluate_scriptblock_detectors(
    script_blocks: tuple[
        PowerShellScriptBlock,
        ...,
    ],
) -> tuple[
    dict[
        str,
        Any,
    ],
    ...,
]:
    records: list[
        dict[
            str,
            Any,
        ]
    ] = []

    expected_ids = tuple(
        spec.detection_id
        for spec
        in POWERSHELL_SCRIPT_BLOCK_DETECTORS
    )

    for block in script_blocks:
        results = (
            evaluate_powershell_script_block(
                block
            )
        )

        observed_ids = tuple(
            result.detection_id
            for result
            in results
        )

        if (
            observed_ids
            != expected_ids
        ):
            raise CaseAnalysisError(
                "detector registry returned "
                "unexpected ScriptBlock-detector ordering"
            )

        for result in results:
            records.append(
                _detection_record(
                    result,
                    evaluated_input_kind=(
                        "powershell_script_block"
                    ),
                    evaluated_input_id=(
                        block.reconstruction_id
                    ),
                )
            )

    return tuple(
        sorted(
            records,
            key=lambda record: (
                str(
                    record[
                        "evaluated_input_id"
                    ]
                ),
                str(
                    record[
                        "detection_id"
                    ]
                ),
            ),
        )
    )


def _relationship_projection_payload(
    projections: tuple[
        object,
        ...,
    ],
) -> dict[
    str,
    object,
]:
    entities: dict[
        str,
        dict[
            str,
            object,
        ],
    ] = {}

    relationships: dict[
        str,
        dict[
            str,
            object,
        ],
    ] = {}

    for projection in projections:
        for entity in (
            projection.source_entity,
            projection.target_entity,
        ):
            entity_record = _jsonable(
                entity
            )

            if not isinstance(
                entity_record,
                dict,
            ):
                raise CaseAnalysisError(
                    "graph entity serialization failed"
                )

            entity_id = entity.entity_id

            existing = entities.get(
                entity_id
            )

            if (
                existing is not None
                and existing
                != entity_record
            ):
                raise CaseAnalysisError(
                    "same graph entity ID produced "
                    "different serialized content"
                )

            entities[
                entity_id
            ] = entity_record

        relationship_record = (
            _jsonable(
                projection.relationship
            )
        )

        if not isinstance(
            relationship_record,
            dict,
        ):
            raise CaseAnalysisError(
                "graph relationship serialization failed"
            )

        relationship_id = (
            projection.relationship.relationship_id
        )

        enriched = {
            **relationship_record,

            "legacy_correlation_id":
                projection.legacy_correlation_id,

            "legacy_correlation_version":
                projection.legacy_correlation_version,

            "legacy_edge_id":
                projection.legacy_edge_id,
        }

        existing_relationship = (
            relationships.get(
                relationship_id
            )
        )

        if (
            existing_relationship is not None
            and existing_relationship
            != enriched
        ):
            raise CaseAnalysisError(
                "same relationship ID produced "
                "different serialized content"
            )

        relationships[
            relationship_id
        ] = enriched

    return {
        "entities": [
            entities[
                entity_id
            ]
            for entity_id
            in sorted(
                entities
            )
        ],

        "relationships": [
            relationships[
                relationship_id
            ]
            for relationship_id
            in sorted(
                relationships
            )
        ],
    }



def _evaluate_case_correlations_legacy(
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ],
) -> tuple[
    tuple[
        dict[
            str,
            Any,
        ],
        ...,
    ],
    tuple[
        object,
        ...,
    ],
    tuple[
        tuple[
            str,
            object,
            object,
            str,
            str,
        ],
        ...,
    ],
]:
    semantic_events = tuple(
        SemanticEvent.from_canonical(
            event
        )
        for event
        in canonical_events
    )

    powershell_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.POWERSHELL
        )
    )

    zeek_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.ZEEK
        )
    )

    sysmon_process_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.SYSMON
            and event.event_type
            == "process_create"
        )
    )

    sysmon_network_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.SYSMON
            and event.event_type
            == "network_connection"
        )
    )

    pcap_packet_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.PCAP
            and event.event_type
            == "network_packet"
        )
    )

    det001 = get_detector_spec(
        "TRC-DET-001"
    )

    det007 = get_detector_spec(
        "TRC-DET-007"
    )

    correlation_records: list[
        dict[
            str,
            Any,
        ]
    ] = []

    projections: list[
        object
    ] = []

    hypothesis_candidates: list[
        tuple[
            str,
            object,
            object,
            str,
            str,
        ]
    ] = []

    for powershell_event in powershell_events:
        detection = det001.evaluate(
            powershell_event
        )

        if not detection.matched:
            continue

        for zeek_event in zeek_events:
            result = (
                correlate_web_retrieval_with_zeek(
                    detection=detection,
                    powershell_event=(
                        powershell_event
                    ),
                    zeek_event=(
                        zeek_event
                    ),
                )
            )

            correlation_records.append(
                _correlation_record(
                    result=result,
                    powershell_event_id=(
                        powershell_event.event_id
                    ),
                    candidate_event_id=(
                        zeek_event.event_id
                    ),
                    candidate_kind=(
                        "zeek_network"
                    ),
                )
            )

            projection = (
                bridge_web_retrieval_correlation(
                    result=result,
                    powershell_event=(
                        powershell_event
                    ),
                    zeek_event=(
                        zeek_event
                    ),
                )
            )

            if projection is not None:
                projections.append(
                    projection
                )

                hypothesis_candidates.append(
                    (
                        result.correlation_id,
                        detection,
                        projection,
                        powershell_event.event_id,
                        zeek_event.event_id,
                    )
                )

        for sysmon_event in (
            sysmon_process_events
        ):
            result = (
                correlate_powershell_detection_with_sysmon_process(
                    detection=detection,
                    powershell_event=(
                        powershell_event
                    ),
                    sysmon_event=(
                        sysmon_event
                    ),
                )
            )

            correlation_records.append(
                _correlation_record(
                    result=result,
                    powershell_event_id=(
                        powershell_event.event_id
                    ),
                    candidate_event_id=(
                        sysmon_event.event_id
                    ),
                    candidate_kind=(
                        "sysmon_process"
                    ),
                )
            )

            projection = (
                bridge_powershell_process_correlation(
                    result=result,
                    sysmon_event=(
                        sysmon_event
                    ),
                    powershell_event=(
                        powershell_event
                    ),
                )
            )

            if projection is not None:
                projections.append(
                    projection
                )

                hypothesis_candidates.append(
                    (
                        result.correlation_id,
                        detection,
                        projection,
                        powershell_event.event_id,
                        sysmon_event.event_id,
                    )
                )


    for sysmon_event in (
        sysmon_network_events
    ):
        detection = det007.evaluate(
            sysmon_event
        )

        if not detection.matched:
            continue

        for pcap_event in (
            pcap_packet_events
        ):
            result = (
                correlate_sysmon_network_with_pcap(
                    detection=detection,
                    sysmon_event=(
                        sysmon_event
                    ),
                    pcap_event=(
                        pcap_event
                    ),
                )
            )

            correlation_records.append(
                _correlation_record(
                    result=result,
                    source_event_id=(
                        sysmon_event.event_id
                    ),
                    source_kind=(
                        "sysmon_network"
                    ),
                    candidate_event_id=(
                        pcap_event.event_id
                    ),
                    candidate_kind=(
                        "pcap_packet"
                    ),
                )
            )

            projection = (
                bridge_sysmon_pcap_network_correlation(
                    result=result,
                    sysmon_event=(
                        sysmon_event
                    ),
                    pcap_event=(
                        pcap_event
                    ),
                )
            )

            if projection is not None:
                projections.append(
                    projection
                )

                hypothesis_candidates.append(
                    (
                        result.correlation_id,
                        detection,
                        projection,
                        sysmon_event.event_id,
                        pcap_event.event_id,
                    )
                )

    ordered_records = tuple(
        sorted(
            correlation_records,
            key=lambda record: (
                str(
                    record[
                        "correlation_id"
                    ]
                ),
                str(
                    record[
                        "source_event_id"
                    ]
                ),
                str(
                    record[
                        "candidate_event_id"
                    ]
                ),
            ),
        )
    )

    ordered_projections = tuple(
        sorted(
            projections,
            key=lambda projection: (
                projection.relationship.relationship_id
            ),
        )
    )

    ordered_candidates = tuple(
        sorted(
            hypothesis_candidates,
            key=lambda item: (
                item[0],
                item[3],
                item[4],
            ),
        )
    )

    return (
        ordered_records,
        ordered_projections,
        ordered_candidates,
    )

def _build_sysmon_process_identity_contradictions(
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ],
) -> tuple[
    object,
    ...,
]:
    """
    Retain a contradiction only when two source-native Sysmon process-create
    observations claim the same strong ProcessGuid but disagree on concrete
    process identity.

    An ordinary failed correlation, time mismatch, or different ProcessGuid
    is not a contradiction.
    """

    import hashlib

    from tracesoc.evidence.correlation_bridge import (
        CorrelationRelationshipProjection,
        _observation_entity,
    )

    from tracesoc.evidence.graph import (
        Relationship,
        RelationshipAnchor,
        RelationshipType,
    )

    from tracesoc.evidence.states import (
        EvidenceState,
    )

    def text(
        value: object,
    ) -> str | None:
        if not isinstance(
            value,
            str,
        ):
            return None

        result = value.strip()

        return (
            result
            if result
            else None
        )

    def process_id(
        value: object,
    ) -> str | None:
        if isinstance(
            value,
            bool,
        ):
            return None

        if isinstance(
            value,
            int,
        ):
            return (
                str(value)
                if value >= 0
                else None
            )

        result = text(value)

        if result is None:
            return None

        try:
            number = int(
                result,
                10,
            )
        except ValueError:
            return None

        return (
            str(number)
            if number >= 0
            else None
        )

    def process_name(
        value: object,
    ) -> str | None:
        result = text(value)

        if result is None:
            return None

        return (
            result
            .replace(
                "\\",
                "/",
            )
            .rsplit(
                "/",
                1,
            )[-1]
            .casefold()
        )

    semantic_events = tuple(
        SemanticEvent.from_canonical(
            event
        )
        for event
        in canonical_events
    )

    process_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.SYSMON
            and event.event_type
            == "process_create"
        )
    )

    by_guid: dict[
        str,
        list[
            SemanticEvent
        ],
    ] = {}

    for event in process_events:
        raw_guid = text(
            event.fields.get(
                "process_guid"
            )
        )

        if raw_guid is None:
            continue

        by_guid.setdefault(
            raw_guid.casefold(),
            [],
        ).append(
            event
        )

    projections: list[
        object
    ] = []

    for guid in sorted(
        by_guid
    ):
        group = sorted(
            by_guid[
                guid
            ],
            key=lambda event: (
                event.event_id
            ),
        )

        for left_index in range(
            len(group)
        ):
            for right_index in range(
                left_index + 1,
                len(group),
            ):
                left = group[
                    left_index
                ]

                right = group[
                    right_index
                ]

                conflicts: list[
                    tuple[
                        str,
                        str,
                        str,
                    ]
                ] = []

                left_host = text(
                    left.host
                )

                right_host = text(
                    right.host
                )

                if (
                    left_host is not None
                    and right_host is not None
                    and left_host.casefold()
                    != right_host.casefold()
                ):
                    conflicts.append(
                        (
                            "host",
                            left_host.casefold(),
                            right_host.casefold(),
                        )
                    )

                left_pid = process_id(
                    left.fields.get(
                        "process_id"
                    )
                )

                right_pid = process_id(
                    right.fields.get(
                        "process_id"
                    )
                )

                if (
                    left_pid is not None
                    and right_pid is not None
                    and left_pid != right_pid
                ):
                    conflicts.append(
                        (
                            "process_id",
                            left_pid,
                            right_pid,
                        )
                    )

                left_name = process_name(
                    left.fields.get(
                        "process_name"
                    )
                )

                right_name = process_name(
                    right.fields.get(
                        "process_name"
                    )
                )

                if (
                    left_name is not None
                    and right_name is not None
                    and left_name != right_name
                ):
                    conflicts.append(
                        (
                            "process_name",
                            left_name,
                            right_name,
                        )
                    )

                if not conflicts:
                    continue

                source_entity = (
                    _observation_entity(
                        left
                    )
                )

                target_entity = (
                    _observation_entity(
                        right
                    )
                )

                relationship = (
                    Relationship.create(
                        relationship_type=(
                            RelationshipType.CONTRADICTS
                        ),
                        source_entity_id=(
                            source_entity.entity_id
                        ),
                        target_entity_id=(
                            target_entity.entity_id
                        ),
                        predicate_version=(
                            "TRC-CONTRADICTION-001@1.0.0"
                        ),
                        supporting_ids=(
                            left.event_id,
                            right.event_id,
                        ),
                        anchors=(
                            RelationshipAnchor(
                                anchor_type=(
                                    "process_guid"
                                ),
                                value=guid,
                                temporal=False,
                            ),
                            *tuple(
                                RelationshipAnchor(
                                    anchor_type=(
                                        "conflicting_"
                                        + field
                                    ),
                                    value=(
                                        first
                                        + "!="
                                        + second
                                    ),
                                    temporal=False,
                                )
                                for (
                                    field,
                                    first,
                                    second,
                                )
                                in sorted(
                                    conflicts
                                )
                            ),
                        ),
                        evidence_state=(
                            EvidenceState.OBSERVED
                        ),
                        rationale=(
                            "Two source-native Sysmon process-creation "
                            "observations claim the same ProcessGuid but "
                            "disagree on concrete process identity: "
                            + ", ".join(
                                item[
                                    0
                                ]
                                for item
                                in conflicts
                            )
                            + ". TraceSOC retains the conflict instead "
                            "of selecting one observation silently."
                        ),
                        alternative_or_falsifier=(
                            "A duplicated, recycled, corrupted, or otherwise "
                            "non-comparable ProcessGuid could explain the "
                            "conflict. This edge records evidentiary "
                            "inconsistency and does not decide which "
                            "observation is correct."
                        ),
                    )
                )

                material = (
                    "TRC-CONTRADICTION-001"
                    + "\x00"
                    + relationship.relationship_id
                )

                projections.append(
                    CorrelationRelationshipProjection(
                        legacy_correlation_id=(
                            "TRC-CONTRADICTION-001"
                        ),
                        legacy_correlation_version=(
                            "1.0.0"
                        ),
                        legacy_edge_id=(
                            "edge_"
                            + hashlib.sha256(
                                material.encode(
                                    "utf-8"
                                )
                            ).hexdigest()
                        ),
                        source_entity=(
                            source_entity
                        ),
                        target_entity=(
                            target_entity
                        ),
                        relationship=(
                            relationship
                        ),
                    )
                )

    return tuple(
        sorted(
            projections,
            key=lambda projection: (
                projection
                .relationship
                .relationship_id
            ),
        )
    )

def _evaluate_security_sysmon_process_correlations(
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ],
) -> tuple[
    tuple[dict[str, Any], ...],
    tuple[object, ...],
]:
    semantic_events = tuple(
        SemanticEvent.from_canonical(
            event
        )
        for event
        in canonical_events
    )

    security_process_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.WINDOWS_SECURITY
            and event.event_type
            == "process_create"
        )
    )

    sysmon_process_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.SYSMON
            and event.event_type
            == "process_create"
        )
    )

    # Candidate generation is deliberately anchored before time is
    # considered. This avoids timestamp-only relationships and prevents
    # an O(Security x Sysmon) cross-product on real event corpora.
    sysmon_index: dict[
        tuple[str, str, str],
        list[SemanticEvent],
    ] = {}

    for event in sysmon_process_events:
        host = (
            event.host.strip().casefold()
            if isinstance(event.host, str)
            else ""
        )
        process_id = normalize_windows_process_id(
            event.fields.get("process_id")
        )
        process_name = normalize_windows_process_path(
            event.fields.get("process_name")
        )

        if (
            not host
            or process_id is None
            or process_name is None
        ):
            continue

        sysmon_index.setdefault(
            (host, process_id, process_name),
            [],
        ).append(event)

    records: list[dict[str, Any]] = []
    projections: list[object] = []

    for security_event in security_process_events:
        host = (
            security_event.host.strip().casefold()
            if isinstance(security_event.host, str)
            else ""
        )
        process_id = normalize_windows_process_id(
            security_event.fields.get("process_id")
        )
        process_name = normalize_windows_process_path(
            security_event.fields.get("process_name")
        )

        if (
            not host
            or process_id is None
            or process_name is None
        ):
            continue

        candidates = sysmon_index.get(
            (host, process_id, process_name),
            (),
        )

        for sysmon_event in candidates:
            result = (
                correlate_windows_security_process_with_sysmon(
                    security_event=security_event,
                    sysmon_event=sysmon_event,
                )
            )

            records.append(
                _correlation_record(
                    result=result,
                    source_event_id=(
                        security_event.event_id
                    ),
                    source_kind=(
                        "windows_security_process"
                    ),
                    candidate_event_id=(
                        sysmon_event.event_id
                    ),
                    candidate_kind=(
                        "sysmon_process"
                    ),
                )
            )

            projection = (
                bridge_security_sysmon_process_correlation(
                    result=result,
                    security_event=security_event,
                    sysmon_event=sysmon_event,
                )
            )

            if projection is not None:
                projections.append(
                    projection
                )

    return (
        tuple(
            sorted(
                records,
                key=lambda record: (
                    str(record[
                        "source_event_id"
                    ]),
                    str(record[
                        "candidate_event_id"
                    ]),
                ),
            )
        ),
        tuple(
            sorted(
                projections,
                key=lambda projection: (
                    projection
                    .relationship
                    .relationship_id
                ),
            )
        ),
    )

def _evaluate_email_sysmon_artifact_correlations(
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ],
) -> tuple[
    tuple[
        dict[
            str,
            Any,
        ],
        ...,
    ],
    tuple[
        object,
        ...,
    ],
]:
    semantic_events = tuple(
        SemanticEvent.from_canonical(
            event
        )
        for event
        in canonical_events
    )

    email_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.EMAIL
            and event.event_type
            == "email_mime_part"
            and isinstance(
                event.fields.get(
                    "derived_artifact_id"
                ),
                str,
            )
            and bool(
                event.fields.get(
                    "derived_artifact_id"
                ).strip()
            )
        )
    )

    sysmon_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.SYSMON
            and event.event_type
            == "process_create"
        )
    )

    # Exact SHA-256 is the candidate selector.
    # Filename and timestamp never create this edge.
    sysmon_index: dict[
        str,
        list[
            SemanticEvent
        ],
    ] = {}

    for event in sysmon_events:
        sha256 = (
            extract_sysmon_sha256(
                event.fields.get(
                    "hashes"
                )
            )
        )

        if sha256 is None:
            continue

        sysmon_index.setdefault(
            sha256,
            [],
        ).append(
            event
        )

    records: list[
        dict[
            str,
            Any,
        ]
    ] = []

    projections: list[
        object
    ] = []

    for email_event in email_events:
        email_sha256 = (
            normalize_sha256(
                email_event.fields.get(
                    "decoded_sha256"
                )
            )
        )

        if email_sha256 is None:
            continue

        candidates = (
            sysmon_index.get(
                email_sha256,
                (),
            )
        )

        for sysmon_event in candidates:
            result = (
                correlate_email_attachment_with_sysmon_process_image(
                    email_event=email_event,
                    sysmon_event=sysmon_event,
                )
            )

            records.append(
                _correlation_record(
                    result=result,
                    source_event_id=(
                        email_event.event_id
                    ),
                    source_kind=(
                        "email_attachment"
                    ),
                    candidate_event_id=(
                        sysmon_event.event_id
                    ),
                    candidate_kind=(
                        "sysmon_hashed_process"
                    ),
                )
            )

            projection = (
                bridge_email_sysmon_artifact_correlation(
                    result=result,
                    email_event=email_event,
                    sysmon_event=sysmon_event,
                )
            )

            if projection is not None:
                projections.append(
                    projection
                )

    return (
        tuple(
            sorted(
                records,
                key=lambda record: (
                    str(
                        record[
                            "source_event_id"
                        ]
                    ),
                    str(
                        record[
                            "candidate_event_id"
                        ]
                    ),
                ),
            )
        ),
        tuple(
            sorted(
                projections,
                key=lambda projection: (
                    projection
                    .relationship
                    .relationship_id
                ),
            )
        ),
    )


def _evaluate_sysmon_process_network_correlations(
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ],
) -> tuple[
    tuple[
        dict[
            str,
            Any,
        ],
        ...,
    ],
    tuple[
        object,
        ...,
    ],
]:
    semantic_events = tuple(
        SemanticEvent.from_canonical(
            event
        )
        for event
        in canonical_events
    )

    process_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.SYSMON
            and event.event_type
            == "process_create"
        )
    )

    network_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.SYSMON
            and event.event_type
            == "network_connection"
        )
    )

    network_index: dict[
        str,
        list[
            SemanticEvent
        ],
    ] = {}

    for event in network_events:
        process_guid = (
            normalize_sysmon_process_guid(
                event.fields.get(
                    "process_guid"
                )
            )
        )

        if process_guid is None:
            continue

        network_index.setdefault(
            process_guid,
            [],
        ).append(
            event
        )

    records: list[
        dict[
            str,
            Any,
        ]
    ] = []

    projections: list[
        object
    ] = []

    for process_event in process_events:
        process_guid = (
            normalize_sysmon_process_guid(
                process_event.fields.get(
                    "process_guid"
                )
            )
        )

        if process_guid is None:
            continue

        for network_event in (
            network_index.get(
                process_guid,
                (),
            )
        ):
            result = (
                correlate_sysmon_process_with_network_activity(
                    process_event=(
                        process_event
                    ),
                    network_event=(
                        network_event
                    ),
                )
            )

            records.append(
                _correlation_record(
                    result=result,
                    source_event_id=(
                        process_event.event_id
                    ),
                    source_kind=(
                        "sysmon_process"
                    ),
                    candidate_event_id=(
                        network_event.event_id
                    ),
                    candidate_kind=(
                        "sysmon_network_activity"
                    ),
                )
            )

            projection = (
                bridge_sysmon_process_network_correlation(
                    result=result,
                    process_event=(
                        process_event
                    ),
                    network_event=(
                        network_event
                    ),
                )
            )

            if projection is not None:
                projections.append(
                    projection
                )

    return (
        tuple(
            sorted(
                records,
                key=lambda record: (
                    str(
                        record[
                            "source_event_id"
                        ]
                    ),
                    str(
                        record[
                            "candidate_event_id"
                        ]
                    ),
                ),
            )
        ),
        tuple(
            sorted(
                projections,
                key=lambda projection: (
                    projection
                    .relationship
                    .relationship_id
                ),
            )
        ),
    )


def _evaluate_case_correlations(
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ],
    script_blocks: tuple[
        PowerShellScriptBlock,
        ...,
    ] = (),
) -> tuple[
    tuple[
        dict[
            str,
            Any,
        ],
        ...,
    ],
    tuple[
        object,
        ...,
    ],
    tuple[
        tuple[
            str,
            object,
            object,
            str,
            str,
        ],
        ...,
    ],
]:
    """
    Evaluate compatibility correlations plus source-native reconstructed
    PowerShell correlations.

    Legacy canonical/JSONL behavior remains available through correlation
    version 1. Mandatory PowerShell 4104 reaches CORR001/002 through
    complete reconstructed ScriptBlock evidence under version 2.
    """

    (
        legacy_records,
        legacy_projections,
        legacy_candidates,
    ) = _evaluate_case_correlations_legacy(
        canonical_events
    )

    (
        security_sysmon_records,
        security_sysmon_projections,
    ) = (
        _evaluate_security_sysmon_process_correlations(
            canonical_events
        )
    )

    (
        email_sysmon_records,
        email_sysmon_projections,
    ) = (
        _evaluate_email_sysmon_artifact_correlations(
            canonical_events
        )
    )

    (
        sysmon_process_network_records,
        sysmon_process_network_projections,
    ) = (
        _evaluate_sysmon_process_network_correlations(
            canonical_events
        )
    )

    contradiction_projections = (
        _build_sysmon_process_identity_contradictions(
            canonical_events
        )
    )

    if not script_blocks:
        return (
            tuple(
                sorted(
                    (
                        tuple(legacy_records)
                        + tuple(security_sysmon_records)
                        + tuple(email_sysmon_records)
                        + tuple(sysmon_process_network_records)
                    ),
                    key=lambda record: (
                        str(record["correlation_id"]),
                        str(record["source_event_id"]),
                        str(record["candidate_event_id"]),
                    ),
                )
            ),
            tuple(
                sorted(
                    (
                        tuple(
                            legacy_projections
                        )
                        + tuple(
                            security_sysmon_projections
                        )
                        + tuple(
                            email_sysmon_projections
                        )
                        + tuple(sysmon_process_network_projections)
                        + tuple(
                            contradiction_projections
                        )
                    ),
                    key=lambda projection: (
                        projection
                        .relationship
                        .relationship_id
                    ),
                )
            ),
            legacy_candidates,
        )

    from tracesoc.correlation.web_retrieval_network import (
        correlate_reconstructed_web_retrieval_with_zeek,
    )

    from tracesoc.correlation.powershell_process import (
        correlate_reconstructed_powershell_with_sysmon_process,
    )

    semantic_events = tuple(
        SemanticEvent.from_canonical(
            event
        )
        for event
        in canonical_events
    )

    semantic_by_id = {
        event.event_id:
            event
        for event
        in semantic_events
    }

    zeek_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.ZEEK
        )
    )

    sysmon_process_events = tuple(
        event
        for event
        in semantic_events
        if (
            event.source_type
            is SourceType.SYSMON
            and event.event_type
            == "process_create"
        )
    )

    det002 = get_detector_spec(
        "TRC-DET-002"
    )

    source_native_records: list[
        dict[
            str,
            Any,
        ]
    ] = []

    source_native_projections: list[
        object
    ] = []

    source_native_candidates: list[
        tuple[
            str,
            object,
            object,
            str,
            str,
        ]
    ] = []

    for block in script_blocks:
        detection = det002.evaluate(
            block
        )

        if not detection.matched:
            continue

        parent_events: list[
            SemanticEvent
        ] = []

        for event_id in (
            block.parent_event_ids
        ):
            event = (
                semantic_by_id.get(
                    event_id
                )
            )

            if event is None:
                raise CaseAnalysisError(
                    "reconstructed ScriptBlock "
                    "parent event is missing "
                    "from canonical events"
                )

            if (
                event.source_type
                is not SourceType.POWERSHELL
            ):
                raise CaseAnalysisError(
                    "reconstructed ScriptBlock "
                    "parent is not PowerShell telemetry"
                )

            if (
                event.event_time_utc
                is None
            ):
                raise CaseAnalysisError(
                    "reconstructed ScriptBlock "
                    "parent has no normalized UTC time"
                )

            parent_events.append(
                event
            )

        if not parent_events:
            raise CaseAnalysisError(
                "matched reconstructed ScriptBlock "
                "has no parent observations"
            )

        first_anchor = min(
            parent_events,
            key=lambda event: (
                event.event_time_utc,
                event.event_id,
            ),
        )

        last_anchor = max(
            parent_events,
            key=lambda event: (
                event.event_time_utc,
                event.event_id,
            ),
        )

        if (
            first_anchor.event_time_utc
            != block.first_event_time_utc
        ):
            raise CaseAnalysisError(
                "first ScriptBlock parent time "
                "does not match reconstruction"
            )

        if (
            last_anchor.event_time_utc
            != block.last_event_time_utc
        ):
            raise CaseAnalysisError(
                "last ScriptBlock parent time "
                "does not match reconstruction"
            )

        for zeek_event in (
            zeek_events
        ):
            result = (
                correlate_reconstructed_web_retrieval_with_zeek(
                    detection=detection,
                    script_block=block,
                    powershell_event=(
                        last_anchor
                    ),
                    zeek_event=(
                        zeek_event
                    ),
                )
            )

            source_native_records.append(
                _correlation_record(
                    result=result,
                    powershell_event_id=(
                        last_anchor.event_id
                    ),
                    candidate_event_id=(
                        zeek_event.event_id
                    ),
                    candidate_kind=(
                        "zeek_network"
                    ),
                )
            )

            projection = (
                bridge_web_retrieval_correlation(
                    result=result,
                    powershell_event=(
                        last_anchor
                    ),
                    zeek_event=(
                        zeek_event
                    ),
                    script_block=(
                        block
                    ),
                )
            )

            if projection is not None:
                source_native_projections.append(
                    projection
                )

                source_native_candidates.append(
                    (
                        result.correlation_id,
                        detection,
                        projection,
                        last_anchor.event_id,
                        zeek_event.event_id,
                    )
                )

        for sysmon_event in (
            sysmon_process_events
        ):
            result = (
                correlate_reconstructed_powershell_with_sysmon_process(
                    detection=detection,
                    script_block=block,
                    powershell_event=(
                        first_anchor
                    ),
                    sysmon_event=(
                        sysmon_event
                    ),
                )
            )

            source_native_records.append(
                _correlation_record(
                    result=result,
                    powershell_event_id=(
                        first_anchor.event_id
                    ),
                    candidate_event_id=(
                        sysmon_event.event_id
                    ),
                    candidate_kind=(
                        "sysmon_process"
                    ),
                )
            )

            projection = (
                bridge_powershell_process_correlation(
                    result=result,
                    sysmon_event=(
                        sysmon_event
                    ),
                    powershell_event=(
                        first_anchor
                    ),
                    script_block=(
                        block
                    ),
                )
            )

            if projection is not None:
                source_native_projections.append(
                    projection
                )

                source_native_candidates.append(
                    (
                        result.correlation_id,
                        detection,
                        projection,
                        first_anchor.event_id,
                        sysmon_event.event_id,
                    )
                )

    records = tuple(
        sorted(
            (
                tuple(
                    legacy_records
                )
                + tuple(
                    security_sysmon_records
                )
                + tuple(
                    email_sysmon_records
                )
                + tuple(sysmon_process_network_records)
                + tuple(
                    source_native_records
                )
            ),
            key=lambda record: (
                str(
                    record[
                        "correlation_id"
                    ]
                ),
                str(
                    record[
                        "source_event_id"
                    ]
                ),
                str(
                    record[
                        "candidate_event_id"
                    ]
                ),
            ),
        )
    )

    projections = tuple(
        sorted(
            (
                tuple(
                    legacy_projections
                )
                + tuple(
                    security_sysmon_projections
                )
                + tuple(
                    email_sysmon_projections
                )
                + tuple(sysmon_process_network_projections)
                + tuple(
                    source_native_projections
                )
                + tuple(
                    contradiction_projections
                )
            ),
            key=lambda projection: (
                projection
                .relationship
                .relationship_id
            ),
        )
    )

    candidates = tuple(
        sorted(
            (
                tuple(
                    legacy_candidates
                )
                + tuple(
                    source_native_candidates
                )
            ),
            key=lambda item: (
                item[0],
                item[3],
                item[4],
            ),
        )
    )

    return (
        records,
        projections,
        candidates,
    )




def _build_corr003_aggregated_hypotheses(
    candidates: tuple[tuple[str, object, object, str, str], ...],
    *,
    contradiction_projections: tuple[object, ...],
) -> tuple[Hypothesis, ...]:
    """Aggregate TRC-CORR-003 analytical conclusions by Sysmon source event.

    Every packet-level relationship and raw locator remains preserved in the
    evidence graph. Multiple matching packet observations corroborating the
    same Sysmon network observation support one analytical hypothesis instead
    of being promoted into independent conclusions.
    """

    def projection_event_ids(projection: object) -> tuple[str, ...]:
        values: set[str] = set()

        for entity in (
            projection.source_entity,
            projection.target_entity,
        ):
            value = dict(
                entity.identity_attributes
            ).get(
                "event_id"
            )

            if (
                isinstance(value, str)
                and value
            ):
                values.add(
                    value
                )

        return tuple(
            sorted(values)
        )

    groups: dict[
        str,
        list[
            tuple[
                str,
                object,
                object,
                str,
                str,
            ]
        ],
    ] = {}

    for candidate in candidates:
        if candidate[0] == "TRC-CORR-003":
            groups.setdefault(
                candidate[3],
                [],
            ).append(
                candidate
            )

    hypotheses: list[
        Hypothesis
    ] = []

    for source_event_id in sorted(
        groups
    ):
        group = tuple(
            sorted(
                groups[source_event_id],
                key=lambda item: item[4],
            )
        )

        detection = group[0][1]

        if any(
            item[1] != detection
            for item in group
        ):
            raise CaseAnalysisError(
                "TRC-CORR-003 aggregation received "
                "different detections for one Sysmon "
                "network observation"
            )

        candidate_event_ids = tuple(
            item[4]
            for item in group
        )

        if (
            len(
                set(candidate_event_ids)
            )
            != len(candidate_event_ids)
        ):
            raise CaseAnalysisError(
                "TRC-CORR-003 aggregation received "
                "duplicate packet candidates"
            )

        projections = tuple(
            item[2]
            for item in group
        )

        versions = {
            str(
                projection.legacy_correlation_version
            )
            for projection in projections
        }

        if len(versions) != 1:
            raise CaseAnalysisError(
                "TRC-CORR-003 aggregation mixed "
                "correlation versions"
            )

        relationships = tuple(
            sorted(
                (
                    projection.relationship
                    for projection in projections
                ),
                key=lambda relationship:
                    relationship.relationship_id,
            )
        )

        relationship_ids = tuple(
            relationship.relationship_id
            for relationship in relationships
        )

        if (
            len(
                set(relationship_ids)
            )
            != len(relationship_ids)
        ):
            raise CaseAnalysisError(
                "TRC-CORR-003 aggregation received "
                "duplicate supporting relationships"
            )

        alternatives: set[str] = set()

        for relationship in relationships:
            alternative = (
                relationship.alternative_or_falsifier
            )

            if (
                not isinstance(
                    alternative,
                    str,
                )
                or not alternative.strip()
            ):
                raise CaseAnalysisError(
                    "corroborating relationship lacks "
                    "alternative/falsifier text"
                )

            alternatives.add(
                alternative.strip()
            )

        if len(alternatives) != 1:
            raise CaseAnalysisError(
                "TRC-CORR-003 aggregation mixed "
                "alternative/falsifier contracts"
            )

        positive_ids = {
            source_event_id,
            *candidate_event_ids,
        }

        attached = tuple(
            contradiction
            for contradiction
            in contradiction_projections
            if (
                positive_ids
                & set(
                    projection_event_ids(
                        contradiction
                    )
                )
            )
        )

        contradictions = tuple(
            sorted(
                (
                    item.relationship
                    for item in attached
                ),
                key=lambda relationship:
                    relationship.relationship_id,
            )
        )

        observations = set(
            positive_ids
        )

        for contradiction in attached:
            observations.update(
                projection_event_ids(
                    contradiction
                )
            )

        rationale = (
            "TRC-CORR-003 matched "
            + str(len(relationships))
            + " preserved PCAP packet observation"
            + (
                ""
                if len(relationships) == 1
                else "s"
            )
            + " to one Sysmon network observation "
            "on source IP, source port, destination "
            "IP, destination port, transport protocol, "
            "and bounded-time support. Every packet-level "
            "relationship and raw locator remains preserved, "
            "but capture multiplicity is not promoted into "
            "multiple analytical conclusions. No "
            "packet-to-process causality, malicious intent, "
            "or incident membership is asserted."
        )

        if contradictions:
            rationale += (
                " A separate strong-identity contradiction is "
                "retained in the hypothesis lineage. It does not "
                "erase the independently corroborating relationship."
            )

        hypotheses.append(
            Hypothesis.create(
                hypothesis_key=(
                    "sysmon-pcap-network-corroboration:"
                    + source_event_id
                ),
                statement=(
                    "Observed Sysmon PowerShell-initiated "
                    "network activity is corroborated by "
                    "one or more preserved PCAP packet "
                    "observations with the same network "
                    "5-tuple within bounded time."
                ),
                evidence_state=(
                    EvidenceState.CORROBORATED
                ),
                detections=(
                    detection,
                ),
                supporting_relationships=(
                    relationships
                ),
                contradicting_relationships=(
                    contradictions
                ),
                observation_ids=tuple(
                    sorted(observations)
                ),
                rationale=rationale,
                alternative_or_falsifier=(
                    next(
                        iter(alternatives)
                    )
                ),
            )
        )

    return tuple(
        sorted(
            hypotheses,
            key=lambda hypothesis:
                hypothesis.hypothesis_id,
        )
    )

def _build_case_hypotheses(
    candidates: tuple[
        tuple[
            str,
            object,
            object,
            str,
            str,
        ],
        ...,
    ],
    *,
    relationship_projections: tuple[
        object,
        ...,
    ] = (),
) -> tuple[
    Hypothesis,
    ...,
]:
    hypotheses: list[
        Hypothesis
    ] = []

    contradiction_types = {
        "CONTRADICTS",
        "FALSIFIES_HYPOTHESIS",
    }

    def event_ids(
        projection: object,
    ) -> tuple[
        str,
        ...,
    ]:
        values: set[
            str
        ] = set()

        for entity in (
            projection.source_entity,
            projection.target_entity,
        ):
            attributes = dict(
                entity.identity_attributes
            )

            value = attributes.get(
                "event_id"
            )

            if (
                isinstance(
                    value,
                    str,
                )
                and value
            ):
                values.add(
                    value
                )

        return tuple(
            sorted(
                values
            )
        )

    contradiction_projections = tuple(
        projection
        for projection
        in relationship_projections
        if (
            projection
            .relationship
            .relationship_type
            .value
            in contradiction_types
        )
    )

    hypotheses.extend(
        _build_corr003_aggregated_hypotheses(
            candidates,
            contradiction_projections=(
                contradiction_projections
            ),
        )
    )

    scalar_candidates = tuple(
        candidate
        for candidate in candidates
        if candidate[0] != "TRC-CORR-003"
    )

    for (
        correlation_id,
        detection,
        projection,
        powershell_event_id,
        candidate_event_id,
    ) in scalar_candidates:
        version = str(
            projection
            .legacy_correlation_version
        )

        if correlation_id == (
            "TRC-CORR-001"
        ):
            hypothesis_key = (
                "powershell-web-retrieval-network:"
                + powershell_event_id
                + ":"
                + candidate_event_id
            )

            statement = (
                "Observed PowerShell web-retrieval "
                "behavior is corroborated by "
                "bounded network telemetry."
            )

            if version == "2.0.0":
                rationale = (
                    "TRC-CORR-001 v2 matched source-native "
                    "reconstructed PowerShell and Zeek evidence "
                    "on script-observed destination IP, destination "
                    "port, direction, and bounded time. No Zeek "
                    "host attribution or PowerShell local-IP "
                    "equivalence is invented."
                )

            else:
                rationale = (
                    "TRC-CORR-001 compatibility correlation matched "
                    "its published compatibility anchors and bounded "
                    "time."
                )

        elif correlation_id == (
            "TRC-CORR-002"
        ):
            hypothesis_key = (
                "powershell-process-corroboration:"
                + powershell_event_id
                + ":"
                + candidate_event_id
            )

            statement = (
                "Observed PowerShell behavior is "
                "corroborated by a bounded Sysmon "
                "PowerShell process-creation observation."
            )

            if version == "2.0.0":
                rationale = (
                    "TRC-CORR-002 v2 matched source-native "
                    "reconstructed PowerShell and Sysmon evidence "
                    "on host, exact process ID, PowerShell process "
                    "family, direction, and bounded time. No "
                    "local-IP or principal equivalence is invented."
                )

            else:
                rationale = (
                    "TRC-CORR-002 compatibility correlation matched "
                    "its published compatibility anchors and bounded "
                    "time."
                )

        else:
            raise CaseAnalysisError(
                "unsupported hypothesis correlation: "
                + str(
                    correlation_id
                )
            )

        relationship = (
            projection.relationship
        )

        alternative = (
            relationship.alternative_or_falsifier
        )

        if (
            not isinstance(
                alternative,
                str,
            )
            or not alternative.strip()
        ):
            raise CaseAnalysisError(
                "corroborating relationship lacks "
                "alternative/falsifier text"
            )

        positive_ids = {
            powershell_event_id,
            candidate_event_id,
        }

        attached = tuple(
            contradiction
            for contradiction
            in contradiction_projections
            if (
                positive_ids
                & set(
                    event_ids(
                        contradiction
                    )
                )
            )
        )

        contradictions = tuple(
            sorted(
                (
                    item.relationship
                    for item
                    in attached
                ),
                key=lambda relationship: (
                    relationship.relationship_id
                ),
            )
        )

        observations = set(
            positive_ids
        )

        for contradiction in attached:
            observations.update(
                event_ids(
                    contradiction
                )
            )

        if contradictions:
            rationale += (
                " A separate strong-identity contradiction is "
                "retained in the hypothesis lineage. It does not "
                "erase the independently corroborating relationship."
            )

        hypothesis = (
            Hypothesis.create(
                hypothesis_key=(
                    hypothesis_key
                ),
                statement=(
                    statement
                ),
                evidence_state=(
                    EvidenceState.CORROBORATED
                ),
                detections=(
                    detection,
                ),
                supporting_relationships=(
                    relationship,
                ),
                contradicting_relationships=(
                    contradictions
                ),
                observation_ids=tuple(
                    sorted(
                        observations
                    )
                ),
                rationale=(
                    rationale
                ),
                alternative_or_falsifier=(
                    alternative
                ),
            )
        )

        hypotheses.append(
            hypothesis
        )

    by_id: dict[
        str,
        Hypothesis,
    ] = {}

    for hypothesis in hypotheses:
        existing = by_id.get(
            hypothesis.hypothesis_id
        )

        if (
            existing is not None
            and existing != hypothesis
        ):
            raise CaseAnalysisError(
                "same hypothesis ID produced "
                "different content"
            )

        by_id[
            hypothesis.hypothesis_id
        ] = hypothesis

    return tuple(
        by_id[
            hypothesis_id
        ]
        for hypothesis_id
        in sorted(
            by_id
        )
    )


def _case_manifest(
    *,
    case_id: str,
    intake: EvidenceDirectoryIntake,
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ],
    script_blocks: tuple[
        PowerShellScriptBlock,
        ...,
    ],
    event_detections: tuple[
        dict[
            str,
            Any,
        ],
        ...,
    ],
    scriptblock_detections: tuple[
        dict[
            str,
            Any,
        ],
        ...,
    ],
    correlations: tuple[
        dict[
            str,
            Any,
        ],
        ...,
    ],
    relationship_payload: dict[
        str,
        object,
    ],
    hypotheses: tuple[
        Hypothesis,
        ...,
    ],
    findings: tuple[
        CaseFinding,
        ...,
    ],
    responses: tuple[
        CaseResponseRecord,
        ...,
    ],
    narratives: tuple[
        CaseNarrativeRecord,
        ...,
    ],
    raw_evidence_records: tuple[
        dict[
            str,
            object,
        ],
        ...,
    ],
    analysis_observed_utc: datetime,
) -> dict[
    str,
    Any,
]:
    detections = (
        event_detections
        + scriptblock_detections
    )

    matched_detections = tuple(
        item
        for item
        in detections
        if item[
            "matched"
        ]
    )

    matched_correlations = tuple(
        item
        for item
        in correlations
        if item[
            "matched"
        ]
    )

    complete_blocks = tuple(
        block
        for block
        in script_blocks
        if (
            block.state
            is ScriptBlockState.COMPLETE
        )
    )

    incomplete_blocks = tuple(
        block
        for block
        in script_blocks
        if (
            block.state
            is ScriptBlockState.INCOMPLETE
        )
    )

    relationships = (
        relationship_payload[
            "relationships"
        ]
    )

    entities = (
        relationship_payload[
            "entities"
        ]
    )

    if not isinstance(
        relationships,
        list,
    ):
        raise CaseAnalysisError(
            "relationship payload is invalid"
        )

    if not isinstance(
        entities,
        list,
    ):
        raise CaseAnalysisError(
            "entity payload is invalid"
        )

    raw_evidence_bytes = sum(
        int(
            record[
                "bytes"
            ]
        )
        for record
        in raw_evidence_records
    )

    return {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "analysis_observed_utc":
            None,

        "analysis_observed_time_status":
            "VOLATILE_RUNTIME_EXCLUDED",

        "runtime_analysis_time_in_sealed_truth":
            False,

        "artifact_accounting": {
            "discovered":
                intake.discovered_artifact_count,

            "supported_processed":
                intake.supported_processed_count,

            "supported_partial":
                intake.supported_partial_count,

            "unsupported_preserved":
                intake.unsupported_preserved_count,

            "malformed_quarantined":
                intake.malformed_quarantined_count,

            "failed_explicit":
                intake.failed_explicit_count,

            "accounted":
                intake.accounted_artifact_count,

            "zero_silent_loss":
                (
                    intake.discovered_artifact_count
                    == intake.accounted_artifact_count
                ),
        },

        "raw_evidence_accounting": {
            "embedded":
                True,

            "file_count":
                len(
                    raw_evidence_records
                ),

            "byte_count":
                raw_evidence_bytes,

            "every_input_artifact_embedded":
                (
                    len(
                        raw_evidence_records
                    )
                    == intake.discovered_artifact_count
                ),

            "source_hash_verified_before_copy":
                True,

            "source_hash_verified_after_copy":
                True,

            "embedded_hash_verified":
                True,
        },

        "analysis_counts": {
            "canonical_events":
                len(
                    canonical_events
                ),

            "native_observations":
                sum(
                    len(
                        item.native_observations
                    )
                    for item
                    in intake.items
                ),

            "powershell_scriptblocks":
                len(
                    script_blocks
                ),

            "complete_powershell_scriptblocks":
                len(
                    complete_blocks
                ),

            "incomplete_powershell_scriptblocks":
                len(
                    incomplete_blocks
                ),

            "event_detection_evaluations":
                len(
                    event_detections
                ),

            "scriptblock_detection_evaluations":
                len(
                    scriptblock_detections
                ),

            "detection_evaluations":
                len(
                    detections
                ),

            "matched_detections":
                len(
                    matched_detections
                ),

            "correlation_evaluations":
                len(
                    correlations
                ),

            "matched_correlations":
                len(
                    matched_correlations
                ),

            "graph_entities":
                len(
                    entities
                ),

            "graph_relationships":
                len(
                    relationships
                ),

            "hypotheses":
                len(
                    hypotheses
                ),

            "findings":
                len(
                    findings
                ),

            "response_records":
                len(
                    responses
                ),

            "narrative_records":
                len(
                    narratives
                ),
        },

        "detector_coverage": {
            "evaluated_event_detectors":
                [
                    spec.detection_id
                    for spec
                    in SEMANTIC_EVENT_DETECTORS
                ],

            "evaluated_scriptblock_detectors":
                [
                    spec.detection_id
                    for spec
                    in POWERSHELL_SCRIPT_BLOCK_DETECTORS
                ],

            "deferred_scriptblock_detectors":
                [],

            "deferred_reason":
                None,

            "all_registered_detectors_integrated":
                True,
        },

        "correlation_coverage": {
            "evaluated_correlation_ids": [
                "TRC-CORR-001",
                "TRC-CORR-002",
                "TRC-CORR-003",
                "TRC-CORR-004",
                "TRC-CORR-005",
                "TRC-CORR-006",
            ],

            "relationships_created_only_for_matches":
                True,

            "timestamp_only_relationship_allowed":
                False,

            "non_temporal_anchor_required":
                True,

            "malicious_intent_inferred":
                False,

            "causality_inferred":
                False,
        },

        "hypothesis_boundary": {
            "created_only_from_matched_correlation_relationships":
                True,

            "no_match_detection_used_as_support":
                False,

            "numeric_confidence_used":
                False,

            "incident_membership_implied":
                False,

            "malicious_intent_implied":
                False,
        },

        "finding_boundary": {
            "created_only_from_corroborated_hypotheses":
                True,

            "concrete_detection_result_reference_required":
                True,

            "supporting_relationship_required":
                True,

            "observation_lineage_required":
                True,

            "rationale_required":
                True,

            "alternative_or_falsifier_required":
                True,

            "numeric_confidence_used":
                False,

            "incident_declared":
                False,

            "malicious_intent_established":
                False,
        },

        "response_boundary": {
            "records_generated_from_findings":
                True,

            "plan_only":
                True,

            "supported_action_type":
                (
                    "SIMULATED_HOST_ISOLATION"
                ),

            "sandbox_lifecycle_available":
                True,

            "dry_run_recorded_as_not_executed":
                True,

            "verification_criteria_present":
                True,

            "rollback_plan_present":
                True,

            "response_actions_executed":
                False,

            "target_state_fabricated":
                False,

            "asset_owner_fabricated":
                False,

            "service_availability_fabricated":
                False,
        },

        "narrative_boundary": {
            "records_generated_from_findings":
                True,

            "finding_citations_required":
                True,

            "hypothesis_citations_required":
                True,

            "detection_citations_required":
                True,

            "relationship_citations_required":
                True,

            "observation_citations_required":
                True,

            "raw_locators_embedded_in_observation_citations":
                True,

            "additional_inference_introduced":
                False,

            "numeric_confidence_used":
                False,

            "incident_declared":
                False,

            "malicious_intent_established":
                False,

            "response_execution_claimed":
                False,

            "alternative_or_falsifier_preserved":
                True,
        },

        "reconstruction_boundary": {
            "eligible_source":
                (
                    "PowerShell canonical Event ID 4104"
                ),

            "incomplete_groups_preserved":
                True,

            "incomplete_groups_assert_complete_text":
                False,

            "detection_mutates_reconstruction":
                False,
        },

        "analytic_boundary": {
            "generic_relationships_created":
                bool(
                    relationships
                ),

            "generic_hypotheses_created":
                bool(
                    hypotheses
                ),

            "generic_findings_created":
                bool(
                    findings
                ),

            "incident_declared":
                False,

            "malicious_intent_established":
                False,

            "response_actions_executed":
                False,
        },

        "outputs":
            list(
                SEALED_DATA_FILES
            ),
    }







def verify_case_seal(
    case_directory: Path,
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

    if not case_directory.is_dir():
        raise NotADirectoryError(
            str(
                case_directory
            )
        )

    seal_path = (
        case_directory
        / SEAL_FILE
    )

    if not seal_path.is_file():
        raise CaseAnalysisError(
            "case seal is missing"
        )

    try:
        seal = json.loads(
            seal_path.read_text(
                encoding="utf-8"
            )
        )
    except json.JSONDecodeError as exc:
        raise CaseAnalysisError(
            "case seal is not valid JSON"
        ) from exc

    if (
        seal.get(
            "case_seal_schema_id"
        )
        != CASE_SEAL_SCHEMA_ID
    ):
        raise CaseAnalysisError(
            "unsupported case seal schema"
        )

    files = seal.get(
        "files"
    )

    if not isinstance(
        files,
        list,
    ):
        raise CaseAnalysisError(
            "case seal file list is invalid"
        )

    fixed_count = len(
        SEALED_DATA_FILES
    )

    if len(files) < fixed_count:
        raise CaseAnalysisError(
            "case seal is missing required "
            "machine outputs"
        )

    fixed_entries = files[
        :fixed_count
    ]

    fixed_names = tuple(
        item.get(
            "path"
        )
        if isinstance(
            item,
            dict,
        )
        else None
        for item
        in fixed_entries
    )

    if (
        fixed_names
        != tuple(
            SEALED_DATA_FILES
        )
    ):
        raise CaseAnalysisError(
            "case seal fixed-file membership "
            "or order changed"
        )

    verified = 0

    for expected_name, item in zip(
        SEALED_DATA_FILES,
        fixed_entries,
        strict=True,
    ):
        if not isinstance(
            item,
            dict,
        ):
            raise CaseAnalysisError(
                "case seal fixed-file entry is invalid"
            )

        name = item.get(
            "path"
        )

        expected_hash = item.get(
            "sha256"
        )

        if (
            name != expected_name
            or not isinstance(
                expected_hash,
                str,
            )
        ):
            raise CaseAnalysisError(
                "case seal fixed-file entry changed"
            )

        path = (
            case_directory
            / expected_name
        )

        if not path.is_file():
            raise CaseAnalysisError(
                "sealed case file is missing: "
                + expected_name
            )

        actual_hash = (
            _sha256_file(
                path
            )
        )

        if (
            actual_hash
            != expected_hash
        ):
            raise CaseAnalysisError(
                "sealed case file hash mismatch: "
                + expected_name
            )

        verified += 1

    raw_index_path = (
        case_directory
        / RAW_EVIDENCE_INDEX_FILE
    )

    try:
        raw_index = json.loads(
            raw_index_path.read_text(
                encoding="utf-8"
            )
        )
    except json.JSONDecodeError as exc:
        raise CaseAnalysisError(
            "raw-evidence index is not valid JSON"
        ) from exc

    if (
        raw_index.get(
            "case_id"
        )
        != seal.get(
            "case_id"
        )
    ):
        raise CaseAnalysisError(
            "raw-evidence index case ID does not "
            "match seal"
        )

    if (
        raw_index.get(
            "raw_evidence_directory"
        )
        != RAW_EVIDENCE_DIRECTORY
    ):
        raise CaseAnalysisError(
            "raw-evidence directory contract changed"
        )

    raw_records = raw_index.get(
        "raw_evidence_files"
    )

    if not isinstance(
        raw_records,
        list,
    ):
        raise CaseAnalysisError(
            "raw-evidence index file list is invalid"
        )

    raw_names: list[
        str
    ] = []

    seen_raw_names: set[
        str
    ] = set()

    for record in raw_records:
        if not isinstance(
            record,
            dict,
        ):
            raise CaseAnalysisError(
                "raw-evidence index entry is invalid"
            )

        case_relative_path = record.get(
            "case_relative_path"
        )

        expected_hash = record.get(
            "sha256"
        )

        expected_bytes = record.get(
            "bytes"
        )

        if (
            not isinstance(
                case_relative_path,
                str,
            )
            or not isinstance(
                expected_hash,
                str,
            )
            or isinstance(
                expected_bytes,
                bool,
            )
            or not isinstance(
                expected_bytes,
                int,
            )
            or expected_bytes < 0
        ):
            raise CaseAnalysisError(
                "raw-evidence index entry has "
                "invalid identity fields"
            )

        safe_path = (
            _safe_case_relative_path(
                case_relative_path
            )
        )

        if (
            not safe_path.parts
            or safe_path.parts[0]
            != RAW_EVIDENCE_DIRECTORY
            or len(
                safe_path.parts
            )
            < 2
        ):
            raise CaseAnalysisError(
                "raw-evidence path escapes its "
                "designated directory"
            )

        if (
            case_relative_path
            in seen_raw_names
        ):
            raise CaseAnalysisError(
                "duplicate raw-evidence case path"
            )

        seen_raw_names.add(
            case_relative_path
        )

        raw_names.append(
            case_relative_path
        )

    expected_all_names = (
        tuple(
            SEALED_DATA_FILES
        )
        + tuple(
            raw_names
        )
    )

    observed_all_names = tuple(
        item.get(
            "path"
        )
        if isinstance(
            item,
            dict,
        )
        else None
        for item
        in files
    )

    if (
        observed_all_names
        != expected_all_names
    ):
        raise CaseAnalysisError(
            "case seal raw-evidence membership "
            "or order changed"
        )

    raw_entries = files[
        fixed_count:
    ]

    if (
        len(
            raw_entries
        )
        != len(
            raw_records
        )
    ):
        raise CaseAnalysisError(
            "case seal raw-evidence count changed"
        )

    for record, seal_entry in zip(
        raw_records,
        raw_entries,
        strict=True,
    ):
        if not isinstance(
            seal_entry,
            dict,
        ):
            raise CaseAnalysisError(
                "raw-evidence seal entry is invalid"
            )

        name = record[
            "case_relative_path"
        ]

        expected_hash = record[
            "sha256"
        ]

        expected_bytes = record[
            "bytes"
        ]

        if (
            seal_entry.get(
                "path"
            )
            != name
            or seal_entry.get(
                "sha256"
            )
            != expected_hash
        ):
            raise CaseAnalysisError(
                "raw-evidence seal/index identity "
                "mismatch: "
                + name
            )

        safe_path = (
            _safe_case_relative_path(
                name
            )
        )

        path = (
            case_directory.joinpath(
                *safe_path.parts
            )
        )

        if not path.is_file():
            raise CaseAnalysisError(
                "sealed raw evidence is missing: "
                + name
            )

        actual_bytes = (
            path.stat().st_size
        )

        actual_hash = (
            _sha256_file(
                path
            )
        )

        if (
            actual_bytes
            != expected_bytes
        ):
            raise CaseAnalysisError(
                "sealed raw evidence byte length "
                "mismatch: "
                + name
            )

        if (
            actual_hash
            != expected_hash
        ):
            raise CaseAnalysisError(
                "sealed raw evidence hash mismatch: "
                + name
            )

        verified += 1

    if (
        seal.get(
            "raw_evidence_embedded"
        )
        is not True
    ):
        raise CaseAnalysisError(
            "case seal does not assert embedded "
            "raw evidence"
        )

    if (
        seal.get(
            "raw_evidence_file_count"
        )
        != len(
            raw_records
        )
    ):
        raise CaseAnalysisError(
            "case seal raw-evidence count does not "
            "match verified index"
        )

    return {
        "case_id":
            seal.get(
                "case_id"
            ),

        "verified_file_count":
            verified,

        "raw_evidence_file_count":
            len(
                raw_records
            ),

        "raw_evidence_hashes_verified":
            len(
                raw_records
            ),

        "raw_evidence_embedded":
            True,

        "seal_verified":
            True,
    }



def analyze_case(
    *,
    evidence_directory: Path,
    output_directory: Path,
) -> dict[
    str,
    Any,
]:
    if not isinstance(
        evidence_directory,
        Path,
    ):
        raise TypeError(
            "evidence_directory must be pathlib.Path"
        )

    if not isinstance(
        output_directory,
        Path,
    ):
        raise TypeError(
            "output_directory must be pathlib.Path"
        )

    if not evidence_directory.is_dir():
        raise NotADirectoryError(
            str(
                evidence_directory
            )
        )

    evidence_root = (
        evidence_directory.resolve()
    )

    output_path = (
        output_directory.resolve()
    )

    if output_path.exists():
        raise FileExistsError(
            str(
                output_path
            )
        )

    if (
        output_path == evidence_root
        or output_path.is_relative_to(
            evidence_root
        )
    ):
        raise CaseAnalysisError(
            "case output must not be inside "
            "the evidence directory"
        )

    analysis_observed_utc = (
        datetime.now(
            timezone.utc
        )
    )

    intake = (
        ingest_evidence_directory(
            evidence_root,
            acquired_or_observed_utc=(
                analysis_observed_utc
            ),
        )
    )

    if (
        intake.discovered_artifact_count
        != intake.accounted_artifact_count
    ):
        raise CaseAnalysisError(
            "artifact accounting is incomplete"
        )

    canonical_events = (
        _collect_canonical_events(
            intake
        )
    )

    script_blocks = (
        reconstruct_powershell_scriptblocks(
            canonical_events
        )
    )

    event_detections = (
        _evaluate_event_detectors(
            canonical_events
        )
    )

    scriptblock_detections = (
        _evaluate_scriptblock_detectors(
            script_blocks
        )
    )

    detections = tuple(
        sorted(
            (
                event_detections
                + scriptblock_detections
            ),
            key=lambda record: (
                str(
                    record[
                        "evaluated_input_kind"
                    ]
                ),
                str(
                    record[
                        "evaluated_input_id"
                    ]
                ),
                str(
                    record[
                        "detection_id"
                    ]
                ),
            ),
        )
    )

    (
        correlations,
        relationship_projections,
        hypothesis_candidates,
    ) = _evaluate_case_correlations(
        canonical_events,
        script_blocks=script_blocks,
    )

    relationship_graph = (
        _relationship_projection_payload(
            relationship_projections
        )
    )

    hypotheses = (
        _build_case_hypotheses(
            hypothesis_candidates,
            relationship_projections=relationship_projections,
        )
    )

    findings = (
        create_case_findings(
            hypotheses
        )
    )

    responses = (
        create_case_response_records(
            findings=findings,
            canonical_events=(
                canonical_events
            ),
        )
    )


    case_id = (
        _case_id(
            intake
        )
    )

    artifact_payload = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "artifacts":
            [
                _artifact_record(
                    item
                )
                for item
                in intake.items
            ],
    }

    event_payload = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "events":
            [
                _event_record(
                    event
                )
                for event
                in canonical_events
            ],
    }

    scriptblock_payload = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "reconstruction_identity_version":
            RECONSTRUCTION_IDENTITY_VERSION,

        "scriptblocks":
            [
                _scriptblock_record(
                    block
                )
                for block
                in script_blocks
            ],
    }

    detection_payload = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "detections":
            list(
                detections
            ),
    }

    correlation_payload = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "correlations":
            list(
                correlations
            ),
    }

    graph_payload = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "entities":
            relationship_graph[
                "entities"
            ],

        "relationships":
            relationship_graph[
                "relationships"
            ],
    }

    hypothesis_payload = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "hypotheses": [
            hypothesis.to_dict()
            for hypothesis
            in hypotheses
        ],
    }

    finding_payload = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "findings": [
            finding.to_dict()
            for finding
            in findings
        ],
    }

    response_payload = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "response_register_schema_id":
            (
                "tracesoc-case-response-register-v1"
            ),

        "responses": [
            response.to_dict()
            for response
            in responses
        ],
    }

    narratives = (
        create_case_narratives(
            findings=findings,
            canonical_events=(
                canonical_events
            ),
            relationship_payload=(
                relationship_graph
            ),
            responses=responses,
        )
    )

    narrative_payload = {
        "case_schema_id":
            CASE_SCHEMA_ID,

        "case_id":
            case_id,

        "narrative_register_schema_id":
            (
                "tracesoc-case-narrative-register-v1"
            ),

        "narratives": [
            narrative.to_dict()
            for narrative
            in narratives
        ],
    }

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_path = Path(
        tempfile.mkdtemp(
            prefix=(
                ".tracesoc-case-"
            ),
            dir=str(
                output_path.parent
            ),
        )
    )

    try:
        raw_evidence_records = (
            _preserve_raw_evidence(
                evidence_root=(
                    evidence_root
                ),
                intake=(
                    intake
                ),
                staging_directory=(
                    temp_path
                ),
            )
        )

        raw_evidence_index_payload = {
            "case_schema_id":
                CASE_SCHEMA_ID,

            "case_id":
                case_id,

            "raw_evidence_directory":
                RAW_EVIDENCE_DIRECTORY,

            "raw_evidence_files":
                list(
                    raw_evidence_records
                ),
        }

        manifest_payload = (
                _case_manifest(
                    case_id=case_id,
                    intake=intake,
                    canonical_events=(
                        canonical_events
                    ),
                    script_blocks=(
                        script_blocks
                    ),
                    event_detections=(
                        event_detections
                    ),
                    scriptblock_detections=(
                        scriptblock_detections
                    ),
                    correlations=(
                        correlations
                    ),
                    relationship_payload=(
                        relationship_graph
                    ),
                    hypotheses=(
                        hypotheses
                    ),
                    findings=(
                        findings
                    ),
                    responses=(
                        responses
                    ),
                    narratives=(
                        narratives
                    ),
                    raw_evidence_records=(
                        raw_evidence_records
                    ),
                    analysis_observed_utc=(
                        analysis_observed_utc
                    ),
                )
            )


        payloads = (
            (
                ARTIFACT_INDEX_FILE,
                artifact_payload,
            ),
            (
                EVENTS_FILE,
                event_payload,
            ),
            (
                SCRIPTBLOCKS_FILE,
                scriptblock_payload,
            ),
            (
                DETECTIONS_FILE,
                detection_payload,
            ),
            (
                CORRELATIONS_FILE,
                correlation_payload,
            ),
            (
                RELATIONSHIPS_FILE,
                graph_payload,
            ),
            (
                HYPOTHESES_FILE,
                hypothesis_payload,
            ),
            (
                FINDINGS_FILE,
                finding_payload,
            ),
            (
                RESPONSES_FILE,
                response_payload,
            ),
            (
                NARRATIVES_FILE,
                narrative_payload,
            ),
            (
                RAW_EVIDENCE_INDEX_FILE,
                raw_evidence_index_payload,
            ),
            (
                MANIFEST_FILE,
                manifest_payload,
            ),
        )

        file_hashes: list[
            dict[
                str,
                str,
            ]
        ] = []

        for filename, payload in payloads:
            digest = (
                _write_json_exclusive(
                    temp_path
                    / filename,
                    payload,
                )
            )

            file_hashes.append(
                {
                    "path":
                        filename,

                    "sha256":
                        digest,
                }
            )

        for record in raw_evidence_records:
            case_relative_path = str(
                record[
                    "case_relative_path"
                ]
            )

            expected_hash = str(
                record[
                    "sha256"
                ]
            )

            safe_path = (
                _safe_case_relative_path(
                    case_relative_path
                )
            )

            preserved_path = (
                temp_path.joinpath(
                    *safe_path.parts
                )
            )

            actual_hash = (
                _sha256_file(
                    preserved_path
                )
            )

            if actual_hash != expected_hash:
                raise CaseAnalysisError(
                    "raw evidence changed before "
                    "case sealing: "
                    + case_relative_path
                )

            file_hashes.append(
                {
                    "path":
                        case_relative_path,

                    "sha256":
                        expected_hash,
                }
            )

        seal_payload = {
            "case_seal_schema_id":
                CASE_SEAL_SCHEMA_ID,

            "case_schema_id":
                CASE_SCHEMA_ID,

            "case_id":
                case_id,

            "files":
                file_hashes,

            "raw_evidence_embedded":
                True,

            "raw_evidence_file_count":
                len(
                    raw_evidence_records
                ),

            "raw_evidence_copy_status":
                (
                    "VERIFIED_BYTE_EXACT_V0.4.5E"
                ),

            "analytic_boundary": {
                "incident_declared":
                    False,

                "malicious_intent_established":
                    False,
            },
        }

        seal_sha256 = (
            _write_json_exclusive(
                temp_path
                / SEAL_FILE,
                seal_payload,
            )
        )

        verification = (
            verify_case_seal(
                temp_path
            )
        )

        if not verification[
            "seal_verified"
        ]:
            raise CaseAnalysisError(
                "case seal verification failed"
            )

        temp_path.rename(
            output_path
        )

    except Exception:
        shutil.rmtree(
            temp_path,
            ignore_errors=True,
        )

        raise

    matched_correlations = sum(
        bool(
            item[
                "matched"
            ]
        )
        for item
        in correlations
    )

    relationships = (
        relationship_graph[
            "relationships"
        ]
    )

    if not isinstance(
        relationships,
        list,
    ):
        raise CaseAnalysisError(
            "relationship output is invalid"
        )

    return {
        "case_id":
            case_id,

        "output_directory":
            str(
                output_path
            ),

        "artifact_count":
            intake.discovered_artifact_count,

        "canonical_event_count":
            len(
                canonical_events
            ),

        "scriptblock_count":
            len(
                script_blocks
            ),

        "event_detection_evaluation_count":
            len(
                event_detections
            ),

        "scriptblock_detection_evaluation_count":
            len(
                scriptblock_detections
            ),

        "detection_evaluation_count":
            len(
                detections
            ),

        "matched_detection_count":
            sum(
                bool(
                    item[
                        "matched"
                    ]
                )
                for item
                in detections
            ),

        "event_detector_count":
            len(
                SEMANTIC_EVENT_DETECTORS
            ),

        "scriptblock_detector_count":
            len(
                POWERSHELL_SCRIPT_BLOCK_DETECTORS
            ),

        "deferred_scriptblock_detector_count":
            0,

        "all_registered_detectors_integrated":
            True,

        "correlation_evaluation_count":
            len(
                correlations
            ),

        "matched_correlation_count":
            matched_correlations,

        "relationship_count":
            len(
                relationships
            ),

        "hypothesis_count":
            len(
                hypotheses
            ),

        "finding_count":
            len(
                findings
            ),

        "response_count":
            len(
                responses
            ),

        "narrative_count":
            len(
                narratives
            ),

        "raw_evidence_file_count":
            len(
                raw_evidence_records
            ),

        "raw_evidence_byte_count":
            sum(
                int(
                    record[
                        "bytes"
                    ]
                )
                for record
                in raw_evidence_records
            ),

        "raw_evidence_embedded":
            True,

        "raw_evidence_hashes_verified":
            len(
                raw_evidence_records
            ),

        "seal_sha256":
            seal_sha256,

        "seal_verified":
            True,
    }
