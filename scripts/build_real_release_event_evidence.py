from __future__ import annotations

import argparse
import csv
import dataclasses
import hashlib
import json
import re
from enum import Enum
from pathlib import Path
from typing import Any

from tracesoc.detection.powershell_reconstructed import (
    PREAUTH_DISCOVERY_DETECTION_ID,
    PREAUTH_DISCOVERY_DETECTION_VERSION,
    detect_domain_user_preauth_discovery,
)
from tracesoc.detection.sysmon_firewall import (
    DETECTION_ID as FIREWALL_DETECTION_ID,
    DETECTION_VERSION as FIREWALL_DETECTION_VERSION,
    detect_sysmon_domain_firewall_zero_write,
)
from tracesoc.models import SemanticEvent
from tracesoc.normalization.powershell_scriptblock import (
    reconstruct_powershell_scriptblocks,
)
from tracesoc.parsers.powershell import (
    load_powershell_windows_event_xml,
)
from tracesoc.parsers.sysmon import (
    load_sysmon_windows_event_xml,
)


POWERSHELL_SOURCE_ID = (
    "TS-DEV-SPLUNK-PS-001"
)

SYSMON_SOURCE_ID = (
    "TS-DEV-SPLUNK-SYSMON-001"
)

EXPECTED_DET003_MATCHES = 5
EXPECTED_DET005_MATCHES = 2

EXPECTED_POWERSHELL_ACCEPTED = 126
EXPECTED_SYSMON_ACCEPTED = 11618


def sha256_file(
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


def canonical_json_bytes(
    value: Any,
) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode(
        "utf-8"
    )


def scalar(
    value: Any,
) -> Any:
    if isinstance(
        value,
        Enum,
    ):
        return value.value

    if isinstance(
        value,
        Path,
    ):
        return str(
            value
        )

    if isinstance(
        value,
        (
            str,
            int,
            float,
            bool,
        ),
    ) or value is None:
        return value

    return str(
        value
    )


def public_dataclass_values(
    value: Any,
) -> dict[str, Any]:
    if dataclasses.is_dataclass(
        value
    ):
        result = {}

        for field in dataclasses.fields(
            value
        ):
            child = getattr(
                value,
                field.name,
            )

            result[
                field.name
            ] = child

        return result

    try:
        return dict(
            vars(
                value
            )
        )
    except TypeError:
        return {}


def acquisition_rows(
    repo: Path,
) -> list[dict[str, str]]:
    path = (
        repo
        / "project-control"
        / "evidence-acquisition-register.csv"
    )

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        return list(
            csv.DictReader(
                handle
            )
        )


def resolve_registered_source(
    *,
    repo: Path,
    evidence_root: Path,
    source_id: str,
) -> dict[str, Any]:
    rows = acquisition_rows(
        repo
    )

    matches = []

    for row in rows:
        exact_values = {
            str(value).strip()
            for value in row.values()
            if value is not None
        }

        if source_id in exact_values:
            matches.append(
                row
            )

    if len(matches) != 1:
        raise RuntimeError(
            "REGISTER_ROW_NOT_UNIQUE:"
            + source_id
            + ":"
            + str(
                len(matches)
            )
        )

    row = matches[0]

    registered_hashes = {
        str(value)
        .strip()
        .casefold()
        for value in row.values()
        if isinstance(
            value,
            str,
        )
        and re.fullmatch(
            r"[0-9a-fA-F]{64}",
            value.strip(),
        )
    }

    if not registered_hashes:
        raise RuntimeError(
            "REGISTERED_SHA256_MISSING:"
            + source_id
        )

    root = evidence_root.resolve()

    candidate_paths = {}

    for raw_value in row.values():
        if not isinstance(
            raw_value,
            str,
        ):
            continue

        text = (
            raw_value
            .strip()
            .strip('"')
        )

        if not text:
            continue

        raw_path = Path(
            text
        )

        possibilities = []

        if raw_path.is_absolute():
            possibilities.append(
                raw_path
            )
        else:
            possibilities.append(
                root
                / raw_path
            )

        for candidate in possibilities:
            try:
                resolved = candidate.resolve()

                resolved.relative_to(
                    root
                )

                if not resolved.is_file():
                    continue
            except (
                OSError,
                ValueError,
            ):
                continue

            candidate_paths[
                str(
                    resolved
                ).casefold()
            ] = resolved

    verified = []

    for candidate in candidate_paths.values():
        digest = sha256_file(
            candidate
        )

        if digest in registered_hashes:
            verified.append(
                (
                    candidate,
                    digest,
                )
            )

    if len(verified) != 1:
        raise RuntimeError(
            "REGISTERED_FILE_RESOLUTION_FAILED:"
            + source_id
            + ":"
            + str(
                len(verified)
            )
        )

    raw_path, raw_sha256 = (
        verified[0]
    )

    relative = raw_path.relative_to(
        root
    )

    return {
        "source_id": source_id,
        "path": raw_path,
        "relative_path": (
            relative.as_posix()
        ),
        "raw_sha256": raw_sha256,
    }


def provenance_reference(
    *,
    canonical_event: Any,
    source_path: Path,
    expected_source_sha256: str,
    expected_source_id: str,
) -> dict[str, Any]:
    provenance = getattr(
        canonical_event,
        "provenance",
        None,
    )

    if provenance is None:
        raise RuntimeError(
            "CANONICAL_PROVENANCE_MISSING"
        )

    values = public_dataclass_values(
        provenance
    )

    logical_source = getattr(
        provenance,
        "logical_source",
        None,
    )

    record_raw_sha256 = getattr(
        provenance,
        "raw_sha256",
        None,
    )

    if not isinstance(
        logical_source,
        str,
    ) or not logical_source:
        raise RuntimeError(
            "LOGICAL_SOURCE_MISSING"
        )

    if (
        logical_source
        != expected_source_id
    ):
        raise RuntimeError(
            "LOGICAL_SOURCE_MISMATCH:"
            + logical_source
        )

    if not isinstance(
        record_raw_sha256,
        str,
    ):
        raise RuntimeError(
            "PROVENANCE_RAW_SHA_MISSING"
        )

    record_raw_sha256 = (
        record_raw_sha256.casefold()
    )

    if not re.fullmatch(
        r"[0-9a-f]{64}",
        record_raw_sha256,
    ):
        raise RuntimeError(
            "PROVENANCE_RAW_SHA_INVALID"
        )

    if not isinstance(
        expected_source_sha256,
        str,
    ):
        raise RuntimeError(
            "SOURCE_SHA256_MISSING"
        )

    expected_source_sha256 = (
        expected_source_sha256.casefold()
    )

    if not re.fullmatch(
        r"[0-9a-f]{64}",
        expected_source_sha256,
    ):
        raise RuntimeError(
            "SOURCE_SHA256_INVALID"
        )

    locator = {}

    locator_names = {
        "record_index",
        "line_number",
        "byte_offset",
        "byte_length",
        "record_number",
        "record_id",
        "source_record_id",
    }

    for name, value in values.items():
        if (
            name
            in locator_names
            and value is not None
        ):
            locator[
                name
            ] = scalar(
                value
            )

    if not locator:
        raise RuntimeError(
            "RAW_LOCATOR_MISSING:"
            + str(
                getattr(
                    canonical_event,
                    "event_id",
                    "<NO_EVENT_ID>",
                )
            )
        )

    byte_offset = locator.get(
        "byte_offset"
    )

    byte_length = locator.get(
        "byte_length"
    )

    if (
        not isinstance(
            byte_offset,
            int,
        )
        or isinstance(
            byte_offset,
            bool,
        )
        or byte_offset < 0
    ):
        raise RuntimeError(
            "RAW_BYTE_OFFSET_MISSING_OR_INVALID"
        )

    if (
        not isinstance(
            byte_length,
            int,
        )
        or isinstance(
            byte_length,
            bool,
        )
        or byte_length <= 0
    ):
        raise RuntimeError(
            "RAW_BYTE_LENGTH_MISSING_OR_INVALID"
        )

    source_path = Path(
        source_path
    )

    if not source_path.is_file():
        raise RuntimeError(
            "REGISTERED_SOURCE_FILE_MISSING"
        )

    source_size = (
        source_path.stat().st_size
    )

    if (
        byte_offset
        + byte_length
        > source_size
    ):
        raise RuntimeError(
            "RAW_LOCATOR_OUT_OF_BOUNDS"
        )

    with source_path.open(
        "rb"
    ) as handle:
        handle.seek(
            byte_offset
        )

        raw_record = handle.read(
            byte_length
        )

    if len(
        raw_record
    ) != byte_length:
        raise RuntimeError(
            "RAW_RECORD_LENGTH_MISMATCH"
        )

    observed_record_sha256 = (
        hashlib.sha256(
            raw_record
        ).hexdigest()
    )

    if (
        observed_record_sha256
        != record_raw_sha256
    ):
        raise RuntimeError(
            "RAW_RECORD_SHA256_MISMATCH"
        )

    event_type = getattr(
        canonical_event,
        "event_type",
        None,
    )

    source_type = getattr(
        canonical_event,
        "source_type",
        None,
    )

    return {
        "event_id": str(
            canonical_event.event_id
        ),
        "source_type": scalar(
            source_type
        ),
        "event_type": scalar(
            event_type
        ),
        "logical_source": (
            logical_source
        ),
        "source_sha256": (
            expected_source_sha256
        ),
        "raw_sha256": (
            record_raw_sha256
        ),
        "record_raw_sha256": (
            record_raw_sha256
        ),
        "locator": locator,
        "record_sha256_verified": True,
        "registered_artifact_sha256_verified": True,
    }


def detection_summary(
    result: Any,
) -> dict[str, Any]:
    summary = {}

    for name in (
        "detection_id",
        "detection_version",
        "state",
        "title",
        "bounded_claim",
        "claim",
        "rationale",
        "reason_code",
    ):
        if not hasattr(
            result,
            name,
        ):
            continue

        value = getattr(
            result,
            name,
        )

        if value is None:
            continue

        summary[
            name
        ] = scalar(
            value
        )

    contributing_event_ids = getattr(
        result,
        "contributing_event_ids",
        None,
    )

    if contributing_event_ids is None:
        raise RuntimeError(
            "DETECTION_EVIDENCE_IDS_MISSING"
        )

    summary[
        "contributing_event_ids"
    ] = [
        str(
            item
        )
        for item in contributing_event_ids
    ]

    return summary


def reconstruct_blocks(
    events: list[Any],
) -> list[Any]:
    reconstructed = (
        reconstruct_powershell_scriptblocks(
            events
        )
    )

    if isinstance(
        reconstructed,
        list,
    ):
        return reconstructed

    if isinstance(
        reconstructed,
        tuple,
    ):
        return list(
            reconstructed
        )

    for attribute in (
        "script_blocks",
        "blocks",
        "accepted",
    ):
        if hasattr(
            reconstructed,
            attribute,
        ):
            candidate = getattr(
                reconstructed,
                attribute,
            )

            return list(
                candidate
            )

    try:
        return list(
            reconstructed
        )
    except TypeError as exc:
        raise RuntimeError(
            "UNSUPPORTED_RECONSTRUCTION_RETURN_TYPE:"
            + type(
                reconstructed
            ).__name__
        ) from exc


def block_summary(
    block: Any,
) -> dict[str, Any]:
    result = {}

    for name in (
        "script_block_id",
        "reconstruction_id",
        "state",
    ):
        if hasattr(
            block,
            name,
        ):
            value = getattr(
                block,
                name,
            )

            if value is not None:
                result[
                    name
                ] = scalar(
                    value
                )

    parent_event_ids = getattr(
        block,
        "parent_event_ids",
        None,
    )

    if parent_event_ids is None:
        raise RuntimeError(
            "SCRIPTBLOCK_PARENT_EVENT_IDS_MISSING"
        )

    result[
        "parent_event_ids"
    ] = [
        str(
            item
        )
        for item in parent_event_ids
    ]

    return result


def evaluate_powershell(
    *,
    source: dict[str, Any],
) -> dict[str, Any]:
    batch = (
        load_powershell_windows_event_xml(
            source["path"],
            logical_source=(
                POWERSHELL_SOURCE_ID
            ),
        )
    )

    accepted = list(
        batch.accepted
    )

    quarantined = list(
        batch.quarantined
    )

    if len(
        accepted
    ) != EXPECTED_POWERSHELL_ACCEPTED:
        raise RuntimeError(
            "POWERSHELL_ACCEPTED_COUNT_MISMATCH:"
            + str(
                len(
                    accepted
                )
            )
        )

    if quarantined:
        raise RuntimeError(
            "POWERSHELL_QUARANTINE_NONZERO:"
            + str(
                len(
                    quarantined
                )
            )
        )

    canonical_by_id = {}

    for event in accepted:
        event_id = str(
            event.event_id
        )

        if event_id in canonical_by_id:
            raise RuntimeError(
                "DUPLICATE_CANONICAL_EVENT_ID:"
                + event_id
            )

        canonical_by_id[
            event_id
        ] = event

    blocks = reconstruct_blocks(
        accepted
    )

    matches = []

    for block in blocks:
        detection = (
            detect_domain_user_preauth_discovery(
                block
            )
        )

        if not detection.matched:
            continue

        detector = detection_summary(
            detection
        )

        if (
            detector.get(
                "detection_id"
            )
            != PREAUTH_DISCOVERY_DETECTION_ID
        ):
            raise RuntimeError(
                "DET003_ID_MISMATCH"
            )

        contributing_event_ids = detector[
            "contributing_event_ids"
        ]

        block_info = block_summary(
            block
        )

        parent_ids = block_info[
            "parent_event_ids"
        ]

        if (
            len(
                contributing_event_ids
            )
            != len(
                set(
                    contributing_event_ids
                )
            )
        ):
            raise RuntimeError(
                "DET003_DUPLICATE_EVIDENCE_ID"
            )

        if set(
            contributing_event_ids
        ) != set(
            parent_ids
        ):
            raise RuntimeError(
                "DET003_PARENT_LINEAGE_MISMATCH"
            )

        raw_references = []

        for event_id in contributing_event_ids:
            canonical = canonical_by_id.get(
                event_id
            )

            if canonical is None:
                raise RuntimeError(
                    "DET003_CANONICAL_EVENT_NOT_FOUND:"
                    + event_id
                )

            raw_references.append(
                provenance_reference(
                    canonical_event=canonical,
                    source_path=source["path"],
                    expected_source_sha256=source['raw_sha256'],
                    expected_source_id=POWERSHELL_SOURCE_ID,
                )
            )

        raw_references.sort(
            key=lambda item: (
                tuple(
                    sorted(
                        item[
                            "locator"
                        ].items()
                    )
                ),
                item[
                    "event_id"
                ],
            )
        )

        matches.append(
            {
                "detection": detector,
                "script_block": (
                    block_info
                ),
                "raw_references": (
                    raw_references
                ),
            }
        )

    if len(
        matches
    ) != EXPECTED_DET003_MATCHES:
        raise RuntimeError(
            "DET003_MATCH_COUNT_MISMATCH:"
            + str(
                len(
                    matches
                )
            )
        )

    matches.sort(
        key=lambda item: (
            tuple(
                item[
                    "detection"
                ][
                    "contributing_event_ids"
                ]
            ),
            json.dumps(
                item[
                    "script_block"
                ],
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    )

    unique_event_ids = sorted(
        {
            reference[
                "event_id"
            ]
            for match in matches
            for reference in match[
                "raw_references"
            ]
        }
    )

    return {
        "source_id": (
            POWERSHELL_SOURCE_ID
        ),
        "raw_relative_path": (
            source[
                "relative_path"
            ]
        ),
        "raw_sha256": (
            source[
                "raw_sha256"
            ]
        ),
        "parser": (
            "load_powershell_windows_event_xml"
        ),
        "accepted_records": len(
            accepted
        ),
        "quarantined_records": len(
            quarantined
        ),
        "reconstructed_scriptblocks": len(
            blocks
        ),
        "detection_id": (
            PREAUTH_DISCOVERY_DETECTION_ID
        ),
        "detection_version": (
            PREAUTH_DISCOVERY_DETECTION_VERSION
        ),
        "historical_aggregate_matches": (
            EXPECTED_DET003_MATCHES
        ),
        "reevaluated_matches": len(
            matches
        ),
        "matched_unique_parent_event_ids": (
            unique_event_ids
        ),
        "matches": matches,
    }


def evaluate_sysmon(
    *,
    source: dict[str, Any],
) -> dict[str, Any]:
    batch = (
        load_sysmon_windows_event_xml(
            source["path"],
            logical_source=(
                SYSMON_SOURCE_ID
            ),
        )
    )

    accepted = list(
        batch.accepted
    )

    quarantined = list(
        batch.quarantined
    )

    if len(
        accepted
    ) != EXPECTED_SYSMON_ACCEPTED:
        raise RuntimeError(
            "SYSMON_ACCEPTED_COUNT_MISMATCH:"
            + str(
                len(
                    accepted
                )
            )
        )

    if quarantined:
        raise RuntimeError(
            "SYSMON_QUARANTINE_NONZERO:"
            + str(
                len(
                    quarantined
                )
            )
        )

    matches = []

    for canonical in accepted:
        semantic = SemanticEvent.from_canonical(
            canonical
        )

        detection = (
            detect_sysmon_domain_firewall_zero_write(
                semantic
            )
        )

        if not detection.matched:
            continue

        detector = detection_summary(
            detection
        )

        if (
            detector.get(
                "detection_id"
            )
            != FIREWALL_DETECTION_ID
        ):
            raise RuntimeError(
                "DET005_ID_MISMATCH"
            )

        contributing_event_ids = detector[
            "contributing_event_ids"
        ]

        if len(
            contributing_event_ids
        ) != 1:
            raise RuntimeError(
                "DET005_EVIDENCE_CARDINALITY:"
                + str(
                    len(
                        contributing_event_ids
                    )
                )
            )

        if (
            contributing_event_ids[0]
            != str(
                canonical.event_id
            )
        ):
            raise RuntimeError(
                "DET005_EVENT_LINEAGE_MISMATCH"
            )

        reference = provenance_reference(
                        canonical_event=canonical,
                        source_path=source["path"],
                        expected_source_sha256=source['raw_sha256'],
                        expected_source_id=SYSMON_SOURCE_ID,
                    )

        semantic_summary = {
            "event_id": str(
                semantic.event_id
            ),
            "source_type": scalar(
                semantic.source_type
            ),
            "event_type": scalar(
                semantic.event_type
            ),
            "clock_state": scalar(
                semantic.clock_state
            ),
            "event_time_utc": (
                semantic.event_time_utc.isoformat()
                if semantic.event_time_utc
                is not None
                else None
            ),
            "host": (
                semantic.host
            ),
            "principal": (
                semantic.principal
            ),
        }

        relevant_fields = {}

        for key, value in sorted(
            semantic.fields.items()
        ):
            lower = str(
                key
            ).casefold()

            if any(
                token
                in lower
                for token in (
                    "registry",
                    "target",
                    "detail",
                )
            ):
                if isinstance(
                    value,
                    (
                        str,
                        int,
                        float,
                        bool,
                    ),
                ) or value is None:
                    relevant_fields[
                        str(
                            key
                        )
                    ] = value

        semantic_summary[
            "relevant_fields"
        ] = relevant_fields

        matches.append(
            {
                "detection": detector,
                "semantic_event": (
                    semantic_summary
                ),
                "raw_reference": (
                    reference
                ),
            }
        )

    if len(
        matches
    ) != EXPECTED_DET005_MATCHES:
        raise RuntimeError(
            "DET005_MATCH_COUNT_MISMATCH:"
            + str(
                len(
                    matches
                )
            )
        )

    matches.sort(
        key=lambda item: (
            tuple(
                sorted(
                    item[
                        "raw_reference"
                    ][
                        "locator"
                    ].items()
                )
            ),
            item[
                "raw_reference"
            ][
                "event_id"
            ],
        )
    )

    unique_event_ids = sorted(
        {
            item[
                "raw_reference"
            ][
                "event_id"
            ]
            for item in matches
        }
    )

    if len(
        unique_event_ids
    ) != EXPECTED_DET005_MATCHES:
        raise RuntimeError(
            "DET005_UNIQUE_EVENT_COUNT_MISMATCH"
        )

    return {
        "source_id": (
            SYSMON_SOURCE_ID
        ),
        "raw_relative_path": (
            source[
                "relative_path"
            ]
        ),
        "raw_sha256": (
            source[
                "raw_sha256"
            ]
        ),
        "parser": (
            "load_sysmon_windows_event_xml"
        ),
        "accepted_records": len(
            accepted
        ),
        "quarantined_records": len(
            quarantined
        ),
        "detection_id": (
            FIREWALL_DETECTION_ID
        ),
        "detection_version": (
            FIREWALL_DETECTION_VERSION
        ),
        "historical_aggregate_matches": (
            EXPECTED_DET005_MATCHES
        ),
        "reevaluated_matches": len(
            matches
        ),
        "matched_unique_event_ids": (
            unique_event_ids
        ),
        "matches": matches,
    }


def build_result(
    *,
    repo: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    repo = repo.resolve()
    evidence_root = (
        evidence_root.resolve()
    )

    powershell_source = (
        resolve_registered_source(
            repo=repo,
            evidence_root=evidence_root,
            source_id=(
                POWERSHELL_SOURCE_ID
            ),
        )
    )

    sysmon_source = (
        resolve_registered_source(
            repo=repo,
            evidence_root=evidence_root,
            source_id=(
                SYSMON_SOURCE_ID
            ),
        )
    )

    powershell = evaluate_powershell(
        source=powershell_source
    )

    sysmon = evaluate_sysmon(
        source=sysmon_source
    )

    implementation_paths = {
        "analytic_freeze_proof": (
            "project-control/"
            "phase4d3s-analytic-freeze-proof.json"
        ),
        "det003_rule": (
            "src/tracesoc/detection/"
            "powershell_reconstructed.py"
        ),
        "det005_rule": (
            "src/tracesoc/detection/"
            "sysmon_firewall.py"
        ),
        "powershell_parser": (
            "src/tracesoc/parsers/"
            "powershell.py"
        ),
        "sysmon_parser": (
            "src/tracesoc/parsers/"
            "sysmon.py"
        ),
        "powershell_reconstruction": (
            "src/tracesoc/normalization/"
            "powershell_scriptblock.py"
        ),
        "historical_det003_proof": (
            "project-control/"
            "phase4d3m-real-powershell-"
            "behavioral-detections-validation.json"
        ),
        "historical_det005_proof": (
            "project-control/"
            "phase4d3o-sysmon-firewall-"
            "configuration-detection-validation.json"
        ),
    }

    identities = {}

    for name, relative in (
        implementation_paths.items()
    ):
        path = (
            repo
            / relative
        )

        if not path.is_file():
            raise RuntimeError(
                "IMPLEMENTATION_ARTIFACT_MISSING:"
                + relative
            )

        identities[
            name
        ] = {
            "path": relative,
            "sha256": sha256_file(
                path
            ),
        }

    return {
        "record_type": (
            "tracesoc-real-event-level-"
            "release-evidence-v1"
        ),
        "schema_version": 1,
        "execution_mode": (
            "FROZEN_REAL_ANALYTIC_REEVALUATION"
        ),
        "raw_access": {
            "registered_artifacts": 2,
            "access_mode": "READ_ONLY",
            "raw_mutation": False,
            "holdout_access": False,
        },
        "historical_proofs": {
            "preserved_unchanged": True,
            "role": (
                "AGGREGATE_HISTORICAL_VALIDATION"
            ),
        },
        "science_boundary": {
            "new_detector_logic": False,
            "detector_tuning": False,
            "correlation_executed": False,
            "unrelated_real_corpora_joined": False,
            "malicious_intent_established": False,
        },
        "implementation_identities": (
            identities
        ),
        "release_paths": [
            powershell,
            sysmon,
        ],
        "continuity": {
            "TRC-DET-003": {
                "historical_matches": 5,
                "reevaluated_matches": (
                    powershell[
                        "reevaluated_matches"
                    ]
                ),
                "match_count_reproduced": True,
            },
            "TRC-DET-005": {
                "historical_matches": 2,
                "reevaluated_matches": (
                    sysmon[
                        "reevaluated_matches"
                    ]
                ),
                "match_count_reproduced": True,
            },
        },
        "result": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Re-evaluate exactly two registered "
            "TraceSOC real development sources "
            "under frozen DET003/DET005 analytics "
            "and persist matched event-level lineage."
        )
    )

    parser.add_argument(
        "--repo",
        required=True,
    )

    parser.add_argument(
        "--evidence-root",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    args = parser.parse_args()

    repo = Path(
        args.repo
    )

    evidence_root = Path(
        args.evidence_root
    )

    output = Path(
        args.output
    )

    if output.exists():
        raise RuntimeError(
            "OUTPUT_ALREADY_EXISTS:"
            + str(
                output
            )
        )

    result = build_result(
        repo=repo,
        evidence_root=evidence_root,
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "xb"
    ) as handle:
        handle.write(
            canonical_json_bytes(
                result
            )
        )

    result_sha256 = sha256_file(
        output
    )

    powershell = result[
        "release_paths"
    ][0]

    sysmon = result[
        "release_paths"
    ][1]

    print(
        "RESULT=PASS"
    )

    print(
        "REGISTERED_REAL_SOURCES=2"
    )

    print(
        "DET003_MATCHES="
        + str(
            powershell[
                "reevaluated_matches"
            ]
        )
    )

    print(
        "DET005_MATCHES="
        + str(
            sysmon[
                "reevaluated_matches"
            ]
        )
    )

    print(
        "DET003_UNIQUE_PARENT_EVENT_IDS="
        + str(
            len(
                powershell[
                    "matched_unique_parent_event_ids"
                ]
            )
        )
    )

    print(
        "DET005_UNIQUE_EVENT_IDS="
        + str(
            len(
                sysmon[
                    "matched_unique_event_ids"
                ]
            )
        )
    )

    print(
        "RAW_LOCATOR_HASH_LINEAGE=PASS"
    )

    print(
        "RAW_MUTATION=FALSE"
    )

    print(
        "HOLDOUT_ACCESS=FALSE"
    )

    print(
        "RESULT_SHA256="
        + result_sha256
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
