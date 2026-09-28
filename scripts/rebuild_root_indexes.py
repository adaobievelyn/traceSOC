from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
from typing import Any, Iterable


EVIDENCE_INDEX_HEADER = [
    "evidence_id",
    "claim_id",
    "phase",
    "record_type",
    "source_id",
    "report_section",
    "claim",
    "observed_fact",
    "inference",
    "artifact_path",
    "exact_locator",
    "collection_time_utc",
    "sha256",
    "parent_evidence_ids",
    "detection_ids",
    "correlation_ids",
    "finding_ids",
    "evidence_state",
    "status",
    "proves",
    "does_not_prove",
    "confidence",
    "alternative_considered",
    "residual_uncertainty",
    "disposition",
    "proof_path",
]

IOC_SET_HEADER = [
    "ioc_id",
    "type",
    "value",
    "first_seen_utc",
    "last_seen_utc",
    "host_or_context",
    "artifact_path",
    "exact_locator",
    "confidence",
    "handling",
    "expiry_or_review_date",
    "false_positive_risk",
]

TIMELINE_HEADER = [
    "event_id",
    "utc_time",
    "original_time",
    "source_timezone",
    "host",
    "user",
    "activity",
    "artifact_path",
    "exact_locator",
    "attack_technique",
    "confidence",
    "primary_or_supporting",
    "alternative_interpretation",
    "notes",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(
        path.read_text(
            encoding="utf-8",
        )
    )


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        return [
            dict(row)
            for row in csv.DictReader(handle)
        ]


def csv_bytes(
    header: list[str],
    rows: Iterable[dict[str, Any]],
) -> bytes:
    buffer = io.StringIO(
        newline="",
    )

    writer = csv.DictWriter(
        buffer,
        fieldnames=header,
        extrasaction="raise",
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )

    writer.writeheader()

    for row in rows:
        normalized = {}

        for field in header:
            value = row.get(
                field,
                "",
            )

            if value is None:
                value = ""

            if isinstance(
                value,
                bool,
            ):
                value = (
                    "true"
                    if value
                    else "false"
                )

            elif not isinstance(
                value,
                str,
            ):
                value = str(value)

            normalized[
                field
            ] = value

        writer.writerow(
            normalized
        )

    return buffer.getvalue().encode(
        "utf-8"
    )


def atomic_write(
    path: Path,
    data: bytes,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_name(
        path.name + ".tmp"
    )

    with temporary.open(
        "wb"
    ) as handle:
        handle.write(
            data
        )

    os.replace(
        temporary,
        path,
    )


def unique_join(
    values: Iterable[str],
) -> str:
    cleaned = sorted(
        {
            str(value).strip()
            for value in values
            if str(value).strip()
        }
    )

    return "|".join(
        cleaned
    )


def split_ids(
    value: str,
) -> list[str]:
    if not value:
        return []

    normalized = value.replace(
        ";",
        "|",
    )

    return [
        item.strip()
        for item in normalized.split("|")
        if item.strip()
    ]


def detector_boundary(
    rationale: str,
) -> tuple[str, str]:
    text = (
        rationale
        or ""
    ).strip()

    if not text:
        return (
            "",
            "",
        )

    markers = (
        " but does not establish ",
        "; it does not establish ",
    )

    lower = text.casefold()

    for marker in markers:
        index = lower.find(
            marker.casefold()
        )

        if index < 0:
            continue

        positive = text[
            :index
        ].strip()

        negative = text[
            index
            + len(marker):
        ].strip()

        if negative:
            negative = (
                "Does not establish "
                + negative
            )

        return (
            positive,
            negative,
        )

    return (
        text,
        "",
    )


def raw_references(
    match: dict[str, Any],
) -> list[dict[str, Any]]:
    if "raw_references" in match:
        references = match[
            "raw_references"
        ]

        if not isinstance(
            references,
            list,
        ):
            raise ValueError(
                "raw_references must be a list"
            )

        return [
            dict(item)
            for item in references
        ]

    if "raw_reference" in match:
        reference = match[
            "raw_reference"
        ]

        if not isinstance(
            reference,
            dict,
        ):
            raise ValueError(
                "raw_reference must be an object"
            )

        return [
            dict(reference)
        ]

    raise ValueError(
        "match has no raw reference"
    )


def locator_text(
    locator: dict[str, Any],
) -> str:
    preferred = [
        "record_index",
        "record_number",
        "line_number",
        "byte_offset",
        "byte_length",
        "record_id",
        "source_record_id",
    ]

    keys = []

    for key in preferred:
        if (
            key in locator
            and locator[
                key
            ] is not None
        ):
            keys.append(
                key
            )

    for key in sorted(
        locator
    ):
        if (
            key not in keys
            and locator[
                key
            ] is not None
        ):
            keys.append(
                key
            )

    return ";".join(
        (
            str(key)
            + "="
            + str(
                locator[
                    key
                ]
            )
        )
        for key in keys
    )


def first_context_value(
    match: dict[str, Any],
    keys: tuple[str, ...],
) -> str:
    containers = [
        match.get(
            "semantic_event"
        ),
        match.get(
            "semantic_summary"
        ),
        match.get(
            "script_block"
        ),
        match.get(
            "canonical_event"
        ),
        match,
    ]

    for container in containers:
        if not isinstance(
            container,
            dict,
        ):
            continue

        for key in keys:
            value = container.get(
                key
            )

            if value is None:
                continue

            rendered = str(
                value
            ).strip()

            if rendered:
                return rendered

    return ""


def proof_phase(
    repo: Path,
    relative: str,
) -> str:
    if not relative:
        return ""

    candidate = (
        repo
        / relative
    )

    try:
        resolved = candidate.resolve()
        root = repo.resolve()

        if (
            resolved != root
            and root not in resolved.parents
        ):
            return ""

        if not resolved.is_file():
            return ""

        payload = read_json(
            resolved
        )

        if not isinstance(
            payload,
            dict,
        ):
            return ""

        phase = payload.get(
            "phase"
        )

        if isinstance(
            phase,
            str,
        ):
            return phase

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ):
        return ""

    return ""


def build_release_event_map(
    release: dict[str, Any],
) -> dict[str, dict[str, str]]:
    result: dict[
        str,
        dict[str, str],
    ] = {}

    paths = release.get(
        "release_paths",
        [],
    )

    if not isinstance(
        paths,
        list,
    ):
        raise ValueError(
            "release_paths must be a list"
        )

    for release_path in paths:
        if not isinstance(
            release_path,
            dict,
        ):
            raise ValueError(
                "release path must be an object"
            )

        detector_id = str(
            release_path.get(
                "detection_id",
                "",
            )
        )

        source_id = str(
            release_path.get(
                "source_id",
                "",
            )
        )

        for match in release_path.get(
            "matches",
            [],
        ):
            if not isinstance(
                match,
                dict,
            ):
                raise ValueError(
                    "release match must be an object"
                )

            for reference in raw_references(
                match
            ):
                event_id = str(
                    reference.get(
                        "event_id",
                        "",
                    )
                ).strip()

                if not event_id:
                    raise ValueError(
                        "release raw reference lacks event_id"
                    )

                existing = result.get(
                    event_id
                )

                current = {
                    "source_id": source_id,
                    "detection_id": detector_id,
                }

                if (
                    existing is not None
                    and existing != current
                ):
                    raise ValueError(
                        "event_id maps to inconsistent release context: "
                        + event_id
                    )

                result[
                    event_id
                ] = current

    return result


def build_evidence_rows(
    repo: Path,
    acquisition_rows: list[dict[str, str]],
    claim_rows: list[dict[str, str]],
    release: dict[str, Any],
    release_sha256: str,
    release_proof: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[
        dict[str, Any]
    ] = []

    for row in acquisition_rows:
        source_id = (
            row.get(
                "source_id",
                "",
            )
            or ""
        ).strip()

        if not source_id:
            raise ValueError(
                "acquisition row lacks source_id"
            )

        integrity_status = (
            row.get(
                "integrity_status",
                "",
            )
            or ""
        ).strip()

        status = (
            row.get(
                "status",
                "",
            )
            or ""
        ).strip()

        filename = (
            row.get(
                "original_filename",
                "",
            )
            or ""
        ).strip()

        byte_size = (
            row.get(
                "byte_size",
                "",
            )
            or ""
        ).strip()

        artifact_sha = (
            row.get(
                "sha256",
                "",
            )
            or ""
        ).strip().casefold()

        title = (
            row.get(
                "source_title",
                "",
            )
            or filename
            or source_id
        ).strip()

        observed = (
            "Registered evidence artifact "
            + filename
            + " with byte_size="
            + byte_size
            + " and SHA-256="
            + artifact_sha
            + "."
        )

        proves = (
            "The acquisition register records this artifact identity, "
            "location, size, SHA-256, role, and integrity disposition."
        )

        limitations = (
            row.get(
                "known_limitations",
                "",
            )
            or ""
        ).strip()

        rows.append(
            {
                "evidence_id": source_id,
                "claim_id": "",
                "phase": "",
                "record_type": "RAW_ARTIFACT",
                "source_id": source_id,
                "report_section": "Evidence inventory",
                "claim": title,
                "observed_fact": observed,
                "inference": "NOT_APPLICABLE",
                "artifact_path": (
                    row.get(
                        "storage_path",
                        "",
                    )
                    or ""
                ).strip(),
                "exact_locator": "WHOLE_ARTIFACT",
                "collection_time_utc": (
                    row.get(
                        "acquired_utc",
                        "",
                    )
                    or ""
                ).strip(),
                "sha256": artifact_sha,
                "parent_evidence_ids": "",
                "detection_ids": "",
                "correlation_ids": "",
                "finding_ids": "",
                "evidence_state": "OBSERVED",
                "status": (
                    status
                    or integrity_status
                ),
                "proves": proves,
                "does_not_prove": limitations,
                "confidence": "",
                "alternative_considered": "",
                "residual_uncertainty": limitations,
                "disposition": (
                    row.get(
                        "role",
                        "",
                    )
                    or ""
                ).strip(),
                "proof_path": (
                    "project-control/"
                    "evidence-acquisition-register.csv"
                ),
            }
        )

    release_phase = str(
        release_proof.get(
            "phase",
            "",
        )
        or ""
    )

    release_paths = release.get(
        "release_paths"
    )

    if not isinstance(
        release_paths,
        list,
    ):
        raise ValueError(
            "release_paths must be a list"
        )

    for index, release_path in enumerate(
        release_paths
    ):
        if not isinstance(
            release_path,
            dict,
        ):
            raise ValueError(
                "release path must be an object"
            )

        detector_id = str(
            release_path.get(
                "detection_id",
                "",
            )
        ).strip()

        source_id = str(
            release_path.get(
                "source_id",
                "",
            )
        ).strip()

        matches = release_path.get(
            "matches"
        )

        if (
            not detector_id
            or not source_id
            or not isinstance(
                matches,
                list,
            )
            or not matches
        ):
            raise ValueError(
                "release path contract incomplete"
            )

        titles = set()
        rationales = set()
        reason_codes = set()
        event_ids = []

        for match in matches:
            if not isinstance(
                match,
                dict,
            ):
                raise ValueError(
                    "release match must be an object"
                )

            detection = match.get(
                "detection"
            )

            if not isinstance(
                detection,
                dict,
            ):
                raise ValueError(
                    "release detection missing"
                )

            title = str(
                detection.get(
                    "title",
                    "",
                )
            ).strip()

            rationale = str(
                detection.get(
                    "rationale",
                    "",
                )
            ).strip()

            reason_code = str(
                detection.get(
                    "reason_code",
                    "",
                )
            ).strip()

            if title:
                titles.add(
                    title
                )

            if rationale:
                rationales.add(
                    rationale
                )

            if reason_code:
                reason_codes.add(
                    reason_code
                )

            ids = detection.get(
                "contributing_event_ids"
            )

            if (
                not isinstance(
                    ids,
                    list,
                )
                or not ids
            ):
                raise ValueError(
                    detector_id
                    + " lacks contributing_event_ids"
                )

            event_ids.extend(
                str(item)
                for item in ids
            )

            for reference in raw_references(
                match
            ):
                if (
                    reference.get(
                        "record_sha256_verified"
                    )
                    is not True
                ):
                    raise ValueError(
                        detector_id
                        + " has unverified record hash"
                    )

                if (
                    reference.get(
                        "registered_artifact_sha256_verified"
                    )
                    is not True
                ):
                    raise ValueError(
                        detector_id
                        + " has unverified artifact hash"
                    )

        if len(titles) != 1:
            raise ValueError(
                detector_id
                + " title is not unique"
            )

        if len(rationales) != 1:
            raise ValueError(
                detector_id
                + " rationale is not unique"
            )

        title = next(
            iter(
                titles
            )
        )

        rationale = next(
            iter(
                rationales
            )
        )

        observed, boundary = (
            detector_boundary(
                rationale
            )
        )

        rows.append(
            {
                "evidence_id": (
                    "RELEASE::"
                    + detector_id
                ),
                "claim_id": "",
                "phase": release_phase,
                "record_type": (
                    "REAL_DETECTION_RELEASE_EVIDENCE"
                ),
                "source_id": source_id,
                "report_section": (
                    "Detection release evidence"
                ),
                "claim": title,
                "observed_fact": observed,
                "inference": "NOT_APPLICABLE",
                "artifact_path": (
                    "results/release/"
                    "real-event-level-release-evidence.json"
                ),
                "exact_locator": (
                    "/release_paths/"
                    + str(index)
                ),
                "collection_time_utc": str(
                    release.get(
                        "generated_utc",
                        "",
                    )
                    or ""
                ),
                "sha256": release_sha256,
                "parent_evidence_ids": unique_join(
                    event_ids
                ),
                "detection_ids": detector_id,
                "correlation_ids": "",
                "finding_ids": "",
                "evidence_state": "OBSERVED",
                "status": "PASS",
                "proves": observed,
                "does_not_prove": boundary,
                "confidence": "",
                "alternative_considered": "",
                "residual_uncertainty": boundary,
                "disposition": (
                    "RETAINED_REAL_RELEASE_EVIDENCE"
                ),
                "proof_path": (
                    "project-control/"
                    "phase4h-real-event-level-"
                    "release-evidence-validation.json"
                ),
            }
        )

    event_map = build_release_event_map(
        release
    )

    acquisition_by_source = {}

    for acquisition_row in acquisition_rows:
        acquisition_source_id = (
            acquisition_row.get(
                "source_id",
                "",
            )
            or ""
        ).strip()

        if not acquisition_source_id:
            raise ValueError(
                "acquisition row lacks source_id"
            )

        if (
            acquisition_source_id
            in acquisition_by_source
        ):
            raise ValueError(
                "duplicate acquisition source_id: "
                + acquisition_source_id
            )

        acquisition_by_source[
            acquisition_source_id
        ] = acquisition_row

    timeline_by_event = {}

    for timeline_row in build_timeline_rows(
        acquisition_rows=acquisition_rows,
        release=release,
    ):
        timeline_event_id = (
            timeline_row.get(
                "event_id",
                "",
            )
            or ""
        ).strip()

        if not timeline_event_id:
            raise ValueError(
                "timeline row lacks event_id"
            )

        if timeline_event_id in timeline_by_event:
            raise ValueError(
                "duplicate timeline event_id: "
                + timeline_event_id
            )

        timeline_by_event[
            timeline_event_id
        ] = timeline_row

    claim_register_path = (
        repo
        / "project-control"
        / "claim-register.csv"
    )

    claim_register_sha = sha256_file(
        claim_register_path
    )

    for claim in claim_rows:
        claim_id = (
            claim.get(
                "claim_id",
                "",
            )
            or ""
        ).strip()

        if not claim_id:
            raise ValueError(
                "claim row lacks claim_id"
            )

        evidence_ids = split_ids(
            (
                claim.get(
                    "evidence_ids",
                    "",
                )
                or ""
            )
        )

        mapped_sources = []
        mapped_detections = []

        for event_id in evidence_ids:
            context = event_map.get(
                event_id
            )

            if context is None:
                continue

            mapped_sources.append(
                context[
                    "source_id"
                ]
            )

            mapped_detections.append(
                context[
                    "detection_id"
                ]
            )

        proof_path = (
            claim.get(
                "proof_path",
                "",
            )
            or ""
        ).strip()

        alternative = (
            claim.get(
                "alternative",
                "",
            )
            or ""
        ).strip()

        residual = (
            claim.get(
                "residual_risk",
                "",
            )
            or ""
        ).strip()

        boundary = " | ".join(
            item
            for item in (
                alternative,
                residual,
            )
            if item
        )

        all_events_mapped = (
            bool(evidence_ids)
            and all(
                event_id in event_map
                for event_id in evidence_ids
            )
        )

        unique_sources = sorted(
            set(mapped_sources)
        )

        collection_time_utc = ""

        if (
            all_events_mapped
            and len(unique_sources) == 1
        ):
            acquisition_row = (
                acquisition_by_source.get(
                    unique_sources[0]
                )
            )

            if acquisition_row is not None:
                collection_time_utc = (
                    acquisition_row.get(
                        "acquired_utc",
                        "",
                    )
                    or ""
                ).strip()

        claim_timeline_rows = [
            timeline_by_event.get(
                event_id
            )
            for event_id in evidence_ids
        ]

        claim_state = (
            claim.get(
                "state",
                "",
            )
            or ""
        ).strip()

        claim_status = (
            claim.get(
                "status",
                "",
            )
            or ""
        ).strip()

        confidence = ""

        if (
            claim_state == "OBSERVED"
            and claim_status == "FINAL"
            and evidence_ids
            and all(
                timeline_row is not None
                for timeline_row in claim_timeline_rows
            )
            and {
                (
                    timeline_row.get(
                        "confidence",
                        "",
                    )
                    or ""
                ).strip()
                for timeline_row in claim_timeline_rows
                if timeline_row is not None
            }
            == {"high"}
        ):
            confidence = "high"

        rows.append(
            {
                "evidence_id": (
                    "CLAIM::"
                    + claim_id
                ),
                "claim_id": claim_id,
                "phase": proof_phase(
                    repo,
                    proof_path,
                ),
                "record_type": "MATERIAL_CLAIM",
                "source_id": unique_join(
                    mapped_sources
                ),
                "report_section": "Material claims",
                "claim": (
                    claim.get(
                        "title",
                        "",
                    )
                    or ""
                ).strip(),
                "observed_fact": (
                    claim.get(
                        "observed_fact",
                        "",
                    )
                    or ""
                ).strip(),
                "inference": (
                    claim.get(
                        "inference",
                        "",
                    )
                    or ""
                ).strip(),
                "artifact_path": (
                    "project-control/"
                    "claim-register.csv"
                ),
                "exact_locator": (
                    "claim_id="
                    + claim_id
                ),
                "collection_time_utc": collection_time_utc,
                "sha256": claim_register_sha,
                "parent_evidence_ids": unique_join(
                    evidence_ids
                ),
                "detection_ids": unique_join(
                    mapped_detections
                ),
                "correlation_ids": "",
                "finding_ids": "",
                "evidence_state": (
                    claim.get(
                        "state",
                        "",
                    )
                    or ""
                ).strip(),
                "status": (
                    claim.get(
                        "status",
                        "",
                    )
                    or ""
                ).strip(),
                "proves": (
                    claim.get(
                        "observed_fact",
                        "",
                    )
                    or ""
                ).strip(),
                "does_not_prove": boundary,
                "confidence": confidence,
                "alternative_considered": alternative,
                "residual_uncertainty": residual,
                "disposition": (
                    claim.get(
                        "decision_required",
                        "",
                    )
                    or ""
                ).strip(),
                "proof_path": proof_path,
            }
        )

    rows.sort(
        key=lambda item: (
            str(
                item[
                    "record_type"
                ]
            ),
            str(
                item[
                    "evidence_id"
                ]
            ),
        )
    )

    identifiers = [
        str(
            row[
                "evidence_id"
            ]
        )
        for row in rows
    ]

    if len(
        identifiers
    ) != len(
        set(
            identifiers
        )
    ):
        raise ValueError(
            "duplicate evidence_id"
        )

    return rows


def structured_ioc_rows(
    repo: Path,
) -> list[dict[str, Any]]:
    directory = (
        repo
        / "results"
        / "iocs"
    )

    if not directory.is_dir():
        return []

    rows: list[
        dict[str, Any]
    ] = []

    for path in sorted(
        directory.glob(
            "*.json"
        )
    ):
        payload = read_json(
            path
        )

        if isinstance(
            payload,
            dict,
        ):
            indicators = payload.get(
                "indicators"
            )

        else:
            indicators = payload

        if not isinstance(
            indicators,
            list,
        ):
            raise ValueError(
                "IOC file must contain a list or indicators list: "
                + str(
                    path
                )
            )

        relative = path.relative_to(
            repo
        ).as_posix()

        for index, item in enumerate(
            indicators
        ):
            if not isinstance(
                item,
                dict,
            ):
                raise ValueError(
                    "IOC item must be an object"
                )

            indicator_type = str(
                item.get(
                    "type",
                    "",
                )
            ).strip()

            value = str(
                item.get(
                    "value",
                    "",
                )
            ).strip()

            context = str(
                item.get(
                    "host_or_context",
                    "",
                )
            ).strip()

            if (
                not indicator_type
                or not value
            ):
                raise ValueError(
                    "IOC requires non-empty type and value"
                )

            ioc_id = str(
                item.get(
                    "ioc_id",
                    "",
                )
            ).strip()

            if not ioc_id:
                digest = hashlib.sha256(
                    (
                        indicator_type
                        + "\0"
                        + value
                        + "\0"
                        + context
                    ).encode(
                        "utf-8"
                    )
                ).hexdigest()

                ioc_id = (
                    "IOC-"
                    + digest[
                        :12
                    ].upper()
                )

            row = {}

            for field in IOC_SET_HEADER:
                row[
                    field
                ] = (
                    item.get(
                        field,
                        "",
                    )
                    or ""
                )

            row[
                "ioc_id"
            ] = ioc_id

            row[
                "type"
            ] = indicator_type

            row[
                "value"
            ] = value

            if not str(
                row[
                    "artifact_path"
                ]
            ).strip():
                row[
                    "artifact_path"
                ] = relative

            if not str(
                row[
                    "exact_locator"
                ]
            ).strip():
                row[
                    "exact_locator"
                ] = (
                    "/indicators/"
                    + str(index)
                )

            rows.append(
                row
            )

    rows.sort(
        key=lambda item: (
            str(
                item[
                    "type"
                ]
            ),
            str(
                item[
                    "value"
                ]
            ),
            str(
                item[
                    "host_or_context"
                ]
            ),
            str(
                item[
                    "ioc_id"
                ]
            ),
        )
    )

    ids = [
        str(
            row[
                "ioc_id"
            ]
        )
        for row in rows
    ]

    if len(
        ids
    ) != len(
        set(
            ids
        )
    ):
        raise ValueError(
            "duplicate ioc_id"
        )

    return rows


def build_timeline_rows(
    acquisition_rows: list[dict[str, str]],
    release: dict[str, Any],
) -> list[dict[str, Any]]:
    acquisition_by_id = {
        (
            row.get(
                "source_id",
                ""
            )
            or ""
        ).strip(): row
        for row in acquisition_rows
    }

    rows: list[
        dict[str, Any]
    ] = []

    paths = release.get(
        "release_paths"
    )

    if not isinstance(
        paths,
        list,
    ):
        raise ValueError(
            "release_paths must be a list"
        )

    seen_events = set()

    for release_path in paths:
        if not isinstance(
            release_path,
            dict,
        ):
            raise ValueError(
                "release path must be an object"
            )

        detector_id = str(
            release_path.get(
                "detection_id",
                "",
            )
        ).strip()

        source_id = str(
            release_path.get(
                "source_id",
                "",
            )
        ).strip()

        acquisition = acquisition_by_id.get(
            source_id
        )

        if acquisition is None:
            raise ValueError(
                "release source missing from acquisition register: "
                + source_id
            )

        raw_artifact_path = (
            acquisition.get(
                "storage_path",
                "",
            )
            or ""
        ).strip()

        for match in release_path.get(
            "matches",
            []
        ):
            if not isinstance(
                match,
                dict,
            ):
                raise ValueError(
                    "release match must be an object"
                )

            detection = match.get(
                "detection"
            )

            if not isinstance(
                detection,
                dict,
            ):
                raise ValueError(
                    "release match lacks detection"
                )

            title = str(
                detection.get(
                    "title",
                    "",
                )
            ).strip()

            rationale = str(
                detection.get(
                    "rationale",
                    "",
                )
            ).strip()

            reason_code = str(
                detection.get(
                    "reason_code",
                    "",
                )
            ).strip()

            _, alternative = (
                detector_boundary(
                    rationale
                )
            )

            utc_time = first_context_value(
                match,
                (
                    "event_time_utc",
                    "first_event_time_utc",
                    "start_time_utc",
                    "first_seen_utc",
                ),
            )

            original_time = first_context_value(
                match,
                (
                    "event_time_raw",
                    "original_time",
                ),
            )

            host = first_context_value(
                match,
                (
                    "host",
                    "hostname",
                    "computer",
                ),
            )

            user = first_context_value(
                match,
                (
                    "principal",
                    "user",
                    "username",
                ),
            )

            for reference in raw_references(
                match
            ):
                event_id = str(
                    reference.get(
                        "event_id",
                        "",
                    )
                ).strip()

                if not event_id:
                    raise ValueError(
                        "timeline reference lacks event_id"
                    )

                if event_id in seen_events:
                    raise ValueError(
                        "duplicate release timeline event_id: "
                        + event_id
                    )

                seen_events.add(
                    event_id
                )

                locator = reference.get(
                    "locator"
                )

                if not isinstance(
                    locator,
                    dict,
                ):
                    raise ValueError(
                        "timeline reference lacks locator"
                    )

                verified = (
                    reference.get(
                        "record_sha256_verified"
                    )
                    is True
                    and
                    reference.get(
                        "registered_artifact_sha256_verified"
                    )
                    is True
                )

                confidence = (
                    "high"
                    if verified
                    else ""
                )

                notes_parts = [
                    "source_id="
                    + source_id,
                    "detection_id="
                    + detector_id,
                ]

                if not utc_time:
                    notes_parts.append(
                        "utc_time=NOT_ESTABLISHED_FROM_RELEASE_EVIDENCE"
                    )

                if not original_time:
                    notes_parts.append(
                        "original_time=NOT_ESTABLISHED_FROM_RELEASE_EVIDENCE"
                    )

                if not host:
                    notes_parts.append(
                        "host=UNKNOWN_FROM_RELEASE_EVIDENCE"
                    )

                if not user:
                    notes_parts.append(
                        "user=UNKNOWN_FROM_RELEASE_EVIDENCE"
                    )

                notes_parts.append(
                    "attack_technique=NOT_ESTABLISHED_FROM_RELEASE_EVIDENCE"
                )

                if reason_code:
                    notes_parts.append(
                        "reason_code="
                        + reason_code
                    )

                record_sha = str(
                    reference.get(
                        "record_raw_sha256",
                        "",
                    )
                ).strip()

                if record_sha:
                    notes_parts.append(
                        "record_sha256="
                        + record_sha
                    )

                notes_parts.append(
                    "confidence_scope=event_and_provenance_observation_not_malicious_intent"
                )

                rows.append(
                    {
                        "event_id": event_id,
                        "utc_time": utc_time,
                        "original_time": original_time,
                        "source_timezone": (
                            "UTC"
                            if utc_time
                            else ""
                        ),
                        "host": host,
                        "user": user,
                        "activity": (
                            detector_id
                            + ": "
                            + title
                        ),
                        "artifact_path": raw_artifact_path,
                        "exact_locator": locator_text(
                            locator
                        ),
                        "attack_technique": "",
                        "confidence": confidence,
                        "primary_or_supporting": "primary",
                        "alternative_interpretation": alternative,
                        "notes": "; ".join(
                            notes_parts
                        ),
                    }
                )

    rows.sort(
        key=lambda item: (
            0
            if str(
                item[
                    "utc_time"
                ]
            ).strip()
            else 1,
            str(
                item[
                    "utc_time"
                ]
            ),
            str(
                item[
                    "event_id"
                ]
            ),
        )
    )

    return rows


def build_outputs(
    repo: Path,
) -> dict[str, bytes]:
    repo = repo.resolve()

    acquisition_path = (
        repo
        / "project-control"
        / "evidence-acquisition-register.csv"
    )

    claim_path = (
        repo
        / "project-control"
        / "claim-register.csv"
    )

    release_path = (
        repo
        / "results"
        / "release"
        / "real-event-level-release-evidence.json"
    )

    release_proof_path = (
        repo
        / "project-control"
        / "phase4h-real-event-level-release-evidence-validation.json"
    )

    for path in (
        acquisition_path,
        claim_path,
        release_path,
        release_proof_path,
    ):
        if not path.is_file():
            raise FileNotFoundError(
                str(
                    path
                )
            )

    acquisition_rows = read_csv_rows(
        acquisition_path
    )

    claim_rows = read_csv_rows(
        claim_path
    )

    release = read_json(
        release_path
    )

    release_proof = read_json(
        release_proof_path
    )

    if not isinstance(
        release,
        dict,
    ):
        raise ValueError(
            "release evidence must be an object"
        )

    if not isinstance(
        release_proof,
        dict,
    ):
        raise ValueError(
            "release proof must be an object"
        )

    evidence_rows = build_evidence_rows(
        repo=repo,
        acquisition_rows=acquisition_rows,
        claim_rows=claim_rows,
        release=release,
        release_sha256=sha256_file(
            release_path
        ),
        release_proof=release_proof,
    )

    ioc_rows = structured_ioc_rows(
        repo
    )

    timeline_rows = build_timeline_rows(
        acquisition_rows=acquisition_rows,
        release=release,
    )

    return {
        "evidence-index.csv": csv_bytes(
            EVIDENCE_INDEX_HEADER,
            evidence_rows,
        ),
        "ioc-set.csv": csv_bytes(
            IOC_SET_HEADER,
            ioc_rows,
        ),
        "timeline.csv": csv_bytes(
            TIMELINE_HEADER,
            timeline_rows,
        ),
    }


def row_counts(
    outputs: dict[str, bytes],
) -> dict[str, int]:
    result = {}

    for name, data in outputs.items():
        text = data.decode(
            "utf-8"
        )

        rows = list(
            csv.reader(
                io.StringIO(
                    text
                )
            )
        )

        result[
            name
        ] = max(
            0,
            len(
                rows
            )
            - 1,
        )

    return result



def validate_visibility_policy(
    outputs: dict[str, bytes],
) -> None:
    def rows_for(
        name: str,
    ) -> list[dict[str, str]]:
        text = outputs[
            name
        ].decode(
            "utf-8"
        )

        return list(
            csv.DictReader(
                io.StringIO(
                    text
                )
            )
        )

    evidence = rows_for(
        "evidence-index.csv"
    )

    iocs = rows_for(
        "ioc-set.csv"
    )

    timeline = rows_for(
        "timeline.csv"
    )

    generic_required = (
        "evidence_id",
        "record_type",
        "source_id",
        "claim",
        "observed_fact",
        "artifact_path",
        "exact_locator",
        "sha256",
        "status",
        "proves",
        "disposition",
        "proof_path",
    )

    for row in evidence:
        for field in generic_required:
            if not row[
                field
            ].strip():
                raise ValueError(
                    "ambiguous blank evidence-index field: "
                    + row[
                        "evidence_id"
                    ]
                    + ":"
                    + field
                )

        record_type = row[
            "record_type"
        ]

        if record_type == "RAW_ARTIFACT":
            if row[
                "evidence_state"
            ] != "OBSERVED":
                raise ValueError(
                    "raw artifact evidence_state must be OBSERVED: "
                    + row[
                        "evidence_id"
                    ]
                )

            if row[
                "inference"
            ] != "NOT_APPLICABLE":
                raise ValueError(
                    "raw artifact inference must be NOT_APPLICABLE: "
                    + row[
                        "evidence_id"
                    ]
                )

        elif (
            record_type
            == "REAL_DETECTION_RELEASE_EVIDENCE"
        ):
            if row[
                "evidence_state"
            ] != "OBSERVED":
                raise ValueError(
                    "release evidence_state must be OBSERVED: "
                    + row[
                        "evidence_id"
                    ]
                )

            if row[
                "inference"
            ] != "NOT_APPLICABLE":
                raise ValueError(
                    "release inference must be NOT_APPLICABLE: "
                    + row[
                        "evidence_id"
                    ]
                )

            for field in (
                "parent_evidence_ids",
                "detection_ids",
                "does_not_prove",
                "residual_uncertainty",
            ):
                if not row[
                    field
                ].strip():
                    raise ValueError(
                        "release row has ambiguous blank: "
                        + row[
                            "evidence_id"
                        ]
                        + ":"
                        + field
                    )

        elif record_type == "MATERIAL_CLAIM":
            for field in (
                "claim_id",
                "observed_fact",
                "inference",
                "evidence_state",
                "status",
                "alternative_considered",
                "residual_uncertainty",
            ):
                if not row[
                    field
                ].strip():
                    raise ValueError(
                        "material claim has ambiguous blank: "
                        + row[
                            "evidence_id"
                        ]
                        + ":"
                        + field
                    )

    for row in iocs:
        for field in (
            "ioc_id",
            "type",
            "value",
        ):
            if not row[
                field
            ].strip():
                raise ValueError(
                    "IOC row has ambiguous blank: "
                    + field
                )

    for row in timeline:
        for field in (
            "event_id",
            "activity",
            "artifact_path",
            "exact_locator",
            "confidence",
            "primary_or_supporting",
            "alternative_interpretation",
            "notes",
        ):
            if not row[
                field
            ].strip():
                raise ValueError(
                    "timeline row has ambiguous required blank: "
                    + row[
                        "event_id"
                    ]
                    + ":"
                    + field
                )

        notes = row[
            "notes"
        ]

        if not row[
            "utc_time"
        ].strip():
            if row[
                "source_timezone"
            ].strip():
                raise ValueError(
                    "timezone present without established UTC time: "
                    + row[
                        "event_id"
                    ]
                )

            if (
                "utc_time=NOT_ESTABLISHED_FROM_RELEASE_EVIDENCE"
                not in notes
            ):
                raise ValueError(
                    "blank utc_time lacks explicit explanation: "
                    + row[
                        "event_id"
                    ]
                )

        if not row[
            "original_time"
        ].strip():
            if (
                "original_time=NOT_ESTABLISHED_FROM_RELEASE_EVIDENCE"
                not in notes
            ):
                raise ValueError(
                    "blank original_time lacks explicit explanation: "
                    + row[
                        "event_id"
                    ]
                )

        if not row[
            "host"
        ].strip():
            if (
                "host=UNKNOWN_FROM_RELEASE_EVIDENCE"
                not in notes
            ):
                raise ValueError(
                    "blank host lacks explicit explanation: "
                    + row[
                        "event_id"
                    ]
                )

        if not row[
            "user"
        ].strip():
            if (
                "user=UNKNOWN_FROM_RELEASE_EVIDENCE"
                not in notes
            ):
                raise ValueError(
                    "blank user lacks explicit explanation: "
                    + row[
                        "event_id"
                    ]
                )

        if not row[
            "attack_technique"
        ].strip():
            if (
                "attack_technique=NOT_ESTABLISHED_FROM_RELEASE_EVIDENCE"
                not in notes
            ):
                raise ValueError(
                    "blank attack_technique lacks explicit explanation: "
                    + row[
                        "event_id"
                    ]
                )

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild legacy TraceSOC engineering indexes into an explicit "
            "non-root output directory. Finalist repository-root submission "
            "artifacts are controlled by scripts/build_finalist_package.py."
        )
    )

    parser.add_argument(
        "--repo",
        required=True,
    )

    parser.add_argument(
        "--output-dir",
        required=True,
    )

    parser.add_argument(
        "--check",
        action="store_true",
    )

    args = parser.parse_args()

    repo = Path(
        args.repo
    ).resolve()

    output_dir = Path(
        args.output_dir
    ).resolve()

    if output_dir == repo:
        raise SystemExit(
            "REFUSING_FINALIST_ROOT_WRITE: "
            "repository-root submission indexes are controlled by "
            "scripts/build_finalist_package.py"
        )

    outputs = build_outputs(
        repo
    )

    validate_visibility_policy(
        outputs
    )

    counts = row_counts(
        outputs
    )

    for name in (
        "evidence-index.csv",
        "ioc-set.csv",
        "timeline.csv",
    ):
        data = outputs[
            name
        ]

        path = (
            output_dir
            / name
        )

        digest = hashlib.sha256(
            data
        ).hexdigest()

        if args.check:
            if not path.is_file():
                raise SystemExit(
                    "STALE_OR_MISSING:"
                    + str(
                        path
                    )
                )

            current = path.read_bytes()

            if current != data:
                raise SystemExit(
                    "STALE_ROOT_INDEX:"
                    + str(
                        path
                    )
                )

        else:
            atomic_write(
                path,
                data,
            )

        print(
            name.upper().replace(
                "-",
                "_"
            ).replace(
                ".",
                "_"
            )
            + "_ROWS="
            + str(
                counts[
                    name
                ]
            )
        )

        print(
            name.upper().replace(
                "-",
                "_"
            ).replace(
                ".",
                "_"
            )
            + "_SHA256="
            + digest
        )

    print(
        "ROOT_INDEX_MODE="
        + (
            "CHECK"
            if args.check
            else "WRITE"
        )
    )

    print(
        "RAW_EVIDENCE_OPENED=FALSE"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
