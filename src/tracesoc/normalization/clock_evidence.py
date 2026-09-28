from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import json
from typing import Iterable

from tracesoc.models import (
    CanonicalEvent,
    ClockState,
    SourceType,
)


CLOCK_EVIDENCE_IDENTITY_VERSION = 1

WINDOWS_SECURITY_WALL_TIME_FORMAT = (
    "%m/%d/%Y %I:%M:%S %p"
)

WINDOWS_SECURITY_SYSMON_PROCESS_METHOD = (
    "windows_security_sysmon_process_"
    "same_second_zero_offset_v1"
)

PROCESS_IDENTITY_DIMENSIONS = (
    "exact_host",
    "process_name_casefold",
    "numeric_process_id",
    "parent_process_casefold",
    "numeric_parent_process_id",
    "exact_principal",
)


class ClockEvidenceState(StrEnum):
    CORROBORATED = "corroborated"


class ClockEvidenceError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ClockEvidence:
    """
    Immutable derived temporal evidence for an unresolved parent event.

    The parent CanonicalEvent is not changed. In particular, this object
    does not change ClockState.UNRESOLVED and does not populate the
    parent's event_time_utc.

    The interval is corroborated UTC-coordinate evidence derived from an
    independently identified observed-UTC supporting event. It is not an
    observed timestamp from the unresolved source.
    """

    evidence_id: str
    state: ClockEvidenceState
    method: str

    target_event_id: str
    supporting_event_ids: tuple[str, ...]

    host: str
    target_event_time_raw: str

    utc_interval_start: datetime
    utc_interval_end_exclusive: datetime

    coordinate_offset_seconds: int
    resolution_seconds: int

    identity_dimensions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError(
                "evidence_id must not be empty"
            )

        if not self.method.strip():
            raise ValueError(
                "method must not be empty"
            )

        if not self.target_event_id.strip():
            raise ValueError(
                "target_event_id must not be empty"
            )

        if not self.supporting_event_ids:
            raise ValueError(
                "supporting_event_ids must not be empty"
            )

        normalized_support_ids = tuple(
            sorted(
                set(
                    self.supporting_event_ids
                )
            )
        )

        if self.supporting_event_ids != normalized_support_ids:
            raise ValueError(
                "supporting_event_ids must be unique and sorted"
            )

        if not self.host.strip():
            raise ValueError(
                "host must not be empty"
            )

        if not self.target_event_time_raw.strip():
            raise ValueError(
                "target_event_time_raw must not be empty"
            )

        for field_name, field_value in (
            (
                "utc_interval_start",
                self.utc_interval_start,
            ),
            (
                "utc_interval_end_exclusive",
                self.utc_interval_end_exclusive,
            ),
        ):
            if field_value.tzinfo is None:
                raise ValueError(
                    f"{field_name} must be timezone-aware"
                )

            if field_value.utcoffset() != timedelta(0):
                raise ValueError(
                    f"{field_name} must use UTC coordinates"
                )

        if self.utc_interval_end_exclusive <= self.utc_interval_start:
            raise ValueError(
                "clock-evidence interval must be positive"
            )

        if self.coordinate_offset_seconds != 0:
            raise ValueError(
                "this method only represents zero-offset evidence"
            )

        if self.resolution_seconds != 1:
            raise ValueError(
                "this method requires one-second source resolution"
            )

        if self.identity_dimensions != PROCESS_IDENTITY_DIMENSIONS:
            raise ValueError(
                "identity_dimensions do not match method contract"
            )


def _optional_text(
    value: object,
) -> str | None:
    if value is None:
        return None

    if not isinstance(
        value,
        str,
    ):
        return None

    candidate = value.strip()

    if not candidate:
        return None

    return candidate


def _numeric_pid(
    value: object,
) -> int | None:
    candidate = _optional_text(
        value
    )

    if candidate is None:
        return None

    try:
        if candidate.lower().startswith(
            "0x"
        ):
            number = int(
                candidate,
                16,
            )
        else:
            number = int(
                candidate,
                10,
            )
    except ValueError:
        return None

    if number < 0:
        return None

    return number


def _identity_key(
    event: CanonicalEvent,
) -> tuple[
    str,
    str,
    int,
    str,
    int,
] | None:
    """
    Build the cross-source process key without using event time.

    Host equality is exact.

    Process and parent-process text receive casefold comparison only.
    No path rewriting or basename extraction occurs.

    PID values receive numeric interpretation only for comparison.
    Their original source strings are never replaced or written back.
    """

    if event.event_type != "process_create":
        return None

    host = _optional_text(
        event.host
    )

    process_name = _optional_text(
        event.semantic_fields.get(
            "process_name"
        )
    )

    process_id = _numeric_pid(
        event.semantic_fields.get(
            "process_id"
        )
    )

    parent_process = _optional_text(
        event.semantic_fields.get(
            "parent_process"
        )
    )

    parent_process_id = _numeric_pid(
        event.semantic_fields.get(
            "parent_process_id"
        )
    )

    if host is None:
        return None

    if process_name is None:
        return None

    if process_id is None:
        return None

    if parent_process is None:
        return None

    if parent_process_id is None:
        return None

    return (
        host,
        process_name.casefold(),
        process_id,
        parent_process.casefold(),
        parent_process_id,
    )


def _validate_input_event(
    event: CanonicalEvent,
    *,
    source_type: SourceType,
    expected_clock_state: ClockState,
) -> None:
    if event.source_type is not source_type:
        raise ClockEvidenceError(
            (
                "clock-evidence input contains "
                f"{event.source_type.value}; "
                f"expected {source_type.value}"
            )
        )

    if event.event_type != "process_create":
        return

    if event.clock_state is not expected_clock_state:
        raise ClockEvidenceError(
            (
                f"{source_type.value} process_create "
                f"must have clock_state="
                f"{expected_clock_state.value}"
            )
        )

    if expected_clock_state is ClockState.UNRESOLVED:
        if event.event_time_utc is not None:
            raise ClockEvidenceError(
                "unresolved target event must not claim UTC"
            )

    if expected_clock_state is ClockState.OBSERVED:
        if event.event_time_utc is None:
            raise ClockEvidenceError(
                "observed supporting event requires UTC"
            )


def _compute_clock_evidence_id(
    *,
    target_event_id: str,
    supporting_event_ids: tuple[str, ...],
    utc_interval_start: datetime,
    utc_interval_end_exclusive: datetime,
) -> str:
    material = {
        "identity_version":
            CLOCK_EVIDENCE_IDENTITY_VERSION,

        "kind":
            "clock_evidence",

        "method":
            WINDOWS_SECURITY_SYSMON_PROCESS_METHOD,

        "target_event_id":
            target_event_id,

        "supporting_event_ids":
            list(
                supporting_event_ids
            ),

        "utc_interval_start":
            utc_interval_start.isoformat(),

        "utc_interval_end_exclusive":
            utc_interval_end_exclusive.isoformat(),
    }

    encoded = json.dumps(
        material,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode(
        "ascii"
    )

    return (
        "clk_"
        + hashlib.sha256(
            encoded
        ).hexdigest()
    )


def _corroborate_pair(
    *,
    security_event: CanonicalEvent,
    sysmon_event: CanonicalEvent,
) -> ClockEvidence | None:
    """
    Test time only after a unique non-temporal identity pair exists.
    """

    security_key = _identity_key(
        security_event
    )

    sysmon_key = _identity_key(
        sysmon_event
    )

    if security_key is None:
        return None

    if sysmon_key is None:
        return None

    if security_key != sysmon_key:
        return None

    security_principal = _optional_text(
        security_event.principal
    )

    sysmon_principal = _optional_text(
        sysmon_event.principal
    )

    if security_principal is None:
        return None

    if sysmon_principal is None:
        return None

    if security_principal != sysmon_principal:
        return None

    raw_time = _optional_text(
        security_event.event_time_raw
    )

    if raw_time is None:
        raise ClockEvidenceError(
            "Security target has no raw timestamp"
        )

    try:
        security_wall = datetime.strptime(
            raw_time,
            WINDOWS_SECURITY_WALL_TIME_FORMAT,
        )
    except ValueError as exc:
        raise ClockEvidenceError(
            (
                "Windows Security raw timestamp "
                "does not match the adjudicated source format"
            )
        ) from exc

    sysmon_utc = (
        sysmon_event.event_time_utc
    )

    if sysmon_utc is None:
        raise ClockEvidenceError(
            "Sysmon supporting event has no UTC timestamp"
        )

    sysmon_coordinate = (
        sysmon_utc
        .astimezone(
            timezone.utc
        )
        .replace(
            tzinfo=None
        )
    )

    sysmon_second = (
        sysmon_coordinate.replace(
            microsecond=0
        )
    )

    if security_wall != sysmon_second:
        return None

    coordinate_delta = (
        sysmon_coordinate
        -
        security_wall
    ).total_seconds()

    if coordinate_delta < 0:
        return None

    if coordinate_delta >= 1:
        return None

    interval_start = (
        security_wall.replace(
            tzinfo=timezone.utc
        )
    )

    interval_end = (
        interval_start
        +
        timedelta(
            seconds=1
        )
    )

    supporting_event_ids = tuple(
        sorted(
            (
                sysmon_event.event_id,
            )
        )
    )

    evidence_id = (
        _compute_clock_evidence_id(
            target_event_id=
                security_event.event_id,

            supporting_event_ids=
                supporting_event_ids,

            utc_interval_start=
                interval_start,

            utc_interval_end_exclusive=
                interval_end,
        )
    )

    return ClockEvidence(
        evidence_id=
            evidence_id,

        state=
            ClockEvidenceState.CORROBORATED,

        method=
            WINDOWS_SECURITY_SYSMON_PROCESS_METHOD,

        target_event_id=
            security_event.event_id,

        supporting_event_ids=
            supporting_event_ids,

        host=
            security_key[0],

        target_event_time_raw=
            raw_time,

        utc_interval_start=
            interval_start,

        utc_interval_end_exclusive=
            interval_end,

        coordinate_offset_seconds=
            0,

        resolution_seconds=
            1,

        identity_dimensions=
            PROCESS_IDENTITY_DIMENSIONS,
    )


def derive_windows_security_sysmon_process_clock_evidence(
    security_events: Iterable[CanonicalEvent],
    sysmon_events: Iterable[CanonicalEvent],
) -> tuple[ClockEvidence, ...]:
    """
    Derive bounded corroborated clock evidence.

    Selection is source-generic within Windows Security and Sysmon.

    A target is eligible only when:
    - it is Windows Security process_create with UNRESOLVED time;
    - support is Sysmon process_create with OBSERVED UTC;
    - a non-temporal process identity key occurs exactly once in each
      supplied source population;
    - principals then agree exactly;
    - only then does the function examine displayed-second alignment.

    Ambiguous identity keys are never resolved with timestamps.

    CanonicalEvent parents are immutable and remain unchanged.
    """

    security = tuple(
        security_events
    )

    sysmon = tuple(
        sysmon_events
    )

    for event in security:
        _validate_input_event(
            event,
            source_type=
                SourceType.WINDOWS_SECURITY,
            expected_clock_state=
                ClockState.UNRESOLVED,
        )

    for event in sysmon:
        _validate_input_event(
            event,
            source_type=
                SourceType.SYSMON,
            expected_clock_state=
                ClockState.OBSERVED,
        )

    security_by_key: dict[
        tuple[
            str,
            str,
            int,
            str,
            int,
        ],
        list[CanonicalEvent],
    ] = defaultdict(
        list
    )

    sysmon_by_key: dict[
        tuple[
            str,
            str,
            int,
            str,
            int,
        ],
        list[CanonicalEvent],
    ] = defaultdict(
        list
    )

    for event in security:
        key = _identity_key(
            event
        )

        if key is not None:
            security_by_key[
                key
            ].append(
                event
            )

    for event in sysmon:
        key = _identity_key(
            event
        )

        if key is not None:
            sysmon_by_key[
                key
            ].append(
                event
            )

    shared_keys = (
        set(
            security_by_key
        )
        &
        set(
            sysmon_by_key
        )
    )

    results: list[
        ClockEvidence
    ] = []

    for key in shared_keys:
        security_group = (
            security_by_key[
                key
            ]
        )

        sysmon_group = (
            sysmon_by_key[
                key
            ]
        )

        if len(security_group) != 1:
            continue

        if len(sysmon_group) != 1:
            continue

        evidence = _corroborate_pair(
            security_event=
                security_group[0],

            sysmon_event=
                sysmon_group[0],
        )

        if evidence is not None:
            results.append(
                evidence
            )

    return tuple(
        sorted(
            results,
            key=lambda item:
                item.evidence_id,
        )
    )