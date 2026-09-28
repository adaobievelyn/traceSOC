from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib
import json
from typing import Iterable, Mapping

from tracesoc.models import (
    CanonicalEvent,
    ClockState,
    SourceType,
)


RECONSTRUCTION_IDENTITY_VERSION = 1
POWERSHELL_SCRIPTBLOCK_EVENT_ID = 4104


class ScriptBlockState(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class ScriptBlockReconstructionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ScriptBlockFragment:
    source_event_id: str
    message_number: int
    script_text: str
    event_time_utc: datetime


@dataclass(frozen=True, slots=True)
class PowerShellScriptBlock:
    reconstruction_id: str
    script_block_id: str
    state: ScriptBlockState

    host: str
    process_id: str
    thread_id: str
    security_user_id: str

    path: str | None

    expected_message_total: int
    observed_message_numbers: tuple[int, ...]
    missing_message_numbers: tuple[int, ...]

    parent_event_ids: tuple[str, ...]
    fragments: tuple[ScriptBlockFragment, ...]

    first_event_time_utc: datetime
    last_event_time_utc: datetime

    script_text: str | None
    script_text_sha256: str | None


@dataclass(frozen=True, slots=True)
class _EligibleFragment:
    source_event_id: str

    script_block_id: str
    message_number: int
    message_total: int
    script_text: str

    host: str
    process_id: str
    thread_id: str
    security_user_id: str

    path: str | None

    event_time_utc: datetime


def _require_text(
    value: object,
    *,
    field: str,
) -> str:
    if not isinstance(value, str):
        raise ScriptBlockReconstructionError(
            f"{field} must be text"
        )

    candidate = value.strip()

    if not candidate:
        raise ScriptBlockReconstructionError(
            f"{field} must not be empty"
        )

    return candidate


def _require_positive_int(
    value: object,
    *,
    field: str,
) -> int:
    candidate = _require_text(
        value,
        field=field,
    )

    try:
        number = int(
            candidate,
            10,
        )
    except ValueError as exc:
        raise ScriptBlockReconstructionError(
            f"{field} must be a decimal integer"
        ) from exc

    if number <= 0:
        raise ScriptBlockReconstructionError(
            f"{field} must be greater than zero"
        )

    return number


def _require_event_data(
    event: CanonicalEvent,
) -> Mapping[str, object]:
    value = event.source_context.get(
        "event_data"
    )

    if not isinstance(value, Mapping):
        raise ScriptBlockReconstructionError(
            (
                "eligible PowerShell event has no "
                "EventData mapping"
            )
        )

    return value


def _extract_fragment(
    event: CanonicalEvent,
) -> _EligibleFragment | None:
    if event.source_type is not SourceType.POWERSHELL:
        return None

    if event.event_type != "powershell_event":
        return None

    raw_event_code = event.source_context.get(
        "event_code"
    )

    try:
        event_code = int(
            raw_event_code
        )
    except (TypeError, ValueError) as exc:
        raise ScriptBlockReconstructionError(
            (
                "PowerShell canonical event has "
                "invalid source EventID"
            )
        ) from exc

    if event_code != POWERSHELL_SCRIPTBLOCK_EVENT_ID:
        return None

    if (
        event.clock_state is not ClockState.OBSERVED
        or
        event.event_time_utc is None
    ):
        raise ScriptBlockReconstructionError(
            (
                "eligible PowerShell 4104 event "
                "must carry OBSERVED UTC"
            )
        )

    if event.host is None:
        raise ScriptBlockReconstructionError(
            "eligible PowerShell 4104 event has no host"
        )

    host = _require_text(
        event.host,
        field="host",
    )

    process_id = _require_text(
        event.source_context.get(
            "execution_process_id"
        ),
        field="execution_process_id",
    )

    thread_id = _require_text(
        event.source_context.get(
            "execution_thread_id"
        ),
        field="execution_thread_id",
    )

    security_user_id = _require_text(
        event.source_context.get(
            "security_user_id"
        ),
        field="security_user_id",
    )

    event_data = _require_event_data(
        event
    )

    script_block_id = _require_text(
        event_data.get(
            "ScriptBlockId"
        ),
        field="ScriptBlockId",
    )

    message_number = _require_positive_int(
        event_data.get(
            "MessageNumber"
        ),
        field="MessageNumber",
    )

    message_total = _require_positive_int(
        event_data.get(
            "MessageTotal"
        ),
        field="MessageTotal",
    )

    if message_number > message_total:
        raise ScriptBlockReconstructionError(
            (
                "MessageNumber exceeds MessageTotal "
                f"for {script_block_id}"
            )
        )

    raw_script_text = event_data.get(
        "ScriptBlockText"
    )

    if not isinstance(
        raw_script_text,
        str,
    ):
        raise ScriptBlockReconstructionError(
            "ScriptBlockText must be text"
        )

    if raw_script_text == "":
        raise ScriptBlockReconstructionError(
            "ScriptBlockText must not be empty"
        )

    raw_path = event_data.get(
        "Path"
    )

    path: str | None = None

    if isinstance(raw_path, str):
        candidate_path = raw_path.strip()

        if candidate_path:
            path = candidate_path

    elif raw_path is not None:
        raise ScriptBlockReconstructionError(
            "Path must be text when present"
        )

    return _EligibleFragment(
        source_event_id=event.event_id,
        script_block_id=script_block_id,
        message_number=message_number,
        message_total=message_total,
        script_text=raw_script_text,
        host=host,
        process_id=process_id,
        thread_id=thread_id,
        security_user_id=security_user_id,
        path=path,
        event_time_utc=event.event_time_utc,
    )


def _single_value(
    values: set[str],
    *,
    field: str,
    script_block_id: str,
) -> str:
    if len(values) != 1:
        raise ScriptBlockReconstructionError(
            (
                f"{field} is inconsistent within "
                f"ScriptBlockId {script_block_id}"
            )
        )

    return next(
        iter(values)
    )


def _merge_path(
    values: set[str | None],
    *,
    script_block_id: str,
) -> str | None:
    nonempty = {
        value
        for value in values
        if value is not None
    }

    if len(nonempty) > 1:
        raise ScriptBlockReconstructionError(
            (
                "Path is inconsistent within "
                f"ScriptBlockId {script_block_id}"
            )
        )

    if not nonempty:
        return None

    return next(
        iter(nonempty)
    )


def _compute_reconstruction_id(
    *,
    script_block_id: str,
    parent_event_ids: tuple[str, ...],
) -> str:
    material = {
        "identity_version":
            RECONSTRUCTION_IDENTITY_VERSION,

        "kind":
            "powershell_scriptblock",

        "script_block_id":
            script_block_id,

        "parent_event_ids":
            list(parent_event_ids),
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
        "psb_"
        + hashlib.sha256(
            encoded
        ).hexdigest()
    )


def reconstruct_powershell_scriptblocks(
    events: Iterable[CanonicalEvent],
) -> tuple[PowerShellScriptBlock, ...]:
    """
    Derive logical PowerShell ScriptBlock groups from canonical
    Event ID 4104 source observations.

    COMPLETE groups expose deterministic complete script_text.

    INCOMPLETE groups preserve every observed fragment and exact
    missing MessageNumber values, but script_text remains None.

    This transform performs reconstruction only. It performs no
    detection, maliciousness classification, or correlation.
    """

    grouped: dict[
        str,
        list[_EligibleFragment],
    ] = {}

    for event in events:
        fragment = _extract_fragment(
            event
        )

        if fragment is None:
            continue

        grouped.setdefault(
            fragment.script_block_id,
            [],
        ).append(
            fragment
        )

    results: list[
        PowerShellScriptBlock
    ] = []

    for script_block_id in sorted(
        grouped
    ):
        group = grouped[
            script_block_id
        ]

        total_values = {
            item.message_total
            for item in group
        }

        if len(total_values) != 1:
            raise ScriptBlockReconstructionError(
                (
                    "MessageTotal is inconsistent within "
                    f"ScriptBlockId {script_block_id}"
                )
            )

        expected_total = next(
            iter(total_values)
        )

        host = _single_value(
            {
                item.host
                for item in group
            },
            field="host",
            script_block_id=script_block_id,
        )

        process_id = _single_value(
            {
                item.process_id
                for item in group
            },
            field="process_id",
            script_block_id=script_block_id,
        )

        thread_id = _single_value(
            {
                item.thread_id
                for item in group
            },
            field="thread_id",
            script_block_id=script_block_id,
        )

        security_user_id = _single_value(
            {
                item.security_user_id
                for item in group
            },
            field="security_user_id",
            script_block_id=script_block_id,
        )

        path = _merge_path(
            {
                item.path
                for item in group
            },
            script_block_id=script_block_id,
        )

        by_message_number: dict[
            int,
            list[_EligibleFragment],
        ] = {}

        for fragment in group:
            by_message_number.setdefault(
                fragment.message_number,
                [],
            ).append(
                fragment
            )

        for (
            message_number,
            observations,
        ) in by_message_number.items():
            observed_texts = {
                item.script_text
                for item in observations
            }

            if len(observed_texts) != 1:
                raise ScriptBlockReconstructionError(
                    (
                        "conflicting duplicate "
                        f"MessageNumber {message_number} "
                        f"for ScriptBlockId {script_block_id}"
                    )
                )

        observed_numbers = tuple(
            sorted(
                by_message_number
            )
        )

        expected_numbers = set(
            range(
                1,
                expected_total + 1,
            )
        )

        observed_number_set = set(
            observed_numbers
        )

        extra_numbers = (
            observed_number_set
            - expected_numbers
        )

        if extra_numbers:
            raise ScriptBlockReconstructionError(
                (
                    "out-of-range MessageNumber values "
                    f"for ScriptBlockId {script_block_id}: "
                    f"{sorted(extra_numbers)}"
                )
            )

        missing_numbers = tuple(
            sorted(
                expected_numbers
                - observed_number_set
            )
        )

        state = (
            ScriptBlockState.COMPLETE
            if not missing_numbers
            else ScriptBlockState.INCOMPLETE
        )

        ordered_source_fragments = sorted(
            group,
            key=lambda item: (
                item.message_number,
                item.source_event_id,
            ),
        )

        fragments = tuple(
            ScriptBlockFragment(
                source_event_id=
                    item.source_event_id,

                message_number=
                    item.message_number,

                script_text=
                    item.script_text,

                event_time_utc=
                    item.event_time_utc,
            )
            for item in ordered_source_fragments
        )

        parent_event_ids = tuple(
            item.source_event_id
            for item in ordered_source_fragments
        )

        script_text: str | None = None
        script_text_sha256: str | None = None

        if state is ScriptBlockState.COMPLETE:
            unique_text_by_number = {
                message_number:
                    by_message_number[
                        message_number
                    ][0].script_text
                for message_number
                in observed_numbers
            }

            script_text = "".join(
                unique_text_by_number[
                    number
                ]
                for number in range(
                    1,
                    expected_total + 1,
                )
            )

            script_text_sha256 = (
                hashlib.sha256(
                    script_text.encode(
                        "utf-8"
                    )
                ).hexdigest()
            )

        first_time = min(
            item.event_time_utc
            for item in group
        )

        last_time = max(
            item.event_time_utc
            for item in group
        )

        reconstruction_id = (
            _compute_reconstruction_id(
                script_block_id=
                    script_block_id,

                parent_event_ids=
                    parent_event_ids,
            )
        )

        results.append(
            PowerShellScriptBlock(
                reconstruction_id=
                    reconstruction_id,

                script_block_id=
                    script_block_id,

                state=
                    state,

                host=
                    host,

                process_id=
                    process_id,

                thread_id=
                    thread_id,

                security_user_id=
                    security_user_id,

                path=
                    path,

                expected_message_total=
                    expected_total,

                observed_message_numbers=
                    observed_numbers,

                missing_message_numbers=
                    missing_numbers,

                parent_event_ids=
                    parent_event_ids,

                fragments=
                    fragments,

                first_event_time_utc=
                    first_time,

                last_event_time_utc=
                    last_time,

                script_text=
                    script_text,

                script_text_sha256=
                    script_text_sha256,
            )
        )

    return tuple(
        results
    )