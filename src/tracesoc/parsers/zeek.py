from __future__ import annotations

import json

from collections.abc import Mapping
from datetime import datetime, timezone
from math import isfinite
from pathlib import Path

from tracesoc.evidence.identity import compute_event_id
from tracesoc.models import CanonicalEvent, ClockState, SourceType
from tracesoc.parsers.real_records import read_zeek_ascii_records
from tracesoc.parsers.common import (
    AdapterBatch,
    RecordValidationError,
    optional_text,
    parse_utc_timestamp,
    quarantine_from_validation,
    read_jsonl_records,
    read_json_object_record,
    require_int,
    require_object,
    require_text,
    source_context,
)


ADAPTER_ID = "tracesoc-zeek-jsonl-v1"
SCHEMA_VERSION = "1"

REAL_ADAPTER_ID = "tracesoc-zeek-ascii-v1"
REAL_SCHEMA_VERSION = "1"
REAL_EVENT_TYPE = "connection"
NATIVE_JSON_ADAPTER_ID = "tracesoc-zeek-native-json-v1"
NATIVE_JSON_SCHEMA_VERSION = "1"


def load_zeek_jsonl(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    accepted = []
    quarantined = []

    for record in read_jsonl_records(
        path=path,
        logical_source=logical_source,
        source_type=SourceType.ZEEK,
        adapter_id=ADAPTER_ID,
        input_schema_version=SCHEMA_VERSION,
    ):
        if record.quarantine is not None:
            quarantined.append(record.quarantine)
            continue

        try:
            payload = require_object(record.payload)

            timestamp = require_text(payload, "timestamp")
            event_type = require_text(payload, "event_type")

            if event_type != "connection":
                raise RecordValidationError(
                    "unsupported_event_type",
                    f"unsupported Zeek event_type: {event_type}",
                )

            uid = require_text(payload, "uid")
            src_ip = require_text(payload, "src_ip")
            dst_ip = require_text(payload, "dst_ip")
            dst_port = require_int(payload, "dst_port")
            proto = require_text(payload, "proto")
            service = require_text(payload, "service")
            bytes_out = require_int(payload, "bytes_out")
            bytes_in = require_int(payload, "bytes_in")

            host = optional_text(payload, "host")

            event_time = parse_utc_timestamp(timestamp)

            event_id = compute_event_id(
                locator=record.locator,
                source_type=SourceType.ZEEK,
                event_type=event_type,
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=SourceType.ZEEK,
                    event_type=event_type,
                    clock_state=ClockState.OBSERVED,
                    provenance=record.locator,
                    event_time_raw=timestamp,
                    event_time_utc=event_time,
                    host=host,
                    principal=None,
                    semantic_fields={
                        "uid": uid,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "proto": proto,
                        "service": service,
                        "bytes_out": bytes_out,
                        "bytes_in": bytes_in,
                    },
                    source_context=source_context(
                        payload,
                        (
                            "log_type",
                            "fixture_id",
                            "expected_answer",
                        ),
                    ),
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=SourceType.ZEEK,
                    locator=record.locator,
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=SourceType.ZEEK,
        adapter_id=ADAPTER_ID,
        accepted=tuple(accepted),
        quarantined=tuple(quarantined),
    )
def _real_zeek_required_text(
    fields: Mapping[str, str],
    field: str,
) -> str:
    value = fields.get(field)

    if value is None:
        raise RecordValidationError(
            "missing_field",
            f"real Zeek field is missing: {field}",
        )

    normalized = value.strip()

    if normalized in {
        "",
        "-",
        "(empty)",
    }:
        raise RecordValidationError(
            "missing_field",
            (
                "real Zeek required field is empty "
                f"or unset: {field}"
            ),
        )

    return normalized


def _real_zeek_optional_text(
    fields: Mapping[str, str],
    field: str,
) -> str | None:
    value = fields.get(field)

    if value is None:
        return None

    normalized = value.strip()

    if normalized in {
        "",
        "-",
        "(empty)",
    }:
        return None

    return normalized


def _real_zeek_required_port(
    fields: Mapping[str, str],
    field: str,
) -> int:
    value = _real_zeek_required_text(
        fields,
        field,
    )

    try:
        port = int(
            value,
            10,
        )
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Zeek port field is not "
                f"a decimal integer: {field}"
            ),
        ) from exc

    if not 0 <= port <= 65535:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Zeek port field is outside "
                f"0..65535: {field}"
            ),
        )

    return port


def _real_zeek_optional_nonnegative_int(
    fields: Mapping[str, str],
    field: str,
) -> int | None:
    value = _real_zeek_optional_text(
        fields,
        field,
    )

    if value is None:
        return None

    try:
        parsed = int(
            value,
            10,
        )
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Zeek numeric field is not "
                f"a decimal integer: {field}"
            ),
        ) from exc

    if parsed < 0:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Zeek numeric field must not "
                f"be negative: {field}"
            ),
        )

    return parsed


def _real_zeek_optional_nonnegative_float(
    fields: Mapping[str, str],
    field: str,
) -> float | None:
    value = _real_zeek_optional_text(
        fields,
        field,
    )

    if value is None:
        return None

    try:
        parsed = float(
            value
        )
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Zeek numeric field is not "
                f"a finite decimal value: {field}"
            ),
        ) from exc

    if (
        not isfinite(parsed)
        or
        parsed < 0
    ):
        raise RecordValidationError(
            "invalid_field",
            (
                "real Zeek numeric field must be "
                f"finite and non-negative: {field}"
            ),
        )

    return parsed


def _parse_real_zeek_epoch_seconds(
    raw_timestamp: str,
) -> datetime:
    try:
        epoch_seconds = float(
            raw_timestamp
        )
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Zeek ts is not valid "
                "Unix epoch seconds"
            ),
        ) from exc

    if not isfinite(
        epoch_seconds
    ):
        raise RecordValidationError(
            "invalid_field",
            (
                "real Zeek ts is not finite "
                "Unix epoch seconds"
            ),
        )

    try:
        return datetime.fromtimestamp(
            epoch_seconds,
            tz=timezone.utc,
        )
    except (
        OverflowError,
        OSError,
        ValueError,
    ) as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Zeek ts is outside the "
                "supported UTC datetime range"
            ),
        ) from exc



_ZEEK_CONN_REQUIRED_PROFILE_KEYS = frozenset(
    {
        "ts",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
    }
)

_ZEEK_CONN_TEXT_FIELDS = frozenset(
    {
        "uid",
        "id.orig_h",
        "id.resp_h",
        "proto",
        "service",
        "conn_state",
        "history",
    }
)

_ZEEK_CONN_NUMERIC_FIELDS = frozenset(
    {
        "ts",
        "id.orig_p",
        "id.resp_p",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "missed_bytes",
        "orig_pkts",
        "orig_ip_bytes",
        "resp_pkts",
        "resp_ip_bytes",
    }
)

_ZEEK_CONN_SEMANTIC_SOURCE_FIELDS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
)


def _is_native_zeek_conn_json_object(
    payload: object,
) -> bool:
    if not isinstance(
        payload,
        dict,
    ):
        return False

    return (
        _ZEEK_CONN_REQUIRED_PROFILE_KEYS
        <= set(
            payload
        )
    )


def probe_zeek_conn_json(
    *,
    raw_bytes: bytes,
    logical_source: str,
) -> bool:
    """
    Identify the declared native Zeek conn JSON profile structurally.

    This probe does not accept the old TraceSOC compatibility schema because
    that schema uses canonicalized names such as src_ip/dst_ip rather than
    Zeek's source-native id.orig_h/id.resp_h field names.
    """

    suffix = Path(
        logical_source
    ).suffix.lower()

    if suffix == ".json":
        try:
            payload = json.loads(
                raw_bytes.decode(
                    "utf-8"
                )
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return False

        return (
            _is_native_zeek_conn_json_object(
                payload
            )
        )

    if suffix != ".jsonl":
        return False

    for line in raw_bytes.splitlines():
        if not line.strip():
            continue

        try:
            payload = json.loads(
                line.decode(
                    "utf-8"
                )
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            continue

        if _is_native_zeek_conn_json_object(
            payload
        ):
            return True

    return False


def _native_zeek_json_scalar_text(
    *,
    field: str,
    value: object,
) -> str:
    """
    Convert only recognized Zeek conn scalar fields into the textual view
    consumed by the existing source-native semantic mapper.

    The original typed JSON object remains in source_context and exact raw
    bytes remain addressable through the RawLocator.
    """

    if value is None:
        return "-"

    if field in _ZEEK_CONN_TEXT_FIELDS:
        if not isinstance(
            value,
            str,
        ):
            raise RecordValidationError(
                "invalid_field",
                (
                    "native Zeek JSON text field "
                    f"must be text or null: {field}"
                ),
            )

        return value

    if field in _ZEEK_CONN_NUMERIC_FIELDS:
        if isinstance(
            value,
            bool,
        ):
            raise RecordValidationError(
                "invalid_field",
                (
                    "native Zeek JSON numeric field "
                    f"must not be boolean: {field}"
                ),
            )

        if isinstance(
            value,
            str,
        ):
            return value

        if isinstance(
            value,
            int,
        ):
            return str(
                value
            )

        if isinstance(
            value,
            float,
        ):
            if not isfinite(
                value
            ):
                raise RecordValidationError(
                    "invalid_field",
                    (
                        "native Zeek JSON numeric field "
                        f"must be finite: {field}"
                    ),
                )

            return repr(
                value
            )

        raise RecordValidationError(
            "invalid_field",
            (
                "native Zeek JSON numeric field "
                f"has unsupported type: {field}"
            ),
        )

    raise RecordValidationError(
        "invalid_field",
        (
            "unexpected Zeek semantic field: "
            + field
        ),
    )


def _native_zeek_json_semantic_fields(
    payload: Mapping[str, object],
) -> dict[str, str]:
    fields: dict[
        str,
        str,
    ] = {}

    for field in (
        _ZEEK_CONN_SEMANTIC_SOURCE_FIELDS
    ):
        if field not in payload:
            continue

        fields[
            field
        ] = (
            _native_zeek_json_scalar_text(
                field=field,
                value=payload[
                    field
                ],
            )
        )

    return fields


def _map_source_native_zeek_conn_fields(
    fields: Mapping[str, str],
) -> tuple[
    str,
    datetime,
    dict[str, object],
]:
    """
    Map source-native Zeek conn fields into the canonical connection model.

    Both ASCII conn.log and native JSON/JSONL converge here.
    """

    raw_timestamp = (
        _real_zeek_required_text(
            fields,
            "ts",
        )
    )

    event_time = (
        _parse_real_zeek_epoch_seconds(
            raw_timestamp
        )
    )

    uid = _real_zeek_required_text(
        fields,
        "uid",
    )

    src_ip = (
        _real_zeek_required_text(
            fields,
            "id.orig_h",
        )
    )

    src_port = (
        _real_zeek_required_port(
            fields,
            "id.orig_p",
        )
    )

    dst_ip = (
        _real_zeek_required_text(
            fields,
            "id.resp_h",
        )
    )

    dst_port = (
        _real_zeek_required_port(
            fields,
            "id.resp_p",
        )
    )

    proto = (
        _real_zeek_required_text(
            fields,
            "proto",
        )
    )

    semantic_fields: dict[
        str,
        object,
    ] = {
        "uid":
            uid,
        "src_ip":
            src_ip,
        "src_port":
            src_port,
        "dst_ip":
            dst_ip,
        "dst_port":
            dst_port,
        "proto":
            proto,
    }

    service = (
        _real_zeek_optional_text(
            fields,
            "service",
        )
    )

    if service is not None:
        semantic_fields[
            "service"
        ] = service

    duration = (
        _real_zeek_optional_nonnegative_float(
            fields,
            "duration",
        )
    )

    if duration is not None:
        semantic_fields[
            "duration"
        ] = duration

    orig_bytes = (
        _real_zeek_optional_nonnegative_int(
            fields,
            "orig_bytes",
        )
    )

    if orig_bytes is not None:
        semantic_fields[
            "bytes_out"
        ] = orig_bytes

    resp_bytes = (
        _real_zeek_optional_nonnegative_int(
            fields,
            "resp_bytes",
        )
    )

    if resp_bytes is not None:
        semantic_fields[
            "bytes_in"
        ] = resp_bytes

    conn_state = (
        _real_zeek_optional_text(
            fields,
            "conn_state",
        )
    )

    if conn_state is not None:
        semantic_fields[
            "conn_state"
        ] = conn_state

    missed_bytes = (
        _real_zeek_optional_nonnegative_int(
            fields,
            "missed_bytes",
        )
    )

    if missed_bytes is not None:
        semantic_fields[
            "missed_bytes"
        ] = missed_bytes

    history = (
        _real_zeek_optional_text(
            fields,
            "history",
        )
    )

    if history is not None:
        semantic_fields[
            "history"
        ] = history

    orig_pkts = (
        _real_zeek_optional_nonnegative_int(
            fields,
            "orig_pkts",
        )
    )

    if orig_pkts is not None:
        semantic_fields[
            "packets_out"
        ] = orig_pkts

    orig_ip_bytes = (
        _real_zeek_optional_nonnegative_int(
            fields,
            "orig_ip_bytes",
        )
    )

    if orig_ip_bytes is not None:
        semantic_fields[
            "ip_bytes_out"
        ] = orig_ip_bytes

    resp_pkts = (
        _real_zeek_optional_nonnegative_int(
            fields,
            "resp_pkts",
        )
    )

    if resp_pkts is not None:
        semantic_fields[
            "packets_in"
        ] = resp_pkts

    resp_ip_bytes = (
        _real_zeek_optional_nonnegative_int(
            fields,
            "resp_ip_bytes",
        )
    )

    if resp_ip_bytes is not None:
        semantic_fields[
            "ip_bytes_in"
        ] = resp_ip_bytes

    return (
        raw_timestamp,
        event_time,
        semantic_fields,
    )


def load_zeek_conn_native_json(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    """
    Load source-native Zeek conn JSON or JSONL.

    Native Zeek field names are preserved. This adapter does not consume the
    historical TraceSOC compatibility JSONL schema.
    """

    suffix = (
        path.suffix.lower()
    )

    if suffix == ".jsonl":
        decoded_records = (
            read_jsonl_records(
                path=path,
                logical_source=(
                    logical_source
                ),
                source_type=(
                    SourceType.ZEEK
                ),
                adapter_id=(
                    NATIVE_JSON_ADAPTER_ID
                ),
                input_schema_version=(
                    NATIVE_JSON_SCHEMA_VERSION
                ),
            )
        )

    elif suffix == ".json":
        decoded_records = (
            read_json_object_record(
                path=path,
                logical_source=(
                    logical_source
                ),
                source_type=(
                    SourceType.ZEEK
                ),
                adapter_id=(
                    NATIVE_JSON_ADAPTER_ID
                ),
                input_schema_version=(
                    NATIVE_JSON_SCHEMA_VERSION
                ),
            ),
        )

    else:
        raise ValueError(
            "native Zeek JSON profile requires .json or .jsonl"
        )

    accepted: list[
        CanonicalEvent
    ] = []

    quarantined = []

    for record in decoded_records:
        if record.quarantine is not None:
            quarantined.append(
                record.quarantine
            )
            continue

        try:
            payload = require_object(
                record.payload
            )

            fields = (
                _native_zeek_json_semantic_fields(
                    payload
                )
            )

            (
                raw_timestamp,
                event_time,
                semantic_fields,
            ) = (
                _map_source_native_zeek_conn_fields(
                    fields
                )
            )

            event_id = compute_event_id(
                locator=record.locator,
                source_type=(
                    SourceType.ZEEK
                ),
                event_type=(
                    REAL_EVENT_TYPE
                ),
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=(
                        SourceType.ZEEK
                    ),
                    event_type=(
                        REAL_EVENT_TYPE
                    ),
                    clock_state=(
                        ClockState.OBSERVED
                    ),
                    provenance=(
                        record.locator
                    ),
                    event_time_raw=(
                        raw_timestamp
                    ),
                    event_time_utc=(
                        event_time
                    ),
                    host=None,
                    principal=None,
                    semantic_fields=(
                        semantic_fields
                    ),
                    source_context={
                        "zeek_fields":
                            dict(
                                payload
                            ),
                    },
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=(
                        SourceType.ZEEK
                    ),
                    locator=(
                        record.locator
                    ),
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=(
            SourceType.ZEEK
        ),
        adapter_id=(
            NATIVE_JSON_ADAPTER_ID
        ),
        accepted=tuple(
            accepted
        ),
        quarantined=tuple(
            quarantined
        ),
    )



def load_zeek_conn_ascii(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    """
    Load source-native Zeek conn.log ASCII rows.

    Both ASCII and native JSON converge on one semantic mapper.
    Representation-specific source fields remain in source_context and
    exact raw provenance remains attached to each event.
    """

    raw_batch = read_zeek_ascii_records(
        path,
        logical_source=logical_source,
        adapter_id=REAL_ADAPTER_ID,
        input_schema_version=(
            REAL_SCHEMA_VERSION
        ),
    )

    accepted: list[
        CanonicalEvent
    ] = []

    quarantined = list(
        raw_batch.quarantined
    )

    for record in raw_batch.accepted:
        try:
            fields = (
                record.field_map
            )

            (
                raw_timestamp,
                event_time,
                semantic_fields,
            ) = (
                _map_source_native_zeek_conn_fields(
                    fields
                )
            )

            event_id = compute_event_id(
                locator=record.locator,
                source_type=(
                    SourceType.ZEEK
                ),
                event_type=(
                    REAL_EVENT_TYPE
                ),
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=(
                        SourceType.ZEEK
                    ),
                    event_type=(
                        REAL_EVENT_TYPE
                    ),
                    clock_state=(
                        ClockState.OBSERVED
                    ),
                    provenance=(
                        record.locator
                    ),
                    event_time_raw=(
                        raw_timestamp
                    ),
                    event_time_utc=(
                        event_time
                    ),
                    host=None,
                    principal=None,
                    semantic_fields=(
                        semantic_fields
                    ),
                    source_context={
                        "zeek_fields":
                            dict(
                                fields
                            ),
                    },
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=(
                        SourceType.ZEEK
                    ),
                    locator=(
                        record.locator
                    ),
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=(
            SourceType.ZEEK
        ),
        adapter_id=(
            REAL_ADAPTER_ID
        ),
        accepted=tuple(
            accepted
        ),
        quarantined=tuple(
            quarantined
        ),
    )
