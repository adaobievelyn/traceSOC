from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from tracesoc.evidence.identity import raw_sha256
from tracesoc.models import CanonicalEvent, RawLocator, SourceType


@dataclass(frozen=True, slots=True)
class QuarantinedRecord:
    """A raw record retained in accounting but rejected from normalization."""

    source_type: SourceType
    locator: RawLocator
    reason_code: str
    detail: str


@dataclass(frozen=True, slots=True)
class AdapterBatch:
    """Complete accounting result for one adapter invocation."""

    source_type: SourceType
    adapter_id: str
    accepted: tuple[CanonicalEvent, ...]
    quarantined: tuple[QuarantinedRecord, ...]

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)

    @property
    def quarantined_count(self) -> int:
        return len(self.quarantined)

    @property
    def total_records(self) -> int:
        return self.accepted_count + self.quarantined_count


@dataclass(frozen=True, slots=True)
class DecodedJsonlRecord:
    locator: RawLocator
    payload: Any | None
    quarantine: QuarantinedRecord | None


class RecordValidationError(ValueError):
    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


def read_jsonl_records(
    *,
    path: Path,
    logical_source: str,
    source_type: SourceType,
    adapter_id: str,
    input_schema_version: str,
) -> tuple[DecodedJsonlRecord, ...]:
    """
    Read JSONL while preserving line number, byte offset, byte length and
    SHA-256 of the exact record bytes excluding only the line terminator.
    """

    raw_file = path.read_bytes()

    records: list[DecodedJsonlRecord] = []
    offset = 0

    for record_index, full_line in enumerate(
        raw_file.splitlines(keepends=True)
    ):
        record_bytes = full_line.rstrip(b"\r\n")

        locator = RawLocator(
            logical_source=logical_source,
            record_index=record_index,
            line_number=record_index + 1,
            byte_offset=offset,
            byte_length=len(record_bytes),
            raw_sha256=raw_sha256(record_bytes),
            adapter_id=adapter_id,
            input_schema_version=input_schema_version,
        )

        try:
            decoded_text = record_bytes.decode("utf-8")
            payload = json.loads(decoded_text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            records.append(
                DecodedJsonlRecord(
                    locator=locator,
                    payload=None,
                    quarantine=QuarantinedRecord(
                        source_type=source_type,
                        locator=locator,
                        reason_code="json_parse_error",
                        detail=str(exc),
                    ),
                )
            )
        else:
            records.append(
                DecodedJsonlRecord(
                    locator=locator,
                    payload=payload,
                    quarantine=None,
                )
            )

        offset += len(full_line)

    return tuple(records)



def read_json_object_record(
    *,
    path: Path,
    logical_source: str,
    source_type: SourceType,
    adapter_id: str,
    input_schema_version: str,
) -> DecodedJsonlRecord:
    """
    Read one JSON object represented by one whole artifact.

    The locator covers the exact artifact bytes, including any formatting
    and trailing newline bytes. Parsing never rewrites the evidence.
    """

    raw_file = path.read_bytes()

    locator = RawLocator(
        logical_source=logical_source,
        record_index=0,
        line_number=1,
        byte_offset=0,
        byte_length=len(raw_file),
        raw_sha256=raw_sha256(
            raw_file
        ),
        adapter_id=adapter_id,
        input_schema_version=(
            input_schema_version
        ),
    )

    try:
        decoded_text = (
            raw_file.decode(
                "utf-8"
            )
        )

        payload = json.loads(
            decoded_text
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        return DecodedJsonlRecord(
            locator=locator,
            payload=None,
            quarantine=(
                QuarantinedRecord(
                    source_type=(
                        source_type
                    ),
                    locator=locator,
                    reason_code=(
                        "json_parse_error"
                    ),
                    detail=str(
                        exc
                    ),
                )
            ),
        )

    return DecodedJsonlRecord(
        locator=locator,
        payload=payload,
        quarantine=None,
    )


def require_object(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, dict):
        raise RecordValidationError(
            "record_not_object",
            "JSON record must be an object",
        )

    return payload


def require_text(
    payload: Mapping[str, Any],
    key: str,
) -> str:
    if key not in payload:
        raise RecordValidationError(
            "missing_field",
            f"required field missing: {key}",
        )

    value = payload[key]

    if not isinstance(value, str) or not value.strip():
        raise RecordValidationError(
            "invalid_field",
            f"field must be non-empty text: {key}",
        )

    return value.strip()


def optional_text(
    payload: Mapping[str, Any],
    key: str,
) -> str | None:
    value = payload.get(key)

    if value is None:
        return None

    if not isinstance(value, str) or not value.strip():
        raise RecordValidationError(
            "invalid_field",
            f"optional field must be non-empty text when present: {key}",
        )

    return value.strip()


def require_int(
    payload: Mapping[str, Any],
    key: str,
) -> int:
    if key not in payload:
        raise RecordValidationError(
            "missing_field",
            f"required field missing: {key}",
        )

    value = payload[key]

    if isinstance(value, bool) or not isinstance(value, int):
        raise RecordValidationError(
            "invalid_field",
            f"field must be an integer: {key}",
        )

    return value


def parse_utc_timestamp(value: str) -> datetime:
    candidate = value.strip()

    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_timestamp",
            f"timestamp is not valid ISO-8601: {value}",
        ) from exc

    if parsed.tzinfo is None:
        raise RecordValidationError(
            "invalid_timestamp",
            "timestamp must include timezone information",
        )

    return parsed.astimezone(timezone.utc)


def source_context(
    payload: Mapping[str, Any],
    keys: tuple[str, ...],
) -> dict[str, Any]:
    return {
        key: payload[key]
        for key in keys
        if key in payload
    }


def quarantine_from_validation(
    *,
    source_type: SourceType,
    locator: RawLocator,
    exc: RecordValidationError,
) -> QuarantinedRecord:
    return QuarantinedRecord(
        source_type=source_type,
        locator=locator,
        reason_code=exc.reason_code,
        detail=exc.detail,
    )