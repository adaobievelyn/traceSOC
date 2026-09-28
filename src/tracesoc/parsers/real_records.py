from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from tracesoc.models import RawLocator, SourceType
from tracesoc.parsers.common import QuarantinedRecord


_XML_EVENT_START = re.compile(br"<Event(?:\s|>)")
_XML_EVENT_END = b"</Event>"

_SECURITY_SPLUNK_TIMESTAMP = re.compile(
    br"^\d{2}/\d{2}/\d{4} "
    br"\d{2}:\d{2}:\d{2} "
    br"(?:AM|PM)$"
)
_SECURITY_SPLUNK_SOURCE = re.compile(
    br"^SourceName=(.+)$"
)
_SECURITY_SPLUNK_EVENT_CODE = re.compile(
    br"^EventCode=(\d+)$"
)


@dataclass(frozen=True)
class RawRecord:
    """
    One raw source record with an exact provenance locator.

    raw_bytes contains exactly the bytes represented by the locator.
    Line terminators surrounding a record are not silently folded into
    that record.
    """

    locator: RawLocator
    raw_bytes: bytes
    field_names: tuple[str, ...] = ()
    field_values: tuple[str, ...] = ()

    @property
    def field_map(self) -> dict[str, str]:
        return dict(
            zip(
                self.field_names,
                self.field_values,
                strict=True,
            )
        )


@dataclass(frozen=True)
class RawRecordBatch:
    source_type: SourceType
    adapter_id: str
    accepted: tuple[RawRecord, ...]
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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _locator(
    *,
    logical_source: str,
    record_index: int,
    line_number: int,
    byte_offset: int,
    record_bytes: bytes,
    adapter_id: str,
    input_schema_version: str,
) -> RawLocator:
    return RawLocator(
        logical_source=logical_source,
        record_index=record_index,
        line_number=line_number,
        byte_offset=byte_offset,
        byte_length=len(record_bytes),
        raw_sha256=_sha256(record_bytes),
        adapter_id=adapter_id,
        input_schema_version=input_schema_version,
    )


def _quarantine(
    *,
    source_type: SourceType,
    logical_source: str,
    record_index: int,
    line_number: int,
    byte_offset: int,
    record_bytes: bytes,
    adapter_id: str,
    input_schema_version: str,
    reason_code: str,
    detail: str,
) -> QuarantinedRecord:
    return QuarantinedRecord(
        source_type=source_type,
        locator=_locator(
            logical_source=logical_source,
            record_index=record_index,
            line_number=line_number,
            byte_offset=byte_offset,
            record_bytes=record_bytes,
            adapter_id=adapter_id,
            input_schema_version=input_schema_version,
        ),
        reason_code=reason_code,
        detail=detail,
    )


def _xml_gap_is_ignorable(
    gap: bytes,
    *,
    initial: bool,
) -> bool:
    candidate = gap

    if initial and candidate.startswith(b"\xef\xbb\xbf"):
        candidate = candidate[3:]

    return not candidate.strip(b" \t\r\n")


def read_windows_event_xml_records(
    path: Path,
    *,
    logical_source: str,
    source_type: SourceType,
    adapter_id: str,
    input_schema_version: str,
) -> RawRecordBatch:
    """
    Split a concatenated Windows Event XML stream into exact event records.

    This reader performs record-boundary work only. It does not interpret
    EventID, provider, EventData, labels, attack meaning, or scenario
    semantics.

    A record is the exact byte range from <Event ...> through </Event>.
    Inter-record whitespace is not part of either event. Unexpected
    non-whitespace bytes and unterminated events are retained as quarantine.
    """

    raw_file = path.read_bytes()

    accepted: list[RawRecord] = []
    quarantined: list[QuarantinedRecord] = []

    cursor = 0
    current_line = 1
    record_index = 0
    first_gap = True

    while cursor < len(raw_file):
        match = _XML_EVENT_START.search(
            raw_file,
            cursor,
        )

        if match is None:
            tail = raw_file[cursor:]

            if tail and not _xml_gap_is_ignorable(
                tail,
                initial=first_gap,
            ):
                quarantined.append(
                    _quarantine(
                        source_type=source_type,
                        logical_source=logical_source,
                        record_index=record_index,
                        line_number=current_line,
                        byte_offset=cursor,
                        record_bytes=tail,
                        adapter_id=adapter_id,
                        input_schema_version=input_schema_version,
                        reason_code="xml_interstitial_bytes",
                        detail=(
                            "non-whitespace bytes remain outside "
                            "a complete Windows Event XML record"
                        ),
                    )
                )

            break

        start = match.start()
        gap = raw_file[cursor:start]

        if gap:
            if not _xml_gap_is_ignorable(
                gap,
                initial=first_gap,
            ):
                quarantined.append(
                    _quarantine(
                        source_type=source_type,
                        logical_source=logical_source,
                        record_index=record_index,
                        line_number=current_line,
                        byte_offset=cursor,
                        record_bytes=gap,
                        adapter_id=adapter_id,
                        input_schema_version=input_schema_version,
                        reason_code="xml_interstitial_bytes",
                        detail=(
                            "unexpected non-whitespace bytes before "
                            "a Windows Event XML record"
                        ),
                    )
                )
                record_index += 1

            current_line += gap.count(b"\n")

        first_gap = False
        event_line = current_line

        close = raw_file.find(
            _XML_EVENT_END,
            start,
        )

        if close < 0:
            record_bytes = raw_file[start:]

            quarantined.append(
                _quarantine(
                    source_type=source_type,
                    logical_source=logical_source,
                    record_index=record_index,
                    line_number=event_line,
                    byte_offset=start,
                    record_bytes=record_bytes,
                    adapter_id=adapter_id,
                    input_schema_version=input_schema_version,
                    reason_code="xml_event_unterminated",
                    detail=(
                        "Windows Event XML record begins with <Event "
                        "but has no closing </Event>"
                    ),
                )
            )
            break

        end = close + len(_XML_EVENT_END)
        record_bytes = raw_file[start:end]

        accepted.append(
            RawRecord(
                locator=_locator(
                    logical_source=logical_source,
                    record_index=record_index,
                    line_number=event_line,
                    byte_offset=start,
                    record_bytes=record_bytes,
                    adapter_id=adapter_id,
                    input_schema_version=input_schema_version,
                ),
                raw_bytes=record_bytes,
            )
        )

        record_index += 1
        current_line += record_bytes.count(b"\n")
        cursor = end

    return RawRecordBatch(
        source_type=source_type,
        adapter_id=adapter_id,
        accepted=tuple(accepted),
        quarantined=tuple(quarantined),
    )


def _line_without_terminator(
    line: bytes,
) -> bytes:
    if line.endswith(b"\r\n"):
        return line[:-2]

    if line.endswith(
        (
            b"\n",
            b"\r",
        )
    ):
        return line[:-1]

    return line


def read_windows_security_splunk_records(
    path: Path,
    *,
    logical_source: str,
    source_type: SourceType = SourceType.WINDOWS_SECURITY,
    adapter_id: str,
    input_schema_version: str,
) -> RawRecordBatch:
    """
    Split the observed multiline Splunk Windows Security export format.

    Boundary contract:

    A structural candidate begins with a standalone Splunk timestamp
    immediately followed by LogName=Security.

    A valid record additionally requires a non-empty SourceName field
    and numeric EventCode field on the next two physical lines.

    Record bytes extend from the candidate timestamp byte through the
    byte immediately before the next structural candidate, or through
    EOF for the final record.

    This layer performs record-boundary work only. It does not interpret
    EventCode meaning, publisher meaning, account data, process data,
    attack labels, scenario identity, or malicious intent.

    Exact source line endings are preserved because records are sliced
    directly from the original byte stream rather than reconstructed
    from decoded text.
    """

    raw_file = path.read_bytes()

    accepted: list[RawRecord] = []
    quarantined: list[QuarantinedRecord] = []

    if not raw_file:
        return RawRecordBatch(
            source_type=source_type,
            adapter_id=adapter_id,
            accepted=(),
            quarantined=(),
        )

    lines: list[
        tuple[
            int,
            int,
            bytes,
        ]
    ] = []

    offset = 0

    for line_number, full_line in enumerate(
        raw_file.splitlines(keepends=True),
        1,
    ):
        content = _line_without_terminator(
            full_line
        )

        lines.append(
            (
                line_number,
                offset,
                content,
            )
        )

        offset += len(full_line)

    if offset != len(raw_file):
        raise ValueError(
            "Windows Security line-byte accounting "
            "does not equal source byte length"
        )

    candidates: list[
        tuple[
            int,
            bool,
        ]
    ] = []

    for index, (
        _line_number,
        _line_offset,
        content,
    ) in enumerate(lines):

        if not _SECURITY_SPLUNK_TIMESTAMP.fullmatch(
            content
        ):
            continue

        # Timestamp-looking message text is not enough to create
        # a boundary. The observed structural record header also
        # requires the Security LogName line immediately after it.
        if (
            index + 1 >= len(lines)
            or
            lines[index + 1][2]
            != b"LogName=Security"
        ):
            continue

        source_valid = (
            index + 2 < len(lines)
            and
            _SECURITY_SPLUNK_SOURCE.fullmatch(
                lines[index + 2][2]
            )
            is not None
        )

        event_code_valid = (
            index + 3 < len(lines)
            and
            _SECURITY_SPLUNK_EVENT_CODE.fullmatch(
                lines[index + 3][2]
            )
            is not None
        )

        candidates.append(
            (
                index,
                source_valid
                and event_code_valid,
            )
        )

    record_index = 0

    if not candidates:
        quarantined.append(
            _quarantine(
                source_type=source_type,
                logical_source=logical_source,
                record_index=record_index,
                line_number=1,
                byte_offset=0,
                record_bytes=raw_file,
                adapter_id=adapter_id,
                input_schema_version=input_schema_version,
                reason_code=(
                    "windows_security_record_boundary_not_found"
                ),
                detail=(
                    "no timestamp plus LogName=Security "
                    "structural record boundary was found"
                ),
            )
        )

        return RawRecordBatch(
            source_type=source_type,
            adapter_id=adapter_id,
            accepted=(),
            quarantined=tuple(quarantined),
        )

    first_candidate_offset = lines[
        candidates[0][0]
    ][1]

    prefix = raw_file[
        :first_candidate_offset
    ]

    if prefix and prefix.strip(
        b" \t\r\n"
    ):
        quarantined.append(
            _quarantine(
                source_type=source_type,
                logical_source=logical_source,
                record_index=record_index,
                line_number=1,
                byte_offset=0,
                record_bytes=prefix,
                adapter_id=adapter_id,
                input_schema_version=input_schema_version,
                reason_code=(
                    "windows_security_interstitial_bytes"
                ),
                detail=(
                    "non-whitespace bytes precede the "
                    "first Windows Security record boundary"
                ),
            )
        )

        record_index += 1

    for candidate_position, (
        line_index,
        header_valid,
    ) in enumerate(candidates):

        line_number, start, _ = lines[
            line_index
        ]

        if candidate_position + 1 < len(
            candidates
        ):
            next_line_index = candidates[
                candidate_position + 1
            ][0]

            end = lines[
                next_line_index
            ][1]

        else:
            end = len(raw_file)

        record_bytes = raw_file[
            start:end
        ]

        if not header_valid:
            quarantined.append(
                _quarantine(
                    source_type=source_type,
                    logical_source=logical_source,
                    record_index=record_index,
                    line_number=line_number,
                    byte_offset=start,
                    record_bytes=record_bytes,
                    adapter_id=adapter_id,
                    input_schema_version=input_schema_version,
                    reason_code=(
                        "windows_security_header_malformed"
                    ),
                    detail=(
                        "timestamp and LogName=Security "
                        "were present but SourceName was empty/"
                        "missing or EventCode was non-numeric/"
                        "missing"
                    ),
                )
            )

        else:
            accepted.append(
                RawRecord(
                    locator=_locator(
                        logical_source=logical_source,
                        record_index=record_index,
                        line_number=line_number,
                        byte_offset=start,
                        record_bytes=record_bytes,
                        adapter_id=adapter_id,
                        input_schema_version=input_schema_version,
                    ),
                    raw_bytes=record_bytes,
                )
            )

        record_index += 1

    return RawRecordBatch(
        source_type=source_type,
        adapter_id=adapter_id,
        accepted=tuple(accepted),
        quarantined=tuple(quarantined),
    )


def _decode_zeek_separator(
    token: bytes,
) -> bytes:
    if len(token) == 1:
        return token

    if (
        len(token) == 4
        and token.startswith(b"\\x")
    ):
        try:
            return bytes(
                [int(token[2:].decode("ascii"), 16)]
            )
        except (
            UnicodeDecodeError,
            ValueError,
        ) as exc:
            raise ValueError(
                "invalid Zeek hexadecimal separator"
            ) from exc

    raise ValueError(
        "unsupported Zeek separator declaration"
    )


def read_zeek_ascii_records(
    path: Path,
    *,
    logical_source: str,
    source_type: SourceType = SourceType.ZEEK,
    adapter_id: str,
    input_schema_version: str,
) -> RawRecordBatch:
    """
    Read Zeek ASCII/TSV records using the source-declared #separator
    and #fields header.

    Header/comment rows are structural metadata, not events.

    Data rows preserve exact line bytes (excluding only the line
    terminator), byte offset, line number and SHA-256. Field names and
    values are decoded only to establish the schema mapping. No label
    field receives special treatment at this layer.
    """

    raw_file = path.read_bytes()

    separator = b"\t"
    field_names: tuple[str, ...] | None = None

    accepted: list[RawRecord] = []
    quarantined: list[QuarantinedRecord] = []

    offset = 0
    record_index = 0

    for line_number, full_line in enumerate(
        raw_file.splitlines(keepends=True),
        1,
    ):
        row = full_line.rstrip(b"\r\n")

        if row.startswith(b"#separator "):
            token = row[len(b"#separator "):]

            try:
                separator = _decode_zeek_separator(
                    token
                )
            except ValueError as exc:
                quarantined.append(
                    _quarantine(
                        source_type=source_type,
                        logical_source=logical_source,
                        record_index=record_index,
                        line_number=line_number,
                        byte_offset=offset,
                        record_bytes=row,
                        adapter_id=adapter_id,
                        input_schema_version=input_schema_version,
                        reason_code="zeek_invalid_separator",
                        detail=str(exc),
                    )
                )
                record_index += 1

            offset += len(full_line)
            continue

        if row.startswith(b"#fields"):
            payload = row[len(b"#fields"):]

            if payload.startswith(separator):
                payload = payload[len(separator):]

            try:
                decoded_fields = tuple(
                    item.decode("utf-8")
                    for item in payload.split(
                        separator
                    )
                    if item
                )
            except UnicodeDecodeError as exc:
                quarantined.append(
                    _quarantine(
                        source_type=source_type,
                        logical_source=logical_source,
                        record_index=record_index,
                        line_number=line_number,
                        byte_offset=offset,
                        record_bytes=row,
                        adapter_id=adapter_id,
                        input_schema_version=input_schema_version,
                        reason_code="zeek_header_decode_error",
                        detail=str(exc),
                    )
                )
                record_index += 1
            else:
                if not decoded_fields:
                    quarantined.append(
                        _quarantine(
                            source_type=source_type,
                            logical_source=logical_source,
                            record_index=record_index,
                            line_number=line_number,
                            byte_offset=offset,
                            record_bytes=row,
                            adapter_id=adapter_id,
                            input_schema_version=input_schema_version,
                            reason_code="zeek_empty_fields_header",
                            detail=(
                                "#fields header did not declare "
                                "any fields"
                            ),
                        )
                    )
                    record_index += 1
                else:
                    field_names = decoded_fields

            offset += len(full_line)
            continue

        if (
            not row
            or row.startswith(b"#")
        ):
            offset += len(full_line)
            continue

        locator = _locator(
            logical_source=logical_source,
            record_index=record_index,
            line_number=line_number,
            byte_offset=offset,
            record_bytes=row,
            adapter_id=adapter_id,
            input_schema_version=input_schema_version,
        )

        if field_names is None:
            quarantined.append(
                QuarantinedRecord(
                    source_type=source_type,
                    locator=locator,
                    reason_code="zeek_missing_fields_header",
                    detail=(
                        "Zeek data row appeared before a valid "
                        "#fields header"
                    ),
                )
            )
            record_index += 1
            offset += len(full_line)
            continue

        parts = row.split(separator)

        if len(parts) != len(field_names):
            quarantined.append(
                QuarantinedRecord(
                    source_type=source_type,
                    locator=locator,
                    reason_code="zeek_field_count_mismatch",
                    detail=(
                        f"expected {len(field_names)} fields "
                        f"but observed {len(parts)}"
                    ),
                )
            )
            record_index += 1
            offset += len(full_line)
            continue

        try:
            field_values = tuple(
                value.decode("utf-8")
                for value in parts
            )
        except UnicodeDecodeError as exc:
            quarantined.append(
                QuarantinedRecord(
                    source_type=source_type,
                    locator=locator,
                    reason_code="zeek_decode_error",
                    detail=str(exc),
                )
            )
        else:
            accepted.append(
                RawRecord(
                    locator=locator,
                    raw_bytes=row,
                    field_names=field_names,
                    field_values=field_values,
                )
            )

        record_index += 1
        offset += len(full_line)

    return RawRecordBatch(
        source_type=source_type,
        adapter_id=adapter_id,
        accepted=tuple(accepted),
        quarantined=tuple(quarantined),
    )
