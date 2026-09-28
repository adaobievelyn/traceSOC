from __future__ import annotations

from pathlib import Path
from typing import Mapping
import xml.etree.ElementTree as ET

from tracesoc.evidence.identity import compute_event_id
from tracesoc.models import CanonicalEvent, ClockState, RawLocator, SourceType
from tracesoc.parsers.common import (
    AdapterBatch,
    RecordValidationError,
    parse_utc_timestamp,
    quarantine_from_validation,
    read_jsonl_records,
    require_int,
    require_object,
    require_text,
    source_context,
)
from tracesoc.parsers.real_records import (
    RawRecord,
    read_windows_event_xml_records,
    read_windows_security_splunk_records,
)
from tracesoc.parsers.windows_event_json import (
    read_windows_event_json_records,
)


ADAPTER_ID = "tracesoc-windows-security-jsonl-v1"
SCHEMA_VERSION = "1"


REAL_ADAPTER_ID = "tracesoc-windows-security-splunk-v1"
REAL_SCHEMA_VERSION = "1"
REAL_EVENT_TYPE = "windows_security_event"
PROCESS_CREATE_EVENT_TYPE = "process_create"
WINDOWS_SECURITY_PROCESS_CREATE_EVENT_CODE = 4688

WINDOWS_SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
WINDOWS_SECURITY_CHANNEL = "Security"

XML_ADAPTER_ID = "tracesoc-windows-security-windows-event-xml-v1"
XML_SCHEMA_VERSION = "1"

WINDOWS_EVENT_JSON_ADAPTER_ID = (
    "tracesoc-windows-security-windows-event-json-v1"
)
WINDOWS_EVENT_JSON_SCHEMA_VERSION = "1"

_REAL_REQUIRED_HEADER_FIELDS = (
    "LogName",
    "SourceName",
    "EventCode",
    "EventType",
    "Type",
    "ComputerName",
    "TaskCategory",
    "OpCode",
    "RecordNumber",
    "Keywords",
    "Message",
)


def _decode_real_ascii(
    value: bytes,
    *,
    field: str,
) -> str:
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Windows Security top-level field "
                f"is not ASCII: {field}"
            ),
        ) from exc

    if not decoded.strip():
        raise RecordValidationError(
            "invalid_field",
            (
                "real Windows Security top-level field "
                f"is empty: {field}"
            ),
        )

    return decoded.strip()


def _parse_real_windows_security_header(
    record: RawRecord,
) -> tuple[
    str,
    dict[str, str],
]:
    lines = record.raw_bytes.splitlines()

    if not lines:
        raise RecordValidationError(
            "invalid_record",
            "real Windows Security record is empty",
        )

    timestamp = _decode_real_ascii(
        lines[0],
        field="timestamp",
    )

    headers: dict[str, str] = {}

    for line in lines[1:]:
        if b"=" not in line:
            break

        key_bytes, value_bytes = line.split(
            b"=",
            1,
        )

        try:
            key = key_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RecordValidationError(
                "invalid_field",
                "real Windows Security header key is not ASCII",
            ) from exc

        if key in headers:
            raise RecordValidationError(
                "duplicate_field",
                (
                    "duplicate real Windows Security "
                    f"top-level field: {key}"
                ),
            )

        headers[key] = _decode_real_ascii(
            value_bytes,
            field=key,
        )

        # Message is the final top-level metadata line.
        # Remaining lines are the multiline event body.
        if key == "Message":
            break

    missing = [
        key
        for key in _REAL_REQUIRED_HEADER_FIELDS
        if key not in headers
    ]

    if missing:
        raise RecordValidationError(
            "missing_field",
            (
                "required real Windows Security "
                "top-level fields missing: "
                + ",".join(missing)
            ),
        )

    if headers["LogName"] != "Security":
        raise RecordValidationError(
            "invalid_field",
            "LogName must equal Security",
        )

    return timestamp, headers


def _real_windows_security_int(
    headers: dict[str, str],
    key: str,
) -> int:
    value = headers[key]

    try:
        return int(value, 10)
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Windows Security field must "
                f"be decimal integer: {key}"
            ),
        ) from exc


def _parse_real_windows_security_body_fields(
    record: RawRecord,
) -> dict[tuple[str, str], str]:
    """
    Parse indented section fields from the multiline Windows Security
    message body.

    This parser does not assign attack meaning. It preserves the
    source-native section/field structure only.
    """

    lines = record.raw_bytes.splitlines()

    message_index: int | None = None

    for index, line in enumerate(lines):
        if line.startswith(b"Message="):
            message_index = index
            break

    if message_index is None:
        raise RecordValidationError(
            "missing_field",
            "real Windows Security record has no Message header",
        )

    current_section: str | None = None
    fields: dict[tuple[str, str], str] = {}

    for raw_line in lines[message_index + 1:]:

        try:
            text = raw_line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RecordValidationError(
                "invalid_field",
                (
                    "real Windows Security message body "
                    "is not valid UTF-8"
                ),
            ) from exc

        if not text.strip():
            continue

        stripped = text.strip()

        # Section headings observed in the export are unindented and
        # terminate with a colon, e.g. "Process Information:".
        if (
            not text.startswith((" ", "\t"))
            and stripped.endswith(":")
        ):
            current_section = stripped[:-1].strip()
            continue

        # Structured body fields are indented.
        if (
            current_section is None
            or
            not text.startswith((" ", "\t"))
            or
            ":" not in stripped
        ):
            continue

        label, value = stripped.split(
            ":",
            1,
        )

        label = label.strip()
        value = value.strip()

        if not label:
            continue

        key = (
            current_section,
            label,
        )

        if key in fields:
            raise RecordValidationError(
                "duplicate_field",
                (
                    "duplicate Windows Security body field: "
                    f"{current_section}/{label}"
                ),
            )

        fields[key] = value

    return fields



def _windows_security_event_data_value(
    event_data: Mapping[str, str],
    field: str,
) -> str | None:
    value = event_data.get(
        field
    )

    if value is None:
        return None

    if not isinstance(
        value,
        str,
    ):
        raise RecordValidationError(
            "invalid_field",
            (
                "Windows Security EventData value "
                f"must be text: {field}"
            ),
        )

    return value.strip()


def _promote_windows_security_event_data(
    *,
    event_code: int,
    event_data: Mapping[str, str],
) -> tuple[
    str,
    str | None,
    dict[str, object],
]:
    """
    Representation-neutral Windows Security semantic promotion.

    Only Event ID 4688 is currently adjudicated for specialized semantic
    promotion. Other event IDs remain generic Windows Security events.

    The native Windows EventData names are the source contract:
    SubjectUserSid, NewProcessId, NewProcessName, ProcessId,
    ParentProcessName and CommandLine.
    """

    if (
        event_code
        != WINDOWS_SECURITY_PROCESS_CREATE_EVENT_CODE
    ):
        return (
            REAL_EVENT_TYPE,
            None,
            {},
        )

    new_process_id = (
        _windows_security_event_data_value(
            event_data,
            "NewProcessId",
        )
    )

    new_process_name = (
        _windows_security_event_data_value(
            event_data,
            "NewProcessName",
        )
    )

    creator_process_id = (
        _windows_security_event_data_value(
            event_data,
            "ProcessId",
        )
    )

    if (
        not new_process_id
        or not new_process_name
        or not creator_process_id
    ):
        return (
            REAL_EVENT_TYPE,
            None,
            {},
        )

    semantic_fields: dict[
        str,
        object,
    ] = {
        "process_name":
            new_process_name,
        "process_id":
            new_process_id,
        "parent_process_id":
            creator_process_id,
    }

    parent_process = (
        _windows_security_event_data_value(
            event_data,
            "ParentProcessName",
        )
    )

    if parent_process:
        semantic_fields[
            "parent_process"
        ] = parent_process

    command_line = (
        _windows_security_event_data_value(
            event_data,
            "CommandLine",
        )
    )

    if command_line:
        semantic_fields[
            "command_line"
        ] = command_line

    creator_security_id = (
        _windows_security_event_data_value(
            event_data,
            "SubjectUserSid",
        )
    )

    principal: str | None = None

    if (
        creator_security_id
        and creator_security_id
        not in {
            "-",
            "NULL SID",
        }
    ):
        principal = (
            creator_security_id
        )

    return (
        PROCESS_CREATE_EVENT_TYPE,
        principal,
        semantic_fields,
    )



def _promote_real_windows_security_semantics(
    *,
    record: RawRecord,
    event_code: int,
) -> tuple[
    str,
    str | None,
    dict[str, object],
]:
    """
    Bridge the observed Splunk multiline representation into the same
    Windows Security semantic mapper used by Windows Event XML/JSON.

    The representation-specific body labels are translated only where the
    source supplies equivalent Windows Security process-creation facts.
    """

    if (
        event_code
        != WINDOWS_SECURITY_PROCESS_CREATE_EVENT_CODE
    ):
        return (
            REAL_EVENT_TYPE,
            None,
            {},
        )

    body = (
        _parse_real_windows_security_body_fields(
            record
        )
    )

    event_data: dict[
        str,
        str,
    ] = {}

    field_bridge = (
        (
            "SubjectUserSid",
            (
                "Creator Subject",
                "Security ID",
            ),
        ),
        (
            "NewProcessId",
            (
                "Process Information",
                "New Process ID",
            ),
        ),
        (
            "NewProcessName",
            (
                "Process Information",
                "New Process Name",
            ),
        ),
        (
            "ProcessId",
            (
                "Process Information",
                "Creator Process ID",
            ),
        ),
        (
            "ParentProcessName",
            (
                "Process Information",
                "Creator Process Name",
            ),
        ),
        (
            "CommandLine",
            (
                "Process Information",
                "Process Command Line",
            ),
        ),
    )

    for native_name, body_key in field_bridge:
        value = body.get(
            body_key
        )

        if value is not None:
            event_data[
                native_name
            ] = value

    return (
        _promote_windows_security_event_data(
            event_code=event_code,
            event_data=event_data,
        )
    )




_WINDOWS_EVENT_NAMESPACE = (
    "{http://schemas.microsoft.com/win/2004/08/events/event}"
)


def _windows_security_required_xml_text(
    parent: ET.Element,
    child_name: str,
    *,
    field: str,
) -> str:
    child = parent.find(
        _WINDOWS_EVENT_NAMESPACE
        + child_name
    )

    if (
        child is None
        or child.text is None
        or not child.text.strip()
    ):
        raise RecordValidationError(
            "missing_field",
            (
                "Windows Security XML required field "
                f"is missing or empty: {field}"
            ),
        )

    return child.text.strip()


def _windows_security_required_decimal(
    value: str,
    *,
    field: str,
) -> int:
    try:
        return int(
            value,
            10,
        )
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "Windows Security field must be "
                f"a decimal integer: {field}"
            ),
        ) from exc


def _windows_security_xml_event_data(
    event_root: ET.Element,
) -> dict[str, str]:
    event_data_node = event_root.find(
        _WINDOWS_EVENT_NAMESPACE
        + "EventData"
    )

    if event_data_node is None:
        raise RecordValidationError(
            "missing_field",
            "Windows Security XML EventData is missing",
        )

    event_data: dict[
        str,
        str,
    ] = {}

    for data_node in event_data_node.findall(
        _WINDOWS_EVENT_NAMESPACE
        + "Data"
    ):
        name = (
            data_node.attrib.get(
                "Name",
                "",
            ).strip()
        )

        if not name:
            raise RecordValidationError(
                "missing_field",
                (
                    "Windows Security XML EventData "
                    "entry is missing Name"
                ),
            )

        if name in event_data:
            raise RecordValidationError(
                "duplicate_field",
                (
                    "duplicate Windows Security "
                    f"EventData field: {name}"
                ),
            )

        event_data[
            name
        ] = (
            data_node.text
            if data_node.text is not None
            else ""
        )

    return event_data


def _canonical_windows_security_windows_event(
    *,
    locator: RawLocator,
    provider: str,
    event_code: int,
    event_record_id: int,
    system_time: str,
    computer: str,
    channel: str,
    event_data: Mapping[str, str],
) -> CanonicalEvent:
    if provider != WINDOWS_SECURITY_PROVIDER:
        raise RecordValidationError(
            "invalid_field",
            (
                "Windows Security Provider Name must equal "
                + WINDOWS_SECURITY_PROVIDER
            ),
        )

    if channel != WINDOWS_SECURITY_CHANNEL:
        raise RecordValidationError(
            "invalid_field",
            (
                "Windows Security channel must equal "
                + WINDOWS_SECURITY_CHANNEL
            ),
        )

    source_time = (
        system_time.strip()
    )

    if not source_time.endswith(
        "Z"
    ):
        raise RecordValidationError(
            "invalid_field",
            (
                "Windows Security Windows Event "
                "SystemTime must carry explicit UTC Z"
            ),
        )

    try:
        event_time = (
            parse_utc_timestamp(
                source_time
            )
        )
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "Windows Security Windows Event "
                "SystemTime is not a valid UTC timestamp"
            ),
        ) from exc

    (
        event_type,
        principal,
        semantic_fields,
    ) = (
        _promote_windows_security_event_data(
            event_code=event_code,
            event_data=event_data,
        )
    )

    event_id = compute_event_id(
        locator=locator,
        source_type=(
            SourceType.WINDOWS_SECURITY
        ),
        event_type=event_type,
    )

    return CanonicalEvent(
        event_id=event_id,
        source_type=(
            SourceType.WINDOWS_SECURITY
        ),
        event_type=event_type,
        clock_state=(
            ClockState.OBSERVED
        ),
        provenance=locator,
        event_time_raw=source_time,
        event_time_utc=event_time,
        host=computer,
        principal=principal,
        semantic_fields=(
            semantic_fields
        ),
        source_context={
            "log_name":
                channel,
            "provider":
                provider,
            "event_code":
                event_code,
            "record_number":
                event_record_id,
            "event_data":
                dict(
                    event_data
                ),
        },
    )


def _parse_windows_security_xml_record(
    record: RawRecord,
) -> CanonicalEvent:
    try:
        root = ET.fromstring(
            record.raw_bytes
        )
    except ET.ParseError as exc:
        raise RecordValidationError(
            "xml_parse_error",
            str(
                exc
            ),
        ) from exc

    if root.tag != (
        _WINDOWS_EVENT_NAMESPACE
        + "Event"
    ):
        raise RecordValidationError(
            "invalid_record",
            (
                "Windows Security XML root must be "
                "Windows Event Event"
            ),
        )

    system = root.find(
        _WINDOWS_EVENT_NAMESPACE
        + "System"
    )

    if system is None:
        raise RecordValidationError(
            "missing_field",
            "Windows Security XML System is missing",
        )

    provider_node = system.find(
        _WINDOWS_EVENT_NAMESPACE
        + "Provider"
    )

    if provider_node is None:
        raise RecordValidationError(
            "missing_field",
            (
                "Windows Security XML "
                "System.Provider is missing"
            ),
        )

    provider = (
        provider_node.attrib.get(
            "Name",
            "",
        ).strip()
    )

    if not provider:
        raise RecordValidationError(
            "missing_field",
            (
                "Windows Security XML "
                "System.Provider.Name is missing"
            ),
        )

    event_code = (
        _windows_security_required_decimal(
            _windows_security_required_xml_text(
                system,
                "EventID",
                field="System.EventID",
            ),
            field="System.EventID",
        )
    )

    event_record_id = (
        _windows_security_required_decimal(
            _windows_security_required_xml_text(
                system,
                "EventRecordID",
                field="System.EventRecordID",
            ),
            field="System.EventRecordID",
        )
    )

    time_created = system.find(
        _WINDOWS_EVENT_NAMESPACE
        + "TimeCreated"
    )

    if time_created is None:
        raise RecordValidationError(
            "missing_field",
            (
                "Windows Security XML "
                "System.TimeCreated is missing"
            ),
        )

    system_time = (
        time_created.attrib.get(
            "SystemTime",
            "",
        ).strip()
    )

    if not system_time:
        raise RecordValidationError(
            "missing_field",
            (
                "Windows Security XML "
                "System.TimeCreated.SystemTime is missing"
            ),
        )

    computer = (
        _windows_security_required_xml_text(
            system,
            "Computer",
            field="System.Computer",
        )
    )

    channel = (
        _windows_security_required_xml_text(
            system,
            "Channel",
            field="System.Channel",
        )
    )

    event_data = (
        _windows_security_xml_event_data(
            root
        )
    )

    return (
        _canonical_windows_security_windows_event(
            locator=record.locator,
            provider=provider,
            event_code=event_code,
            event_record_id=event_record_id,
            system_time=system_time,
            computer=computer,
            channel=channel,
            event_data=event_data,
        )
    )


def load_windows_security_windows_event_xml(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    raw_batch = (
        read_windows_event_xml_records(
            path,
            logical_source=logical_source,
            source_type=(
                SourceType.WINDOWS_SECURITY
            ),
            adapter_id=(
                XML_ADAPTER_ID
            ),
            input_schema_version=(
                XML_SCHEMA_VERSION
            ),
        )
    )

    accepted: list[
        CanonicalEvent
    ] = []

    quarantined = list(
        raw_batch.quarantined
    )

    for record in raw_batch.accepted:
        try:
            accepted.append(
                _parse_windows_security_xml_record(
                    record
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=(
                        SourceType.WINDOWS_SECURITY
                    ),
                    locator=(
                        record.locator
                    ),
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=(
            SourceType.WINDOWS_SECURITY
        ),
        adapter_id=(
            XML_ADAPTER_ID
        ),
        accepted=tuple(
            accepted
        ),
        quarantined=tuple(
            quarantined
        ),
    )


def load_windows_security_windows_event_json(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    raw_batch = (
        read_windows_event_json_records(
            path,
            logical_source=logical_source,
            source_type=(
                SourceType.WINDOWS_SECURITY
            ),
            adapter_id=(
                WINDOWS_EVENT_JSON_ADAPTER_ID
            ),
            input_schema_version=(
                WINDOWS_EVENT_JSON_SCHEMA_VERSION
            ),
        )
    )

    accepted: list[
        CanonicalEvent
    ] = []

    quarantined = list(
        raw_batch.quarantined
    )

    for record in raw_batch.accepted:
        try:
            accepted.append(
                _canonical_windows_security_windows_event(
                    locator=record.locator,
                    provider=record.provider,
                    event_code=record.event_code,
                    event_record_id=(
                        record.event_record_id
                    ),
                    system_time=(
                        record.system_time
                    ),
                    computer=(
                        record.computer
                    ),
                    channel=(
                        record.channel
                    ),
                    event_data=(
                        record.event_data
                    ),
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=(
                        SourceType.WINDOWS_SECURITY
                    ),
                    locator=(
                        record.locator
                    ),
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=(
            SourceType.WINDOWS_SECURITY
        ),
        adapter_id=(
            WINDOWS_EVENT_JSON_ADAPTER_ID
        ),
        accepted=tuple(
            accepted
        ),
        quarantined=tuple(
            quarantined
        ),
    )


def load_windows_security_splunk(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    """
    Normalize the observed Splunk Windows Security text export.

    This is the generic canonical baseline only.

    The source timestamp is retained verbatim but no UTC value is
    fabricated because the acquired source and current project
    documentation do not establish a timezone for this timestamp.

    EventCode, provider and related source-native header metadata are
    retained as source_context. They are not exposed as detector-facing
    semantic fields at this generic layer.

    Event-specific semantic promotion is intentionally deferred until
    each event family is separately evidence-adjudicated.
    """

    raw_batch = read_windows_security_splunk_records(
        path,
        logical_source=logical_source,
        source_type=SourceType.WINDOWS_SECURITY,
        adapter_id=REAL_ADAPTER_ID,
        input_schema_version=REAL_SCHEMA_VERSION,
    )

    accepted: list[CanonicalEvent] = []
    quarantined = list(
        raw_batch.quarantined
    )

    for record in raw_batch.accepted:
        try:
            timestamp, headers = (
                _parse_real_windows_security_header(
                    record
                )
            )

            event_code = _real_windows_security_int(
                headers,
                "EventCode",
            )

            windows_event_type = (
                _real_windows_security_int(
                    headers,
                    "EventType",
                )
            )

            record_number = (
                _real_windows_security_int(
                    headers,
                    "RecordNumber",
                )
            )

            host = headers["ComputerName"]

            (
                event_type,
                principal,
                semantic_fields,
            ) = _promote_real_windows_security_semantics(
                record=record,
                event_code=event_code,
            )

            event_id = compute_event_id(
                locator=record.locator,
                source_type=SourceType.WINDOWS_SECURITY,
                event_type=event_type,
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=(
                        SourceType.WINDOWS_SECURITY
                    ),
                    event_type=event_type,
                    clock_state=(
                        ClockState.UNRESOLVED
                    ),
                    provenance=record.locator,
                    event_time_raw=timestamp,
                    event_time_utc=None,
                    host=host,
                    principal=principal,
                    semantic_fields=semantic_fields,
                    source_context={
                        "log_name":
                            headers["LogName"],
                        "provider":
                            headers["SourceName"],
                        "event_code":
                            event_code,
                        "windows_event_type":
                            windows_event_type,
                        "type":
                            headers["Type"],
                        "task_category":
                            headers["TaskCategory"],
                        "opcode":
                            headers["OpCode"],
                        "record_number":
                            record_number,
                        "keywords":
                            headers["Keywords"],
                        "message":
                            headers["Message"],
                    },
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=(
                        SourceType.WINDOWS_SECURITY
                    ),
                    locator=record.locator,
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=SourceType.WINDOWS_SECURITY,
        adapter_id=REAL_ADAPTER_ID,
        accepted=tuple(accepted),
        quarantined=tuple(quarantined),
    )


def load_windows_security_jsonl(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    accepted = []
    quarantined = []

    for record in read_jsonl_records(
        path=path,
        logical_source=logical_source,
        source_type=SourceType.WINDOWS_SECURITY,
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

            if event_type != "logon":
                raise RecordValidationError(
                    "unsupported_event_type",
                    f"unsupported Windows Security event_type: {event_type}",
                )

            host = require_text(payload, "host")
            principal = require_text(payload, "principal")
            logon_type = require_int(payload, "logon_type")
            status = require_text(payload, "status")
            source_ip = require_text(payload, "source_ip")
            local_ip = require_text(payload, "local_ip")

            event_time = parse_utc_timestamp(timestamp)

            event_id = compute_event_id(
                locator=record.locator,
                source_type=SourceType.WINDOWS_SECURITY,
                event_type=event_type,
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=SourceType.WINDOWS_SECURITY,
                    event_type=event_type,
                    clock_state=ClockState.OBSERVED,
                    provenance=record.locator,
                    event_time_raw=timestamp,
                    event_time_utc=event_time,
                    host=host,
                    principal=principal,
                    semantic_fields={
                        "logon_type": logon_type,
                        "status": status,
                        "source_ip": source_ip,
                        "local_ip": local_ip,
                    },
                    source_context=source_context(
                        payload,
                        (
                            "provider",
                            "event_code",
                            "fixture_id",
                            "expected_answer",
                        ),
                    ),
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=SourceType.WINDOWS_SECURITY,
                    locator=record.locator,
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=SourceType.WINDOWS_SECURITY,
        adapter_id=ADAPTER_ID,
        accepted=tuple(accepted),
        quarantined=tuple(quarantined),
    )