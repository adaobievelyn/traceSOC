from __future__ import annotations

from pathlib import Path
from typing import Mapping
import xml.etree.ElementTree as ET

from tracesoc.evidence.identity import compute_event_id
from tracesoc.models import CanonicalEvent, ClockState, SourceType
from tracesoc.parsers.common import (
    AdapterBatch,
    RecordValidationError,
    parse_utc_timestamp,
    quarantine_from_validation,
    read_jsonl_records,
    require_object,
    require_text,
    source_context,
)
from tracesoc.parsers.real_records import (
    RawRecord,
    read_windows_event_xml_records,
)


from tracesoc.parsers.windows_event_json import (
    read_windows_event_json_records,
)


ADAPTER_ID = "tracesoc-powershell-jsonl-v1"
SCHEMA_VERSION = "1"

REAL_ADAPTER_ID = "tracesoc-powershell-windows-event-xml-v1"
REAL_SCHEMA_VERSION = "1"
REAL_EVENT_TYPE = "powershell_event"
REAL_PROVIDER = "Microsoft-Windows-PowerShell"
JSON_ADAPTER_ID = "tracesoc-powershell-windows-event-json-v1"
JSON_SCHEMA_VERSION = "1"

_EVENT_NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event",
}


def _real_powershell_required_text(
    parent: ET.Element,
    path: str,
    *,
    field: str,
) -> str:
    node = parent.find(
        path,
        _EVENT_NS,
    )

    if (
        node is None
        or
        node.text is None
        or
        not node.text.strip()
    ):
        raise RecordValidationError(
            "missing_field",
            (
                "required real PowerShell XML field "
                f"is missing or empty: {field}"
            ),
        )

    return node.text.strip()


def _real_powershell_required_decimal(
    parent: ET.Element,
    path: str,
    *,
    field: str,
) -> int:
    value = _real_powershell_required_text(
        parent,
        path,
        field=field,
    )

    try:
        return int(
            value,
            10,
        )
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "real PowerShell XML field must be "
                f"a decimal integer: {field}"
            ),
        ) from exc


def _real_powershell_event_data(
    root: ET.Element,
) -> dict[str, str]:
    event_data = root.find(
        "e:EventData",
        _EVENT_NS,
    )

    fields: dict[str, str] = {}

    if event_data is None:
        return fields

    for index, node in enumerate(
        event_data.findall(
            "e:Data",
            _EVENT_NS,
        )
    ):
        name = (
            node.attrib
            .get("Name", "")
            .strip()
        )

        if not name:
            name = (
                f"<unnamed_{index}>"
            )

        if name in fields:
            raise RecordValidationError(
                "duplicate_field",
                (
                    "duplicate real PowerShell EventData "
                    f"field: {name}"
                ),
            )

        fields[name] = (
            node.text
            if node.text is not None
            else ""
        )

    return fields



def _validate_powershell_source_semantics(
    *,
    event_code: int,
    execution_process_id: str | None,
    execution_thread_id: str | None,
    security_user_id: str | None,
    event_data: Mapping[str, str],
) -> None:
    """
    Validate source-defined PowerShell fields needed downstream.

    This validation is intentionally representation-neutral. Windows Event
    XML and declared Windows Event JSON/JSONL both converge here before
    producing a powershell_event CanonicalEvent.
    """

    if event_code != 4104:
        return

    required_source_identity = (
        (
            "execution_process_id",
            execution_process_id,
        ),
        (
            "execution_thread_id",
            execution_thread_id,
        ),
        (
            "security_user_id",
            security_user_id,
        ),
    )

    for field, value in required_source_identity:
        if (
            not isinstance(
                value,
                str,
            )
            or not value.strip()
        ):
            raise RecordValidationError(
                "missing_field",
                (
                    "PowerShell 4104 field required "
                    "for ScriptBlock reconstruction "
                    f"is missing or empty: {field}"
                ),
            )

    script_block_id = event_data.get(
        "ScriptBlockId"
    )

    if (
        not isinstance(
            script_block_id,
            str,
        )
        or not script_block_id.strip()
    ):
        raise RecordValidationError(
            "missing_field",
            (
                "PowerShell 4104 EventData field "
                "is missing or empty: ScriptBlockId"
            ),
        )

    message_values: dict[
        str,
        int,
    ] = {}

    for field in (
        "MessageNumber",
        "MessageTotal",
    ):
        raw_value = event_data.get(
            field
        )

        if (
            not isinstance(
                raw_value,
                str,
            )
            or not raw_value.strip()
        ):
            raise RecordValidationError(
                "missing_field",
                (
                    "PowerShell 4104 EventData field "
                    f"is missing or empty: {field}"
                ),
            )

        try:
            number = int(
                raw_value.strip(),
                10,
            )
        except ValueError as exc:
            raise RecordValidationError(
                "invalid_field",
                (
                    "PowerShell 4104 EventData field "
                    f"must be a decimal integer: {field}"
                ),
            ) from exc

        if number <= 0:
            raise RecordValidationError(
                "invalid_field",
                (
                    "PowerShell 4104 EventData field "
                    f"must be greater than zero: {field}"
                ),
            )

        message_values[
            field
        ] = number

    if (
        message_values[
            "MessageNumber"
        ]
        > message_values[
            "MessageTotal"
        ]
    ):
        raise RecordValidationError(
            "invalid_field",
            (
                "PowerShell 4104 MessageNumber "
                "exceeds MessageTotal"
            ),
        )

    script_block_text = event_data.get(
        "ScriptBlockText"
    )

    if not isinstance(
        script_block_text,
        str,
    ):
        raise RecordValidationError(
            "missing_field",
            (
                "PowerShell 4104 EventData field "
                "is missing: ScriptBlockText"
            ),
        )

    if script_block_text == "":
        raise RecordValidationError(
            "missing_field",
            (
                "PowerShell 4104 EventData field "
                "is empty: ScriptBlockText"
            ),
        )


def _parse_real_powershell_record(
    record: RawRecord,
) -> tuple[
    int,
    int,
    str,
    str,
    str,
    str,
    str | None,
    str | None,
    str | None,
    dict[str, str],
]:
    try:
        root = ET.fromstring(
            record.raw_bytes
        )
    except ET.ParseError as exc:
        raise RecordValidationError(
            "invalid_record",
            "real PowerShell record is not valid XML",
        ) from exc

    system = root.find(
        "e:System",
        _EVENT_NS,
    )

    if system is None:
        raise RecordValidationError(
            "missing_field",
            "real PowerShell XML record has no System element",
        )

    provider_node = system.find(
        "e:Provider",
        _EVENT_NS,
    )

    provider = (
        provider_node.attrib
        .get("Name", "")
        .strip()
        if provider_node is not None
        else ""
    )

    if not provider:
        raise RecordValidationError(
            "missing_field",
            "real PowerShell Provider Name is missing",
        )

    if provider != REAL_PROVIDER:
        raise RecordValidationError(
            "invalid_field",
            (
                "real PowerShell Provider Name is not "
                f"{REAL_PROVIDER}"
            ),
        )

    event_code = _real_powershell_required_decimal(
        system,
        "e:EventID",
        field="EventID",
    )

    event_record_id = _real_powershell_required_decimal(
        system,
        "e:EventRecordID",
        field="EventRecordID",
    )

    host = _real_powershell_required_text(
        system,
        "e:Computer",
        field="Computer",
    )

    channel = _real_powershell_required_text(
        system,
        "e:Channel",
        field="Channel",
    )

    time_node = system.find(
        "e:TimeCreated",
        _EVENT_NS,
    )

    system_time = (
        time_node.attrib
        .get("SystemTime", "")
        .strip()
        if time_node is not None
        else ""
    )

    if not system_time:
        raise RecordValidationError(
            "missing_field",
            (
                "real PowerShell TimeCreated/SystemTime "
                "is missing"
            ),
        )

    # This adapter accepts only an explicitly UTC-zoned source
    # timestamp. It does not infer or correct a timezone.
    if not system_time.endswith("Z"):
        raise RecordValidationError(
            "invalid_field",
            (
                "real PowerShell TimeCreated/SystemTime "
                "does not carry explicit UTC Z"
            ),
        )

    try:
        parse_utc_timestamp(
            system_time
        )
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_field",
            (
                "real PowerShell TimeCreated/SystemTime "
                "is not a valid UTC timestamp"
            ),
        ) from exc

    execution_node = system.find(
        "e:Execution",
        _EVENT_NS,
    )

    execution_process_id: str | None = None
    execution_thread_id: str | None = None

    if execution_node is not None:

        raw_process_id = (
            execution_node.attrib
            .get("ProcessID", "")
            .strip()
        )

        raw_thread_id = (
            execution_node.attrib
            .get("ThreadID", "")
            .strip()
        )

        if raw_process_id:
            execution_process_id = raw_process_id

        if raw_thread_id:
            execution_thread_id = raw_thread_id

    security_node = system.find(
        "e:Security",
        _EVENT_NS,
    )

    security_user_id: str | None = None

    if security_node is not None:

        raw_user_id = (
            security_node.attrib
            .get("UserID", "")
            .strip()
        )

        if raw_user_id:
            security_user_id = raw_user_id

    event_data = _real_powershell_event_data(
        root
    )

    _validate_powershell_source_semantics(
        event_code=event_code,
        execution_process_id=execution_process_id,
        execution_thread_id=execution_thread_id,
        security_user_id=security_user_id,
        event_data=event_data,
    )

    return (
        event_code,
        event_record_id,
        provider,
        host,
        channel,
        system_time,
        execution_process_id,
        execution_thread_id,
        security_user_id,
        event_data,
    )


def load_powershell_windows_event_xml(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    """
    Normalize real PowerShell Windows Event XML into the bounded
    generic CanonicalEvent contract.

    TimeCreated/SystemTime is used only when the source supplies an
    explicit UTC Z timestamp, producing ClockState.OBSERVED.

    EventData is preserved losslessly at the parsed field level inside
    source_context. No ScriptBlock fragment is promoted to script_text
    and no Event ID is called script_execution at this layer.
    """

    raw_batch = read_windows_event_xml_records(
        path,
        logical_source=logical_source,
        source_type=SourceType.POWERSHELL,
        adapter_id=REAL_ADAPTER_ID,
        input_schema_version=REAL_SCHEMA_VERSION,
    )

    accepted: list[CanonicalEvent] = []

    quarantined = list(
        raw_batch.quarantined
    )

    for record in raw_batch.accepted:

        try:
            (
                event_code,
                event_record_id,
                provider,
                host,
                channel,
                system_time,
                execution_process_id,
                execution_thread_id,
                security_user_id,
                event_data,
            ) = _parse_real_powershell_record(
                record
            )

            event_time = parse_utc_timestamp(
                system_time
            )

            event_id = compute_event_id(
                locator=record.locator,
                source_type=SourceType.POWERSHELL,
                event_type=REAL_EVENT_TYPE,
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=SourceType.POWERSHELL,
                    event_type=REAL_EVENT_TYPE,
                    clock_state=ClockState.OBSERVED,
                    provenance=record.locator,
                    event_time_raw=system_time,
                    event_time_utc=event_time,
                    host=host,
                    principal=None,
                    semantic_fields={},
                    source_context={
                        "provider":
                            provider,
                        "event_code":
                            event_code,
                        "event_record_id":
                            event_record_id,
                        "channel":
                            channel,
                        "execution_process_id":
                            execution_process_id,
                        "execution_thread_id":
                            execution_thread_id,
                        "security_user_id":
                            security_user_id,
                        "event_data":
                            event_data,
                    },
                )
            )

        except RecordValidationError as exc:

            quarantined.append(
                quarantine_from_validation(
                    source_type=SourceType.POWERSHELL,
                    locator=record.locator,
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=SourceType.POWERSHELL,
        adapter_id=REAL_ADAPTER_ID,
        accepted=tuple(accepted),
        quarantined=tuple(quarantined),
    )



def load_powershell_windows_event_json(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    """
    Normalize declared PowerShell Windows Event JSON/JSONL.

    This route emits the same pre-reconstruction powershell_event contract as
    the Windows Event XML adapter. It does not promote ScriptBlockText to
    script_execution and does not bypass ScriptBlock reconstruction.
    """

    raw_batch = read_windows_event_json_records(
        path,
        logical_source=logical_source,
        source_type=SourceType.POWERSHELL,
        adapter_id=JSON_ADAPTER_ID,
        input_schema_version=(
            JSON_SCHEMA_VERSION
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
            if record.provider != REAL_PROVIDER:
                raise RecordValidationError(
                    "invalid_field",
                    (
                        "PowerShell Windows Event JSON Provider Name "
                        f"is not {REAL_PROVIDER}"
                    ),
                )

            system_time = (
                record.system_time.strip()
            )

            if not system_time.endswith(
                "Z"
            ):
                raise RecordValidationError(
                    "invalid_field",
                    (
                        "PowerShell Windows Event JSON "
                        "TimeCreated/SystemTime does not carry explicit UTC Z"
                    ),
                )

            try:
                event_time = (
                    parse_utc_timestamp(
                        system_time
                    )
                )
            except ValueError as exc:
                raise RecordValidationError(
                    "invalid_field",
                    (
                        "PowerShell Windows Event JSON "
                        "TimeCreated/SystemTime is not a valid UTC timestamp"
                    ),
                ) from exc

            event_data = dict(
                record.event_data
            )

            _validate_powershell_source_semantics(
                event_code=record.event_code,
                execution_process_id=(
                    record.execution_process_id
                ),
                execution_thread_id=(
                    record.execution_thread_id
                ),
                security_user_id=(
                    record.security_user_id
                ),
                event_data=event_data,
            )

            event_id = compute_event_id(
                locator=record.locator,
                source_type=(
                    SourceType.POWERSHELL
                ),
                event_type=(
                    REAL_EVENT_TYPE
                ),
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=(
                        SourceType.POWERSHELL
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
                        system_time
                    ),
                    event_time_utc=(
                        event_time
                    ),
                    host=(
                        record.computer
                    ),
                    principal=None,
                    semantic_fields={},
                    source_context={
                        "provider":
                            record.provider,
                        "event_code":
                            record.event_code,
                        "event_record_id":
                            record.event_record_id,
                        "channel":
                            record.channel,
                        "execution_process_id":
                            record.execution_process_id,
                        "execution_thread_id":
                            record.execution_thread_id,
                        "security_user_id":
                            record.security_user_id,
                        "event_data":
                            event_data,
                    },
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=(
                        SourceType.POWERSHELL
                    ),
                    locator=(
                        record.locator
                    ),
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=(
            SourceType.POWERSHELL
        ),
        adapter_id=(
            JSON_ADAPTER_ID
        ),
        accepted=tuple(
            accepted
        ),
        quarantined=tuple(
            quarantined
        ),
    )


def load_powershell_jsonl(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    accepted = []
    quarantined = []

    for record in read_jsonl_records(
        path=path,
        logical_source=logical_source,
        source_type=SourceType.POWERSHELL,
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

            if event_type != "script_execution":
                raise RecordValidationError(
                    "unsupported_event_type",
                    f"unsupported PowerShell event_type: {event_type}",
                )

            host = require_text(payload, "host")
            principal = require_text(payload, "principal")
            engine = require_text(payload, "engine")
            command_family = require_text(payload, "command_family")
            script_text = require_text(payload, "script_text")
            local_ip = require_text(payload, "local_ip")

            event_time = parse_utc_timestamp(timestamp)

            event_id = compute_event_id(
                locator=record.locator,
                source_type=SourceType.POWERSHELL,
                event_type=event_type,
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=SourceType.POWERSHELL,
                    event_type=event_type,
                    clock_state=ClockState.OBSERVED,
                    provenance=record.locator,
                    event_time_raw=timestamp,
                    event_time_utc=event_time,
                    host=host,
                    principal=principal,
                    semantic_fields={
                        "engine": engine,
                        "command_family": command_family,
                        "script_text": script_text,
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
                    source_type=SourceType.POWERSHELL,
                    locator=record.locator,
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=SourceType.POWERSHELL,
        adapter_id=ADAPTER_ID,
        accepted=tuple(accepted),
        quarantined=tuple(quarantined),
    )