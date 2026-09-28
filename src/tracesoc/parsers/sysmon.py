from __future__ import annotations

from pathlib import Path
import re
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


ADAPTER_ID = "tracesoc-sysmon-jsonl-v1"
SCHEMA_VERSION = "1"

REAL_ADAPTER_ID = "tracesoc-sysmon-windows-event-xml-v1"
REAL_SCHEMA_VERSION = "1"
REAL_EVENT_TYPE = "sysmon_event"
REAL_PROVIDER = "Microsoft-Windows-Sysmon"
JSON_ADAPTER_ID = "tracesoc-sysmon-windows-event-json-v1"
JSON_SCHEMA_VERSION = "1"
PROCESS_CREATE_EVENT_TYPE = "process_create"
SYSMON_PROCESS_CREATE_EVENT_ID = 1

_REAL_SYSMON_BEHAVIORAL_PROMOTIONS = {
    3: (
        "network_connection",
        (
            ("Image", "process_name"),
            ("ProcessId", "process_id"),
            ("ProcessGuid", "process_guid"),
            ("SourceIp", "src_ip"),
            ("SourcePort", "src_port"),
            ("DestinationIp", "dst_ip"),
            ("DestinationHostname", "dst_hostname"),
            ("DestinationPort", "dst_port"),
            ("Protocol", "proto"),
            ("Initiated", "initiated"),
        ),
    ),
    10: (
        "process_access",
        (
            ("SourceImage", "source_process"),
            ("SourceProcessId", "source_process_id"),
            ("SourceProcessGUID", "source_process_guid"),
            ("SourceThreadId", "source_thread_id"),
            ("TargetImage", "target_process"),
            ("TargetProcessId", "target_process_id"),
            ("TargetProcessGUID", "target_process_guid"),
            ("GrantedAccess", "granted_access"),
            ("CallTrace", "call_trace"),
        ),
    ),
    11: (
        "file_create",
        (
            ("Image", "process_name"),
            ("ProcessId", "process_id"),
            ("ProcessGuid", "process_guid"),
            ("TargetFilename", "file_path"),
            ("CreationUtcTime", "file_creation_time_raw"),
        ),
    ),
    12: (
        "registry_delete",
        (
            ("Image", "process_name"),
            ("ProcessId", "process_id"),
            ("ProcessGuid", "process_guid"),
            ("TargetObject", "registry_path"),
            ("EventType", "registry_operation"),
        ),
    ),
    13: (
        "registry_set_value",
        (
            ("Image", "process_name"),
            ("ProcessId", "process_id"),
            ("ProcessGuid", "process_guid"),
            ("TargetObject", "registry_path"),
            ("Details", "registry_details"),
            ("EventType", "registry_operation"),
        ),
    ),
    17: (
        "named_pipe_create",
        (
            ("Image", "process_name"),
            ("ProcessId", "process_id"),
            ("ProcessGuid", "process_guid"),
            ("PipeName", "pipe_name"),
            ("EventType", "pipe_operation"),
        ),
    ),
    18: (
        "named_pipe_connect",
        (
            ("Image", "process_name"),
            ("ProcessId", "process_id"),
            ("ProcessGuid", "process_guid"),
            ("PipeName", "pipe_name"),
            ("EventType", "pipe_operation"),
        ),
    ),
    22: (
        "dns_query",
        (
            ("Image", "process_name"),
            ("ProcessId", "process_id"),
            ("ProcessGuid", "process_guid"),
            ("QueryName", "query_name"),
            ("QueryStatus", "query_status"),
            ("QueryResults", "query_results"),
        ),
    ),
    23: (
        "file_delete",
        (
            ("Image", "process_name"),
            ("ProcessId", "process_id"),
            ("ProcessGuid", "process_guid"),
            ("TargetFilename", "file_path"),
            ("Hashes", "hashes"),
            ("Archived", "archived"),
            ("IsExecutable", "is_executable"),
        ),
    ),
}


_EVENT_NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event",
}

_REAL_SYSMON_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}\.\d{3}$"
)

_EVENT_LOG_SYSTEM_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?Z$"
)


def _real_sysmon_required_text(
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
                "required real Sysmon XML field "
                f"is missing or empty: {field}"
            ),
        )

    return node.text.strip()


def _real_sysmon_required_decimal(
    parent: ET.Element,
    path: str,
    *,
    field: str,
) -> int:
    value = _real_sysmon_required_text(
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
                "real Sysmon XML field must be "
                f"decimal integer: {field}"
            ),
        ) from exc


def _real_sysmon_event_data(
    root: ET.Element,
) -> dict[str, str]:
    event_data = root.find(
        "e:EventData",
        _EVENT_NS,
    )

    fields: dict[str, str] = {}

    if event_data is None:
        return fields

    for node in event_data.findall(
        "e:Data",
        _EVENT_NS,
    ):
        name = (
            node.attrib
            .get("Name", "")
            .strip()
        )

        if not name:
            continue

        if name in fields:
            raise RecordValidationError(
                "duplicate_field",
                (
                    "duplicate real Sysmon EventData "
                    f"field: {name}"
                ),
            )

        fields[name] = (
            node.text
            if node.text is not None
            else ""
        ).strip()

    return fields


def _parse_real_sysmon_utc_time(
    value: str,
):
    """
    Parse the source-native Sysmon EventData UtcTime value.

    The observed real corpus encodes this field as
    YYYY-MM-DD HH:MM:SS.mmm. Sysmon defines its event timestamps
    in UTC; converting the source representation to an explicit
    ISO-8601 UTC representation is parsing, not clock correction.
    """

    if _REAL_SYSMON_UTC_RE.fullmatch(
        value
    ) is None:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Sysmon UtcTime does not match "
                "YYYY-MM-DD HH:MM:SS.mmm"
            ),
        )

    iso_utc = (
        value.replace(
            " ",
            "T",
            1,
        )
        + "Z"
    )

    try:
        return parse_utc_timestamp(
            iso_utc
        )
    except ValueError as exc:
        raise RecordValidationError(
            "invalid_field",
            "real Sysmon UtcTime is not a valid UTC timestamp",
        ) from exc


def _parse_real_sysmon_record(
    record: RawRecord,
) -> tuple[
    int,
    int,
    str,
    str,
    str,
    str,
]:
    try:
        root = ET.fromstring(
            record.raw_bytes
        )
    except ET.ParseError as exc:
        raise RecordValidationError(
            "invalid_record",
            "real Sysmon record is not valid XML",
        ) from exc

    system = root.find(
        "e:System",
        _EVENT_NS,
    )

    if system is None:
        raise RecordValidationError(
            "missing_field",
            "real Sysmon XML record has no System element",
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
            "real Sysmon Provider Name is missing",
        )

    if provider != REAL_PROVIDER:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Sysmon Provider Name is not "
                f"{REAL_PROVIDER}"
            ),
        )

    event_code = _real_sysmon_required_decimal(
        system,
        "e:EventID",
        field="EventID",
    )

    event_record_id = _real_sysmon_required_decimal(
        system,
        "e:EventRecordID",
        field="EventRecordID",
    )

    host = _real_sysmon_required_text(
        system,
        "e:Computer",
        field="Computer",
    )

    channel = _real_sysmon_required_text(
        system,
        "e:Channel",
        field="Channel",
    )

    time_node = system.find(
        "e:TimeCreated",
        _EVENT_NS,
    )

    event_log_system_time = (
        time_node.attrib
        .get("SystemTime", "")
        .strip()
        if time_node is not None
        else ""
    )

    if not event_log_system_time:
        raise RecordValidationError(
            "missing_field",
            (
                "real Sysmon TimeCreated/SystemTime "
                "is missing"
            ),
        )

    if _EVENT_LOG_SYSTEM_TIME_RE.fullmatch(
        event_log_system_time
    ) is None:
        raise RecordValidationError(
            "invalid_field",
            (
                "real Sysmon TimeCreated/SystemTime "
                "does not carry the expected explicit UTC Z form"
            ),
        )

    event_data = _real_sysmon_event_data(
        root
    )

    utc_time = event_data.get(
        "UtcTime",
        "",
    ).strip()

    if not utc_time:
        raise RecordValidationError(
            "missing_field",
            "real Sysmon EventData UtcTime is missing",
        )

    return (
        event_code,
        event_record_id,
        provider,
        host,
        channel,
        event_log_system_time,
        utc_time,
    )



def _promote_sysmon_event_data_semantics(
    *,
    event_data: Mapping[str, str],
    event_code: int,
) -> tuple[
    str,
    str | None,
    dict[str, object],
]:
    """
    Promote source-defined Sysmon semantics independent of representation.

    XML and declared Windows Event JSON representations both converge here.
    Event IDs select source-defined telemetry families only. They never act
    as maliciousness, fixture, scenario, or expected-answer selectors.
    """

    if event_code == SYSMON_PROCESS_CREATE_EVENT_ID:
        event_type = PROCESS_CREATE_EVENT_TYPE

        field_map = (
            (
                "Image",
                "process_name",
            ),
            (
                "ProcessId",
                "process_id",
            ),
            (
                "ProcessGuid",
                "process_guid",
            ),
            (
                "CommandLine",
                "command_line",
            ),
            (
                "Hashes",
                "hashes",
            ),
            (
                "ParentImage",
                "parent_process",
            ),
            (
                "ParentProcessId",
                "parent_process_id",
            ),
            (
                "ParentProcessGuid",
                "parent_process_guid",
            ),
            (
                "ParentCommandLine",
                "parent_command_line",
            ),
        )

    else:
        specification = (
            _REAL_SYSMON_BEHAVIORAL_PROMOTIONS.get(
                event_code
            )
        )

        if specification is None:
            return (
                REAL_EVENT_TYPE,
                None,
                {},
            )

        (
            event_type,
            field_map,
        ) = specification

    semantic_fields: dict[
        str,
        object,
    ] = {}

    for source_field, semantic_field in field_map:
        value = event_data.get(
            source_field,
            "",
        ).strip()

        if (
            value
            and value != "-"
        ):
            semantic_fields[
                semantic_field
            ] = value

    user = event_data.get(
        "User",
        "",
    ).strip()

    principal: str | None = None

    if (
        user
        and user not in {
            "-",
            "NULL SID",
        }
    ):
        principal = user

    return (
        event_type,
        principal,
        semantic_fields,
    )


def _promote_real_sysmon_semantics(
    *,
    record: RawRecord,
    event_code: int,
) -> tuple[
    str,
    str | None,
    dict[str, object],
]:
    """
    XML representation wrapper around the shared Sysmon semantic mapper.
    """

    try:
        root = ET.fromstring(
            record.raw_bytes
        )
    except ET.ParseError as exc:
        raise RecordValidationError(
            "invalid_record",
            "real Sysmon record is not valid XML",
        ) from exc

    event_data = _real_sysmon_event_data(
        root
    )

    return _promote_sysmon_event_data_semantics(
        event_data=event_data,
        event_code=event_code,
    )



def load_sysmon_windows_event_xml(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    """
    Normalize real Sysmon Windows Event XML into the generic
    CanonicalEvent contract.

    EventData UtcTime is the source-native activity timestamp and
    is normalized as OBSERVED UTC. TimeCreated/SystemTime is
    retained separately in source_context as event-log metadata.

    This layer intentionally does not interpret individual Sysmon
    EventIDs. Event-specific semantic promotion is a separate
    evidence-adjudicated step.
    """

    raw_batch = read_windows_event_xml_records(
        path,
        logical_source=logical_source,
        source_type=SourceType.SYSMON,
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
                event_log_system_time,
                utc_time,
            ) = _parse_real_sysmon_record(
                record
            )

            event_time = (
                _parse_real_sysmon_utc_time(
                    utc_time
                )
            )

            (
                event_type,
                principal,
                semantic_fields,
            ) = _promote_real_sysmon_semantics(
                record=record,
                event_code=event_code,
            )

            event_id = compute_event_id(
                locator=record.locator,
                source_type=SourceType.SYSMON,
                event_type=event_type,
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=SourceType.SYSMON,
                    event_type=event_type,
                    clock_state=ClockState.OBSERVED,
                    provenance=record.locator,
                    event_time_raw=utc_time,
                    event_time_utc=event_time,
                    host=host,
                    principal=principal,
                    semantic_fields=semantic_fields,
                    source_context={
                        "provider":
                            provider,
                        "event_code":
                            event_code,
                        "event_record_id":
                            event_record_id,
                        "channel":
                            channel,
                        "event_log_system_time":
                            event_log_system_time,
                    },
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=SourceType.SYSMON,
                    locator=record.locator,
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=SourceType.SYSMON,
        adapter_id=REAL_ADAPTER_ID,
        accepted=tuple(accepted),
        quarantined=tuple(quarantined),
    )



def load_sysmon_windows_event_json(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    """
    Normalize the declared Windows Event JSON representation of Sysmon.

    The JSON representation carries the same System/EventData semantics used
    by Windows Event XML. Representation-specific provenance remains distinct,
    while semantic promotion is shared with the XML adapter.
    """

    raw_batch = read_windows_event_json_records(
        path,
        logical_source=logical_source,
        source_type=SourceType.SYSMON,
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
                        "Sysmon Windows Event JSON Provider Name is not "
                        f"{REAL_PROVIDER}"
                    ),
                )

            event_data = dict(
                record.event_data
            )

            utc_time = event_data.get(
                "UtcTime",
                "",
            ).strip()

            if not utc_time:
                raise RecordValidationError(
                    "missing_field",
                    "Sysmon Windows Event JSON EventData UtcTime is missing",
                )

            event_time = (
                _parse_real_sysmon_utc_time(
                    utc_time
                )
            )

            (
                event_type,
                principal,
                semantic_fields,
            ) = _promote_sysmon_event_data_semantics(
                event_data=event_data,
                event_code=(
                    record.event_code
                ),
            )

            event_id = compute_event_id(
                locator=record.locator,
                source_type=SourceType.SYSMON,
                event_type=event_type,
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=SourceType.SYSMON,
                    event_type=event_type,
                    clock_state=ClockState.OBSERVED,
                    provenance=record.locator,
                    event_time_raw=utc_time,
                    event_time_utc=event_time,
                    host=record.computer,
                    principal=principal,
                    semantic_fields=(
                        semantic_fields
                    ),
                    source_context={
                        "provider":
                            record.provider,
                        "event_code":
                            record.event_code,
                        "event_record_id":
                            record.event_record_id,
                        "channel":
                            record.channel,
                        "event_log_system_time":
                            record.system_time,
                    },
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=SourceType.SYSMON,
                    locator=record.locator,
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=SourceType.SYSMON,
        adapter_id=JSON_ADAPTER_ID,
        accepted=tuple(
            accepted
        ),
        quarantined=tuple(
            quarantined
        ),
    )


def load_sysmon_jsonl(
    path: Path,
    *,
    logical_source: str,
) -> AdapterBatch:
    accepted = []
    quarantined = []

    for record in read_jsonl_records(
        path=path,
        logical_source=logical_source,
        source_type=SourceType.SYSMON,
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

            if event_type != "process_create":
                raise RecordValidationError(
                    "unsupported_event_type",
                    f"unsupported Sysmon event_type: {event_type}",
                )

            host = require_text(payload, "host")
            principal = require_text(payload, "principal")
            process_name = require_text(payload, "process_name")
            parent_process = require_text(payload, "parent_process")
            command_line = require_text(payload, "command_line")
            local_ip = require_text(payload, "local_ip")

            event_time = parse_utc_timestamp(timestamp)

            event_id = compute_event_id(
                locator=record.locator,
                source_type=SourceType.SYSMON,
                event_type=event_type,
            )

            accepted.append(
                CanonicalEvent(
                    event_id=event_id,
                    source_type=SourceType.SYSMON,
                    event_type=event_type,
                    clock_state=ClockState.OBSERVED,
                    provenance=record.locator,
                    event_time_raw=timestamp,
                    event_time_utc=event_time,
                    host=host,
                    principal=principal,
                    semantic_fields={
                        "process_name": process_name,
                        "parent_process": parent_process,
                        "command_line": command_line,
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
                    source_type=SourceType.SYSMON,
                    locator=record.locator,
                    exc=exc,
                )
            )

    return AdapterBatch(
        source_type=SourceType.SYSMON,
        adapter_id=ADAPTER_ID,
        accepted=tuple(accepted),
        quarantined=tuple(quarantined),
    )