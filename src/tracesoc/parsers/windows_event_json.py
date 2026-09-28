from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from tracesoc.evidence.identity import raw_sha256
from tracesoc.models import RawLocator, SourceType
from tracesoc.parsers.common import (
    DecodedJsonlRecord,
    QuarantinedRecord,
    RecordValidationError,
    quarantine_from_validation,
    read_jsonl_records,
    require_object,
)


WINDOWS_EVENT_JSON_PROFILE_VERSION = "1"



@dataclass(frozen=True, slots=True)
class WindowsEventJsonRecord:
    """
    One recognized Windows Event JSON record.

    The object preserves representation-specific provenance while exposing
    source-defined Windows Event fields only. Execution and Security
    identities are retained when the source supplies them; their semantic
    necessity is determined by the family adapter, not by this reader.
    """

    locator: RawLocator
    provider: str
    event_code: int
    event_record_id: int
    system_time: str
    computer: str
    channel: str
    execution_process_id: str | None
    execution_thread_id: str | None
    security_user_id: str | None
    event_data: Mapping[str, str]



@dataclass(frozen=True, slots=True)
class WindowsEventJsonBatch:
    source_type: SourceType
    adapter_id: str
    accepted: tuple[WindowsEventJsonRecord, ...]
    quarantined: tuple[QuarantinedRecord, ...]

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)

    @property
    def quarantined_count(self) -> int:
        return len(self.quarantined)

    @property
    def total_records(self) -> int:
        return (
            self.accepted_count
            + self.quarantined_count
        )


def _mapping(
    payload: Mapping[str, Any],
    key: str,
) -> Mapping[str, Any]:
    value = payload.get(key)

    if not isinstance(
        value,
        dict,
    ):
        raise RecordValidationError(
            "missing_field",
            f"{key} must be a JSON object",
        )

    return value


def _required_text_value(
    value: Any,
    *,
    field: str,
) -> str:
    if isinstance(
        value,
        bool,
    ):
        raise RecordValidationError(
            "invalid_field",
            f"{field} must be text or an integer",
        )

    if isinstance(
        value,
        (
            str,
            int,
        ),
    ):
        rendered = str(
            value
        ).strip()

        if rendered:
            return rendered

    raise RecordValidationError(
        "missing_field",
        f"{field} is missing or empty",
    )


def _required_decimal(
    value: Any,
    *,
    field: str,
) -> int:
    rendered = _required_text_value(
        value,
        field=field,
    )

    if not rendered.isdecimal():
        raise RecordValidationError(
            "invalid_field",
            f"{field} must be decimal",
        )

    return int(
        rendered,
        10,
    )


def _event_data_map(
    payload: Mapping[str, Any],
) -> dict[str, str]:
    raw = _mapping(
        payload,
        "EventData",
    )

    mapped: dict[
        str,
        str,
    ] = {}

    for key, value in raw.items():
        if (
            not isinstance(
                key,
                str,
            )
            or not key.strip()
        ):
            raise RecordValidationError(
                "invalid_field",
                "EventData field names must be non-empty text",
            )

        if value is None:
            rendered = ""

        elif isinstance(
            value,
            bool,
        ):
            rendered = (
                "true"
                if value
                else "false"
            )

        elif isinstance(
            value,
            (
                str,
                int,
                float,
            ),
        ):
            rendered = str(
                value
            )

        else:
            raise RecordValidationError(
                "invalid_field",
                (
                    "EventData values must be scalar; "
                    f"{key} is {type(value).__name__}"
                ),
            )

        mapped[
            key
        ] = rendered

    return mapped



def _parse_profile(
    *,
    locator: RawLocator,
    payload: Any,
) -> WindowsEventJsonRecord:
    obj = require_object(
        payload
    )

    system = _mapping(
        obj,
        "System",
    )

    provider_object = _mapping(
        system,
        "Provider",
    )

    provider = _required_text_value(
        provider_object.get(
            "Name"
        ),
        field="System.Provider.Name",
    )

    event_code = _required_decimal(
        system.get(
            "EventID"
        ),
        field="System.EventID",
    )

    event_record_id = _required_decimal(
        system.get(
            "EventRecordID"
        ),
        field="System.EventRecordID",
    )

    time_created = _mapping(
        system,
        "TimeCreated",
    )

    system_time = _required_text_value(
        time_created.get(
            "SystemTime"
        ),
        field="System.TimeCreated.SystemTime",
    )

    computer = _required_text_value(
        system.get(
            "Computer"
        ),
        field="System.Computer",
    )

    channel = _required_text_value(
        system.get(
            "Channel"
        ),
        field="System.Channel",
    )

    execution_process_id: str | None = None
    execution_thread_id: str | None = None
    security_user_id: str | None = None

    execution = system.get(
        "Execution"
    )

    if execution is not None:
        if not isinstance(
            execution,
            dict,
        ):
            raise RecordValidationError(
                "invalid_field",
                "System.Execution must be a JSON object when present",
            )

        raw_process_id = execution.get(
            "ProcessID"
        )

        if raw_process_id is not None:
            execution_process_id = (
                _required_text_value(
                    raw_process_id,
                    field=(
                        "System.Execution.ProcessID"
                    ),
                )
            )

        raw_thread_id = execution.get(
            "ThreadID"
        )

        if raw_thread_id is not None:
            execution_thread_id = (
                _required_text_value(
                    raw_thread_id,
                    field=(
                        "System.Execution.ThreadID"
                    ),
                )
            )

    security = system.get(
        "Security"
    )

    if security is not None:
        if not isinstance(
            security,
            dict,
        ):
            raise RecordValidationError(
                "invalid_field",
                "System.Security must be a JSON object when present",
            )

        raw_user_id = security.get(
            "UserID"
        )

        if raw_user_id is not None:
            security_user_id = (
                _required_text_value(
                    raw_user_id,
                    field=(
                        "System.Security.UserID"
                    ),
                )
            )

    return WindowsEventJsonRecord(
        locator=locator,
        provider=provider,
        event_code=event_code,
        event_record_id=event_record_id,
        system_time=system_time,
        computer=computer,
        channel=channel,
        execution_process_id=(
            execution_process_id
        ),
        execution_thread_id=(
            execution_thread_id
        ),
        security_user_id=(
            security_user_id
        ),
        event_data=_event_data_map(
            obj
        ),
    )



def _single_json_decoded_record(
    *,
    path: Path,
    logical_source: str,
    source_type: SourceType,
    adapter_id: str,
    input_schema_version: str,
) -> DecodedJsonlRecord:
    raw = path.read_bytes()

    locator = RawLocator(
        logical_source=logical_source,
        record_index=0,
        line_number=1,
        byte_offset=0,
        byte_length=len(
            raw
        ),
        raw_sha256=raw_sha256(
            raw
        ),
        adapter_id=adapter_id,
        input_schema_version=(
            input_schema_version
        ),
    )

    try:
        decoded = raw.decode(
            "utf-8"
        )

        payload = json.loads(
            decoded
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        return DecodedJsonlRecord(
            locator=locator,
            payload=None,
            quarantine=QuarantinedRecord(
                source_type=source_type,
                locator=locator,
                reason_code=(
                    "json_parse_error"
                ),
                detail=str(
                    exc
                ),
            ),
        )

    return DecodedJsonlRecord(
        locator=locator,
        payload=payload,
        quarantine=None,
    )


def read_windows_event_json_records(
    path: Path,
    *,
    logical_source: str,
    source_type: SourceType,
    adapter_id: str,
    input_schema_version: str,
) -> WindowsEventJsonBatch:
    """
    Read one declared Windows Event JSON representation.

    Supported containers:
    - .jsonl: one JSON object per physical line;
    - .json: one JSON object for the whole artifact.

    The representation profile mirrors Windows Event XML structure:
    System.Provider.Name, System.EventID, System.EventRecordID,
    System.TimeCreated.SystemTime, System.Computer, System.Channel,
    and EventData name/value fields.

    This is intentionally not a generic "any JSON containing Windows terms"
    parser. Unknown JSON schemas are outside this profile.
    """

    suffix = path.suffix.lower()

    if suffix == ".jsonl":
        decoded_records = read_jsonl_records(
            path=path,
            logical_source=logical_source,
            source_type=source_type,
            adapter_id=adapter_id,
            input_schema_version=(
                input_schema_version
            ),
        )

    elif suffix == ".json":
        decoded_records = (
            _single_json_decoded_record(
                path=path,
                logical_source=logical_source,
                source_type=source_type,
                adapter_id=adapter_id,
                input_schema_version=(
                    input_schema_version
                ),
            ),
        )

    else:
        raise ValueError(
            "Windows Event JSON profile requires .json or .jsonl"
        )

    accepted: list[
        WindowsEventJsonRecord
    ] = []

    quarantined: list[
        QuarantinedRecord
    ] = []

    for decoded in decoded_records:
        if decoded.quarantine is not None:
            quarantined.append(
                decoded.quarantine
            )
            continue

        try:
            accepted.append(
                _parse_profile(
                    locator=(
                        decoded.locator
                    ),
                    payload=(
                        decoded.payload
                    ),
                )
            )

        except RecordValidationError as exc:
            quarantined.append(
                quarantine_from_validation(
                    source_type=source_type,
                    locator=decoded.locator,
                    exc=exc,
                )
            )

    return WindowsEventJsonBatch(
        source_type=source_type,
        adapter_id=adapter_id,
        accepted=tuple(
            accepted
        ),
        quarantined=tuple(
            quarantined
        ),
    )


def _probe_provider(
    payload: Any,
) -> str | None:
    """
    Structural probe only.

    It intentionally requires the Windows Event hierarchy rather than merely
    searching arbitrary JSON text for a provider name. Detailed field
    validation belongs to the adapter, where malformed supported records can
    be quarantined explicitly.
    """

    if not isinstance(
        payload,
        dict,
    ):
        return None

    system = payload.get(
        "System"
    )

    event_data = payload.get(
        "EventData"
    )

    if (
        not isinstance(
            system,
            dict,
        )
        or not isinstance(
            event_data,
            dict,
        )
    ):
        return None

    provider = system.get(
        "Provider"
    )

    if not isinstance(
        provider,
        dict,
    ):
        return None

    name = provider.get(
        "Name"
    )

    if not isinstance(
        name,
        str,
    ):
        return None

    name = name.strip()

    return (
        name
        if name
        else None
    )


def probe_windows_event_json_providers(
    *,
    raw_bytes: bytes,
    logical_source: str,
) -> tuple[str, ...]:
    """
    Return unique providers found in structurally recognized records.

    Malformed rows are ignored by the classifier probe. Once a supported
    provider is established, the real adapter performs complete record
    accounting and quarantines malformed rows.
    """

    suffix = Path(
        logical_source
    ).suffix.lower()

    providers: set[
        str
    ] = set()

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
            return ()

        provider = _probe_provider(
            payload
        )

        if provider is not None:
            providers.add(
                provider
            )

        return tuple(
            sorted(
                providers
            )
        )

    if suffix != ".jsonl":
        return ()

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

        provider = _probe_provider(
            payload
        )

        if provider is not None:
            providers.add(
                provider
            )

    return tuple(
        sorted(
            providers
        )
    )
