from __future__ import annotations

from collections.abc import Mapping

from tracesoc.detection.models import (
    DetectionResult,
    DetectionState,
)
from tracesoc.models import SourceType


DETECTION_VERSION = "1.0.0"

DETECTION_ID_006 = "TRC-DET-006"
DETECTION_ID_007 = "TRC-DET-007"
DETECTION_ID_008 = "TRC-DET-008"

TITLE_006 = "PowerShell process creation observation"
TITLE_007 = "PowerShell-initiated network connection"
TITLE_008 = "PowerShell cross-process access observation"

_POWERSHELL_EXECUTABLES = {
    "powershell.exe",
    "pwsh.exe",
}


def _fields(event: object) -> Mapping:
    semantic_fields = getattr(
        event,
        "semantic_fields",
        None,
    )

    if isinstance(
        semantic_fields,
        Mapping,
    ):
        return semantic_fields

    fields = getattr(
        event,
        "fields",
        None,
    )

    if isinstance(
        fields,
        Mapping,
    ):
        return fields

    return {}


def _field(
    event: object,
    key: str,
) -> str:
    value = _fields(event).get(key)

    if value is None:
        return ""

    return str(value).strip()


def _event_id(event: object) -> str:
    value = getattr(
        event,
        "event_id",
        None,
    )

    if value is None:
        return ""

    return str(value).strip()


def _basename(value: str) -> str:
    normalized = (
        value
        .replace("\\", "/")
        .strip()
    )

    if not normalized:
        return ""

    return (
        normalized
        .rsplit("/", 1)[-1]
        .casefold()
    )


def _is_powershell(value: str) -> bool:
    return (
        _basename(value)
        in _POWERSHELL_EXECUTABLES
    )


def _result(
    *,
    detection_id: str,
    title: str,
    state: DetectionState,
    reason_code: str,
    rationale: str,
    contributing_event_ids: tuple[str, ...],
) -> DetectionResult:
    return DetectionResult(
        detection_id=detection_id,
        detection_version=DETECTION_VERSION,
        title=title,
        state=state,
        reason_code=reason_code,
        rationale=rationale,
        contributing_event_ids=contributing_event_ids,
    )


def _no_match(
    *,
    detection_id: str,
    title: str,
    reason_code: str,
    rationale: str,
) -> DetectionResult:
    return _result(
        detection_id=detection_id,
        title=title,
        state=DetectionState.NO_MATCH,
        reason_code=reason_code,
        rationale=rationale,
        contributing_event_ids=(),
    )


def detect_powershell_process_creation(
    event: object,
) -> DetectionResult:
    if (
        getattr(event, "source_type", None)
        != SourceType.SYSMON
    ):
        return _no_match(
            detection_id=DETECTION_ID_006,
            title=TITLE_006,
            reason_code="wrong_source",
            rationale="Event is not Sysmon.",
        )

    if (
        getattr(event, "event_type", "")
        != "process_create"
    ):
        return _no_match(
            detection_id=DETECTION_ID_006,
            title=TITLE_006,
            reason_code="wrong_event_type",
            rationale="Event is not process creation.",
        )

    process_name = _field(
        event,
        "process_name",
    )

    if not process_name:
        return _no_match(
            detection_id=DETECTION_ID_006,
            title=TITLE_006,
            reason_code="missing_process_name",
            rationale="Process identity is unavailable.",
        )

    if not _is_powershell(process_name):
        return _no_match(
            detection_id=DETECTION_ID_006,
            title=TITLE_006,
            reason_code="process_family_mismatch",
            rationale="Created process is not PowerShell.",
        )

    command_line = _field(
        event,
        "command_line",
    )

    if not command_line:
        return _no_match(
            detection_id=DETECTION_ID_006,
            title=TITLE_006,
            reason_code="missing_command_line",
            rationale="PowerShell command line is unavailable.",
        )

    event_id = _event_id(event)

    if not event_id:
        return _no_match(
            detection_id=DETECTION_ID_006,
            title=TITLE_006,
            reason_code="missing_event_id",
            rationale="Matching behavior lacks an event identifier.",
        )

    return _result(
        detection_id=DETECTION_ID_006,
        title=TITLE_006,
        state=DetectionState.MATCH,
        reason_code="powershell_process_creation_observed",
        rationale=(
            "Sysmon recorded creation of a PowerShell process "
            "with an observed command line."
        ),
        contributing_event_ids=(
            event_id,
        ),
    )


def detect_powershell_initiated_network_connection(
    event: object,
) -> DetectionResult:
    if (
        getattr(event, "source_type", None)
        != SourceType.SYSMON
    ):
        return _no_match(
            detection_id=DETECTION_ID_007,
            title=TITLE_007,
            reason_code="wrong_source",
            rationale="Event is not Sysmon.",
        )

    if (
        getattr(event, "event_type", "")
        != "network_connection"
    ):
        return _no_match(
            detection_id=DETECTION_ID_007,
            title=TITLE_007,
            reason_code="wrong_event_type",
            rationale="Event is not a network connection.",
        )

    process_name = _field(
        event,
        "process_name",
    )

    if not process_name:
        return _no_match(
            detection_id=DETECTION_ID_007,
            title=TITLE_007,
            reason_code="missing_process_name",
            rationale="Network process identity is unavailable.",
        )

    if not _is_powershell(process_name):
        return _no_match(
            detection_id=DETECTION_ID_007,
            title=TITLE_007,
            reason_code="process_family_mismatch",
            rationale="Network process is not PowerShell.",
        )

    initiated = _field(
        event,
        "initiated",
    ).casefold()

    if initiated not in {
        "true",
        "1",
        "yes",
    }:
        return _no_match(
            detection_id=DETECTION_ID_007,
            title=TITLE_007,
            reason_code="not_initiated",
            rationale=(
                "Network event is not recorded as initiated."
            ),
        )

    destination_ip = _field(
        event,
        "dst_ip",
    )

    destination_port = _field(
        event,
        "dst_port",
    )

    if (
        not destination_ip
        or not destination_port
    ):
        return _no_match(
            detection_id=DETECTION_ID_007,
            title=TITLE_007,
            reason_code="missing_destination",
            rationale=(
                "PowerShell network event lacks destination "
                "IP or destination port."
            ),
        )

    event_id = _event_id(event)

    if not event_id:
        return _no_match(
            detection_id=DETECTION_ID_007,
            title=TITLE_007,
            reason_code="missing_event_id",
            rationale="Matching behavior lacks an event identifier.",
        )

    return _result(
        detection_id=DETECTION_ID_007,
        title=TITLE_007,
        state=DetectionState.MATCH,
        reason_code=(
            "powershell_initiated_network_connection_observed"
        ),
        rationale=(
            "Sysmon recorded PowerShell initiating a network "
            "connection with a populated destination."
        ),
        contributing_event_ids=(
            event_id,
        ),
    )


def detect_powershell_cross_process_access(
    event: object,
) -> DetectionResult:
    if (
        getattr(event, "source_type", None)
        != SourceType.SYSMON
    ):
        return _no_match(
            detection_id=DETECTION_ID_008,
            title=TITLE_008,
            reason_code="wrong_source",
            rationale="Event is not Sysmon.",
        )

    if (
        getattr(event, "event_type", "")
        != "process_access"
    ):
        return _no_match(
            detection_id=DETECTION_ID_008,
            title=TITLE_008,
            reason_code="wrong_event_type",
            rationale="Event is not process access.",
        )

    source_process = _field(
        event,
        "source_process",
    )

    if not source_process:
        return _no_match(
            detection_id=DETECTION_ID_008,
            title=TITLE_008,
            reason_code="missing_source_process",
            rationale="Source process identity is unavailable.",
        )

    if not _is_powershell(source_process):
        return _no_match(
            detection_id=DETECTION_ID_008,
            title=TITLE_008,
            reason_code="source_process_family_mismatch",
            rationale="Process-access source is not PowerShell.",
        )

    source_process_id = _field(
        event,
        "source_process_id",
    )

    target_process = _field(
        event,
        "target_process",
    )

    target_process_id = _field(
        event,
        "target_process_id",
    )

    granted_access = _field(
        event,
        "granted_access",
    )

    if (
        not source_process_id
        or not target_process
        or not target_process_id
    ):
        return _no_match(
            detection_id=DETECTION_ID_008,
            title=TITLE_008,
            reason_code="missing_process_context",
            rationale=(
                "PowerShell process-access event lacks "
                "source or target process context."
            ),
        )

    if source_process_id == target_process_id:
        return _no_match(
            detection_id=DETECTION_ID_008,
            title=TITLE_008,
            reason_code="same_process",
            rationale=(
                "Source and target process identifiers are identical."
            ),
        )

    if not granted_access:
        return _no_match(
            detection_id=DETECTION_ID_008,
            title=TITLE_008,
            reason_code="missing_granted_access",
            rationale=(
                "PowerShell process-access event lacks an "
                "explicit granted-access value."
            ),
        )

    event_id = _event_id(event)

    if not event_id:
        return _no_match(
            detection_id=DETECTION_ID_008,
            title=TITLE_008,
            reason_code="missing_event_id",
            rationale="Matching behavior lacks an event identifier.",
        )

    return _result(
        detection_id=DETECTION_ID_008,
        title=TITLE_008,
        state=DetectionState.MATCH,
        reason_code=(
            "powershell_cross_process_access_observed"
        ),
        rationale=(
            "Sysmon recorded PowerShell accessing a different "
            "process with an explicit granted-access value."
        ),
        contributing_event_ids=(
            event_id,
        ),
    )