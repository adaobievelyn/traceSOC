from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re

from tracesoc.correlation.models import (
    CorrelationState,
)
from tracesoc.detection.models import (
    DetectionResult,
)
from tracesoc.models import (
    SemanticEvent,
    SourceType,
)


CORRELATION_ID = "TRC-CORR-002"
CORRELATION_VERSION = "1.0.0"

RELATIONSHIP = (
    "powershell_process_corroborates_"
    "powershell_behavior"
)

_POWERSHELL_PROCESS_NAMES = {
    "powershell.exe",
    "pwsh.exe",
}


@dataclass(
    frozen=True,
    slots=True,
)
class ProcessCorrelationEdge:
    correlation_id: str
    correlation_version: str
    edge_id: str
    relationship: str
    source_event_id: str
    target_event_id: str
    delta_seconds: float
    process_name: str
    matched_dimensions: tuple[str, ...]
    local_ip: str | None = None
    principal: str | None = None
    process_id: str | None = None

    def __post_init__(
        self,
    ) -> None:
        if not self.edge_id:
            raise ValueError(
                "edge_id must not be empty"
            )

        if self.delta_seconds < 0:
            raise ValueError(
                "delta_seconds must be nonnegative"
            )

        if not self.process_name:
            raise ValueError(
                "process_name must not be empty"
            )

        if (
            self.correlation_version
            == "2.0.0"
        ):
            if not self.process_id:
                raise ValueError(
                    "source-native process correlation "
                    "requires process_id"
                )

        else:
            if not self.local_ip:
                raise ValueError(
                    "local_ip must not be empty"
                )

            if not self.principal:
                raise ValueError(
                    "principal must not be empty"
                )


@dataclass(
    frozen=True,
    slots=True,
)
class ProcessCorrelationResult:
    correlation_id: str
    correlation_version: str
    state: CorrelationState
    reason_code: str
    rationale: str
    edge: ProcessCorrelationEdge | None

    @property
    def matched(
        self,
    ) -> bool:
        return (
            self.state
            == CorrelationState.MATCH
        )

    def __post_init__(
        self,
    ) -> None:
        if (
            self.state
            == CorrelationState.MATCH
            and self.edge is None
        ):
            raise ValueError(
                "matched process correlation requires an edge"
            )

        if (
            self.state
            != CorrelationState.MATCH
            and self.edge is not None
        ):
            raise ValueError(
                "non-match process correlation must not contain an edge"
            )


def correlate_powershell_detection_with_sysmon_process(
    *,
    detection: DetectionResult,
    powershell_event: SemanticEvent,
    sysmon_event: SemanticEvent,
    max_seconds: float = 30.0,
) -> ProcessCorrelationResult:
    if max_seconds <= 0:
        raise ValueError(
            "max_seconds must be greater than zero"
        )

    if not detection.matched:
        return _no_match(
            "detection_not_matched",
            (
                "The PowerShell behavioral detector "
                "did not match."
            ),
        )

    if (
        powershell_event.event_id
        not in detection.contributing_event_ids
    ):
        return _no_match(
            "detection_event_mismatch",
            (
                "The PowerShell event is not a contributing "
                "event for the detection."
            ),
        )

    if (
        powershell_event.source_type
        != SourceType.POWERSHELL
    ):
        return _no_match(
            "source_type_mismatch",
            (
                "Source event is not PowerShell "
                "telemetry."
            ),
        )

    if (
        sysmon_event.source_type
        != SourceType.SYSMON
    ):
        return _no_match(
            "target_type_mismatch",
            (
                "Target event is not Sysmon "
                "telemetry."
            ),
        )

    if (
        sysmon_event.event_type
        != "process_create"
    ):
        return _no_match(
            "target_event_type_mismatch",
            (
                "Sysmon event is not a process "
                "creation observation."
            ),
        )

    if (
        powershell_event.event_time_utc
        is None
    ):
        return _no_match(
            "source_time_unavailable",
            (
                "PowerShell event has no normalized "
                "UTC time."
            ),
        )

    if (
        sysmon_event.event_time_utc
        is None
    ):
        return _no_match(
            "target_time_unavailable",
            (
                "Sysmon event has no normalized "
                "UTC time."
            ),
        )

    if (
        not powershell_event.host
        or not sysmon_event.host
    ):
        return _no_match(
            "host_unavailable",
            (
                "Both telemetry sources must "
                "identify the host."
            ),
        )

    if (
        powershell_event.host.casefold()
        != sysmon_event.host.casefold()
    ):
        return _no_match(
            "host_mismatch",
            (
                "PowerShell and Sysmon observations "
                "identify different hosts."
            ),
        )

    if (
        not powershell_event.principal
        or not sysmon_event.principal
    ):
        return _no_match(
            "principal_unavailable",
            (
                "Both telemetry sources must "
                "identify the principal."
            ),
        )

    if (
        powershell_event.principal.casefold()
        != sysmon_event.principal.casefold()
    ):
        return _no_match(
            "principal_mismatch",
            (
                "PowerShell and Sysmon observations "
                "identify different principals."
            ),
        )

    source_ip = _normalized_ip(
        powershell_event.fields.get(
            "local_ip"
        )
    )

    target_ip = _normalized_ip(
        sysmon_event.fields.get(
            "local_ip"
        )
    )

    if (
        source_ip is None
        or target_ip is None
    ):
        return _no_match(
            "local_ip_unavailable",
            (
                "Both telemetry sources require "
                "valid local IP addresses."
            ),
        )

    if source_ip != target_ip:
        return _no_match(
            "local_ip_mismatch",
            (
                "PowerShell and Sysmon local IP "
                "addresses do not match."
            ),
        )

    process_name = _process_basename(
        sysmon_event.fields.get(
            "process_name"
        )
    )

    if process_name is None:
        return _no_match(
            "process_name_unavailable",
            (
                "Sysmon process name is unavailable."
            ),
        )

    if (
        process_name.casefold()
        not in _POWERSHELL_PROCESS_NAMES
    ):
        return _no_match(
            "process_family_mismatch",
            (
                "Sysmon process creation is not "
                "a PowerShell process."
            ),
        )

    delta_seconds = (
        powershell_event.event_time_utc
        - sysmon_event.event_time_utc
    ).total_seconds()

    if delta_seconds < 0:
        return _no_match(
            "process_creation_after_behavior",
            (
                "Sysmon process creation occurs "
                "after the PowerShell behavior."
            ),
        )

    if delta_seconds > max_seconds:
        return _no_match(
            "outside_time_window",
            (
                "PowerShell behavior falls outside "
                "the bounded process-corroboration "
                "window."
            ),
        )

    dimensions = (
        "host",
        "principal",
        "local_ip",
        "powershell_process_family",
        "directional_time_window",
    )

    edge = ProcessCorrelationEdge(
        correlation_id=CORRELATION_ID,
        correlation_version=(
            CORRELATION_VERSION
        ),
        edge_id=_edge_id(
            source_event_id=(
                sysmon_event.event_id
            ),
            target_event_id=(
                powershell_event.event_id
            ),
            process_name=process_name,
            local_ip=source_ip,
            principal=(
                powershell_event.principal
            ),
            max_seconds=max_seconds,
        ),
        relationship=RELATIONSHIP,
        source_event_id=(
            sysmon_event.event_id
        ),
        target_event_id=(
            powershell_event.event_id
        ),
        delta_seconds=delta_seconds,
        process_name=process_name,
        local_ip=source_ip,
        principal=(
            powershell_event.principal
        ),
        matched_dimensions=dimensions,
    )

    return ProcessCorrelationResult(
        correlation_id=CORRELATION_ID,
        correlation_version=(
            CORRELATION_VERSION
        ),
        state=CorrelationState.MATCH,
        reason_code=(
            "powershell_process_corroborated"
        ),
        rationale=(
            "Sysmon process creation and detected "
            "PowerShell behavior agree on host, "
            "principal, local IP, PowerShell process "
            "family, and directional bounded time. "
            "This corroborates contemporaneous "
            "PowerShell execution but does not "
            "establish exact PID ancestry, causality, "
            "or malicious intent."
        ),
        edge=edge,
    )


def _process_basename(
    value: object,
) -> str | None:
    if not isinstance(
        value,
        str,
    ):
        return None

    stripped = value.strip()

    if not stripped:
        return None

    parts = re.split(
        r"[\\/]",
        stripped,
    )

    if not parts:
        return None

    basename = parts[-1].strip()

    if not basename:
        return None

    return basename


def _normalized_ip(
    value: object,
) -> str | None:
    if not isinstance(
        value,
        str,
    ):
        return None

    try:
        return str(
            ipaddress.ip_address(
                value.strip()
            )
        )
    except ValueError:
        return None


def _edge_id(
    *,
    source_event_id: str,
    target_event_id: str,
    process_name: str,
    local_ip: str,
    principal: str,
    max_seconds: float,
) -> str:
    material = {
        "correlation_id": (
            CORRELATION_ID
        ),
        "correlation_version": (
            CORRELATION_VERSION
        ),
        "relationship": RELATIONSHIP,
        "source_event_id": (
            source_event_id
        ),
        "target_event_id": (
            target_event_id
        ),
        "process_name": (
            process_name.casefold()
        ),
        "local_ip": local_ip,
        "principal": (
            principal.casefold()
        ),
        "max_seconds": max_seconds,
    }

    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return "edge_" + hashlib.sha256(
        encoded
    ).hexdigest()


def _no_match(
    reason_code: str,
    rationale: str,
) -> ProcessCorrelationResult:
    return ProcessCorrelationResult(
        correlation_id=CORRELATION_ID,
        correlation_version=(
            CORRELATION_VERSION
        ),
        state=CorrelationState.NO_MATCH,
        reason_code=reason_code,
        rationale=rationale,
        edge=None,
    )


SOURCE_NATIVE_CORRELATION_VERSION = "2.0.0"


def _source_native_process_id(
    value: object,
) -> str | None:
    if isinstance(
        value,
        bool,
    ):
        return None

    if isinstance(
        value,
        int,
    ):
        if value < 0:
            return None

        return str(
            value
        )

    if not isinstance(
        value,
        str,
    ):
        return None

    text = value.strip()

    if not text:
        return None

    try:
        number = int(
            text,
            10,
        )
    except ValueError:
        return None

    if number < 0:
        return None

    return str(
        number
    )


def _source_native_process_edge_id(
    *,
    source_event_id: str,
    target_event_id: str,
    detection_id: str,
    process_id: str,
    process_name: str,
    max_seconds: float,
) -> str:
    import hashlib

    material = "\x00".join(
        (
            CORRELATION_ID,
            SOURCE_NATIVE_CORRELATION_VERSION,
            source_event_id,
            target_event_id,
            detection_id,
            process_id,
            process_name.casefold(),
            format(
                max_seconds,
                ".6f",
            ),
        )
    )

    return (
        "edge_"
        + hashlib.sha256(
            material.encode(
                "utf-8"
            )
        ).hexdigest()
    )


def correlate_reconstructed_powershell_with_sysmon_process(
    *,
    detection: DetectionResult,
    script_block: object,
    powershell_event: SemanticEvent,
    sysmon_event: SemanticEvent,
    max_seconds: float = 30.0,
) -> ProcessCorrelationResult:
    """
    Correlate a matched reconstructed PowerShell ScriptBlock with a Sysmon
    process-creation event using source-native process identity.

    The non-temporal anchors are host, exact process identifier, and
    PowerShell process family. No local IP or principal equivalence is
    invented.
    """

    if max_seconds <= 0:
        raise ValueError(
            "max_seconds must be greater than zero"
        )

    if not detection.matched:
        return _no_match(
            "detection_not_matched",
            (
                "The reconstructed PowerShell "
                "behavioral detector did not match."
            ),
        )

    parent_event_ids = tuple(
        getattr(
            script_block,
            "parent_event_ids",
            (),
        )
    )

    if not parent_event_ids:
        return _no_match(
            "reconstruction_lineage_unavailable",
            (
                "The reconstructed ScriptBlock "
                "has no parent PowerShell events."
            ),
        )

    if (
        tuple(
            detection.contributing_event_ids
        )
        != parent_event_ids
    ):
        return _no_match(
            "detection_reconstruction_mismatch",
            (
                "The detection lineage does not exactly "
                "match the reconstructed ScriptBlock lineage."
            ),
        )

    if (
        powershell_event.event_id
        not in parent_event_ids
    ):
        return _no_match(
            "detection_event_mismatch",
            (
                "The PowerShell anchor event is not "
                "part of the reconstructed ScriptBlock."
            ),
        )

    if (
        powershell_event.source_type
        != SourceType.POWERSHELL
    ):
        return _no_match(
            "source_type_mismatch",
            (
                "Source event is not "
                "PowerShell telemetry."
            ),
        )

    if (
        sysmon_event.source_type
        != SourceType.SYSMON
    ):
        return _no_match(
            "target_type_mismatch",
            (
                "Target event is not "
                "Sysmon telemetry."
            ),
        )

    if (
        sysmon_event.event_type
        != "process_create"
    ):
        return _no_match(
            "target_event_type_mismatch",
            (
                "Sysmon event is not a "
                "process creation observation."
            ),
        )

    source_time = getattr(
        script_block,
        "first_event_time_utc",
        None,
    )

    if source_time is None:
        return _no_match(
            "source_time_unavailable",
            (
                "The reconstructed ScriptBlock "
                "has no first observed UTC time."
            ),
        )

    if (
        powershell_event.event_time_utc
        != source_time
    ):
        return _no_match(
            "source_anchor_time_mismatch",
            (
                "The PowerShell anchor event is not "
                "the first observed fragment of the "
                "reconstructed ScriptBlock."
            ),
        )

    if (
        sysmon_event.event_time_utc
        is None
    ):
        return _no_match(
            "target_time_unavailable",
            (
                "Sysmon event has no "
                "normalized UTC time."
            ),
        )

    block_host = getattr(
        script_block,
        "host",
        None,
    )

    if (
        not isinstance(
            block_host,
            str,
        )
        or not block_host.strip()
        or not sysmon_event.host
    ):
        return _no_match(
            "host_unavailable",
            (
                "Both reconstructed PowerShell "
                "evidence and Sysmon must "
                "identify the host."
            ),
        )

    if (
        block_host.casefold()
        != sysmon_event.host.casefold()
    ):
        return _no_match(
            "host_mismatch",
            (
                "PowerShell reconstruction and "
                "Sysmon identify different hosts."
            ),
        )

    source_process_id = (
        _source_native_process_id(
            getattr(
                script_block,
                "process_id",
                None,
            )
        )
    )

    target_process_id = (
        _source_native_process_id(
            sysmon_event.fields.get(
                "process_id"
            )
        )
    )

    if (
        source_process_id is None
        or target_process_id is None
    ):
        return _no_match(
            "process_id_unavailable",
            (
                "PowerShell reconstruction and Sysmon "
                "must expose valid process identifiers."
            ),
        )

    if (
        source_process_id
        != target_process_id
    ):
        return _no_match(
            "process_id_mismatch",
            (
                "PowerShell execution ProcessID and "
                "Sysmon ProcessId do not match."
            ),
        )

    process_name = _process_basename(
        sysmon_event.fields.get(
            "process_name"
        )
    )

    if process_name is None:
        return _no_match(
            "process_name_unavailable",
            (
                "Sysmon process name "
                "is unavailable."
            ),
        )

    if (
        process_name.casefold()
        not in _POWERSHELL_PROCESS_NAMES
    ):
        return _no_match(
            "process_family_mismatch",
            (
                "Sysmon process creation is not "
                "a PowerShell process."
            ),
        )

    delta_seconds = (
        source_time
        - sysmon_event.event_time_utc
    ).total_seconds()

    if delta_seconds < 0:
        return _no_match(
            "process_creation_after_behavior",
            (
                "Sysmon process creation occurs after "
                "the first observed PowerShell "
                "ScriptBlock fragment."
            ),
        )

    if delta_seconds > max_seconds:
        return _no_match(
            "outside_time_window",
            (
                "PowerShell ScriptBlock falls outside "
                "the bounded process-corroboration "
                "window."
            ),
        )

    dimensions = (
        "host",
        "process_id",
        "powershell_process_family",
        "directional_time_window",
    )

    edge = ProcessCorrelationEdge(
        correlation_id=(
            CORRELATION_ID
        ),
        correlation_version=(
            SOURCE_NATIVE_CORRELATION_VERSION
        ),
        edge_id=(
            _source_native_process_edge_id(
                source_event_id=(
                    sysmon_event.event_id
                ),
                target_event_id=(
                    powershell_event.event_id
                ),
                detection_id=(
                    detection.detection_id
                ),
                process_id=(
                    source_process_id
                ),
                process_name=(
                    process_name
                ),
                max_seconds=max_seconds,
            )
        ),
        relationship=RELATIONSHIP,
        source_event_id=(
            sysmon_event.event_id
        ),
        target_event_id=(
            powershell_event.event_id
        ),
        delta_seconds=(
            delta_seconds
        ),
        process_name=(
            process_name
        ),
        matched_dimensions=(
            dimensions
        ),
        process_id=(
            source_process_id
        ),
    )

    return ProcessCorrelationResult(
        correlation_id=(
            CORRELATION_ID
        ),
        correlation_version=(
            SOURCE_NATIVE_CORRELATION_VERSION
        ),
        state=(
            CorrelationState.MATCH
        ),
        reason_code=(
            "source_native_powershell_"
            "process_corroborated"
        ),
        rationale=(
            "Sysmon process creation and a detected reconstructed "
            "PowerShell ScriptBlock agree on host, exact process ID, "
            "PowerShell process family, and directional bounded time. "
            "This corroborates process-level execution evidence without "
            "inventing local-IP or principal equivalence and does not "
            "establish causality or malicious intent."
        ),
        edge=edge,
    )
