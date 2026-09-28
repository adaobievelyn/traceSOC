from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from tracesoc.correlation.models import (
    CorrelationState,
)
from tracesoc.models import (
    SemanticEvent,
    SourceType,
)


CORRELATION_ID = "TRC-CORR-004"
CORRELATION_VERSION = "1.0.0"

RELATIONSHIP = (
    "windows_security_sysmon_process_corroboration"
)

DEFAULT_MAX_SECONDS = 5.0


@dataclass(
    frozen=True,
    slots=True,
)
class SecuritySysmonProcessEdge:
    correlation_id: str
    correlation_version: str
    edge_id: str
    relationship: str
    source_event_id: str
    target_event_id: str
    delta_seconds: float
    process_id: str
    process_name: str
    matched_dimensions: tuple[str, ...]
    parent_process_id: str | None = None
    parent_process: str | None = None

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

        if not self.process_id:
            raise ValueError(
                "process_id must not be empty"
            )

        if not self.process_name:
            raise ValueError(
                "process_name must not be empty"
            )

        if not self.matched_dimensions:
            raise ValueError(
                "matched_dimensions must not be empty"
            )


@dataclass(
    frozen=True,
    slots=True,
)
class SecuritySysmonProcessResult:
    correlation_id: str
    correlation_version: str
    state: CorrelationState
    reason_code: str
    rationale: str
    edge: SecuritySysmonProcessEdge | None

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
                "matched Security/Sysmon process "
                "correlation requires an edge"
            )

        if (
            self.state
            != CorrelationState.MATCH
            and self.edge is not None
        ):
            raise ValueError(
                "non-match Security/Sysmon process "
                "correlation must not contain an edge"
            )


def _fields(
    event: SemanticEvent,
) -> object:
    value = getattr(
        event,
        "fields",
        None,
    )

    if not hasattr(
        value,
        "get",
    ):
        return {}

    return value


def normalize_windows_process_id(
    value: object,
) -> str | None:
    """
    Normalize decimal or hexadecimal Windows process identifiers.

    Windows Security 4688 commonly renders process IDs in hexadecimal,
    while Sysmon Event 1 commonly renders them in decimal. The result is
    a base-10 string so equivalent source values can be compared without
    representation-specific string equality.
    """

    if isinstance(
        value,
        bool,
    ):
        return None

    if isinstance(
        value,
        int,
    ):
        number = value

    elif isinstance(
        value,
        str,
    ):
        text = value.strip()

        if not text:
            return None

        try:
            if text.casefold().startswith(
                "0x"
            ):
                number = int(
                    text,
                    16,
                )
            else:
                number = int(
                    text,
                    10,
                )
        except ValueError:
            return None

    else:
        return None

    if number < 0:
        return None

    return str(
        number
    )


def normalize_windows_process_path(
    value: object,
) -> str | None:
    if not isinstance(
        value,
        str,
    ):
        return None

    text = value.strip()

    if not text:
        return None

    if (
        len(text) >= 2
        and text[0] == text[-1]
        and text[0] in {
            '"',
            "'",
        }
    ):
        text = text[1:-1].strip()

    if not text:
        return None

    return text.replace(
        "/",
        "\\",
    ).casefold()


def _edge_id(
    *,
    source_event_id: str,
    target_event_id: str,
    process_id: str,
    process_name: str,
    parent_process_id: str | None,
    parent_process: str | None,
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
        "process_id": process_id,
        "process_name": process_name,
        "parent_process_id": (
            parent_process_id
        ),
        "parent_process": (
            parent_process
        ),
        "max_seconds": max_seconds,
    }

    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    ).encode(
        "utf-8"
    )

    return (
        "edge_"
        + hashlib.sha256(
            encoded
        ).hexdigest()
    )


def _no_match(
    reason_code: str,
    rationale: str,
) -> SecuritySysmonProcessResult:
    return SecuritySysmonProcessResult(
        correlation_id=(
            CORRELATION_ID
        ),
        correlation_version=(
            CORRELATION_VERSION
        ),
        state=(
            CorrelationState.NO_MATCH
        ),
        reason_code=reason_code,
        rationale=rationale,
        edge=None,
    )


def correlate_windows_security_process_with_sysmon(
    *,
    security_event: SemanticEvent,
    sysmon_event: SemanticEvent,
    max_seconds: float = DEFAULT_MAX_SECONDS,
) -> SecuritySysmonProcessResult:
    """
    Corroborate Windows Security 4688 and Sysmon Event 1 observations.

    Required non-temporal anchors are host, exact normalized process ID,
    and exact normalized process image/path. Parent process ID/name are
    additional anchors when both sources provide them. Bounded time is
    supporting evidence only and can never establish a relationship by
    itself.

    This relationship corroborates two observations of process creation.
    It does not establish malicious intent, causal ancestry beyond the
    source fields, or incident membership.
    """

    if max_seconds <= 0:
        raise ValueError(
            "max_seconds must be greater than zero"
        )

    if (
        security_event.source_type
        is not SourceType.WINDOWS_SECURITY
    ):
        return _no_match(
            "source_type_mismatch",
            (
                "Source event is not Windows "
                "Security telemetry."
            ),
        )

    if (
        sysmon_event.source_type
        is not SourceType.SYSMON
    ):
        return _no_match(
            "target_type_mismatch",
            (
                "Target event is not Sysmon "
                "telemetry."
            ),
        )

    if (
        security_event.event_type
        != "process_create"
    ):
        return _no_match(
            "source_event_type_mismatch",
            (
                "Windows Security event is not a "
                "process creation observation."
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
        security_event.event_time_utc
        is None
    ):
        return _no_match(
            "source_time_unavailable",
            (
                "Windows Security event has no "
                "normalized UTC time."
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

    security_host = (
        security_event.host.strip()
        if isinstance(
            security_event.host,
            str,
        )
        else ""
    )

    sysmon_host = (
        sysmon_event.host.strip()
        if isinstance(
            sysmon_event.host,
            str,
        )
        else ""
    )

    if (
        not security_host
        or not sysmon_host
    ):
        return _no_match(
            "host_unavailable",
            (
                "Both telemetry sources must "
                "identify the host."
            ),
        )

    if (
        security_host.casefold()
        != sysmon_host.casefold()
    ):
        return _no_match(
            "host_mismatch",
            (
                "Windows Security and Sysmon "
                "process observations identify "
                "different hosts."
            ),
        )

    security_fields = _fields(
        security_event
    )

    sysmon_fields = _fields(
        sysmon_event
    )

    security_process_id = (
        normalize_windows_process_id(
            security_fields.get(
                "process_id"
            )
        )
    )

    sysmon_process_id = (
        normalize_windows_process_id(
            sysmon_fields.get(
                "process_id"
            )
        )
    )

    if (
        security_process_id is None
        or sysmon_process_id is None
    ):
        return _no_match(
            "process_id_unavailable",
            (
                "Both process creation observations "
                "must expose a valid process ID."
            ),
        )

    if (
        security_process_id
        != sysmon_process_id
    ):
        return _no_match(
            "process_id_mismatch",
            (
                "Windows Security and Sysmon "
                "process IDs do not identify the "
                "same process."
            ),
        )

    security_process_name = (
        normalize_windows_process_path(
            security_fields.get(
                "process_name"
            )
        )
    )

    sysmon_process_name = (
        normalize_windows_process_path(
            sysmon_fields.get(
                "process_name"
            )
        )
    )

    if (
        security_process_name is None
        or sysmon_process_name is None
    ):
        return _no_match(
            "process_name_unavailable",
            (
                "Both process creation observations "
                "must expose a process image/path."
            ),
        )

    if (
        security_process_name
        != sysmon_process_name
    ):
        return _no_match(
            "process_name_mismatch",
            (
                "Windows Security and Sysmon "
                "process image/path values do not "
                "identify the same process image."
            ),
        )

    security_parent_id = (
        normalize_windows_process_id(
            security_fields.get(
                "parent_process_id"
            )
        )
    )

    sysmon_parent_id = (
        normalize_windows_process_id(
            sysmon_fields.get(
                "parent_process_id"
            )
        )
    )

    matched_dimensions: list[str] = [
        "host",
        "process_id",
        "process_name",
    ]

    parent_process_id: str | None = None

    if (
        security_parent_id is not None
        and sysmon_parent_id is not None
    ):
        if (
            security_parent_id
            != sysmon_parent_id
        ):
            return _no_match(
                "parent_process_id_mismatch",
                (
                    "Both sources expose parent "
                    "process IDs, but the values "
                    "do not agree."
                ),
            )

        parent_process_id = (
            security_parent_id
        )
        matched_dimensions.append(
            "parent_process_id"
        )

    security_parent = (
        normalize_windows_process_path(
            security_fields.get(
                "parent_process"
            )
        )
    )

    sysmon_parent = (
        normalize_windows_process_path(
            sysmon_fields.get(
                "parent_process"
            )
        )
    )

    parent_process: str | None = None

    if (
        security_parent is not None
        and sysmon_parent is not None
    ):
        if (
            security_parent
            != sysmon_parent
        ):
            return _no_match(
                "parent_process_mismatch",
                (
                    "Both sources expose parent "
                    "process image/path values, but "
                    "the values do not agree."
                ),
            )

        parent_process = (
            security_parent
        )
        matched_dimensions.append(
            "parent_process"
        )

    delta_seconds = abs(
        (
            sysmon_event.event_time_utc
            - security_event.event_time_utc
        ).total_seconds()
    )

    if delta_seconds > max_seconds:
        return _no_match(
            "outside_time_window",
            (
                "The independently observed process "
                "creation timestamps are outside "
                "the bounded correlation tolerance."
            ),
        )

    matched_dimensions.append(
        "bounded_absolute_time_window"
    )

    dimensions = tuple(
        matched_dimensions
    )

    edge = SecuritySysmonProcessEdge(
        correlation_id=(
            CORRELATION_ID
        ),
        correlation_version=(
            CORRELATION_VERSION
        ),
        edge_id=_edge_id(
            source_event_id=(
                security_event.event_id
            ),
            target_event_id=(
                sysmon_event.event_id
            ),
            process_id=(
                security_process_id
            ),
            process_name=(
                security_process_name
            ),
            parent_process_id=(
                parent_process_id
            ),
            parent_process=(
                parent_process
            ),
            max_seconds=max_seconds,
        ),
        relationship=RELATIONSHIP,
        source_event_id=(
            security_event.event_id
        ),
        target_event_id=(
            sysmon_event.event_id
        ),
        delta_seconds=(
            delta_seconds
        ),
        process_id=(
            security_process_id
        ),
        process_name=(
            security_process_name
        ),
        parent_process_id=(
            parent_process_id
        ),
        parent_process=(
            parent_process
        ),
        matched_dimensions=(
            dimensions
        ),
    )

    return SecuritySysmonProcessResult(
        correlation_id=(
            CORRELATION_ID
        ),
        correlation_version=(
            CORRELATION_VERSION
        ),
        state=(
            CorrelationState.MATCH
        ),
        reason_code=(
            "windows_process_creation_corroborated"
        ),
        rationale=(
            "Windows Security process-creation "
            "telemetry and Sysmon process-creation "
            "telemetry independently agree on host, "
            "normalized process ID, and exact process "
            "image/path within a bounded timestamp "
            "tolerance. Parent process identity is "
            "also preserved as corroboration when both "
            "sources expose it. This relationship "
            "corroborates two observations of process "
            "creation; it does not establish malicious "
            "intent, incident membership, or causality."
        ),
        edge=edge,
    )
