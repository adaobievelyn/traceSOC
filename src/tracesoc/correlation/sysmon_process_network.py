from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from uuid import UUID

from tracesoc.correlation.models import (
    CorrelationState,
)
from tracesoc.correlation.security_sysmon_process import (
    normalize_windows_process_id,
    normalize_windows_process_path,
)
from tracesoc.models import (
    SemanticEvent,
    SourceType,
)


CORRELATION_ID = "TRC-CORR-006"
CORRELATION_VERSION = "1.0.0"

RELATIONSHIP = (
    "sysmon_process_network_process_guid_identity"
)


@dataclass(
    frozen=True,
    slots=True,
)
class SysmonProcessNetworkEdge:
    correlation_id: str
    correlation_version: str
    edge_id: str
    relationship: str
    source_event_id: str
    target_event_id: str
    host: str
    process_guid: str
    matched_dimensions: tuple[str, ...]
    process_id: str | None = None
    process_name: str | None = None
    delta_seconds: float | None = None

    def __post_init__(
        self,
    ) -> None:
        if not self.edge_id:
            raise ValueError(
                "edge_id must not be empty"
            )

        if not self.host:
            raise ValueError(
                "host must not be empty"
            )

        if (
            normalize_sysmon_process_guid(
                self.process_guid
            )
            is None
        ):
            raise ValueError(
                "process_guid must be valid"
            )

        if not self.matched_dimensions:
            raise ValueError(
                "matched_dimensions must not be empty"
            )

        if (
            self.delta_seconds
            is not None
            and self.delta_seconds < 0
        ):
            raise ValueError(
                "delta_seconds must be nonnegative"
            )


@dataclass(
    frozen=True,
    slots=True,
)
class SysmonProcessNetworkResult:
    correlation_id: str
    correlation_version: str
    state: CorrelationState
    reason_code: str
    rationale: str
    edge: SysmonProcessNetworkEdge | None

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
            self.matched
            and self.edge is None
        ):
            raise ValueError(
                "matched Sysmon process/network "
                "correlation requires edge"
            )

        if (
            not self.matched
            and self.edge is not None
        ):
            raise ValueError(
                "non-match Sysmon process/network "
                "correlation must not contain edge"
            )


def normalize_sysmon_process_guid(
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

    try:
        parsed = UUID(
            text.strip(
                "{}"
            )
        )
    except ValueError:
        return None

    return (
        "{"
        + str(
            parsed
        )
        + "}"
    )


def _normalize_host(
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

    return text.casefold()


def _value_present(
    value: object,
) -> bool:
    if value is None:
        return False

    if isinstance(
        value,
        str,
    ):
        return bool(
            value.strip()
        )

    return True


def _no_match(
    reason_code: str,
    rationale: str,
) -> SysmonProcessNetworkResult:
    return SysmonProcessNetworkResult(
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


def _edge_id(
    *,
    source_event_id: str,
    target_event_id: str,
    host: str,
    process_guid: str,
    process_id: str | None,
    process_name: str | None,
) -> str:
    material = {
        "correlation_id":
            CORRELATION_ID,

        "correlation_version":
            CORRELATION_VERSION,

        "relationship":
            RELATIONSHIP,

        "source_event_id":
            source_event_id,

        "target_event_id":
            target_event_id,

        "host":
            host,

        "process_guid":
            process_guid,

        "process_id":
            process_id,

        "process_name":
            process_name,
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


def correlate_sysmon_process_with_network_activity(
    *,
    process_event: SemanticEvent,
    network_event: SemanticEvent,
) -> SysmonProcessNetworkResult:
    """
    Link Sysmon Event 1 process creation to Sysmon Event 3 network
    activity using exact source-native ProcessGuid identity.

    ProcessGuid is the identity selector. Host is a required
    consistency boundary. Process ID and process image/path are
    additional consistency checks when both records expose them.

    Time never creates the relationship. When both events are timed,
    impossible ordering is rejected.

    This establishes Sysmon process-instance attribution only. It does
    not establish malicious intent, user action, higher-level causal
    intent, or incident membership.
    """

    if (
        process_event.source_type
        is not SourceType.SYSMON
    ):
        return _no_match(
            "source_type_mismatch",
            "Source event is not Sysmon telemetry.",
        )

    if (
        network_event.source_type
        is not SourceType.SYSMON
    ):
        return _no_match(
            "target_type_mismatch",
            "Target event is not Sysmon telemetry.",
        )

    if (
        process_event.event_type
        != "process_create"
    ):
        return _no_match(
            "source_event_type_mismatch",
            (
                "Source Sysmon event is not "
                "process creation telemetry."
            ),
        )

    if (
        network_event.event_type
        != "network_connection"
    ):
        return _no_match(
            "target_event_type_mismatch",
            (
                "Target Sysmon event is not "
                "network connection telemetry."
            ),
        )

    process_fields = (
        process_event.fields
    )

    network_fields = (
        network_event.fields
    )

    process_guid = (
        normalize_sysmon_process_guid(
            process_fields.get(
                "process_guid"
            )
        )
    )

    network_guid = (
        normalize_sysmon_process_guid(
            network_fields.get(
                "process_guid"
            )
        )
    )

    if process_guid is None:
        return _no_match(
            "source_process_guid_unavailable",
            (
                "Sysmon process creation has no "
                "valid ProcessGuid."
            ),
        )

    if network_guid is None:
        return _no_match(
            "target_process_guid_unavailable",
            (
                "Sysmon network activity has no "
                "valid ProcessGuid."
            ),
        )

    if process_guid != network_guid:
        return _no_match(
            "process_guid_mismatch",
            (
                "Sysmon process creation and "
                "network activity identify "
                "different process instances."
            ),
        )

    process_host = (
        _normalize_host(
            process_event.host
        )
    )

    network_host = (
        _normalize_host(
            network_event.host
        )
    )

    if (
        process_host is None
        or network_host is None
    ):
        return _no_match(
            "host_unavailable",
            (
                "Both Sysmon observations "
                "must identify a host."
            ),
        )

    if (
        process_host
        != network_host
    ):
        return _no_match(
            "host_mismatch",
            (
                "Matching ProcessGuid text "
                "is present on different hosts."
            ),
        )

    matched_dimensions = [
        "process_guid",
        "host",
    ]

    process_pid_raw = (
        process_fields.get(
            "process_id"
        )
    )

    network_pid_raw = (
        network_fields.get(
            "process_id"
        )
    )

    process_pid = (
        normalize_windows_process_id(
            process_pid_raw
        )
    )

    network_pid = (
        normalize_windows_process_id(
            network_pid_raw
        )
    )

    if (
        _value_present(
            process_pid_raw
        )
        and process_pid is None
    ):
        return _no_match(
            "source_process_id_invalid",
            (
                "Sysmon process creation "
                "exposes an invalid process ID."
            ),
        )

    if (
        _value_present(
            network_pid_raw
        )
        and network_pid is None
    ):
        return _no_match(
            "target_process_id_invalid",
            (
                "Sysmon network activity "
                "exposes an invalid process ID."
            ),
        )

    shared_pid: str | None = None

    if (
        process_pid is not None
        and network_pid is not None
    ):
        if (
            process_pid
            != network_pid
        ):
            return _no_match(
                "process_id_mismatch",
                (
                    "The same ProcessGuid is "
                    "accompanied by conflicting "
                    "process IDs."
                ),
            )

        shared_pid = (
            process_pid
        )

        matched_dimensions.append(
            "process_id"
        )

    process_name_raw = (
        process_fields.get(
            "process_name"
        )
    )

    network_name_raw = (
        network_fields.get(
            "process_name"
        )
    )

    process_name = (
        normalize_windows_process_path(
            process_name_raw
        )
    )

    network_name = (
        normalize_windows_process_path(
            network_name_raw
        )
    )

    if (
        _value_present(
            process_name_raw
        )
        and process_name is None
    ):
        return _no_match(
            "source_process_name_invalid",
            (
                "Sysmon process creation "
                "exposes an invalid process image."
            ),
        )

    if (
        _value_present(
            network_name_raw
        )
        and network_name is None
    ):
        return _no_match(
            "target_process_name_invalid",
            (
                "Sysmon network activity "
                "exposes an invalid process image."
            ),
        )

    shared_name: str | None = None

    if (
        process_name is not None
        and network_name is not None
    ):
        if (
            process_name
            != network_name
        ):
            return _no_match(
                "process_name_mismatch",
                (
                    "The same ProcessGuid is "
                    "accompanied by conflicting "
                    "process image/path values."
                ),
            )

        shared_name = (
            process_name
        )

        matched_dimensions.append(
            "process_name"
        )

    delta_seconds: float | None = None

    if (
        process_event.event_time_utc
        is not None
        and network_event.event_time_utc
        is not None
    ):
        delta_seconds = (
            network_event.event_time_utc
            - process_event.event_time_utc
        ).total_seconds()

        if delta_seconds < 0:
            return _no_match(
                "network_precedes_process_creation",
                (
                    "Sysmon network activity "
                    "precedes process creation "
                    "for the same ProcessGuid."
                ),
            )

    edge = SysmonProcessNetworkEdge(
        correlation_id=(
            CORRELATION_ID
        ),
        correlation_version=(
            CORRELATION_VERSION
        ),
        edge_id=_edge_id(
            source_event_id=(
                process_event.event_id
            ),
            target_event_id=(
                network_event.event_id
            ),
            host=process_host,
            process_guid=(
                process_guid
            ),
            process_id=(
                shared_pid
            ),
            process_name=(
                shared_name
            ),
        ),
        relationship=(
            RELATIONSHIP
        ),
        source_event_id=(
            process_event.event_id
        ),
        target_event_id=(
            network_event.event_id
        ),
        host=process_host,
        process_guid=(
            process_guid
        ),
        process_id=(
            shared_pid
        ),
        process_name=(
            shared_name
        ),
        delta_seconds=(
            delta_seconds
        ),
        matched_dimensions=tuple(
            matched_dimensions
        ),
    )

    return SysmonProcessNetworkResult(
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
            "sysmon_process_instance_network_activity"
        ),
        rationale=(
            "Sysmon process creation and Sysmon "
            "network activity carry the same "
            "source-native ProcessGuid on the "
            "same host. Process ID and process "
            "image/path are checked for "
            "consistency when both observations "
            "provide them. Time is not an identity "
            "selector and is used only to reject "
            "impossible ordering when both events "
            "are timed. This establishes Sysmon "
            "process-instance attribution only "
            "and does not establish malicious "
            "intent, user action, higher-level "
            "causal intent, or incident membership."
        ),
        edge=edge,
    )
