from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json

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


CORRELATION_ID = "TRC-CORR-003"
CORRELATION_VERSION = "1.0.0"

RELATIONSHIP = (
    "sysmon_network_pcap_packet_corroboration"
)

REQUIRED_DETECTION_ID = "TRC-DET-007"

DEFAULT_MAX_SECONDS = 5.0


@dataclass(
    frozen=True,
    slots=True,
)
class NetworkTupleCorrelationEdge:
    correlation_id: str
    correlation_version: str
    edge_id: str
    relationship: str

    source_event_id: str
    target_event_id: str

    delta_seconds: float

    source_ip: str
    source_port: int

    destination_ip: str
    destination_port: int

    protocol: str

    matched_dimensions: tuple[
        str,
        ...,
    ]

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

        if not self.source_ip:
            raise ValueError(
                "source_ip must not be empty"
            )

        if not (
            0
            <= self.source_port
            <= 65535
        ):
            raise ValueError(
                "source_port is out of range"
            )

        if not self.destination_ip:
            raise ValueError(
                "destination_ip must not be empty"
            )

        if not (
            0
            <= self.destination_port
            <= 65535
        ):
            raise ValueError(
                "destination_port is out of range"
            )

        if self.protocol not in {
            "tcp",
            "udp",
        }:
            raise ValueError(
                "protocol must be tcp or udp"
            )


@dataclass(
    frozen=True,
    slots=True,
)
class NetworkTupleCorrelationResult:
    correlation_id: str
    correlation_version: str
    state: CorrelationState
    reason_code: str
    rationale: str

    edge: (
        NetworkTupleCorrelationEdge
        | None
    )

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
                "matched network tuple correlation "
                "requires an edge"
            )

        if (
            self.state
            != CorrelationState.MATCH
            and self.edge is not None
        ):
            raise ValueError(
                "non-match network tuple correlation "
                "must not contain an edge"
            )


def _fields(
    event: object,
) -> object:
    fields = getattr(
        event,
        "fields",
        None,
    )

    if not hasattr(
        fields,
        "get",
    ):
        return {}

    return fields


def _normalized_ip(
    value: object,
) -> str | None:
    if not isinstance(
        value,
        str,
    ):
        return None

    value = value.strip()

    if not value:
        return None

    try:
        return str(
            ipaddress.ip_address(
                value
            )
        )
    except ValueError:
        return None


def _normalized_port(
    value: object,
) -> int | None:
    if isinstance(
        value,
        bool,
    ):
        return None

    if isinstance(
        value,
        int,
    ):
        port = value

    elif isinstance(
        value,
        str,
    ):
        stripped = value.strip()

        if not stripped:
            return None

        try:
            port = int(
                stripped,
                10,
            )
        except ValueError:
            return None

    else:
        return None

    if not (
        0
        <= port
        <= 65535
    ):
        return None

    return port


def _normalized_protocol(
    value: object,
) -> str | None:
    if not isinstance(
        value,
        str,
    ):
        return None

    protocol = (
        value.strip().casefold()
    )

    if protocol not in {
        "tcp",
        "udp",
    }:
        return None

    return protocol


def normalized_network_tuple(
    event: object,
) -> tuple[
    str,
    int,
    str,
    int,
    str,
] | None:
    source_type = getattr(
        event,
        "source_type",
        None,
    )

    fields = _fields(
        event
    )

    if source_type is SourceType.SYSMON:
        protocol_value = fields.get(
            "proto"
        )

    elif source_type is SourceType.PCAP:
        protocol_value = fields.get(
            "protocol"
        )

    else:
        return None

    source_ip = _normalized_ip(
        fields.get(
            "src_ip"
        )
    )

    source_port = _normalized_port(
        fields.get(
            "src_port"
        )
    )

    destination_ip = _normalized_ip(
        fields.get(
            "dst_ip"
        )
    )

    destination_port = _normalized_port(
        fields.get(
            "dst_port"
        )
    )

    protocol = _normalized_protocol(
        protocol_value
    )

    if (
        source_ip is None
        or source_port is None
        or destination_ip is None
        or destination_port is None
        or protocol is None
    ):
        return None

    return (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
    )


def _no_match(
    reason_code: str,
    rationale: str,
) -> NetworkTupleCorrelationResult:
    return NetworkTupleCorrelationResult(
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
    network_tuple: tuple[
        str,
        int,
        str,
        int,
        str,
    ],
    max_seconds: float,
) -> str:
    (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
    ) = network_tuple

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

        "source_ip":
            source_ip,

        "source_port":
            source_port,

        "destination_ip":
            destination_ip,

        "destination_port":
            destination_port,

        "protocol":
            protocol,

        "max_seconds":
            max_seconds,
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


def correlate_sysmon_network_with_pcap(
    *,
    detection: DetectionResult,
    sysmon_event: SemanticEvent,
    pcap_event: SemanticEvent,
    max_seconds: float = DEFAULT_MAX_SECONDS,
) -> NetworkTupleCorrelationResult:
    if max_seconds <= 0:
        raise ValueError(
            "max_seconds must be greater than zero"
        )

    if (
        getattr(
            detection,
            "detection_id",
            None,
        )
        != REQUIRED_DETECTION_ID
    ):
        return _no_match(
            "wrong_detection_id",
            (
                "The correlation requires "
                "TRC-DET-007."
            ),
        )

    if not detection.matched:
        return _no_match(
            "detection_not_matched",
            (
                "The Sysmon PowerShell network "
                "detector did not match."
            ),
        )

    sysmon_event_id = getattr(
        sysmon_event,
        "event_id",
        "",
    )

    if (
        not sysmon_event_id
        or sysmon_event_id
        not in detection.contributing_event_ids
    ):
        return _no_match(
            "detection_event_mismatch",
            (
                "The Sysmon event is not a "
                "contributing event for DET007."
            ),
        )

    if (
        getattr(
            sysmon_event,
            "source_type",
            None,
        )
        is not SourceType.SYSMON
    ):
        return _no_match(
            "source_type_mismatch",
            (
                "Source event is not Sysmon "
                "telemetry."
            ),
        )

    if (
        getattr(
            sysmon_event,
            "event_type",
            None,
        )
        != "network_connection"
    ):
        return _no_match(
            "source_event_type_mismatch",
            (
                "Sysmon source event is not a "
                "network connection."
            ),
        )

    if (
        getattr(
            pcap_event,
            "source_type",
            None,
        )
        is not SourceType.PCAP
    ):
        return _no_match(
            "target_type_mismatch",
            (
                "Target event is not PCAP "
                "telemetry."
            ),
        )

    if (
        getattr(
            pcap_event,
            "event_type",
            None,
        )
        != "network_packet"
    ):
        return _no_match(
            "target_event_type_mismatch",
            (
                "PCAP target event is not a "
                "network packet observation."
            ),
        )

    sysmon_time = getattr(
        sysmon_event,
        "event_time_utc",
        None,
    )

    pcap_time = getattr(
        pcap_event,
        "event_time_utc",
        None,
    )

    if sysmon_time is None:
        return _no_match(
            "source_time_unavailable",
            (
                "Sysmon network event has no "
                "normalized UTC time."
            ),
        )

    if pcap_time is None:
        return _no_match(
            "target_time_unavailable",
            (
                "PCAP packet has no normalized "
                "UTC time."
            ),
        )

    sysmon_tuple = (
        normalized_network_tuple(
            sysmon_event
        )
    )

    pcap_tuple = (
        normalized_network_tuple(
            pcap_event
        )
    )

    if sysmon_tuple is None:
        return _no_match(
            "source_tuple_unavailable",
            (
                "Sysmon network event lacks a "
                "complete valid source IP, source "
                "port, destination IP, destination "
                "port, and transport protocol tuple."
            ),
        )

    if pcap_tuple is None:
        return _no_match(
            "target_tuple_unavailable",
            (
                "PCAP packet lacks a complete valid "
                "source IP, source port, destination "
                "IP, destination port, and transport "
                "protocol tuple."
            ),
        )

    dimension_names = (
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "protocol",
    )

    for index, dimension in enumerate(
        dimension_names
    ):
        if (
            sysmon_tuple[
                index
            ]
            != pcap_tuple[
                index
            ]
        ):
            return _no_match(
                dimension
                + "_mismatch",
                (
                    "Sysmon and PCAP observations "
                    "do not agree on "
                    + dimension
                    + "."
                ),
            )

    delta_seconds = abs(
        (
            pcap_time
            - sysmon_time
        ).total_seconds()
    )

    if delta_seconds > max_seconds:
        return _no_match(
            "outside_time_window",
            (
                "The exact network tuple agrees, "
                "but the observations fall outside "
                "the bounded timestamp tolerance."
            ),
        )

    source_event_id = str(
        sysmon_event_id
    )

    target_event_id = str(
        getattr(
            pcap_event,
            "event_id",
            "",
        )
    )

    if not target_event_id:
        return _no_match(
            "target_event_id_unavailable",
            (
                "PCAP observation lacks an event "
                "identifier."
            ),
        )

    (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
    ) = sysmon_tuple

    dimensions = (
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "protocol",
        "bounded_absolute_time_window",
    )

    edge = NetworkTupleCorrelationEdge(
        correlation_id=(
            CORRELATION_ID
        ),
        correlation_version=(
            CORRELATION_VERSION
        ),
        edge_id=_edge_id(
            source_event_id=(
                source_event_id
            ),
            target_event_id=(
                target_event_id
            ),
            network_tuple=(
                sysmon_tuple
            ),
            max_seconds=(
                max_seconds
            ),
        ),
        relationship=(
            RELATIONSHIP
        ),
        source_event_id=(
            source_event_id
        ),
        target_event_id=(
            target_event_id
        ),
        delta_seconds=(
            delta_seconds
        ),
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=(
            destination_ip
        ),
        destination_port=(
            destination_port
        ),
        protocol=protocol,
        matched_dimensions=(
            dimensions
        ),
    )

    return NetworkTupleCorrelationResult(
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
            "sysmon_pcap_network_tuple_corroborated"
        ),
        rationale=(
            "Sysmon network telemetry and a PCAP "
            "packet independently agree on source "
            "IP, source port, destination IP, "
            "destination port, and transport "
            "protocol within a bounded absolute "
            "timestamp tolerance. This corroborates "
            "a consistent network observation but "
            "does not establish packet-to-process "
            "causality, malicious intent, or "
            "incident membership."
        ),
        edge=edge,
    )
