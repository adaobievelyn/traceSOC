from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from tracesoc.correlation.models import (
    CorrelationResult,
)
from tracesoc.correlation.powershell_process import (
    CORRELATION_ID as PROCESS_CORRELATION_ID,
    CORRELATION_VERSION as PROCESS_CORRELATION_VERSION,
    RELATIONSHIP as PROCESS_RELATIONSHIP,
    ProcessCorrelationResult,
)
from tracesoc.correlation.sysmon_pcap_network import (
    CORRELATION_ID as SYSMON_PCAP_CORRELATION_ID,
    CORRELATION_VERSION as SYSMON_PCAP_CORRELATION_VERSION,
    RELATIONSHIP as SYSMON_PCAP_RELATIONSHIP,
    NetworkTupleCorrelationResult,
    normalized_network_tuple,
)
from tracesoc.correlation.security_sysmon_process import (
    CORRELATION_ID as SECURITY_SYSMON_CORRELATION_ID,
    CORRELATION_VERSION as SECURITY_SYSMON_CORRELATION_VERSION,
    RELATIONSHIP as SECURITY_SYSMON_RELATIONSHIP,
    SecuritySysmonProcessResult,
    normalize_windows_process_id,
    normalize_windows_process_path,
)
from tracesoc.correlation.email_sysmon_artifact import (
    CORRELATION_ID as EMAIL_SYSMON_CORRELATION_ID,
    CORRELATION_VERSION as EMAIL_SYSMON_CORRELATION_VERSION,
    RELATIONSHIP as EMAIL_SYSMON_RELATIONSHIP,
    EmailSysmonArtifactResult,
    extract_sysmon_sha256,
    normalize_sha256,
)
from tracesoc.correlation.sysmon_process_network import (
    CORRELATION_ID as SYSMON_PROCESS_NETWORK_CORRELATION_ID,
    CORRELATION_VERSION as SYSMON_PROCESS_NETWORK_CORRELATION_VERSION,
    RELATIONSHIP as SYSMON_PROCESS_NETWORK_RELATIONSHIP,
    SysmonProcessNetworkResult,
    normalize_sysmon_process_guid,
)
from tracesoc.correlation.web_retrieval_network import (
    CORRELATION_ID as NETWORK_CORRELATION_ID,
    CORRELATION_VERSION as NETWORK_CORRELATION_VERSION,
    RELATIONSHIP as NETWORK_RELATIONSHIP,
)
from tracesoc.evidence.graph import (
    Entity,
    EntityKind,
    Relationship,
    RelationshipAnchor,
    RelationshipType,
)
from tracesoc.evidence.states import (
    EvidenceState,
)
from tracesoc.models import (
    SemanticEvent,
    SourceType,
)


class CorrelationBridgeError(
    RuntimeError
):
    pass


@dataclass(
    frozen=True,
    slots=True,
)
class CorrelationRelationshipProjection:
    legacy_correlation_id: str
    legacy_correlation_version: str
    legacy_edge_id: str
    source_entity: Entity
    target_entity: Entity
    relationship: Relationship


def _require_text(
    value: object,
    field_name: str,
) -> str:
    if not isinstance(
        value,
        str,
    ):
        raise CorrelationBridgeError(
            field_name
            + " must be text"
        )

    normalized = value.strip()

    if not normalized:
        raise CorrelationBridgeError(
            field_name
            + " must not be blank"
        )

    return normalized


def _normalized_ip(
    value: object,
    field_name: str,
) -> str:
    text = _require_text(
        value,
        field_name,
    )

    try:
        return str(
            ipaddress.ip_address(
                text
            )
        )
    except ValueError as exc:
        raise CorrelationBridgeError(
            field_name
            + " is not a valid IP address"
        ) from exc


def _observation_entity(
    event: SemanticEvent,
) -> Entity:
    event_id = _require_text(
        getattr(
            event,
            "event_id",
            None,
        ),
        "event_id",
    )

    source_type = getattr(
        event,
        "source_type",
        None,
    )

    if not isinstance(
        source_type,
        SourceType,
    ):
        raise CorrelationBridgeError(
            "event source_type must be SourceType"
        )

    return Entity.create(
        kind=EntityKind.OBSERVATION,
        identity_attributes=(
            (
                "event_id",
                event_id,
            ),
            (
                "source_type",
                source_type.value,
            ),
        ),
        display_name=event_id,
    )


def _verify_legacy_result(
    *,
    result: object,
    expected_correlation_id: str,
    expected_correlation_version: str,
) -> object | None:
    correlation_id = _require_text(
        getattr(
            result,
            "correlation_id",
            None,
        ),
        "correlation_id",
    )

    correlation_version = _require_text(
        getattr(
            result,
            "correlation_version",
            None,
        ),
        "correlation_version",
    )

    if (
        correlation_id
        != expected_correlation_id
    ):
        raise CorrelationBridgeError(
            "unexpected legacy correlation_id"
        )

    if (
        correlation_version
        != expected_correlation_version
    ):
        raise CorrelationBridgeError(
            "unexpected legacy correlation_version"
        )

    matched = getattr(
        result,
        "matched",
        None,
    )

    if not isinstance(
        matched,
        bool,
    ):
        raise CorrelationBridgeError(
            "legacy result matched property "
            "must be bool"
        )

    edge = getattr(
        result,
        "edge",
        None,
    )

    if not matched:
        if edge is not None:
            raise CorrelationBridgeError(
                "non-matched legacy result "
                "must not contain edge"
            )

        return None

    if edge is None:
        raise CorrelationBridgeError(
            "matched legacy result requires edge"
        )

    return edge


def _verify_edge_common(
    *,
    edge: object,
    expected_correlation_id: str,
    expected_correlation_version: str,
    expected_relationship: str,
    source_event: SemanticEvent,
    target_event: SemanticEvent,
) -> tuple[
    str,
    float,
]:
    if (
        _require_text(
            getattr(
                edge,
                "correlation_id",
                None,
            ),
            "edge correlation_id",
        )
        != expected_correlation_id
    ):
        raise CorrelationBridgeError(
            "edge correlation_id mismatch"
        )

    if (
        _require_text(
            getattr(
                edge,
                "correlation_version",
                None,
            ),
            "edge correlation_version",
        )
        != expected_correlation_version
    ):
        raise CorrelationBridgeError(
            "edge correlation_version mismatch"
        )

    if (
        _require_text(
            getattr(
                edge,
                "relationship",
                None,
            ),
            "edge relationship",
        )
        != expected_relationship
    ):
        raise CorrelationBridgeError(
            "legacy relationship name mismatch"
        )

    source_event_id = _require_text(
        getattr(
            source_event,
            "event_id",
            None,
        ),
        "source event_id",
    )

    target_event_id = _require_text(
        getattr(
            target_event,
            "event_id",
            None,
        ),
        "target event_id",
    )

    if (
        _require_text(
            getattr(
                edge,
                "source_event_id",
                None,
            ),
            "edge source_event_id",
        )
        != source_event_id
    ):
        raise CorrelationBridgeError(
            "legacy edge source orientation mismatch"
        )

    if (
        _require_text(
            getattr(
                edge,
                "target_event_id",
                None,
            ),
            "edge target_event_id",
        )
        != target_event_id
    ):
        raise CorrelationBridgeError(
            "legacy edge target orientation mismatch"
        )

    edge_id = _require_text(
        getattr(
            edge,
            "edge_id",
            None,
        ),
        "edge_id",
    )

    delta_seconds = getattr(
        edge,
        "delta_seconds",
        None,
    )

    if (
        isinstance(
            delta_seconds,
            bool,
        )
        or not isinstance(
            delta_seconds,
            (
                int,
                float,
            ),
        )
    ):
        raise CorrelationBridgeError(
            "edge delta_seconds must be numeric"
        )

    delta = float(
        delta_seconds
    )

    if delta < 0:
        raise CorrelationBridgeError(
            "edge delta_seconds must be nonnegative"
        )

    return (
        edge_id,
        delta,
    )


def _matched_dimensions(
    edge: object,
) -> tuple[
    str,
    ...,
]:
    value = getattr(
        edge,
        "matched_dimensions",
        None,
    )

    if not isinstance(
        value,
        tuple,
    ):
        raise CorrelationBridgeError(
            "matched_dimensions must be tuple"
        )

    normalized = tuple(
        _require_text(
            item,
            "matched dimension",
        )
        for item
        in value
    )

    if not normalized:
        raise CorrelationBridgeError(
            "matched_dimensions must not be empty"
        )

    return normalized


def _host_anchor(
    source_event: SemanticEvent,
    target_event: SemanticEvent,
) -> RelationshipAnchor:
    source_host = _require_text(
        getattr(
            source_event,
            "host",
            None,
        ),
        "source host",
    )

    target_host = _require_text(
        getattr(
            target_event,
            "host",
            None,
        ),
        "target host",
    )

    if (
        source_host.casefold()
        != target_host.casefold()
    ):
        raise CorrelationBridgeError(
            "legacy matched edge supplied "
            "with mismatched hosts"
        )

    return RelationshipAnchor(
        anchor_type="host",
        value=source_host.casefold(),
        temporal=False,
    )


def _bridge_web_retrieval_correlation_v1(
    *,
    result: CorrelationResult,
    powershell_event: SemanticEvent,
    zeek_event: SemanticEvent,
) -> CorrelationRelationshipProjection | None:
    edge = _verify_legacy_result(
        result=result,
        expected_correlation_id=(
            NETWORK_CORRELATION_ID
        ),
        expected_correlation_version=(
            NETWORK_CORRELATION_VERSION
        ),
    )

    if edge is None:
        return None

    if (
        getattr(
            powershell_event,
            "source_type",
            None,
        )
        is not SourceType.POWERSHELL
    ):
        raise CorrelationBridgeError(
            "source event is not PowerShell"
        )

    if (
        getattr(
            zeek_event,
            "source_type",
            None,
        )
        is not SourceType.ZEEK
    ):
        raise CorrelationBridgeError(
            "target event is not Zeek"
        )

    edge_id, delta = (
        _verify_edge_common(
            edge=edge,
            expected_correlation_id=(
                NETWORK_CORRELATION_ID
            ),
            expected_correlation_version=(
                NETWORK_CORRELATION_VERSION
            ),
            expected_relationship=(
                NETWORK_RELATIONSHIP
            ),
            source_event=(
                powershell_event
            ),
            target_event=(
                zeek_event
            ),
        )
    )

    dimensions = (
        _matched_dimensions(
            edge
        )
    )

    expected_dimensions = {
        "host",
        "source_ip",
        "destination_ip",
        "destination_port",
        "directional_time_window",
    }

    if set(
        dimensions
    ) != expected_dimensions:
        raise CorrelationBridgeError(
            "TRC-CORR-001 matched dimensions changed"
        )

    source_fields = getattr(
        powershell_event,
        "fields",
        None,
    )

    target_fields = getattr(
        zeek_event,
        "fields",
        None,
    )

    if (
        not hasattr(
            source_fields,
            "get",
        )
        or not hasattr(
            target_fields,
            "get",
        )
    ):
        raise CorrelationBridgeError(
            "semantic event fields are unavailable"
        )

    source_ip = _normalized_ip(
        source_fields.get(
            "local_ip"
        ),
        "PowerShell local_ip",
    )

    zeek_source_ip = _normalized_ip(
        target_fields.get(
            "src_ip"
        ),
        "Zeek src_ip",
    )

    if source_ip != zeek_source_ip:
        raise CorrelationBridgeError(
            "TRC-CORR-001 source IP anchor mismatch"
        )

    destination_ip = _normalized_ip(
        getattr(
            edge,
            "destination_ip",
            None,
        ),
        "edge destination_ip",
    )

    zeek_destination_ip = _normalized_ip(
        target_fields.get(
            "dst_ip"
        ),
        "Zeek dst_ip",
    )

    if (
        destination_ip
        != zeek_destination_ip
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-001 destination IP "
            "anchor mismatch"
        )

    destination_port = getattr(
        edge,
        "destination_port",
        None,
    )

    observed_port = target_fields.get(
        "dst_port"
    )

    if (
        isinstance(
            destination_port,
            bool,
        )
        or not isinstance(
            destination_port,
            int,
        )
        or isinstance(
            observed_port,
            bool,
        )
        or not isinstance(
            observed_port,
            int,
        )
        or destination_port
        != observed_port
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-001 destination port "
            "anchor mismatch"
        )

    source_entity = (
        _observation_entity(
            powershell_event
        )
    )

    target_entity = (
        _observation_entity(
            zeek_event
        )
    )

    relationship = (
        Relationship.create(
            relationship_type=(
                RelationshipType.CORROBORATES
            ),
            source_entity_id=(
                source_entity.entity_id
            ),
            target_entity_id=(
                target_entity.entity_id
            ),
            predicate_version=(
                NETWORK_CORRELATION_ID
                + "@"
                + NETWORK_CORRELATION_VERSION
            ),
            supporting_ids=(
                edge_id,
                powershell_event.event_id,
                zeek_event.event_id,
            ),
            anchors=(
                _host_anchor(
                    powershell_event,
                    zeek_event,
                ),
                RelationshipAnchor(
                    anchor_type="source_ip",
                    value=source_ip,
                    temporal=False,
                ),
                RelationshipAnchor(
                    anchor_type="destination_ip",
                    value=destination_ip,
                    temporal=False,
                ),
                RelationshipAnchor(
                    anchor_type="destination_port",
                    value=str(
                        destination_port
                    ),
                    temporal=False,
                ),
                RelationshipAnchor(
                    anchor_type="directional_delta_seconds",
                    value=format(
                        delta,
                        ".6f",
                    ),
                    temporal=True,
                ),
            ),
            evidence_state=(
                EvidenceState.CORROBORATED
            ),
            rationale=_require_text(
                getattr(
                    result,
                    "rationale",
                    None,
                ),
                "correlation rationale",
            ),
            alternative_or_falsifier=(
                "A mismatch in host, source IP, "
                "destination IP, destination port, "
                "event direction, or the bounded "
                "time predicate falsifies this "
                "legacy correlation."
            ),
        )
    )

    return CorrelationRelationshipProjection(
        legacy_correlation_id=(
            NETWORK_CORRELATION_ID
        ),
        legacy_correlation_version=(
            NETWORK_CORRELATION_VERSION
        ),
        legacy_edge_id=edge_id,
        source_entity=(
            source_entity
        ),
        target_entity=(
            target_entity
        ),
        relationship=(
            relationship
        ),
    )


def _bridge_powershell_process_correlation_v1(
    *,
    result: ProcessCorrelationResult,
    sysmon_event: SemanticEvent,
    powershell_event: SemanticEvent,
) -> CorrelationRelationshipProjection | None:
    edge = _verify_legacy_result(
        result=result,
        expected_correlation_id=(
            PROCESS_CORRELATION_ID
        ),
        expected_correlation_version=(
            PROCESS_CORRELATION_VERSION
        ),
    )

    if edge is None:
        return None

    if (
        getattr(
            sysmon_event,
            "source_type",
            None,
        )
        is not SourceType.SYSMON
    ):
        raise CorrelationBridgeError(
            "source event is not Sysmon"
        )

    if (
        getattr(
            powershell_event,
            "source_type",
            None,
        )
        is not SourceType.POWERSHELL
    ):
        raise CorrelationBridgeError(
            "target event is not PowerShell"
        )

    edge_id, delta = (
        _verify_edge_common(
            edge=edge,
            expected_correlation_id=(
                PROCESS_CORRELATION_ID
            ),
            expected_correlation_version=(
                PROCESS_CORRELATION_VERSION
            ),
            expected_relationship=(
                PROCESS_RELATIONSHIP
            ),
            source_event=(
                sysmon_event
            ),
            target_event=(
                powershell_event
            ),
        )
    )

    dimensions = (
        _matched_dimensions(
            edge
        )
    )

    expected_dimensions = {
        "host",
        "principal",
        "local_ip",
        "powershell_process_family",
        "directional_time_window",
    }

    if set(
        dimensions
    ) != expected_dimensions:
        raise CorrelationBridgeError(
            "TRC-CORR-002 matched dimensions changed"
        )

    principal = _require_text(
        getattr(
            edge,
            "principal",
            None,
        ),
        "edge principal",
    )

    source_principal = _require_text(
        getattr(
            sysmon_event,
            "principal",
            None,
        ),
        "Sysmon principal",
    )

    target_principal = _require_text(
        getattr(
            powershell_event,
            "principal",
            None,
        ),
        "PowerShell principal",
    )

    if not (
        principal.casefold()
        == source_principal.casefold()
        == target_principal.casefold()
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-002 principal anchor mismatch"
        )

    local_ip = _normalized_ip(
        getattr(
            edge,
            "local_ip",
            None,
        ),
        "edge local_ip",
    )

    source_fields = getattr(
        sysmon_event,
        "fields",
        None,
    )

    target_fields = getattr(
        powershell_event,
        "fields",
        None,
    )

    if (
        not hasattr(
            source_fields,
            "get",
        )
        or not hasattr(
            target_fields,
            "get",
        )
    ):
        raise CorrelationBridgeError(
            "semantic event fields are unavailable"
        )

    source_local_ip = _normalized_ip(
        source_fields.get(
            "local_ip"
        ),
        "Sysmon local_ip",
    )

    target_local_ip = _normalized_ip(
        target_fields.get(
            "local_ip"
        ),
        "PowerShell local_ip",
    )

    if not (
        local_ip
        == source_local_ip
        == target_local_ip
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-002 local IP anchor mismatch"
        )

    process_name = _require_text(
        getattr(
            edge,
            "process_name",
            None,
        ),
        "edge process_name",
    )

    source_entity = (
        _observation_entity(
            sysmon_event
        )
    )

    target_entity = (
        _observation_entity(
            powershell_event
        )
    )

    relationship = (
        Relationship.create(
            relationship_type=(
                RelationshipType.CORROBORATES
            ),
            source_entity_id=(
                source_entity.entity_id
            ),
            target_entity_id=(
                target_entity.entity_id
            ),
            predicate_version=(
                PROCESS_CORRELATION_ID
                + "@"
                + PROCESS_CORRELATION_VERSION
            ),
            supporting_ids=(
                edge_id,
                sysmon_event.event_id,
                powershell_event.event_id,
            ),
            anchors=(
                _host_anchor(
                    sysmon_event,
                    powershell_event,
                ),
                RelationshipAnchor(
                    anchor_type="principal",
                    value=(
                        principal.casefold()
                    ),
                    temporal=False,
                ),
                RelationshipAnchor(
                    anchor_type="local_ip",
                    value=local_ip,
                    temporal=False,
                ),
                RelationshipAnchor(
                    anchor_type=(
                        "powershell_process_family"
                    ),
                    value=(
                        process_name.casefold()
                    ),
                    temporal=False,
                ),
                RelationshipAnchor(
                    anchor_type=(
                        "directional_delta_seconds"
                    ),
                    value=format(
                        delta,
                        ".6f",
                    ),
                    temporal=True,
                ),
            ),
            evidence_state=(
                EvidenceState.CORROBORATED
            ),
            rationale=_require_text(
                getattr(
                    result,
                    "rationale",
                    None,
                ),
                "correlation rationale",
            ),
            alternative_or_falsifier=(
                "A mismatch in host, principal, "
                "local IP, PowerShell process family, "
                "event direction, or the bounded "
                "time predicate falsifies this "
                "legacy correlation."
            ),
        )
    )

    return CorrelationRelationshipProjection(
        legacy_correlation_id=(
            PROCESS_CORRELATION_ID
        ),
        legacy_correlation_version=(
            PROCESS_CORRELATION_VERSION
        ),
        legacy_edge_id=edge_id,
        source_entity=(
            source_entity
        ),
        target_entity=(
            target_entity
        ),
        relationship=(
            relationship
        ),
    )


def bridge_sysmon_pcap_network_correlation(
    *,
    result: NetworkTupleCorrelationResult,
    sysmon_event: SemanticEvent,
    pcap_event: SemanticEvent,
) -> CorrelationRelationshipProjection | None:
    if (
        result.correlation_id
        != SYSMON_PCAP_CORRELATION_ID
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 correlation ID changed"
        )

    if (
        result.correlation_version
        != SYSMON_PCAP_CORRELATION_VERSION
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 correlation version changed"
        )

    if not result.matched:
        if result.edge is not None:
            raise CorrelationBridgeError(
                "TRC-CORR-003 non-match contains an edge"
            )

        return None

    edge = result.edge

    if edge is None:
        raise CorrelationBridgeError(
            "TRC-CORR-003 match has no edge"
        )

    if (
        getattr(
            sysmon_event,
            "source_type",
            None,
        )
        is not SourceType.SYSMON
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 source is not Sysmon"
        )

    if (
        getattr(
            sysmon_event,
            "event_type",
            None,
        )
        != "network_connection"
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 source is not a "
            "network connection"
        )

    if (
        getattr(
            pcap_event,
            "source_type",
            None,
        )
        is not SourceType.PCAP
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 target is not PCAP"
        )

    if (
        getattr(
            pcap_event,
            "event_type",
            None,
        )
        != "network_packet"
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 target is not a "
            "network packet"
        )

    if (
        edge.correlation_id
        != SYSMON_PCAP_CORRELATION_ID
        or edge.correlation_version
        != SYSMON_PCAP_CORRELATION_VERSION
        or edge.relationship
        != SYSMON_PCAP_RELATIONSHIP
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 edge identity changed"
        )

    if (
        edge.source_event_id
        != getattr(
            sysmon_event,
            "event_id",
            None,
        )
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 source event orientation changed"
        )

    if (
        edge.target_event_id
        != getattr(
            pcap_event,
            "event_id",
            None,
        )
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 target event orientation changed"
        )

    dimensions = set(
        edge.matched_dimensions
    )

    expected_dimensions = {
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "protocol",
        "bounded_absolute_time_window",
    }

    if dimensions != expected_dimensions:
        raise CorrelationBridgeError(
            "TRC-CORR-003 matched dimensions changed"
        )

    source_tuple = (
        normalized_network_tuple(
            sysmon_event
        )
    )

    target_tuple = (
        normalized_network_tuple(
            pcap_event
        )
    )

    if (
        source_tuple is None
        or target_tuple is None
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 network tuple unavailable"
        )

    if source_tuple != target_tuple:
        raise CorrelationBridgeError(
            "TRC-CORR-003 network tuple anchor mismatch"
        )

    (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
    ) = source_tuple

    if (
        edge.source_ip
        != source_ip
        or edge.source_port
        != source_port
        or edge.destination_ip
        != destination_ip
        or edge.destination_port
        != destination_port
        or edge.protocol
        != protocol
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 edge tuple does not match "
            "source evidence"
        )

    delta = edge.delta_seconds

    if (
        isinstance(
            delta,
            bool,
        )
        or not isinstance(
            delta,
            (
                int,
                float,
            ),
        )
        or delta < 0
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-003 delta is invalid"
        )

    source_entity = (
        _observation_entity(
            sysmon_event
        )
    )

    target_entity = (
        _observation_entity(
            pcap_event
        )
    )

    relationship = Relationship.create(
        relationship_type=(
            RelationshipType.CORROBORATES
        ),
        source_entity_id=(
            source_entity.entity_id
        ),
        target_entity_id=(
            target_entity.entity_id
        ),
        predicate_version=(
            SYSMON_PCAP_CORRELATION_ID
            + "@"
            + SYSMON_PCAP_CORRELATION_VERSION
        ),
        supporting_ids=(
            edge.edge_id,
            sysmon_event.event_id,
            pcap_event.event_id,
        ),
        anchors=(
            RelationshipAnchor(
                anchor_type="source_ip",
                value=source_ip,
                temporal=False,
            ),
            RelationshipAnchor(
                anchor_type="source_port",
                value=str(
                    source_port
                ),
                temporal=False,
            ),
            RelationshipAnchor(
                anchor_type="destination_ip",
                value=destination_ip,
                temporal=False,
            ),
            RelationshipAnchor(
                anchor_type="destination_port",
                value=str(
                    destination_port
                ),
                temporal=False,
            ),
            RelationshipAnchor(
                anchor_type="protocol",
                value=protocol,
                temporal=False,
            ),
            RelationshipAnchor(
                anchor_type="absolute_delta_seconds",
                value=format(
                    float(
                        delta
                    ),
                    ".6f",
                ),
                temporal=True,
            ),
        ),
        evidence_state=(
            EvidenceState.CORROBORATED
        ),
        rationale=_require_text(
            result.rationale,
            "correlation rationale",
        ),
        alternative_or_falsifier=(
            "A mismatch in source IP, source port, "
            "destination IP, destination port, "
            "transport protocol, or the bounded "
            "timestamp tolerance falsifies this "
            "cross-source correlation."
        ),
    )

    return CorrelationRelationshipProjection(
        legacy_correlation_id=(
            SYSMON_PCAP_CORRELATION_ID
        ),
        legacy_correlation_version=(
            SYSMON_PCAP_CORRELATION_VERSION
        ),
        legacy_edge_id=(
            edge.edge_id
        ),
        source_entity=(
            source_entity
        ),
        target_entity=(
            target_entity
        ),
        relationship=(
            relationship
        ),
    )


def _source_native_bridge_pid(
    value: object,
    *,
    field: str,
) -> str:
    if isinstance(
        value,
        bool,
    ):
        raise CorrelationBridgeError(
            field
            + " is not a valid process identifier"
        )

    if isinstance(
        value,
        int,
    ):
        if value < 0:
            raise CorrelationBridgeError(
                field
                + " is not a valid process identifier"
            )

        return str(
            value
        )

    text = _require_text(
        value,
        field,
    )

    try:
        number = int(
            text,
            10,
        )
    except ValueError as exc:
        raise CorrelationBridgeError(
            field
            + " is not a valid process identifier"
        ) from exc

    if number < 0:
        raise CorrelationBridgeError(
            field
            + " is not a valid process identifier"
        )

    return str(
        number
    )


def bridge_web_retrieval_correlation(
    *,
    result: CorrelationResult,
    powershell_event: SemanticEvent,
    zeek_event: SemanticEvent,
    script_block: object | None = None,
) -> CorrelationRelationshipProjection | None:
    version = getattr(
        result,
        "correlation_version",
        None,
    )

    if (
        version
        == NETWORK_CORRELATION_VERSION
    ):
        return (
            _bridge_web_retrieval_correlation_v1(
                result=result,
                powershell_event=(
                    powershell_event
                ),
                zeek_event=(
                    zeek_event
                ),
            )
        )

    if version != "2.0.0":
        raise CorrelationBridgeError(
            "unsupported TRC-CORR-001 correlation version"
        )

    if script_block is None:
        raise CorrelationBridgeError(
            "TRC-CORR-001 v2 requires "
            "reconstructed ScriptBlock evidence"
        )

    edge = _verify_legacy_result(
        result=result,
        expected_correlation_id=(
            NETWORK_CORRELATION_ID
        ),
        expected_correlation_version=(
            "2.0.0"
        ),
    )

    if edge is None:
        return None

    if (
        getattr(
            powershell_event,
            "source_type",
            None,
        )
        is not SourceType.POWERSHELL
    ):
        raise CorrelationBridgeError(
            "source event is not PowerShell"
        )

    if (
        getattr(
            zeek_event,
            "source_type",
            None,
        )
        is not SourceType.ZEEK
    ):
        raise CorrelationBridgeError(
            "target event is not Zeek"
        )

    (
        edge_id,
        delta,
    ) = _verify_edge_common(
        edge=edge,
        expected_correlation_id=(
            NETWORK_CORRELATION_ID
        ),
        expected_correlation_version=(
            "2.0.0"
        ),
        expected_relationship=(
            NETWORK_RELATIONSHIP
        ),
        source_event=(
            powershell_event
        ),
        target_event=(
            zeek_event
        ),
    )

    dimensions = (
        _matched_dimensions(
            edge
        )
    )

    expected_dimensions = {
        "script_uri_destination_ip",
        "script_uri_destination_port",
        "directional_time_window",
    }

    if (
        set(
            dimensions
        )
        != expected_dimensions
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-001 v2 "
            "matched dimensions changed"
        )

    parent_event_ids = tuple(
        getattr(
            script_block,
            "parent_event_ids",
            (),
        )
    )

    if (
        not parent_event_ids
        or powershell_event.event_id
        not in parent_event_ids
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-001 v2 "
            "ScriptBlock lineage mismatch"
        )

    block_time = getattr(
        script_block,
        "last_event_time_utc",
        None,
    )

    if (
        block_time is None
        or powershell_event.event_time_utc
        != block_time
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-001 v2 "
            "PowerShell anchor time mismatch"
        )

    target_fields = getattr(
        zeek_event,
        "fields",
        None,
    )

    if not hasattr(
        target_fields,
        "get",
    ):
        raise CorrelationBridgeError(
            "Zeek semantic fields are unavailable"
        )

    destination_ip = _normalized_ip(
        getattr(
            edge,
            "destination_ip",
            None,
        ),
        "edge destination_ip",
    )

    zeek_destination_ip = (
        _normalized_ip(
            target_fields.get(
                "dst_ip"
            ),
            "Zeek dst_ip",
        )
    )

    if (
        destination_ip
        != zeek_destination_ip
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-001 v2 "
            "destination IP anchor mismatch"
        )

    destination_port = getattr(
        edge,
        "destination_port",
        None,
    )

    observed_port = (
        target_fields.get(
            "dst_port"
        )
    )

    if (
        isinstance(
            destination_port,
            bool,
        )
        or not isinstance(
            destination_port,
            int,
        )
        or isinstance(
            observed_port,
            bool,
        )
        or not isinstance(
            observed_port,
            int,
        )
        or destination_port
        != observed_port
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-001 v2 "
            "destination port anchor mismatch"
        )

    source_entity = (
        _observation_entity(
            powershell_event
        )
    )

    target_entity = (
        _observation_entity(
            zeek_event
        )
    )

    relationship = (
        Relationship.create(
            relationship_type=(
                RelationshipType.CORROBORATES
            ),
            source_entity_id=(
                source_entity.entity_id
            ),
            target_entity_id=(
                target_entity.entity_id
            ),
            predicate_version=(
                NETWORK_CORRELATION_ID
                + "@2.0.0"
            ),
            supporting_ids=(
                edge_id,
                powershell_event.event_id,
                zeek_event.event_id,
            ),
            anchors=(
                RelationshipAnchor(
                    anchor_type=(
                        "script_uri_destination_ip"
                    ),
                    value=(
                        destination_ip
                    ),
                    temporal=False,
                ),
                RelationshipAnchor(
                    anchor_type=(
                        "script_uri_destination_port"
                    ),
                    value=str(
                        destination_port
                    ),
                    temporal=False,
                ),
                RelationshipAnchor(
                    anchor_type=(
                        "directional_delta_seconds"
                    ),
                    value=format(
                        delta,
                        ".6f",
                    ),
                    temporal=True,
                ),
            ),
            evidence_state=(
                EvidenceState.CORROBORATED
            ),
            rationale=_require_text(
                getattr(
                    result,
                    "rationale",
                    None,
                ),
                "correlation rationale",
            ),
            alternative_or_falsifier=(
                "A mismatch in the script-observed "
                "destination IP, destination port, event "
                "direction, or bounded time predicate "
                "falsifies this relationship. Source-host "
                "attribution remains explicitly "
                "unestablished by Zeek."
            ),
        )
    )

    return CorrelationRelationshipProjection(
        legacy_correlation_id=(
            NETWORK_CORRELATION_ID
        ),
        legacy_correlation_version=(
            "2.0.0"
        ),
        legacy_edge_id=edge_id,
        source_entity=(
            source_entity
        ),
        target_entity=(
            target_entity
        ),
        relationship=(
            relationship
        ),
    )


def bridge_powershell_process_correlation(
    *,
    result: ProcessCorrelationResult,
    sysmon_event: SemanticEvent,
    powershell_event: SemanticEvent,
    script_block: object | None = None,
) -> CorrelationRelationshipProjection | None:
    version = getattr(
        result,
        "correlation_version",
        None,
    )

    if (
        version
        == PROCESS_CORRELATION_VERSION
    ):
        return (
            _bridge_powershell_process_correlation_v1(
                result=result,
                sysmon_event=(
                    sysmon_event
                ),
                powershell_event=(
                    powershell_event
                ),
            )
        )

    if version != "2.0.0":
        raise CorrelationBridgeError(
            "unsupported TRC-CORR-002 correlation version"
        )

    if script_block is None:
        raise CorrelationBridgeError(
            "TRC-CORR-002 v2 requires "
            "reconstructed ScriptBlock evidence"
        )

    edge = _verify_legacy_result(
        result=result,
        expected_correlation_id=(
            PROCESS_CORRELATION_ID
        ),
        expected_correlation_version=(
            "2.0.0"
        ),
    )

    if edge is None:
        return None

    if (
        getattr(
            sysmon_event,
            "source_type",
            None,
        )
        is not SourceType.SYSMON
    ):
        raise CorrelationBridgeError(
            "source event is not Sysmon"
        )

    if (
        getattr(
            powershell_event,
            "source_type",
            None,
        )
        is not SourceType.POWERSHELL
    ):
        raise CorrelationBridgeError(
            "target event is not PowerShell"
        )

    (
        edge_id,
        delta,
    ) = _verify_edge_common(
        edge=edge,
        expected_correlation_id=(
            PROCESS_CORRELATION_ID
        ),
        expected_correlation_version=(
            "2.0.0"
        ),
        expected_relationship=(
            PROCESS_RELATIONSHIP
        ),
        source_event=(
            sysmon_event
        ),
        target_event=(
            powershell_event
        ),
    )

    dimensions = (
        _matched_dimensions(
            edge
        )
    )

    expected_dimensions = {
        "host",
        "process_id",
        "powershell_process_family",
        "directional_time_window",
    }

    if (
        set(
            dimensions
        )
        != expected_dimensions
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-002 v2 "
            "matched dimensions changed"
        )

    parent_event_ids = tuple(
        getattr(
            script_block,
            "parent_event_ids",
            (),
        )
    )

    if (
        not parent_event_ids
        or powershell_event.event_id
        not in parent_event_ids
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-002 v2 "
            "ScriptBlock lineage mismatch"
        )

    block_time = getattr(
        script_block,
        "first_event_time_utc",
        None,
    )

    if (
        block_time is None
        or powershell_event.event_time_utc
        != block_time
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-002 v2 "
            "PowerShell anchor time mismatch"
        )

    block_host = _require_text(
        getattr(
            script_block,
            "host",
            None,
        ),
        "ScriptBlock host",
    )

    sysmon_host = _require_text(
        getattr(
            sysmon_event,
            "host",
            None,
        ),
        "Sysmon host",
    )

    powershell_host = (
        _require_text(
            getattr(
                powershell_event,
                "host",
                None,
            ),
            "PowerShell host",
        )
    )

    if not (
        block_host.casefold()
        == sysmon_host.casefold()
        == powershell_host.casefold()
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-002 v2 "
            "host anchor mismatch"
        )

    source_fields = getattr(
        sysmon_event,
        "fields",
        None,
    )

    if not hasattr(
        source_fields,
        "get",
    ):
        raise CorrelationBridgeError(
            "Sysmon semantic fields are unavailable"
        )

    edge_process_id = (
        _source_native_bridge_pid(
            getattr(
                edge,
                "process_id",
                None,
            ),
            field="edge process_id",
        )
    )

    block_process_id = (
        _source_native_bridge_pid(
            getattr(
                script_block,
                "process_id",
                None,
            ),
            field="ScriptBlock process_id",
        )
    )

    sysmon_process_id = (
        _source_native_bridge_pid(
            source_fields.get(
                "process_id"
            ),
            field="Sysmon process_id",
        )
    )

    if not (
        edge_process_id
        == block_process_id
        == sysmon_process_id
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-002 v2 "
            "process ID anchor mismatch"
        )

    process_name = _require_text(
        getattr(
            edge,
            "process_name",
            None,
        ),
        "edge process_name",
    )

    raw_sysmon_process_name = (
        _require_text(
            source_fields.get(
                "process_name"
            ),
            "Sysmon process_name",
        )
    )

    sysmon_process_name = (
        raw_sysmon_process_name
        .replace(
            "\\",
            "/",
        )
        .rsplit(
            "/",
            1,
        )[-1]
    )

    if (
        process_name.casefold()
        != sysmon_process_name.casefold()
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-002 v2 "
            "process-family anchor mismatch"
        )

    source_entity = (
        _observation_entity(
            sysmon_event
        )
    )

    target_entity = (
        _observation_entity(
            powershell_event
        )
    )

    relationship = (
        Relationship.create(
            relationship_type=(
                RelationshipType.CORROBORATES
            ),
            source_entity_id=(
                source_entity.entity_id
            ),
            target_entity_id=(
                target_entity.entity_id
            ),
            predicate_version=(
                PROCESS_CORRELATION_ID
                + "@2.0.0"
            ),
            supporting_ids=(
                edge_id,
                sysmon_event.event_id,
                powershell_event.event_id,
            ),
            anchors=(
                _host_anchor(
                    sysmon_event,
                    powershell_event,
                ),
                RelationshipAnchor(
                    anchor_type=(
                        "process_id"
                    ),
                    value=(
                        edge_process_id
                    ),
                    temporal=False,
                ),
                RelationshipAnchor(
                    anchor_type=(
                        "powershell_process_family"
                    ),
                    value=(
                        process_name.casefold()
                    ),
                    temporal=False,
                ),
                RelationshipAnchor(
                    anchor_type=(
                        "directional_delta_seconds"
                    ),
                    value=format(
                        delta,
                        ".6f",
                    ),
                    temporal=True,
                ),
            ),
            evidence_state=(
                EvidenceState.CORROBORATED
            ),
            rationale=_require_text(
                getattr(
                    result,
                    "rationale",
                    None,
                ),
                "correlation rationale",
            ),
            alternative_or_falsifier=(
                "A mismatch in host, exact process ID, "
                "PowerShell process family, event direction, "
                "or the bounded time predicate falsifies "
                "this relationship."
            ),
        )
    )

    return CorrelationRelationshipProjection(
        legacy_correlation_id=(
            PROCESS_CORRELATION_ID
        ),
        legacy_correlation_version=(
            "2.0.0"
        ),
        legacy_edge_id=edge_id,
        source_entity=(
            source_entity
        ),
        target_entity=(
            target_entity
        ),
        relationship=(
            relationship
        ),
    )

def bridge_security_sysmon_process_correlation(
    *,
    result: SecuritySysmonProcessResult,
    security_event: SemanticEvent,
    sysmon_event: SemanticEvent,
) -> CorrelationRelationshipProjection | None:
    if (
        result.correlation_id
        != SECURITY_SYSMON_CORRELATION_ID
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-004 correlation ID changed"
        )

    if (
        result.correlation_version
        != SECURITY_SYSMON_CORRELATION_VERSION
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-004 correlation version changed"
        )

    if not result.matched:
        if result.edge is not None:
            raise CorrelationBridgeError(
                "TRC-CORR-004 non-match contains an edge"
            )

        return None

    edge = result.edge

    if edge is None:
        raise CorrelationBridgeError(
            "TRC-CORR-004 match has no edge"
        )

    if (
        security_event.source_type
        is not SourceType.WINDOWS_SECURITY
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-004 source is not Windows Security"
        )

    if (
        security_event.event_type
        != "process_create"
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-004 source is not a process creation"
        )

    if (
        sysmon_event.source_type
        is not SourceType.SYSMON
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-004 target is not Sysmon"
        )

    if (
        sysmon_event.event_type
        != "process_create"
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-004 target is not a process creation"
        )

    (
        edge_id,
        delta,
    ) = _verify_edge_common(
        edge=edge,
        expected_correlation_id=(
            SECURITY_SYSMON_CORRELATION_ID
        ),
        expected_correlation_version=(
            SECURITY_SYSMON_CORRELATION_VERSION
        ),
        expected_relationship=(
            SECURITY_SYSMON_RELATIONSHIP
        ),
        source_event=security_event,
        target_event=sysmon_event,
    )

    dimensions = set(
        _matched_dimensions(
            edge
        )
    )

    required_dimensions = {
        "host",
        "process_id",
        "process_name",
        "bounded_absolute_time_window",
    }

    optional_dimensions = {
        "parent_process_id",
        "parent_process",
    }

    if not required_dimensions.issubset(
        dimensions
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-004 required matched dimensions changed"
        )

    if not dimensions.issubset(
        required_dimensions
        | optional_dimensions
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-004 unexpected matched dimension"
        )

    _host_anchor(
        security_event,
        sysmon_event,
    )

    security_fields = security_event.fields
    sysmon_fields = sysmon_event.fields

    security_pid = normalize_windows_process_id(
        security_fields.get(
            "process_id"
        )
    )
    sysmon_pid = normalize_windows_process_id(
        sysmon_fields.get(
            "process_id"
        )
    )
    edge_pid = normalize_windows_process_id(
        edge.process_id
    )

    if (
        security_pid is None
        or sysmon_pid is None
        or edge_pid is None
        or not (
            security_pid
            == sysmon_pid
            == edge_pid
        )
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-004 process ID anchor mismatch"
        )

    security_process = normalize_windows_process_path(
        security_fields.get(
            "process_name"
        )
    )
    sysmon_process = normalize_windows_process_path(
        sysmon_fields.get(
            "process_name"
        )
    )
    edge_process = normalize_windows_process_path(
        edge.process_name
    )

    if (
        security_process is None
        or sysmon_process is None
        or edge_process is None
        or not (
            security_process
            == sysmon_process
            == edge_process
        )
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-004 process image anchor mismatch"
        )

    anchors = [
        _host_anchor(
            security_event,
            sysmon_event,
        ),
        RelationshipAnchor(
            anchor_type="process_id",
            value=security_pid,
            temporal=False,
        ),
        RelationshipAnchor(
            anchor_type="process_name",
            value=security_process,
            temporal=False,
        ),
    ]

    if (
        "parent_process_id"
        in dimensions
    ):
        security_parent_id = normalize_windows_process_id(
            security_fields.get(
                "parent_process_id"
            )
        )
        sysmon_parent_id = normalize_windows_process_id(
            sysmon_fields.get(
                "parent_process_id"
            )
        )
        edge_parent_id = normalize_windows_process_id(
            edge.parent_process_id
        )

        if (
            security_parent_id is None
            or sysmon_parent_id is None
            or edge_parent_id is None
            or not (
                security_parent_id
                == sysmon_parent_id
                == edge_parent_id
            )
        ):
            raise CorrelationBridgeError(
                "TRC-CORR-004 parent process ID anchor mismatch"
            )

        anchors.append(
            RelationshipAnchor(
                anchor_type="parent_process_id",
                value=security_parent_id,
                temporal=False,
            )
        )

    if (
        "parent_process"
        in dimensions
    ):
        security_parent = normalize_windows_process_path(
            security_fields.get(
                "parent_process"
            )
        )
        sysmon_parent = normalize_windows_process_path(
            sysmon_fields.get(
                "parent_process"
            )
        )
        edge_parent = normalize_windows_process_path(
            edge.parent_process
        )

        if (
            security_parent is None
            or sysmon_parent is None
            or edge_parent is None
            or not (
                security_parent
                == sysmon_parent
                == edge_parent
            )
        ):
            raise CorrelationBridgeError(
                "TRC-CORR-004 parent process image anchor mismatch"
            )

        anchors.append(
            RelationshipAnchor(
                anchor_type="parent_process",
                value=security_parent,
                temporal=False,
            )
        )

    anchors.append(
        RelationshipAnchor(
            anchor_type="absolute_delta_seconds",
            value=format(
                delta,
                ".6f",
            ),
            temporal=True,
        )
    )

    source_entity = _observation_entity(
        security_event
    )
    target_entity = _observation_entity(
        sysmon_event
    )

    relationship = Relationship.create(
        relationship_type=(
            RelationshipType.CORROBORATES
        ),
        source_entity_id=(
            source_entity.entity_id
        ),
        target_entity_id=(
            target_entity.entity_id
        ),
        predicate_version=(
            SECURITY_SYSMON_CORRELATION_ID
            + "@"
            + SECURITY_SYSMON_CORRELATION_VERSION
        ),
        supporting_ids=(
            edge_id,
            security_event.event_id,
            sysmon_event.event_id,
        ),
        anchors=tuple(
            anchors
        ),
        evidence_state=(
            EvidenceState.CORROBORATED
        ),
        rationale=_require_text(
            result.rationale,
            "correlation rationale",
        ),
        alternative_or_falsifier=(
            "A mismatch in host, normalized process ID, "
            "exact process image/path, any mutually "
            "available parent-process anchor, or the "
            "bounded timestamp tolerance falsifies this "
            "cross-source process corroboration. Matching "
            "process observations do not establish "
            "malicious intent or incident membership."
        ),
    )

    return CorrelationRelationshipProjection(
        legacy_correlation_id=(
            SECURITY_SYSMON_CORRELATION_ID
        ),
        legacy_correlation_version=(
            SECURITY_SYSMON_CORRELATION_VERSION
        ),
        legacy_edge_id=edge_id,
        source_entity=source_entity,
        target_entity=target_entity,
        relationship=relationship,
    )

def bridge_email_sysmon_artifact_correlation(
    *,
    result: EmailSysmonArtifactResult,
    email_event: SemanticEvent,
    sysmon_event: SemanticEvent,
) -> CorrelationRelationshipProjection | None:
    if (
        result.correlation_id
        != EMAIL_SYSMON_CORRELATION_ID
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-005 correlation ID changed"
        )

    if (
        result.correlation_version
        != EMAIL_SYSMON_CORRELATION_VERSION
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-005 correlation version changed"
        )

    if not result.matched:
        if result.edge is not None:
            raise CorrelationBridgeError(
                "TRC-CORR-005 non-match contains an edge"
            )

        return None

    edge = result.edge

    if edge is None:
        raise CorrelationBridgeError(
            "TRC-CORR-005 match has no edge"
        )

    if (
        email_event.source_type
        is not SourceType.EMAIL
        or email_event.event_type
        != "email_mime_part"
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-005 source is not an "
            "email MIME part"
        )

    if (
        sysmon_event.source_type
        is not SourceType.SYSMON
        or sysmon_event.event_type
        != "process_create"
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-005 target is not a "
            "Sysmon process creation"
        )

    if (
        edge.source_event_id
        != email_event.event_id
        or edge.target_event_id
        != sysmon_event.event_id
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-005 edge orientation mismatch"
        )

    if (
        edge.relationship
        != EMAIL_SYSMON_RELATIONSHIP
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-005 relationship name changed"
        )

    if (
        set(
            edge.matched_dimensions
        )
        != {
            "sha256",
        }
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-005 matched dimensions changed"
        )

    email_sha256 = (
        normalize_sha256(
            email_event.fields.get(
                "decoded_sha256"
            )
        )
    )

    sysmon_sha256 = (
        extract_sysmon_sha256(
            sysmon_event.fields.get(
                "hashes"
            )
        )
    )

    edge_sha256 = (
        normalize_sha256(
            edge.sha256
        )
    )

    if (
        email_sha256 is None
        or sysmon_sha256 is None
        or edge_sha256 is None
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-005 SHA-256 anchor unavailable"
        )

    if not (
        email_sha256
        == sysmon_sha256
        == edge_sha256
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-005 SHA-256 anchor mismatch"
        )

    source_entity = (
        _observation_entity(
            email_event
        )
    )

    target_entity = (
        _observation_entity(
            sysmon_event
        )
    )

    relationship = (
        Relationship.create(
            relationship_type=(
                RelationshipType.CORROBORATES
            ),
            source_entity_id=(
                source_entity.entity_id
            ),
            target_entity_id=(
                target_entity.entity_id
            ),
            predicate_version=(
                EMAIL_SYSMON_CORRELATION_ID
                + "@"
                + EMAIL_SYSMON_CORRELATION_VERSION
            ),
            supporting_ids=(
                edge.edge_id,
                email_event.event_id,
                sysmon_event.event_id,
            ),
            anchors=(
                RelationshipAnchor(
                    anchor_type=(
                        "sha256"
                    ),
                    value=(
                        email_sha256
                    ),
                    temporal=False,
                ),
            ),
            evidence_state=(
                EvidenceState.CORROBORATED
            ),
            rationale=_require_text(
                result.rationale,
                "correlation rationale",
            ),
            alternative_or_falsifier=(
                "Any mismatch in the decoded MIME "
                "attachment SHA-256 and the explicit "
                "Sysmon process-image SHA256 falsifies "
                "byte identity. Matching hashes do not "
                "by themselves establish message "
                "delivery, user interaction, causal "
                "execution from the email, malicious "
                "intent, or incident membership."
            ),
        )
    )

    return CorrelationRelationshipProjection(
        legacy_correlation_id=(
            EMAIL_SYSMON_CORRELATION_ID
        ),
        legacy_correlation_version=(
            EMAIL_SYSMON_CORRELATION_VERSION
        ),
        legacy_edge_id=(
            edge.edge_id
        ),
        source_entity=(
            source_entity
        ),
        target_entity=(
            target_entity
        ),
        relationship=(
            relationship
        ),
    )

def bridge_sysmon_process_network_correlation(
    *,
    result: SysmonProcessNetworkResult,
    process_event: SemanticEvent,
    network_event: SemanticEvent,
) -> CorrelationRelationshipProjection | None:
    if (
        result.correlation_id
        != SYSMON_PROCESS_NETWORK_CORRELATION_ID
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-006 correlation ID changed"
        )

    if (
        result.correlation_version
        != SYSMON_PROCESS_NETWORK_CORRELATION_VERSION
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-006 correlation version changed"
        )

    if not result.matched:
        if result.edge is not None:
            raise CorrelationBridgeError(
                "TRC-CORR-006 non-match contains edge"
            )

        return None

    edge = result.edge

    if edge is None:
        raise CorrelationBridgeError(
            "TRC-CORR-006 match has no edge"
        )

    if (
        process_event.source_type
        is not SourceType.SYSMON
        or process_event.event_type
        != "process_create"
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-006 source type changed"
        )

    if (
        network_event.source_type
        is not SourceType.SYSMON
        or network_event.event_type
        != "network_connection"
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-006 target type changed"
        )

    if (
        edge.source_event_id
        != process_event.event_id
        or edge.target_event_id
        != network_event.event_id
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-006 edge orientation mismatch"
        )

    if (
        edge.relationship
        != SYSMON_PROCESS_NETWORK_RELATIONSHIP
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-006 relationship name changed"
        )

    dimensions = set(
        edge.matched_dimensions
    )

    required = {
        "process_guid",
        "host",
    }

    optional = {
        "process_id",
        "process_name",
    }

    if not required.issubset(
        dimensions
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-006 required dimensions changed"
        )

    if not dimensions.issubset(
        required
        | optional
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-006 unexpected matched dimension"
        )

    process_guid = (
        normalize_sysmon_process_guid(
            process_event.fields.get(
                "process_guid"
            )
        )
    )

    network_guid = (
        normalize_sysmon_process_guid(
            network_event.fields.get(
                "process_guid"
            )
        )
    )

    edge_guid = (
        normalize_sysmon_process_guid(
            edge.process_guid
        )
    )

    if (
        process_guid is None
        or network_guid is None
        or edge_guid is None
        or not (
            process_guid
            == network_guid
            == edge_guid
        )
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-006 ProcessGuid anchor mismatch"
        )

    process_host = (
        process_event.host.strip().casefold()
        if isinstance(
            process_event.host,
            str,
        )
        and process_event.host.strip()
        else None
    )

    network_host = (
        network_event.host.strip().casefold()
        if isinstance(
            network_event.host,
            str,
        )
        and network_event.host.strip()
        else None
    )

    edge_host = (
        edge.host.strip().casefold()
        if isinstance(
            edge.host,
            str,
        )
        and edge.host.strip()
        else None
    )

    if (
        process_host is None
        or network_host is None
        or edge_host is None
        or not (
            process_host
            == network_host
            == edge_host
        )
    ):
        raise CorrelationBridgeError(
            "TRC-CORR-006 host anchor mismatch"
        )

    anchors = [
        RelationshipAnchor(
            anchor_type=(
                "process_guid"
            ),
            value=(
                process_guid
            ),
            temporal=False,
        ),
        RelationshipAnchor(
            anchor_type=(
                "host"
            ),
            value=(
                process_host
            ),
            temporal=False,
        ),
    ]

    if "process_id" in dimensions:
        process_pid = (
            normalize_windows_process_id(
                process_event.fields.get(
                    "process_id"
                )
            )
        )

        network_pid = (
            normalize_windows_process_id(
                network_event.fields.get(
                    "process_id"
                )
            )
        )

        edge_pid = (
            normalize_windows_process_id(
                edge.process_id
            )
        )

        if (
            process_pid is None
            or network_pid is None
            or edge_pid is None
            or not (
                process_pid
                == network_pid
                == edge_pid
            )
        ):
            raise CorrelationBridgeError(
                "TRC-CORR-006 process ID mismatch"
            )

        anchors.append(
            RelationshipAnchor(
                anchor_type=(
                    "process_id"
                ),
                value=(
                    process_pid
                ),
                temporal=False,
            )
        )

    if "process_name" in dimensions:
        process_name = (
            normalize_windows_process_path(
                process_event.fields.get(
                    "process_name"
                )
            )
        )

        network_name = (
            normalize_windows_process_path(
                network_event.fields.get(
                    "process_name"
                )
            )
        )

        edge_name = (
            normalize_windows_process_path(
                edge.process_name
            )
        )

        if (
            process_name is None
            or network_name is None
            or edge_name is None
            or not (
                process_name
                == network_name
                == edge_name
            )
        ):
            raise CorrelationBridgeError(
                "TRC-CORR-006 process image mismatch"
            )

        anchors.append(
            RelationshipAnchor(
                anchor_type=(
                    "process_name"
                ),
                value=(
                    process_name
                ),
                temporal=False,
            )
        )

    source_entity = (
        _observation_entity(
            process_event
        )
    )

    target_entity = (
        _observation_entity(
            network_event
        )
    )

    relationship = (
        Relationship.create(
            relationship_type=(
                RelationshipType.CORROBORATES
            ),
            source_entity_id=(
                source_entity.entity_id
            ),
            target_entity_id=(
                target_entity.entity_id
            ),
            predicate_version=(
                SYSMON_PROCESS_NETWORK_CORRELATION_ID
                + "@"
                + SYSMON_PROCESS_NETWORK_CORRELATION_VERSION
            ),
            supporting_ids=(
                edge.edge_id,
                process_event.event_id,
                network_event.event_id,
            ),
            anchors=tuple(
                anchors
            ),
            evidence_state=(
                EvidenceState.CORROBORATED
            ),
            rationale=_require_text(
                result.rationale,
                "correlation rationale",
            ),
            alternative_or_falsifier=(
                "This edge records Sysmon's "
                "source-native process-instance "
                "attribution only. It does not "
                "establish malicious intent, user "
                "action, higher-level causal intent, "
                "or incident membership."
            ),
        )
    )

    return CorrelationRelationshipProjection(
        legacy_correlation_id=(
            SYSMON_PROCESS_NETWORK_CORRELATION_ID
        ),
        legacy_correlation_version=(
            SYSMON_PROCESS_NETWORK_CORRELATION_VERSION
        ),
        legacy_edge_id=(
            edge.edge_id
        ),
        source_entity=(
            source_entity
        ),
        target_entity=(
            target_entity
        ),
        relationship=(
            relationship
        ),
    )
