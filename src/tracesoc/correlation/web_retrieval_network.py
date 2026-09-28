from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

from tracesoc.correlation.models import (
    CorrelationEdge,
    CorrelationResult,
    CorrelationState,
)
from tracesoc.detection.models import DetectionResult
from tracesoc.models import SemanticEvent, SourceType


CORRELATION_ID = "TRC-CORR-001"
CORRELATION_VERSION = "1.0.0"
RELATIONSHIP = "powershell_web_retrieval_network_corroboration"

DEFAULT_MAX_SECONDS = 60.0

_URI_RE = re.compile(
    r"""https?://[^\s"'<>]+""",
    re.IGNORECASE,
)


def correlate_web_retrieval_with_zeek(
    *,
    detection: DetectionResult,
    powershell_event: SemanticEvent,
    zeek_event: SemanticEvent,
    max_seconds: float = DEFAULT_MAX_SECONDS,
) -> CorrelationResult:
    """
    Correlate one matched PowerShell retrieval behavior with one Zeek
    connection using explicit relational evidence.

    Time proximity alone is insufficient.
    """

    if max_seconds <= 0:
        raise ValueError("max_seconds must be greater than zero")

    if not detection.matched:
        return _no_match(
            "detection_not_matched",
            "The required PowerShell behavioral detection did not match.",
        )

    if powershell_event.event_id not in detection.contributing_event_ids:
        return _no_match(
            "detection_event_mismatch",
            "The PowerShell event is not a contributing event for the detection.",
        )

    if powershell_event.source_type != SourceType.POWERSHELL:
        return _no_match(
            "wrong_source_event_type",
            "Source event is not PowerShell telemetry.",
        )

    if zeek_event.source_type != SourceType.ZEEK:
        return _no_match(
            "wrong_target_event_type",
            "Target event is not Zeek telemetry.",
        )

    if powershell_event.event_time_utc is None:
        return _no_match(
            "source_time_unavailable",
            "PowerShell event has no normalized UTC time.",
        )

    if zeek_event.event_time_utc is None:
        return _no_match(
            "target_time_unavailable",
            "Zeek event has no normalized UTC time.",
        )

    if not powershell_event.host or not zeek_event.host:
        return _no_match(
            "host_unavailable",
            "Both telemetry sources must identify the host.",
        )

    if powershell_event.host.casefold() != zeek_event.host.casefold():
        return _no_match(
            "host_mismatch",
            "PowerShell and Zeek observations identify different hosts.",
        )

    source_ip = _normalized_ip(
        powershell_event.fields.get("local_ip")
    )

    network_source_ip = _normalized_ip(
        zeek_event.fields.get("src_ip")
    )

    if source_ip is None or network_source_ip is None:
        return _no_match(
            "source_ip_unavailable",
            "Both telemetry sources require valid source/local IP addresses.",
        )

    if source_ip != network_source_ip:
        return _no_match(
            "source_ip_mismatch",
            "PowerShell local IP and Zeek source IP do not match.",
        )

    script_text = powershell_event.fields.get("script_text")

    if not isinstance(script_text, str) or not script_text.strip():
        return _no_match(
            "script_text_unavailable",
            "PowerShell script text is unavailable.",
        )

    destination = _extract_ip_destination(
        script_text
    )

    if destination is None:
        return _no_match(
            "uri_destination_not_correlatable",
            "No HTTP(S) URI with an IP-literal destination could be extracted.",
        )

    expected_ip, expected_port = destination

    observed_destination_ip = _normalized_ip(
        zeek_event.fields.get("dst_ip")
    )

    observed_destination_port = (
        zeek_event.fields.get("dst_port")
    )

    if observed_destination_ip is None:
        return _no_match(
            "destination_ip_unavailable",
            "Zeek destination IP is unavailable or invalid.",
        )

    if expected_ip != observed_destination_ip:
        return _no_match(
            "destination_ip_mismatch",
            "PowerShell URI destination and Zeek destination IP do not match.",
        )

    if (
        isinstance(observed_destination_port, bool)
        or not isinstance(observed_destination_port, int)
    ):
        return _no_match(
            "destination_port_unavailable",
            "Zeek destination port is unavailable or invalid.",
        )

    if expected_port != observed_destination_port:
        return _no_match(
            "destination_port_mismatch",
            "PowerShell URI port and Zeek destination port do not match.",
        )

    delta_seconds = (
        zeek_event.event_time_utc
        - powershell_event.event_time_utc
    ).total_seconds()

    if delta_seconds < 0:
        return _no_match(
            "network_precedes_behavior",
            "Zeek connection occurs before the PowerShell retrieval event.",
        )

    if delta_seconds > max_seconds:
        return _no_match(
            "outside_time_window",
            "Zeek connection falls outside the bounded correlation window.",
        )

    dimensions = (
        "host",
        "source_ip",
        "destination_ip",
        "destination_port",
        "directional_time_window",
    )

    edge_id = _edge_id(
        source_event_id=powershell_event.event_id,
        target_event_id=zeek_event.event_id,
        destination_ip=expected_ip,
        destination_port=expected_port,
        max_seconds=max_seconds,
    )

    edge = CorrelationEdge(
        correlation_id=CORRELATION_ID,
        correlation_version=CORRELATION_VERSION,
        edge_id=edge_id,
        relationship=RELATIONSHIP,
        source_event_id=powershell_event.event_id,
        target_event_id=zeek_event.event_id,
        delta_seconds=delta_seconds,
        destination_ip=expected_ip,
        destination_port=expected_port,
        matched_dimensions=dimensions,
    )

    return CorrelationResult(
        correlation_id=CORRELATION_ID,
        correlation_version=CORRELATION_VERSION,
        state=CorrelationState.MATCH,
        reason_code="cross_source_retrieval_corroborated",
        rationale=(
            "PowerShell retrieval behavior and Zeek network telemetry agree "
            "on host, source IP, destination IP, destination port, and a "
            "directional bounded time window. This corroborates the behavior "
            "but does not establish malicious intent."
        ),
        edge=edge,
    )


def _extract_ip_destination(
    script_text: str,
) -> tuple[str, int] | None:
    match = _URI_RE.search(script_text)

    if match is None:
        return None

    raw_uri = match.group(0).rstrip(
        ").,;]"
    )

    try:
        parsed = urlsplit(raw_uri)
    except ValueError:
        return None

    hostname = parsed.hostname

    if hostname is None:
        return None

    try:
        destination_ip = str(
            ipaddress.ip_address(hostname)
        )
    except ValueError:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    if port is None:
        if parsed.scheme.casefold() == "http":
            port = 80
        elif parsed.scheme.casefold() == "https":
            port = 443
        else:
            return None

    return destination_ip, port


def _normalized_ip(
    value: object,
) -> str | None:
    if not isinstance(value, str):
        return None

    try:
        return str(
            ipaddress.ip_address(value.strip())
        )
    except ValueError:
        return None


def _edge_id(
    *,
    source_event_id: str,
    target_event_id: str,
    destination_ip: str,
    destination_port: int,
    max_seconds: float,
) -> str:
    material = {
        "correlation_id": CORRELATION_ID,
        "correlation_version": CORRELATION_VERSION,
        "relationship": RELATIONSHIP,
        "source_event_id": source_event_id,
        "target_event_id": target_event_id,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
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
) -> CorrelationResult:
    return CorrelationResult(
        correlation_id=CORRELATION_ID,
        correlation_version=CORRELATION_VERSION,
        state=CorrelationState.NO_MATCH,
        reason_code=reason_code,
        rationale=rationale,
        edge=None,
    )


SOURCE_NATIVE_CORRELATION_VERSION = "2.0.0"


def _source_native_edge_id(
    *,
    source_event_id: str,
    target_event_id: str,
    destination_ip: str,
    destination_port: int,
    max_seconds: float,
) -> str:
    import hashlib

    material = "\x00".join(
        (
            CORRELATION_ID,
            SOURCE_NATIVE_CORRELATION_VERSION,
            source_event_id,
            target_event_id,
            destination_ip,
            str(
                destination_port
            ),
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


def correlate_reconstructed_web_retrieval_with_zeek(
    *,
    detection: DetectionResult,
    script_block: object,
    powershell_event: SemanticEvent,
    zeek_event: SemanticEvent,
    max_seconds: float = DEFAULT_MAX_SECONDS,
) -> CorrelationResult:
    """
    Correlate a matched reconstructed PowerShell ScriptBlock with one Zeek
    connection using only source-native fields both sources can actually
    provide.

    The relationship is limited to the script-observed destination IP/port
    plus directional bounded time. Zeek conn.log does not, by itself,
    establish the originating Windows host identity.
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
                "detector did not match."
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
            "wrong_source_event_type",
            "Source event is not PowerShell telemetry.",
        )

    if (
        zeek_event.source_type
        != SourceType.ZEEK
    ):
        return _no_match(
            "wrong_target_event_type",
            "Target event is not Zeek telemetry.",
        )

    source_time = getattr(
        script_block,
        "last_event_time_utc",
        None,
    )

    if source_time is None:
        return _no_match(
            "source_time_unavailable",
            (
                "The reconstructed ScriptBlock has "
                "no final observed UTC time."
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
                "the final observed fragment of the "
                "reconstructed ScriptBlock."
            ),
        )

    if (
        zeek_event.event_time_utc
        is None
    ):
        return _no_match(
            "target_time_unavailable",
            "Zeek event has no normalized UTC time.",
        )

    script_text = getattr(
        script_block,
        "script_text",
        None,
    )

    if (
        not isinstance(
            script_text,
            str,
        )
        or not script_text.strip()
    ):
        return _no_match(
            "script_text_unavailable",
            (
                "Complete reconstructed PowerShell "
                "script text is unavailable."
            ),
        )

    destination = (
        _extract_ip_destination(
            script_text
        )
    )

    if destination is None:
        return _no_match(
            "uri_destination_not_correlatable",
            (
                "No HTTP(S) URI with an IP-literal "
                "destination could be extracted from "
                "the reconstructed script."
            ),
        )

    (
        expected_ip,
        expected_port,
    ) = destination

    observed_destination_ip = (
        _normalized_ip(
            zeek_event.fields.get(
                "dst_ip"
            )
        )
    )

    observed_destination_port = (
        zeek_event.fields.get(
            "dst_port"
        )
    )

    if observed_destination_ip is None:
        return _no_match(
            "destination_ip_unavailable",
            (
                "Zeek destination IP is "
                "unavailable or invalid."
            ),
        )

    if (
        expected_ip
        != observed_destination_ip
    ):
        return _no_match(
            "destination_ip_mismatch",
            (
                "PowerShell URI destination and "
                "Zeek destination IP do not match."
            ),
        )

    if (
        isinstance(
            observed_destination_port,
            bool,
        )
        or not isinstance(
            observed_destination_port,
            int,
        )
    ):
        return _no_match(
            "destination_port_unavailable",
            (
                "Zeek destination port is "
                "unavailable or invalid."
            ),
        )

    if (
        expected_port
        != observed_destination_port
    ):
        return _no_match(
            "destination_port_mismatch",
            (
                "PowerShell URI port and Zeek "
                "destination port do not match."
            ),
        )

    delta_seconds = (
        zeek_event.event_time_utc
        - source_time
    ).total_seconds()

    if delta_seconds < 0:
        return _no_match(
            "network_precedes_behavior",
            (
                "Zeek connection occurs before "
                "the final observed ScriptBlock fragment."
            ),
        )

    if delta_seconds > max_seconds:
        return _no_match(
            "outside_time_window",
            (
                "Zeek connection falls outside "
                "the bounded source-native "
                "correlation window."
            ),
        )

    dimensions = (
        "script_uri_destination_ip",
        "script_uri_destination_port",
        "directional_time_window",
    )

    edge = CorrelationEdge(
        correlation_id=CORRELATION_ID,
        correlation_version=(
            SOURCE_NATIVE_CORRELATION_VERSION
        ),
        edge_id=(
            _source_native_edge_id(
                source_event_id=(
                    powershell_event.event_id
                ),
                target_event_id=(
                    zeek_event.event_id
                ),
                destination_ip=(
                    expected_ip
                ),
                destination_port=(
                    expected_port
                ),
                max_seconds=max_seconds,
            )
        ),
        relationship=RELATIONSHIP,
        source_event_id=(
            powershell_event.event_id
        ),
        target_event_id=(
            zeek_event.event_id
        ),
        delta_seconds=delta_seconds,
        destination_ip=expected_ip,
        destination_port=(
            expected_port
        ),
        matched_dimensions=(
            dimensions
        ),
    )

    return CorrelationResult(
        correlation_id=CORRELATION_ID,
        correlation_version=(
            SOURCE_NATIVE_CORRELATION_VERSION
        ),
        state=CorrelationState.MATCH,
        reason_code=(
            "source_native_retrieval_"
            "destination_corroborated"
        ),
        rationale=(
            "A complete reconstructed PowerShell ScriptBlock "
            "contains an HTTP(S) IP-literal destination that "
            "agrees with Zeek on destination IP and destination "
            "port within a directional bounded time window. "
            "This corroborates destination-level network evidence "
            "only; Zeek does not establish the originating Windows "
            "host, process causality, retrieval success, or "
            "malicious intent."
        ),
        edge=edge,
    )
