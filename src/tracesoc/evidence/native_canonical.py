from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)
from email.utils import (
    parsedate_to_datetime,
)
from typing import Any

from tracesoc.evidence.identity import (
    compute_event_id,
)
from tracesoc.evidence.intake import (
    AdapterFamily,
    EvidenceDirectoryIntake,
    EvidenceFileIntake,
)
from tracesoc.evidence.locators import (
    EvidenceLocator,
)
from tracesoc.models import (
    CanonicalEvent,
    ClockState,
    RawLocator,
    SourceType,
)
from tracesoc.parsers.eml import (
    EmailMessageObservation,
    EmailPartObservation,
)
from tracesoc.parsers.pcap import (
    PcapPacketObservation,
)


class NativeCanonicalizationError(
    ValueError
):
    pass


def _native_locator_record(
    locator: EvidenceLocator,
) -> dict[
    str,
    Any,
]:
    return {
        "artifact_id":
            locator.artifact_id,

        "artifact_type":
            locator.artifact_type,

        "locator_kind":
            locator.locator_kind.value,

        "raw_sha256":
            locator.raw_sha256,

        "adapter_id":
            locator.adapter_id,

        "input_schema_version":
            locator.input_schema_version,

        "record_index":
            locator.record_index,

        "line_number":
            locator.line_number,

        "byte_offset":
            locator.byte_offset,

        "byte_length":
            locator.byte_length,

        "mime_part_path":
            (
                None
                if locator.mime_part_path
                is None
                else list(
                    locator.mime_part_path
                )
            ),

        "packet_number":
            locator.packet_number,
    }


def _canonical_raw_locator(
    *,
    item: EvidenceFileIntake,
    locator: EvidenceLocator,
    record_index: int,
) -> RawLocator:
    if locator.artifact_id != item.artifact.artifact_id:
        raise NativeCanonicalizationError(
            "native locator artifact_id does not "
            "match intake artifact"
        )

    if (
        locator.artifact_type
        != item.artifact.artifact_type
    ):
        raise NativeCanonicalizationError(
            "native locator artifact_type does not "
            "match intake artifact"
        )

    return RawLocator(
        logical_source=(
            item.artifact.source_path_display
        ),
        record_index=record_index,
        line_number=locator.line_number,
        byte_offset=locator.byte_offset,
        byte_length=locator.byte_length,
        raw_sha256=locator.raw_sha256,
        adapter_id=locator.adapter_id,
        input_schema_version=(
            locator.input_schema_version
        ),
    )


def _email_time(
    raw_date: str | None,
) -> tuple[
    ClockState,
    datetime | None,
]:
    if raw_date is None:
        return (
            ClockState.UNTIMED,
            None,
        )

    try:
        parsed = parsedate_to_datetime(
            raw_date
        )
    except (
        TypeError,
        ValueError,
        OverflowError,
    ):
        return (
            ClockState.UNRESOLVED,
            None,
        )

    if (
        parsed is None
        or parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        return (
            ClockState.UNRESOLVED,
            None,
        )

    return (
        ClockState.OBSERVED,
        parsed.astimezone(
            timezone.utc
        ),
    )


def _email_message_event(
    *,
    item: EvidenceFileIntake,
    observation: EmailMessageObservation,
    native_index: int,
) -> CanonicalEvent:
    if observation.source_type is not SourceType.EMAIL:
        raise NativeCanonicalizationError(
            "email message observation has wrong "
            "source_type"
        )

    locator = _canonical_raw_locator(
        item=item,
        locator=observation.locator,
        record_index=native_index,
    )

    clock_state, event_time_utc = (
        _email_time(
            observation.date
        )
    )

    source_context = {
        "artifact_id":
            observation.artifact_id,

        "native_locator":
            _native_locator_record(
                observation.locator
            ),

        "canonical_record_index_basis":
            "native_observation_order_zero_based",

        "message_id":
            observation.message_id,

        "date":
            observation.date,

        "from_value":
            observation.from_value,

        "to_value":
            observation.to_value,

        "subject":
            observation.subject,

        "defects":
            list(
                observation.defects
            ),
    }

    semantic_fields = {
        "message_id":
            observation.message_id,

        "from_value":
            observation.from_value,

        "to_value":
            observation.to_value,

        "subject":
            observation.subject,
    }

    return CanonicalEvent(
        event_id=compute_event_id(
            locator=locator,
            source_type=observation.source_type,
            event_type=observation.event_type,
        ),
        source_type=observation.source_type,
        event_type=observation.event_type,
        clock_state=clock_state,
        provenance=locator,
        event_time_raw=observation.date,
        event_time_utc=event_time_utc,
        host=None,
        principal=None,
        semantic_fields=semantic_fields,
        source_context=source_context,
    )


def _email_part_event(
    *,
    item: EvidenceFileIntake,
    observation: EmailPartObservation,
    native_index: int,
) -> CanonicalEvent:
    if observation.source_type is not SourceType.EMAIL:
        raise NativeCanonicalizationError(
            "email part observation has wrong "
            "source_type"
        )

    locator = _canonical_raw_locator(
        item=item,
        locator=observation.locator,
        record_index=native_index,
    )

    source_context = {
        "artifact_id":
            observation.artifact_id,

        "native_locator":
            _native_locator_record(
                observation.locator
            ),

        "canonical_record_index_basis":
            "native_observation_order_zero_based",

        "content_type":
            observation.content_type,

        "content_disposition":
            observation.content_disposition,

        "filename":
            observation.filename,

        "content_id":
            observation.content_id,

        "transfer_encoding":
            observation.transfer_encoding,

        "decoded_sha256":
            observation.decoded_sha256,

        "decoded_bytes":
            observation.decoded_bytes,

        "derived_artifact_id":
            observation.derived_artifact_id,
    }

    semantic_fields = {
        "content_type":
            observation.content_type,

        "content_disposition":
            observation.content_disposition,

        "filename":
            observation.filename,

        "decoded_sha256":
            observation.decoded_sha256,

        "decoded_bytes":
            observation.decoded_bytes,

        "derived_artifact_id":
            observation.derived_artifact_id,
    }

    return CanonicalEvent(
        event_id=compute_event_id(
            locator=locator,
            source_type=observation.source_type,
            event_type=observation.event_type,
        ),
        source_type=observation.source_type,
        event_type=observation.event_type,
        clock_state=ClockState.UNTIMED,
        provenance=locator,
        event_time_raw=None,
        event_time_utc=None,
        host=None,
        principal=None,
        semantic_fields=semantic_fields,
        source_context=source_context,
    )


def _pcap_time(
    observation: PcapPacketObservation,
) -> tuple[
    str,
    datetime,
    int,
]:
    seconds = observation.timestamp_seconds
    fraction = observation.timestamp_fraction
    resolution = observation.timestamp_resolution

    if seconds < 0:
        raise NativeCanonicalizationError(
            "PCAP timestamp seconds cannot be negative"
        )

    if resolution == "microsecond":
        if not (
            0
            <= fraction
            < 1_000_000
        ):
            raise NativeCanonicalizationError(
                "PCAP microsecond timestamp fraction "
                "is out of range"
            )

        fraction_width = 6
        microseconds = fraction
        submicrosecond_remainder = 0

    elif resolution == "nanosecond":
        if not (
            0
            <= fraction
            < 1_000_000_000
        ):
            raise NativeCanonicalizationError(
                "PCAP nanosecond timestamp fraction "
                "is out of range"
            )

        fraction_width = 9
        microseconds = (
            fraction
            // 1_000
        )

        submicrosecond_remainder = (
            fraction
            % 1_000
        )

    else:
        raise NativeCanonicalizationError(
            "unsupported PCAP timestamp resolution: "
            + resolution
        )

    try:
        base = datetime.fromtimestamp(
            seconds,
            tz=timezone.utc,
        )

        event_time_utc = (
            base
            + timedelta(
                microseconds=microseconds
            )
        )
    except (
        OverflowError,
        OSError,
        ValueError,
    ) as exc:
        raise NativeCanonicalizationError(
            "PCAP timestamp cannot be normalized "
            "to UTC datetime"
        ) from exc

    event_time_raw = (
        str(
            seconds
        )
        + "."
        + str(
            fraction
        ).zfill(
            fraction_width
        )
        + " "
        + resolution
        + " epoch"
    )

    return (
        event_time_raw,
        event_time_utc,
        submicrosecond_remainder,
    )


def _pcap_packet_event(
    *,
    item: EvidenceFileIntake,
    observation: PcapPacketObservation,
) -> CanonicalEvent:
    if observation.source_type is not SourceType.PCAP:
        raise NativeCanonicalizationError(
            "PCAP observation has wrong source_type"
        )

    if observation.packet_number < 1:
        raise NativeCanonicalizationError(
            "PCAP packet_number must be positive"
        )

    locator = _canonical_raw_locator(
        item=item,
        locator=observation.locator,
        record_index=(
            observation.packet_number
            - 1
        ),
    )

    (
        event_time_raw,
        event_time_utc,
        submicrosecond_remainder,
    ) = _pcap_time(
        observation
    )

    source_context = {
        "artifact_id":
            observation.artifact_id,

        "native_locator":
            _native_locator_record(
                observation.locator
            ),

        "canonical_record_index_basis":
            "packet_number_minus_one",

        "packet_number":
            observation.packet_number,

        "timestamp_seconds":
            observation.timestamp_seconds,

        "timestamp_fraction":
            observation.timestamp_fraction,

        "timestamp_resolution":
            observation.timestamp_resolution,

        "datetime_precision":
            "microsecond",

        "submicrosecond_remainder_nanoseconds":
            submicrosecond_remainder,

        "captured_length":
            observation.captured_length,

        "original_length":
            observation.original_length,

        "ethernet_type":
            observation.ethernet_type,

        "source_ip":
            observation.source_ip,

        "destination_ip":
            observation.destination_ip,

        "transport_protocol":
            observation.transport_protocol,

        "source_port":
            observation.source_port,

        "destination_port":
            observation.destination_port,
    }

    semantic_fields = {
        "src_ip":
            observation.source_ip,

        "dst_ip":
            observation.destination_ip,

        "src_port":
            observation.source_port,

        "dst_port":
            observation.destination_port,

        "protocol":
            observation.transport_protocol,
    }

    return CanonicalEvent(
        event_id=compute_event_id(
            locator=locator,
            source_type=observation.source_type,
            event_type=observation.event_type,
        ),
        source_type=observation.source_type,
        event_type=observation.event_type,
        clock_state=ClockState.OBSERVED,
        provenance=locator,
        event_time_raw=event_time_raw,
        event_time_utc=event_time_utc,
        host=None,
        principal=None,
        semantic_fields=semantic_fields,
        source_context=source_context,
    )


def canonicalize_native_observations(
    intake: EvidenceDirectoryIntake,
) -> tuple[
    CanonicalEvent,
    ...,
]:
    if not isinstance(
        intake,
        EvidenceDirectoryIntake,
    ):
        raise TypeError(
            "intake must be EvidenceDirectoryIntake"
        )

    events: list[
        CanonicalEvent
    ] = []

    seen_event_ids: set[
        str
    ] = set()

    for item in intake.items:
        observations = (
            item.native_observations
        )

        if not observations:
            continue

        if (
            item.adapter_family
            is AdapterFamily.EMAIL
        ):
            for native_index, observation in enumerate(
                observations
            ):
                if isinstance(
                    observation,
                    EmailMessageObservation,
                ):
                    event = _email_message_event(
                        item=item,
                        observation=observation,
                        native_index=native_index,
                    )

                elif isinstance(
                    observation,
                    EmailPartObservation,
                ):
                    event = _email_part_event(
                        item=item,
                        observation=observation,
                        native_index=native_index,
                    )

                else:
                    raise NativeCanonicalizationError(
                        "EML intake contains unsupported "
                        "native observation type: "
                        + type(
                            observation
                        ).__name__
                    )

                if event.event_id in seen_event_ids:
                    raise NativeCanonicalizationError(
                        "duplicate canonical event identity"
                    )

                seen_event_ids.add(
                    event.event_id
                )

                events.append(
                    event
                )

            continue

        if (
            item.adapter_family
            in {
                AdapterFamily.PCAP,
                AdapterFamily.PCAPNG,
            }
        ):
            for observation in observations:
                if not isinstance(
                    observation,
                    PcapPacketObservation,
                ):
                    raise NativeCanonicalizationError(
                        "PCAP intake contains unsupported "
                        "native observation type: "
                        + type(
                            observation
                        ).__name__
                    )

                event = _pcap_packet_event(
                    item=item,
                    observation=observation,
                )

                if event.event_id in seen_event_ids:
                    raise NativeCanonicalizationError(
                        "duplicate canonical event identity"
                    )

                seen_event_ids.add(
                    event.event_id
                )

                events.append(
                    event
                )

            continue

        raise NativeCanonicalizationError(
            "native observations exist for unsupported "
            "adapter family: "
            + item.adapter_family.value
        )

    return tuple(
        events
    )
