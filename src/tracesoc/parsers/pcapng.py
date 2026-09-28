from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime

from tracesoc.evidence.artifacts import (
    Artifact,
    ArtifactImmutabilityState,
    ArtifactProcessingState,
)
from tracesoc.evidence.locators import EvidenceLocator, LocatorKind
from tracesoc.models import SourceType
from tracesoc.parsers.pcap import (
    DLT_EN10MB,
    PCAP_PACKET_EVENT_TYPE,
    PcapAdapterResult,
    PcapPacketIssue,
    PcapPacketObservation,
    _parse_supported_frame,
)

PCAPNG_ADAPTER_ID = "tracesoc-pcapng-v1"
PCAPNG_INPUT_SCHEMA_VERSION = "1"
PCAPNG_ARTIFACT_TYPE = "application/x-pcapng"

PCAPNG_SECTION_HEADER_BLOCK = 0x0A0D0D0A
PCAPNG_INTERFACE_DESCRIPTION_BLOCK = 0x00000001
PCAPNG_PACKET_BLOCK = 0x00000002
PCAPNG_SIMPLE_PACKET_BLOCK = 0x00000003
PCAPNG_ENHANCED_PACKET_BLOCK = 0x00000006

PCAPNG_OPTION_END = 0
PCAPNG_OPTION_IF_TSRESOL = 9
PCAPNG_OPTION_IF_TSOFFSET = 14

_PCAPNG_MAGIC_BYTES = b"\x0a\x0d\x0d\x0a"
_LITTLE_ENDIAN_BOM_BYTES = b"\x4d\x3c\x2b\x1a"
_BIG_ENDIAN_BOM_BYTES = b"\x1a\x2b\x3c\x4d"


@dataclass(frozen=True, slots=True)
class PcapngInterface:
    link_type: int
    snaplen: int
    timestamp_resolution: str | None
    timestamp_units_per_second: int | None
    timestamp_offset_seconds: int
    timestamp_issue: str | None = None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _source_artifact(
    *,
    raw_bytes: bytes,
    source_path_display: str,
    acquired_or_observed_utc: datetime,
    processing_state: ArtifactProcessingState,
) -> Artifact:
    return Artifact.create(
        artifact_type=PCAPNG_ARTIFACT_TYPE,
        source_path_display=source_path_display,
        sha256=_sha256(raw_bytes),
        bytes=len(raw_bytes),
        acquired_or_observed_utc=acquired_or_observed_utc,
        immutability_state=ArtifactImmutabilityState.PRESERVED_SOURCE,
        processing_state=processing_state,
    )


def _packet_locator(
    *,
    artifact: Artifact,
    frame: bytes,
    packet_number: int,
    byte_offset: int,
) -> EvidenceLocator:
    return EvidenceLocator(
        artifact_id=artifact.artifact_id,
        artifact_type=artifact.artifact_type,
        locator_kind=LocatorKind.PCAP_PACKET,
        raw_sha256=_sha256(frame),
        adapter_id=PCAPNG_ADAPTER_ID,
        input_schema_version=PCAPNG_INPUT_SCHEMA_VERSION,
        packet_number=packet_number,
        byte_offset=byte_offset,
        byte_length=len(frame),
    )


def _whole_artifact_result(
    *,
    raw_bytes: bytes,
    source_path_display: str,
    acquired_or_observed_utc: datetime,
    processing_state: ArtifactProcessingState,
    error: str,
) -> PcapAdapterResult:
    artifact = _source_artifact(
        raw_bytes=raw_bytes,
        source_path_display=source_path_display,
        acquired_or_observed_utc=acquired_or_observed_utc,
        processing_state=processing_state,
    )

    return PcapAdapterResult(
        artifact=artifact,
        global_header=None,
        packets=(),
        issues=(),
        errors=(error,),
    )


def _option_values(
    *,
    block: bytes,
    byte_order: str,
    options_offset: int,
    options_end: int,
) -> tuple[tuple[int, bytes], ...]:
    values: list[
        tuple[
            int,
            bytes,
        ]
    ] = []

    offset = options_offset

    while offset < options_end:
        if options_end - offset < 4:
            raise ValueError(
                "pcapng_option_header_truncated"
            )

        (
            option_code,
            option_length,
        ) = struct.unpack(
            byte_order + "HH",
            block[
                offset:
                offset + 4
            ],
        )

        offset += 4

        if option_code == PCAPNG_OPTION_END:
            if option_length != 0:
                raise ValueError(
                    "pcapng_end_option_length_nonzero"
                )

            return tuple(
                values
            )

        padded_length = (
            (
                option_length
                + 3
            )
            // 4
        ) * 4

        if (
            offset
            + padded_length
            > options_end
        ):
            raise ValueError(
                "pcapng_option_data_truncated"
            )

        values.append(
            (
                option_code,
                block[
                    offset:
                    offset + option_length
                ],
            )
        )

        offset += padded_length

    return tuple(
        values
    )


def _interface_from_block(
    *,
    block: bytes,
    byte_order: str,
) -> PcapngInterface:
    if len(block) < 20:
        raise ValueError(
            "pcapng_idb_too_short"
        )

    (
        link_type,
        _reserved,
        snaplen,
    ) = struct.unpack(
        byte_order + "HHI",
        block[
            8:16
        ],
    )

    options = _option_values(
        block=block,
        byte_order=byte_order,
        options_offset=16,
        options_end=(
            len(block) - 4
        ),
    )

    tsresol_values = [
        value
        for code, value
        in options
        if code
        == PCAPNG_OPTION_IF_TSRESOL
    ]

    tsoffset_values = [
        value
        for code, value
        in options
        if code
        == PCAPNG_OPTION_IF_TSOFFSET
    ]

    if len(tsresol_values) > 1:
        raise ValueError(
            "pcapng_duplicate_if_tsresol"
        )

    if len(tsoffset_values) > 1:
        raise ValueError(
            "pcapng_duplicate_if_tsoffset"
        )

    resolution: str | None = (
        "microsecond"
    )

    units_per_second: int | None = (
        1_000_000
    )

    timestamp_issue: str | None = None

    if tsresol_values:
        value = tsresol_values[0]

        if len(value) != 1:
            raise ValueError(
                "pcapng_if_tsresol_invalid_length"
            )

        raw_resolution = value[0]

        if raw_resolution & 0x80:
            exponent = (
                raw_resolution
                & 0x7F
            )

            resolution = None
            units_per_second = None
            timestamp_issue = (
                "unsupported_pcapng_timestamp_resolution:"
                "binary:"
                + str(exponent)
            )

        elif raw_resolution == 6:
            resolution = (
                "microsecond"
            )

            units_per_second = (
                1_000_000
            )

        elif raw_resolution == 9:
            resolution = (
                "nanosecond"
            )

            units_per_second = (
                1_000_000_000
            )

        else:
            resolution = None
            units_per_second = None
            timestamp_issue = (
                "unsupported_pcapng_timestamp_resolution:"
                "decimal:"
                + str(
                    raw_resolution
                )
            )

    offset_seconds = 0

    if tsoffset_values:
        value = (
            tsoffset_values[
                0
            ]
        )

        if len(value) != 8:
            raise ValueError(
                "pcapng_if_tsoffset_invalid_length"
            )

        offset_seconds = (
            struct.unpack(
                byte_order
                + "q",
                value,
            )[0]
        )

    return PcapngInterface(
        link_type=link_type,
        snaplen=snaplen,
        timestamp_resolution=resolution,
        timestamp_units_per_second=(
            units_per_second
        ),
        timestamp_offset_seconds=(
            offset_seconds
        ),
        timestamp_issue=(
            timestamp_issue
        ),
    )


def _section_byte_order(
    *,
    raw_bytes: bytes,
    offset: int,
) -> str:
    if (
        len(raw_bytes)
        - offset
        < 12
    ):
        raise ValueError(
            "pcapng_section_header_truncated"
        )

    bom = raw_bytes[
        offset + 8:
        offset + 12
    ]

    if bom == _LITTLE_ENDIAN_BOM_BYTES:
        return "<"

    if bom == _BIG_ENDIAN_BOM_BYTES:
        return ">"

    raise ValueError(
        "pcapng_invalid_byte_order_magic"
    )


def _validated_block_length(
    *,
    raw_bytes: bytes,
    offset: int,
    byte_order: str,
) -> int:
    remaining = (
        len(raw_bytes)
        - offset
    )

    if remaining < 12:
        raise ValueError(
            "pcapng_block_header_truncated"
        )

    total_length = struct.unpack(
        byte_order + "I",
        raw_bytes[
            offset + 4:
            offset + 8
        ],
    )[0]

    if (
        total_length < 12
        or total_length % 4 != 0
    ):
        raise ValueError(
            "pcapng_invalid_block_total_length:"
            + str(total_length)
        )

    if total_length > remaining:
        raise ValueError(
            "pcapng_block_truncated:"
            "declared="
            + str(total_length)
            + ":available="
            + str(remaining)
        )

    trailing = struct.unpack(
        byte_order + "I",
        raw_bytes[
            offset
            + total_length
            - 4:
            offset
            + total_length
        ],
    )[0]

    if trailing != total_length:
        raise ValueError(
            "pcapng_block_length_mismatch:"
            "leading="
            + str(total_length)
            + ":trailing="
            + str(trailing)
        )

    return total_length


def load_pcapng_bytes(
    *,
    raw_bytes: bytes,
    source_path_display: str,
    acquired_or_observed_utc: datetime,
) -> PcapAdapterResult:
    if not isinstance(
        raw_bytes,
        bytes,
    ):
        raise TypeError(
            "raw_bytes must be bytes"
        )

    if len(raw_bytes) < 4:
        return _whole_artifact_result(
            raw_bytes=raw_bytes,
            source_path_display=(
                source_path_display
            ),
            acquired_or_observed_utc=(
                acquired_or_observed_utc
            ),
            processing_state=(
                ArtifactProcessingState.MALFORMED_QUARANTINED
            ),
            error=(
                "pcapng_magic_truncated"
            ),
        )

    if (
        raw_bytes[:4]
        != _PCAPNG_MAGIC_BYTES
    ):
        return _whole_artifact_result(
            raw_bytes=raw_bytes,
            source_path_display=(
                source_path_display
            ),
            acquired_or_observed_utc=(
                acquired_or_observed_utc
            ),
            processing_state=(
                ArtifactProcessingState.UNSUPPORTED_PRESERVED
            ),
            error=(
                "unsupported_pcapng_magic"
            ),
        )

    records: list[
        dict[
            str,
            object,
        ]
    ] = []

    errors: list[str] = []

    interfaces: list[
        PcapngInterface
    ] = []

    offset = 0
    packet_number = 1
    byte_order: str | None = None
    section_seen = False

    terminal_state: (
        ArtifactProcessingState
        | None
    ) = None

    unsupported_content = False

    while offset < len(raw_bytes):
        if (
            len(raw_bytes)
            - offset
            < 4
        ):
            errors.append(
                "pcapng_block_type_truncated:"
                "offset="
                + str(offset)
            )

            break

        is_section_header = (
            raw_bytes[
                offset:
                offset + 4
            ]
            == _PCAPNG_MAGIC_BYTES
        )

        if is_section_header:
            try:
                current_order = (
                    _section_byte_order(
                        raw_bytes=raw_bytes,
                        offset=offset,
                    )
                )

                total_length = (
                    _validated_block_length(
                        raw_bytes=raw_bytes,
                        offset=offset,
                        byte_order=(
                            current_order
                        ),
                    )
                )

            except ValueError as exc:
                errors.append(
                    str(exc)
                    + ":offset="
                    + str(offset)
                )

                break

            if total_length < 28:
                errors.append(
                    "pcapng_section_header_too_short:"
                    "offset="
                    + str(offset)
                )

                break

            (
                major,
                minor,
            ) = struct.unpack(
                current_order + "HH",
                raw_bytes[
                    offset + 12:
                    offset + 16
                ],
            )

            if (
                major,
                minor,
            ) != (
                1,
                0,
            ):
                errors.append(
                    "unsupported_pcapng_version:"
                    + str(major)
                    + "."
                    + str(minor)
                    + ":offset="
                    + str(offset)
                )

                if not records:
                    terminal_state = (
                        ArtifactProcessingState.UNSUPPORTED_PRESERVED
                    )

                break

            byte_order = current_order
            interfaces = []
            section_seen = True
            offset += total_length
            continue

        if (
            not section_seen
            or byte_order is None
        ):
            errors.append(
                "pcapng_block_before_section_header:"
                "offset="
                + str(offset)
            )

            break

        try:
            total_length = (
                _validated_block_length(
                    raw_bytes=raw_bytes,
                    offset=offset,
                    byte_order=byte_order,
                )
            )

        except ValueError as exc:
            errors.append(
                str(exc)
                + ":offset="
                + str(offset)
            )

            break

        block = raw_bytes[
            offset:
            offset + total_length
        ]

        block_type = struct.unpack(
            byte_order + "I",
            block[:4],
        )[0]

        if (
            block_type
            == PCAPNG_INTERFACE_DESCRIPTION_BLOCK
        ):
            try:
                interfaces.append(
                    _interface_from_block(
                        block=block,
                        byte_order=byte_order,
                    )
                )

            except ValueError as exc:
                errors.append(
                    str(exc)
                    + ":offset="
                    + str(offset)
                )

                break

        elif (
            block_type
            == PCAPNG_ENHANCED_PACKET_BLOCK
        ):
            if total_length < 32:
                errors.append(
                    "pcapng_epb_too_short:"
                    "offset="
                    + str(offset)
                )

                break

            (
                interface_id,
                timestamp_high,
                timestamp_low,
                captured_length,
                original_length,
            ) = struct.unpack(
                byte_order + "IIIII",
                block[
                    8:28
                ],
            )

            frame_offset = (
                offset
                + 28
            )

            padded_length = (
                (
                    captured_length
                    + 3
                )
                // 4
            ) * 4

            if (
                28
                + padded_length
                > total_length
                - 4
            ):
                errors.append(
                    "pcapng_epb_packet_data_truncated:"
                    "declared="
                    + str(
                        captured_length
                    )
                    + ":block_length="
                    + str(
                        total_length
                    )
                    + ":offset="
                    + str(offset)
                )

                break

            frame = raw_bytes[
                frame_offset:
                frame_offset
                + captured_length
            ]

            record: dict[
                str,
                object,
            ] = {
                "kind":
                    "packet",
                "packet_number":
                    packet_number,
                "frame":
                    frame,
                "byte_offset":
                    frame_offset,
                "captured_length":
                    captured_length,
                "original_length":
                    original_length,
            }

            if (
                interface_id
                >= len(
                    interfaces
                )
            ):
                record[
                    "kind"
                ] = "issue_packet"

                record[
                    "reason_code"
                ] = (
                    "pcapng_invalid_interface_id:"
                    + str(
                        interface_id
                    )
                )

            else:
                interface = (
                    interfaces[
                        interface_id
                    ]
                )

                if (
                    captured_length
                    > original_length
                ):
                    record[
                        "kind"
                    ] = "issue_packet"

                    record[
                        "reason_code"
                    ] = (
                        "pcapng_captured_length_exceeds_original_length"
                    )

                elif (
                    interface.snaplen > 0
                    and captured_length
                    > interface.snaplen
                ):
                    record[
                        "kind"
                    ] = "issue_packet"

                    record[
                        "reason_code"
                    ] = (
                        "captured_length_exceeds_snaplen"
                    )

                elif (
                    interface.link_type
                    != DLT_EN10MB
                ):
                    record[
                        "kind"
                    ] = "issue_packet"

                    record[
                        "reason_code"
                    ] = (
                        "unsupported_link_type:"
                        + str(
                            interface.link_type
                        )
                    )

                elif (
                    interface.timestamp_issue
                    is not None
                    or interface.timestamp_units_per_second
                    is None
                    or interface.timestamp_resolution
                    is None
                ):
                    record[
                        "kind"
                    ] = "issue_packet"

                    record[
                        "reason_code"
                    ] = (
                        interface.timestamp_issue
                        or (
                            "unsupported_pcapng_timestamp_resolution"
                        )
                    )

                else:
                    timestamp_value = (
                        (
                            timestamp_high
                            << 32
                        )
                        | timestamp_low
                    )

                    units = (
                        interface.timestamp_units_per_second
                    )

                    seconds = (
                        timestamp_value
                        // units
                        + interface.timestamp_offset_seconds
                    )

                    fraction = (
                        timestamp_value
                        % units
                    )

                    if seconds < 0:
                        record[
                            "kind"
                        ] = "issue_packet"

                        record[
                            "reason_code"
                        ] = (
                            "pcapng_negative_timestamp_after_offset"
                        )

                    else:
                        try:
                            (
                                ethernet_type,
                                source_ip,
                                destination_ip,
                                transport_protocol,
                                source_port,
                                destination_port,
                            ) = (
                                _parse_supported_frame(
                                    frame
                                )
                            )

                        except ValueError as exc:
                            record[
                                "kind"
                            ] = "issue_packet"

                            record[
                                "reason_code"
                            ] = str(exc)

                        else:
                            record.update(
                                {
                                    "timestamp_seconds":
                                        seconds,
                                    "timestamp_fraction":
                                        fraction,
                                    "timestamp_resolution":
                                        interface.timestamp_resolution,
                                    "ethernet_type":
                                        ethernet_type,
                                    "source_ip":
                                        source_ip,
                                    "destination_ip":
                                        destination_ip,
                                    "transport_protocol":
                                        transport_protocol,
                                    "source_port":
                                        source_port,
                                    "destination_port":
                                        destination_port,
                                }
                            )

            records.append(
                record
            )

            packet_number += 1

        elif block_type in {
            PCAPNG_PACKET_BLOCK,
            PCAPNG_SIMPLE_PACKET_BLOCK,
        }:
            unsupported_content = True

            errors.append(
                "unsupported_pcapng_packet_block_type:"
                + str(
                    block_type
                )
                + ":offset="
                + str(offset)
            )

        else:
            # Unknown/non-packet blocks remain preserved in the immutable
            # artifact and do not fabricate packet observations.
            pass

        offset += total_length

    has_issue = any(
        record[
            "kind"
        ]
        != "packet"
        for record in records
    )

    if terminal_state is not None:
        processing_state = (
            terminal_state
        )

    elif unsupported_content:
        processing_state = (
            ArtifactProcessingState.SUPPORTED_PARTIAL
            if records
            else ArtifactProcessingState.UNSUPPORTED_PRESERVED
        )

    elif errors or has_issue:
        processing_state = (
            ArtifactProcessingState.SUPPORTED_PARTIAL
            if records
            else ArtifactProcessingState.MALFORMED_QUARANTINED
        )

    else:
        processing_state = (
            ArtifactProcessingState.SUPPORTED_PROCESSED
        )

    artifact = _source_artifact(
        raw_bytes=raw_bytes,
        source_path_display=(
            source_path_display
        ),
        acquired_or_observed_utc=(
            acquired_or_observed_utc
        ),
        processing_state=(
            processing_state
        ),
    )

    packets: list[
        PcapPacketObservation
    ] = []

    issues: list[
        PcapPacketIssue
    ] = []

    for record in records:
        frame = record[
            "frame"
        ]

        if not isinstance(
            frame,
            bytes,
        ):
            raise TypeError(
                "internal PCAPNG packet frame is not bytes"
            )

        current_number = int(
            record[
                "packet_number"
            ]
        )

        locator = _packet_locator(
            artifact=artifact,
            frame=frame,
            packet_number=(
                current_number
            ),
            byte_offset=int(
                record[
                    "byte_offset"
                ]
            ),
        )

        if (
            record[
                "kind"
            ]
            != "packet"
        ):
            issues.append(
                PcapPacketIssue(
                    packet_number=(
                        current_number
                    ),
                    reason_code=str(
                        record[
                            "reason_code"
                        ]
                    ),
                    locator=locator,
                )
            )

            continue

        packets.append(
            PcapPacketObservation(
                artifact_id=(
                    artifact.artifact_id
                ),
                source_type=(
                    SourceType.PCAP
                ),
                event_type=(
                    PCAP_PACKET_EVENT_TYPE
                ),
                locator=locator,
                packet_number=(
                    current_number
                ),
                timestamp_seconds=int(
                    record[
                        "timestamp_seconds"
                    ]
                ),
                timestamp_fraction=int(
                    record[
                        "timestamp_fraction"
                    ]
                ),
                timestamp_resolution=str(
                    record[
                        "timestamp_resolution"
                    ]
                ),
                captured_length=int(
                    record[
                        "captured_length"
                    ]
                ),
                original_length=int(
                    record[
                        "original_length"
                    ]
                ),
                ethernet_type=int(
                    record[
                        "ethernet_type"
                    ]
                ),
                source_ip=str(
                    record[
                        "source_ip"
                    ]
                ),
                destination_ip=str(
                    record[
                        "destination_ip"
                    ]
                ),
                transport_protocol=str(
                    record[
                        "transport_protocol"
                    ]
                ),
                source_port=int(
                    record[
                        "source_port"
                    ]
                ),
                destination_port=int(
                    record[
                        "destination_port"
                    ]
                ),
            )
        )

    return PcapAdapterResult(
        artifact=artifact,
        global_header=None,
        packets=tuple(
            packets
        ),
        issues=tuple(
            issues
        ),
        errors=tuple(
            errors
        ),
    )
