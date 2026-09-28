from __future__ import annotations

import hashlib
import ipaddress
import struct
from dataclasses import dataclass
from datetime import datetime

from tracesoc.evidence.artifacts import (
    Artifact,
    ArtifactImmutabilityState,
    ArtifactProcessingState,
)
from tracesoc.evidence.locators import (
    EvidenceLocator,
    LocatorKind,
)
from tracesoc.models import SourceType


PCAP_ADAPTER_ID = "tracesoc-classic-pcap-v1"
PCAP_INPUT_SCHEMA_VERSION = "1"
PCAP_ARTIFACT_TYPE = "application/vnd.tcpdump.pcap"
PCAP_PACKET_EVENT_TYPE = "network_packet"

DLT_EN10MB = 1

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": (
        "<",
        "microsecond",
    ),
    b"\xa1\xb2\xc3\xd4": (
        ">",
        "microsecond",
    ),
    b"\x4d\x3c\xb2\xa1": (
        "<",
        "nanosecond",
    ),
    b"\xa1\xb2\x3c\x4d": (
        ">",
        "nanosecond",
    ),
}


def _sha256(
    value: bytes,
) -> str:
    return hashlib.sha256(
        value
    ).hexdigest()


@dataclass(
    frozen=True,
    slots=True,
)
class PcapGlobalHeader:
    byte_order: str
    timestamp_resolution: str
    version_major: int
    version_minor: int
    snaplen: int
    link_type: int


@dataclass(
    frozen=True,
    slots=True,
)
class PcapPacketObservation:
    artifact_id: str
    source_type: SourceType
    event_type: str
    locator: EvidenceLocator
    packet_number: int
    timestamp_seconds: int
    timestamp_fraction: int
    timestamp_resolution: str
    captured_length: int
    original_length: int
    ethernet_type: int
    source_ip: str
    destination_ip: str
    transport_protocol: str
    source_port: int
    destination_port: int


@dataclass(
    frozen=True,
    slots=True,
)
class PcapPacketIssue:
    packet_number: int
    reason_code: str
    locator: EvidenceLocator


@dataclass(
    frozen=True,
    slots=True,
)
class PcapAdapterResult:
    artifact: Artifact
    global_header: PcapGlobalHeader | None
    packets: tuple[
        PcapPacketObservation,
        ...,
    ]
    issues: tuple[
        PcapPacketIssue,
        ...,
    ]
    errors: tuple[
        str,
        ...,
    ] = ()

    @property
    def accounted_packet_count(
        self,
    ) -> int:
        return (
            len(
                self.packets
            )
            + len(
                self.issues
            )
        )


def _source_artifact(
    *,
    raw_bytes: bytes,
    source_path_display: str,
    acquired_or_observed_utc: datetime,
    processing_state: ArtifactProcessingState,
) -> Artifact:
    return Artifact.create(
        artifact_type=PCAP_ARTIFACT_TYPE,
        source_path_display=source_path_display,
        sha256=_sha256(
            raw_bytes
        ),
        bytes=len(
            raw_bytes
        ),
        acquired_or_observed_utc=(
            acquired_or_observed_utc
        ),
        immutability_state=(
            ArtifactImmutabilityState.PRESERVED_SOURCE
        ),
        processing_state=processing_state,
    )


def _byte_range_locator(
    *,
    artifact: Artifact,
    raw_bytes: bytes,
    byte_offset: int,
    byte_length: int,
) -> EvidenceLocator:
    selected = raw_bytes[
        byte_offset:
        byte_offset + byte_length
    ]

    return EvidenceLocator(
        artifact_id=artifact.artifact_id,
        artifact_type=artifact.artifact_type,
        locator_kind=LocatorKind.BYTE_RANGE,
        raw_sha256=_sha256(
            selected
        ),
        adapter_id=PCAP_ADAPTER_ID,
        input_schema_version=(
            PCAP_INPUT_SCHEMA_VERSION
        ),
        byte_offset=byte_offset,
        byte_length=byte_length,
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
        raw_sha256=_sha256(
            frame
        ),
        adapter_id=PCAP_ADAPTER_ID,
        input_schema_version=(
            PCAP_INPUT_SCHEMA_VERSION
        ),
        packet_number=packet_number,
        byte_offset=byte_offset,
        byte_length=len(
            frame
        ),
    )


def _parse_supported_frame(
    frame: bytes,
) -> tuple[
    int,
    str,
    str,
    str,
    int,
    int,
]:
    if len(frame) < 14:
        raise ValueError(
            "ethernet_header_truncated"
        )

    ethernet_type = struct.unpack(
        "!H",
        frame[12:14],
    )[0]

    if ethernet_type != 0x0800:
        raise ValueError(
            "unsupported_ethertype:"
            + hex(
                ethernet_type
            )
        )

    ipv4_offset = 14

    if len(frame) < (
        ipv4_offset
        + 20
    ):
        raise ValueError(
            "ipv4_header_truncated"
        )

    version_ihl = frame[
        ipv4_offset
    ]

    version = (
        version_ihl
        >> 4
    )

    ihl_words = (
        version_ihl
        & 0x0F
    )

    if version != 4:
        raise ValueError(
            "unsupported_ip_version:"
            + str(
                version
            )
        )

    if ihl_words < 5:
        raise ValueError(
            "invalid_ipv4_header_length"
        )

    ihl = (
        ihl_words
        * 4
    )

    if len(frame) < (
        ipv4_offset
        + ihl
    ):
        raise ValueError(
            "ipv4_header_truncated"
        )

    total_length = struct.unpack(
        "!H",
        frame[
            ipv4_offset + 2:
            ipv4_offset + 4
        ],
    )[0]

    if total_length < ihl:
        raise ValueError(
            "invalid_ipv4_total_length"
        )

    flags_fragment = struct.unpack(
        "!H",
        frame[
            ipv4_offset + 6:
            ipv4_offset + 8
        ],
    )[0]

    fragment_offset = (
        flags_fragment
        & 0x1FFF
    )

    if fragment_offset != 0:
        raise ValueError(
            "ipv4_noninitial_fragment_unsupported"
        )

    protocol = frame[
        ipv4_offset + 9
    ]

    source_ip = str(
        ipaddress.IPv4Address(
            frame[
                ipv4_offset + 12:
                ipv4_offset + 16
            ]
        )
    )

    destination_ip = str(
        ipaddress.IPv4Address(
            frame[
                ipv4_offset + 16:
                ipv4_offset + 20
            ]
        )
    )

    transport_offset = (
        ipv4_offset
        + ihl
    )

    if protocol == 6:
        if len(frame) < (
            transport_offset
            + 20
        ):
            raise ValueError(
                "tcp_header_truncated"
            )

        source_port, destination_port = (
            struct.unpack(
                "!HH",
                frame[
                    transport_offset:
                    transport_offset + 4
                ],
            )
        )

        transport_protocol = (
            "tcp"
        )

    elif protocol == 17:
        if len(frame) < (
            transport_offset
            + 8
        ):
            raise ValueError(
                "udp_header_truncated"
            )

        source_port, destination_port = (
            struct.unpack(
                "!HH",
                frame[
                    transport_offset:
                    transport_offset + 4
                ],
            )
        )

        transport_protocol = (
            "udp"
        )

    else:
        raise ValueError(
            "unsupported_ip_protocol:"
            + str(
                protocol
            )
        )

    return (
        ethernet_type,
        source_ip,
        destination_ip,
        transport_protocol,
        source_port,
        destination_port,
    )


def load_pcap_bytes(
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

    if len(
        raw_bytes
    ) < 4:
        artifact = _source_artifact(
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
        )

        return PcapAdapterResult(
            artifact=artifact,
            global_header=None,
            packets=(),
            issues=(),
            errors=(
                "pcap_magic_truncated",
            ),
        )

    magic = raw_bytes[
        0:4
    ]

    magic_contract = (
        _MAGIC.get(
            magic
        )
    )

    if magic_contract is None:
        artifact = _source_artifact(
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
        )

        return PcapAdapterResult(
            artifact=artifact,
            global_header=None,
            packets=(),
            issues=(),
            errors=(
                "unsupported_pcap_magic",
            ),
        )

    if len(
        raw_bytes
    ) < 24:
        artifact = _source_artifact(
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
        )

        return PcapAdapterResult(
            artifact=artifact,
            global_header=None,
            packets=(),
            issues=(),
            errors=(
                "pcap_global_header_truncated",
            ),
        )

    byte_order, timestamp_resolution = (
        magic_contract
    )

    (
        version_major,
        version_minor,
        _thiszone,
        _sigfigs,
        snaplen,
        link_type,
    ) = struct.unpack(
        byte_order
        + "HHiIII",
        raw_bytes[
            4:24
        ],
    )

    global_header = (
        PcapGlobalHeader(
            byte_order=byte_order,
            timestamp_resolution=(
                timestamp_resolution
            ),
            version_major=(
                version_major
            ),
            version_minor=(
                version_minor
            ),
            snaplen=snaplen,
            link_type=link_type,
        )
    )

    if (
        version_major,
        version_minor,
    ) != (
        2,
        4,
    ):
        artifact = _source_artifact(
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
        )

        return PcapAdapterResult(
            artifact=artifact,
            global_header=global_header,
            packets=(),
            issues=(),
            errors=(
                "unsupported_pcap_version:"
                + str(
                    version_major
                )
                + "."
                + str(
                    version_minor
                ),
            ),
        )

    records: list[
        dict[str, object]
    ] = []

    errors: list[
        str
    ] = []

    offset = 24
    packet_number = 1

    while offset < len(
        raw_bytes
    ):
        remaining = (
            len(
                raw_bytes
            )
            - offset
        )

        if remaining < 16:
            records.append(
                {
                    "kind":
                        "issue_header",
                    "packet_number":
                        packet_number,
                    "byte_offset":
                        offset,
                    "byte_length":
                        remaining,
                    "reason_code":
                        "pcap_packet_header_truncated",
                }
            )

            break

        (
            timestamp_seconds,
            timestamp_fraction,
            captured_length,
            original_length,
        ) = struct.unpack(
            byte_order
            + "IIII",
            raw_bytes[
                offset:
                offset + 16
            ],
        )

        frame_offset = (
            offset
            + 16
        )

        available = (
            len(
                raw_bytes
            )
            - frame_offset
        )

        if captured_length > available:
            frame = raw_bytes[
                frame_offset:
            ]

            records.append(
                {
                    "kind":
                        "issue_packet",
                    "packet_number":
                        packet_number,
                    "frame":
                        frame,
                    "byte_offset":
                        frame_offset,
                    "reason_code":
                        "pcap_packet_data_truncated:"
                        + "declared="
                        + str(
                            captured_length
                        )
                        + ":available="
                        + str(
                            available
                        ),
                }
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
            "timestamp_seconds":
                timestamp_seconds,
            "timestamp_fraction":
                timestamp_fraction,
            "captured_length":
                captured_length,
            "original_length":
                original_length,
            "frame":
                frame,
            "byte_offset":
                frame_offset,
        }

        if (
            snaplen > 0
            and captured_length
            > snaplen
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
            link_type
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
                    link_type
                )
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
                ) = _parse_supported_frame(
                    frame
                )
            except ValueError as exc:
                record[
                    "kind"
                ] = "issue_packet"

                record[
                    "reason_code"
                ] = str(
                    exc
                )
            else:
                record[
                    "ethernet_type"
                ] = ethernet_type

                record[
                    "source_ip"
                ] = source_ip

                record[
                    "destination_ip"
                ] = destination_ip

                record[
                    "transport_protocol"
                ] = (
                    transport_protocol
                )

                record[
                    "source_port"
                ] = source_port

                record[
                    "destination_port"
                ] = destination_port

        records.append(
            record
        )

        offset = (
            frame_offset
            + captured_length
        )

        packet_number += 1

    has_issue = any(
        record[
            "kind"
        ] != "packet"
        for record in records
    )

    processing_state = (
        ArtifactProcessingState.SUPPORTED_PARTIAL
        if has_issue
        else ArtifactProcessingState.SUPPORTED_PROCESSED
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
        kind = str(
            record[
                "kind"
            ]
        )

        current_packet_number = int(
            record[
                "packet_number"
            ]
        )

        if kind == "issue_header":
            issue_offset = int(
                record[
                    "byte_offset"
                ]
            )

            issue_length = int(
                record[
                    "byte_length"
                ]
            )

            issues.append(
                PcapPacketIssue(
                    packet_number=(
                        current_packet_number
                    ),
                    reason_code=str(
                        record[
                            "reason_code"
                        ]
                    ),
                    locator=(
                        _byte_range_locator(
                            artifact=artifact,
                            raw_bytes=(
                                raw_bytes
                            ),
                            byte_offset=(
                                issue_offset
                            ),
                            byte_length=(
                                issue_length
                            ),
                        )
                    ),
                )
            )

            continue

        frame = record[
            "frame"
        ]

        if not isinstance(
            frame,
            bytes,
        ):
            raise TypeError(
                "internal packet frame is not bytes"
            )

        frame_offset = int(
            record[
                "byte_offset"
            ]
        )

        locator = _packet_locator(
            artifact=artifact,
            frame=frame,
            packet_number=(
                current_packet_number
            ),
            byte_offset=(
                frame_offset
            ),
        )

        if kind == "issue_packet":
            issues.append(
                PcapPacketIssue(
                    packet_number=(
                        current_packet_number
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
                    current_packet_number
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
                timestamp_resolution=(
                    timestamp_resolution
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
        global_header=global_header,
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
