from __future__ import annotations

import hashlib
import ipaddress
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tracesoc.evidence.intake import (
    AdapterFamily,
    classify_evidence_bytes,
    ingest_evidence_directory,
    ingest_evidence_file,
)
from tracesoc.evidence.native_canonical import (
    canonicalize_native_observations,
)
from tracesoc.parsers.pcap import (
    DLT_EN10MB,
    PCAP_ADAPTER_ID,
    load_pcap_bytes,
)
from tracesoc.parsers.pcapng import (
    PCAPNG_ADAPTER_ID,
    PCAPNG_ARTIFACT_TYPE,
    load_pcapng_bytes,
)

ACQUIRED = datetime(
    2026,
    9,
    23,
    20,
    0,
    tzinfo=timezone.utc,
)


def sha256(
    value: bytes,
) -> str:
    return hashlib.sha256(
        value
    ).hexdigest()


def ethernet_ipv4_tcp(
    src_ip: str = "10.0.0.5",
    dst_ip: str = "198.51.100.20",
    src_port: int = 50000,
    dst_port: int = 443,
) -> bytes:
    ethernet = (
        b"\x00\x11\x22\x33\x44\x55"
        + b"\x66\x77\x88\x99\xaa\xbb"
        + struct.pack(
            "!H",
            0x0800,
        )
    )

    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        0,
        0,
        5 << 4,
        0x02,
        8192,
        0,
        0,
    )

    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        0,
        0,
        64,
        6,
        0,
        ipaddress.IPv4Address(
            src_ip
        ).packed,
        ipaddress.IPv4Address(
            dst_ip
        ).packed,
    )

    return (
        ethernet
        + ipv4
        + tcp
    )


def ethernet_ipv4_udp(
    src_ip: str = "10.0.0.6",
    dst_ip: str = "203.0.113.53",
    src_port: int = 53000,
    dst_port: int = 53,
) -> bytes:
    ethernet = (
        b"\x00\x11\x22\x33\x44\x55"
        + b"\x66\x77\x88\x99\xaa\xbb"
        + struct.pack(
            "!H",
            0x0800,
        )
    )

    udp = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        8,
        0,
    )

    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28,
        0,
        0,
        64,
        17,
        0,
        ipaddress.IPv4Address(
            src_ip
        ).packed,
        ipaddress.IPv4Address(
            dst_ip
        ).packed,
    )

    return (
        ethernet
        + ipv4
        + udp
    )


def padded(
    value: bytes,
) -> bytes:
    return (
        value
        + (
            b"\x00"
            * (
                (
                    -len(value)
                )
                % 4
            )
        )
    )


def option(
    byte_order: str,
    code: int,
    value: bytes,
) -> bytes:
    return (
        struct.pack(
            byte_order + "HH",
            code,
            len(value),
        )
        + padded(value)
    )


def block(
    byte_order: str,
    block_type: int,
    body: bytes,
) -> bytes:
    if len(body) % 4:
        raise AssertionError(
            "fixture block body must be aligned"
        )

    total = (
        12
        + len(body)
    )

    return (
        struct.pack(
            byte_order + "II",
            block_type,
            total,
        )
        + body
        + struct.pack(
            byte_order + "I",
            total,
        )
    )


def section_header(
    byte_order: str = "<",
) -> bytes:
    return block(
        byte_order,
        0x0A0D0D0A,
        struct.pack(
            byte_order + "IHHq",
            0x1A2B3C4D,
            1,
            0,
            -1,
        ),
    )


def interface_description(
    *,
    byte_order: str = "<",
    link_type: int = DLT_EN10MB,
    snaplen: int = 65535,
    tsresol: int | None = None,
    tsoffset: int | None = None,
) -> bytes:
    options = bytearray()

    if tsresol is not None:
        options.extend(
            option(
                byte_order,
                9,
                bytes(
                    (
                        tsresol,
                    )
                ),
            )
        )

    if tsoffset is not None:
        options.extend(
            option(
                byte_order,
                14,
                struct.pack(
                    byte_order + "q",
                    tsoffset,
                ),
            )
        )

    if options:
        options.extend(
            struct.pack(
                byte_order + "HH",
                0,
                0,
            )
        )

    return block(
        byte_order,
        1,
        (
            struct.pack(
                byte_order + "HHI",
                link_type,
                0,
                snaplen,
            )
            + bytes(options)
        ),
    )


def enhanced_packet(
    *,
    frame: bytes,
    timestamp_units: int,
    byte_order: str = "<",
    interface_id: int = 0,
    original_length: int | None = None,
) -> bytes:
    if original_length is None:
        original_length = len(frame)

    body = (
        struct.pack(
            byte_order + "IIIII",
            interface_id,
            timestamp_units >> 32,
            timestamp_units & 0xFFFFFFFF,
            len(frame),
            original_length,
        )
        + padded(frame)
    )

    return block(
        byte_order,
        6,
        body,
    )


def pcapng(
    *,
    frames: tuple[
        bytes,
        ...,
    ],
    byte_order: str = "<",
    tsresol: int | None = None,
    tsoffset: int | None = None,
    interface_count: int = 1,
) -> bytes:
    output = bytearray(
        section_header(
            byte_order
        )
    )

    for _ in range(
        interface_count
    ):
        output.extend(
            interface_description(
                byte_order=byte_order,
                tsresol=tsresol,
                tsoffset=tsoffset,
            )
        )

    units = (
        1_000_000_000
        if tsresol == 9
        else 1_000_000
    )

    fraction = (
        123_456_789
        if tsresol == 9
        else 123_456
    )

    for index, frame in enumerate(
        frames,
        start=1,
    ):
        timestamp = (
            (
                1_700_000_000
                + index
            )
            * units
            + fraction
        )

        output.extend(
            enhanced_packet(
                frame=frame,
                timestamp_units=timestamp,
                byte_order=byte_order,
                interface_id=(
                    (
                        index - 1
                    )
                    % interface_count
                ),
            )
        )

    return bytes(
        output
    )


def classic_pcap(
    *,
    frame: bytes,
    seconds: int,
    fraction: int,
) -> bytes:
    return (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack(
            "<HHiIII",
            2,
            4,
            0,
            0,
            65535,
            DLT_EN10MB,
        )
        + struct.pack(
            "<IIII",
            seconds,
            fraction,
            len(frame),
            len(frame),
        )
        + frame
    )


class PcapngAdapterTests(
    unittest.TestCase
):
    def test_little_endian_default_microsecond_epb_is_parsed(
        self,
    ) -> None:
        frame = (
            ethernet_ipv4_tcp()
        )

        result = (
            load_pcapng_bytes(
                raw_bytes=(
                    pcapng(
                        frames=(
                            frame,
                        )
                    )
                ),
                source_path_display=(
                    "capture.pcapng"
                ),
                acquired_or_observed_utc=(
                    ACQUIRED
                ),
            )
        )

        self.assertEqual(
            len(
                result.packets
            ),
            1,
        )

        self.assertEqual(
            result.issues,
            (),
        )

        self.assertEqual(
            result.errors,
            (),
        )

        packet = (
            result.packets[
                0
            ]
        )

        self.assertEqual(
            packet.timestamp_seconds,
            1_700_000_001,
        )

        self.assertEqual(
            packet.timestamp_fraction,
            123456,
        )

        self.assertEqual(
            packet.timestamp_resolution,
            "microsecond",
        )

        self.assertEqual(
            packet.source_ip,
            "10.0.0.5",
        )

        self.assertEqual(
            packet.destination_ip,
            "198.51.100.20",
        )

        self.assertEqual(
            packet.transport_protocol,
            "tcp",
        )

        self.assertEqual(
            packet.source_port,
            50000,
        )

        self.assertEqual(
            packet.destination_port,
            443,
        )

        self.assertEqual(
            packet.locator.raw_sha256,
            sha256(
                frame
            ),
        )

        self.assertEqual(
            packet.locator.adapter_id,
            PCAPNG_ADAPTER_ID,
        )

        self.assertEqual(
            result.artifact.artifact_type,
            PCAPNG_ARTIFACT_TYPE,
        )

    def test_big_endian_nanosecond_epb_is_parsed(
        self,
    ) -> None:
        result = load_pcapng_bytes(
            raw_bytes=(
                pcapng(
                    frames=(
                        ethernet_ipv4_udp(),
                    ),
                    byte_order=">",
                    tsresol=9,
                )
            ),
            source_path_display=(
                "capture.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        )

        packet = (
            result.packets[
                0
            ]
        )

        self.assertEqual(
            packet.timestamp_seconds,
            1_700_000_001,
        )

        self.assertEqual(
            packet.timestamp_fraction,
            123456789,
        )

        self.assertEqual(
            packet.timestamp_resolution,
            "nanosecond",
        )

        self.assertEqual(
            packet.transport_protocol,
            "udp",
        )

        self.assertEqual(
            packet.destination_port,
            53,
        )

    def test_if_tsoffset_is_applied(
        self,
    ) -> None:
        result = load_pcapng_bytes(
            raw_bytes=(
                pcapng(
                    frames=(
                        ethernet_ipv4_tcp(),
                    ),
                    tsoffset=5,
                )
            ),
            source_path_display=(
                "offset.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        )

        self.assertEqual(
            result.packets[
                0
            ].timestamp_seconds,
            1_700_000_006,
        )

    def test_multiple_interfaces_are_supported(
        self,
    ) -> None:
        result = load_pcapng_bytes(
            raw_bytes=(
                pcapng(
                    frames=(
                        ethernet_ipv4_tcp(),
                        ethernet_ipv4_udp(),
                    ),
                    interface_count=2,
                )
            ),
            source_path_display=(
                "multi.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        )

        self.assertEqual(
            len(
                result.packets
            ),
            2,
        )

        self.assertEqual(
            result.accounted_packet_count,
            2,
        )

    def test_unsupported_link_type_is_explicit_issue(
        self,
    ) -> None:
        frame = (
            ethernet_ipv4_tcp()
        )

        raw = (
            section_header()
            + interface_description(
                link_type=101
            )
            + enhanced_packet(
                frame=frame,
                timestamp_units=(
                    1_700_000_001_123_456
                ),
            )
        )

        result = load_pcapng_bytes(
            raw_bytes=raw,
            source_path_display=(
                "unsupported-link.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        )

        self.assertEqual(
            len(
                result.packets
            ),
            0,
        )

        self.assertEqual(
            len(
                result.issues
            ),
            1,
        )

        self.assertEqual(
            result.issues[
                0
            ].reason_code,
            "unsupported_link_type:101",
        )

        self.assertEqual(
            result.issues[
                0
            ].locator.raw_sha256,
            sha256(
                frame
            ),
        )

    def test_unknown_block_is_skipped_without_packet_fabrication(
        self,
    ) -> None:
        frame = (
            ethernet_ipv4_tcp()
        )

        raw = (
            section_header()
            + interface_description()
            + block(
                "<",
                0x00000BAD,
                b"ABCD",
            )
            + enhanced_packet(
                frame=frame,
                timestamp_units=(
                    1_700_000_001_123_456
                ),
            )
        )

        result = load_pcapng_bytes(
            raw_bytes=raw,
            source_path_display=(
                "unknown-block.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        )

        self.assertEqual(
            len(
                result.packets
            ),
            1,
        )

        self.assertEqual(
            result.accounted_packet_count,
            1,
        )

        self.assertEqual(
            result.errors,
            (),
        )

    def test_simple_packet_block_is_not_silently_discarded(
        self,
    ) -> None:
        frame = (
            ethernet_ipv4_tcp()
        )

        simple_packet_body = (
            struct.pack(
                "<I",
                len(frame),
            )
            + padded(
                frame
            )
        )

        raw = (
            section_header()
            + interface_description()
            + block(
                "<",
                3,
                simple_packet_body,
            )
        )

        result = load_pcapng_bytes(
            raw_bytes=raw,
            source_path_display=(
                "simple-packet.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        )

        self.assertEqual(
            len(
                result.packets
            ),
            0,
        )

        self.assertTrue(
            result.errors
        )

        self.assertEqual(
            result.errors[
                0
            ],
            (
                "unsupported_pcapng_packet_block_type:"
                "3:offset=48"
            ),
        )

    def test_invalid_interface_id_is_explicit_issue(
        self,
    ) -> None:
        frame = (
            ethernet_ipv4_udp()
        )

        raw = (
            section_header()
            + interface_description()
            + enhanced_packet(
                frame=frame,
                timestamp_units=(
                    1_700_000_001_123_456
                ),
                interface_id=7,
            )
        )

        result = load_pcapng_bytes(
            raw_bytes=raw,
            source_path_display=(
                "invalid-interface.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        )

        self.assertEqual(
            len(
                result.issues
            ),
            1,
        )

        self.assertEqual(
            result.issues[
                0
            ].reason_code,
            "pcapng_invalid_interface_id:7",
        )

    def test_binary_timestamp_resolution_fails_closed_per_packet(
        self,
    ) -> None:
        frame = (
            ethernet_ipv4_tcp()
        )

        raw = (
            section_header()
            + interface_description(
                tsresol=(
                    0x80
                    | 10
                )
            )
            + enhanced_packet(
                frame=frame,
                timestamp_units=(
                    1_700_000_001
                    * 1024
                ),
            )
        )

        result = load_pcapng_bytes(
            raw_bytes=raw,
            source_path_display=(
                "binary-resolution.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        )

        self.assertEqual(
            len(
                result.packets
            ),
            0,
        )

        self.assertEqual(
            len(
                result.issues
            ),
            1,
        )

        self.assertEqual(
            result.issues[
                0
            ].reason_code,
            (
                "unsupported_pcapng_timestamp_resolution:"
                "binary:10"
            ),
        )

    def test_trailing_block_length_mismatch_is_explicit_error(
        self,
    ) -> None:
        frame = (
            ethernet_ipv4_tcp()
        )

        epb = bytearray(
            enhanced_packet(
                frame=frame,
                timestamp_units=(
                    1_700_000_001_123_456
                ),
            )
        )

        epb[
            -4:
        ] = struct.pack(
            "<I",
            len(epb) + 4,
        )

        raw = (
            section_header()
            + interface_description()
            + bytes(epb)
        )

        result = load_pcapng_bytes(
            raw_bytes=raw,
            source_path_display=(
                "mismatch.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        )

        self.assertEqual(
            len(
                result.packets
            ),
            0,
        )

        self.assertTrue(
            result.errors[
                0
            ].startswith(
                "pcapng_block_length_mismatch:"
            )
        )

    def test_truncated_block_is_explicit_error(
        self,
    ) -> None:
        frame = (
            ethernet_ipv4_tcp()
        )

        raw = (
            section_header()
            + interface_description()
            + enhanced_packet(
                frame=frame,
                timestamp_units=(
                    1_700_000_001_123_456
                ),
            )[
                :-3
            ]
        )

        result = load_pcapng_bytes(
            raw_bytes=raw,
            source_path_display=(
                "truncated.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        )

        self.assertEqual(
            len(
                result.packets
            ),
            0,
        )

        self.assertTrue(
            result.errors[
                0
            ].startswith(
                "pcapng_block_truncated:"
            )
        )

    def test_generic_intake_routes_pcapng_and_preserves_source(
        self,
    ) -> None:
        frame = (
            ethernet_ipv4_tcp()
        )

        raw = pcapng(
            frames=(
                frame,
            )
        )

        classification = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "capture.pcapng"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.PCAPNG,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = (
                root
                / "capture.pcapng"
            )

            path.write_bytes(
                raw
            )

            result = ingest_evidence_file(
                path,
                root=root,
                acquired_or_observed_utc=(
                    ACQUIRED
                ),
            )

            self.assertEqual(
                path.read_bytes(),
                raw,
            )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.PCAPNG,
        )

        self.assertEqual(
            len(
                result.native_observations
            ),
            1,
        )

        self.assertEqual(
            len(
                result.evidence_locators
            ),
            1,
        )

    def test_classic_and_pcapng_have_equivalent_packet_semantics(
        self,
    ) -> None:
        frame = (
            ethernet_ipv4_tcp()
        )

        classic = load_pcap_bytes(
            raw_bytes=(
                classic_pcap(
                    frame=frame,
                    seconds=(
                        1_700_000_001
                    ),
                    fraction=123456,
                )
            ),
            source_path_display=(
                "capture.pcap"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        ).packets[0]

        modern = load_pcapng_bytes(
            raw_bytes=(
                pcapng(
                    frames=(
                        frame,
                    )
                )
            ),
            source_path_display=(
                "capture.pcapng"
            ),
            acquired_or_observed_utc=(
                ACQUIRED
            ),
        ).packets[0]

        def semantics(
            packet,
        ):
            return (
                packet.packet_number,
                packet.timestamp_seconds,
                packet.timestamp_fraction,
                packet.timestamp_resolution,
                packet.captured_length,
                packet.original_length,
                packet.ethernet_type,
                packet.source_ip,
                packet.destination_ip,
                packet.transport_protocol,
                packet.source_port,
                packet.destination_port,
            )

        self.assertEqual(
            semantics(
                classic
            ),
            semantics(
                modern
            ),
        )

        self.assertEqual(
            classic.locator.raw_sha256,
            modern.locator.raw_sha256,
        )

        self.assertEqual(
            classic.locator.raw_sha256,
            sha256(
                frame
            ),
        )

        self.assertEqual(
            classic.locator.adapter_id,
            PCAP_ADAPTER_ID,
        )

        self.assertEqual(
            modern.locator.adapter_id,
            PCAPNG_ADAPTER_ID,
        )

        self.assertNotEqual(
            classic.locator.byte_offset,
            modern.locator.byte_offset,
        )

        self.assertNotEqual(
            classic.artifact_id,
            modern.artifact_id,
        )

    def test_native_canonicalization_accepts_pcapng_family(
        self,
    ) -> None:
        raw = pcapng(
            frames=(
                ethernet_ipv4_tcp(),
            )
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            (
                root
                / "capture.pcapng"
            ).write_bytes(
                raw
            )

            intake = ingest_evidence_directory(
                root,
                acquired_or_observed_utc=(
                    ACQUIRED
                ),
            )

            events = (
                canonicalize_native_observations(
                    intake
                )
            )

        self.assertEqual(
            len(
                events
            ),
            1,
        )

        event = events[
            0
        ]

        self.assertEqual(
            event.semantic_fields,
            {
                "src_ip":
                    "10.0.0.5",
                "dst_ip":
                    "198.51.100.20",
                "src_port":
                    50000,
                "dst_port":
                    443,
                "protocol":
                    "tcp",
            },
        )

        self.assertEqual(
            event.event_time_raw,
            (
                "1700000001.123456 "
                "microsecond epoch"
            ),
        )

        self.assertEqual(
            event.provenance.adapter_id,
            PCAPNG_ADAPTER_ID,
        )


if __name__ == "__main__":
    unittest.main()
