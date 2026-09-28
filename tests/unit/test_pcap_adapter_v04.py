from __future__ import annotations

import hashlib
import ipaddress
import struct
import unittest
from datetime import datetime, timezone

from tracesoc.evidence.artifacts import (
    ArtifactProcessingState,
)
from tracesoc.evidence.locators import (
    LocatorKind,
)
from tracesoc.models import SourceType
from tracesoc.parsers.pcap import (
    DLT_EN10MB,
    PCAP_PACKET_EVENT_TYPE,
    load_pcap_bytes,
)


UTC_TIME = datetime(
    2026,
    9,
    22,
    12,
    0,
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
    *,
    source_ip: str = "192.0.2.10",
    destination_ip: str = "198.51.100.20",
    source_port: int = 50000,
    destination_port: int = 443,
) -> bytes:
    ethernet = (
        b"\x00\x11\x22\x33\x44\x55"
        b"\x66\x77\x88\x99\xaa\xbb"
        + struct.pack(
            "!H",
            0x0800,
        )
    )

    source = (
        ipaddress.IPv4Address(
            source_ip
        ).packed
    )

    destination = (
        ipaddress.IPv4Address(
            destination_ip
        ).packed
    )

    tcp = (
        struct.pack(
            "!HHIIHHHH",
            source_port,
            destination_port,
            0,
            0,
            5 << 12,
            0,
            0,
            0,
        )
    )

    total_length = (
        20
        + len(tcp)
    )

    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        6,
        0,
        source,
        destination,
    )

    return (
        ethernet
        + ipv4
        + tcp
    )


def ethernet_ipv4_udp(
    *,
    source_ip: str = "203.0.113.5",
    destination_ip: str = "203.0.113.53",
    source_port: int = 53000,
    destination_port: int = 53,
) -> bytes:
    ethernet = (
        b"\x00\x11\x22\x33\x44\x55"
        b"\x66\x77\x88\x99\xaa\xbb"
        + struct.pack(
            "!H",
            0x0800,
        )
    )

    source = (
        ipaddress.IPv4Address(
            source_ip
        ).packed
    )

    destination = (
        ipaddress.IPv4Address(
            destination_ip
        ).packed
    )

    udp = struct.pack(
        "!HHHH",
        source_port,
        destination_port,
        8,
        0,
    )

    total_length = (
        20
        + len(udp)
    )

    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        2,
        0,
        64,
        17,
        0,
        source,
        destination,
    )

    return (
        ethernet
        + ipv4
        + udp
    )


def classic_pcap(
    frames: tuple[
        bytes,
        ...,
    ],
    *,
    byte_order: str = "<",
    nanosecond: bool = False,
    link_type: int = DLT_EN10MB,
    snaplen: int = 65535,
) -> bytes:
    if (
        byte_order,
        nanosecond,
    ) == (
        "<",
        False,
    ):
        magic = (
            b"\xd4\xc3\xb2\xa1"
        )
    elif (
        byte_order,
        nanosecond,
    ) == (
        ">",
        False,
    ):
        magic = (
            b"\xa1\xb2\xc3\xd4"
        )
    elif (
        byte_order,
        nanosecond,
    ) == (
        "<",
        True,
    ):
        magic = (
            b"\x4d\x3c\xb2\xa1"
        )
    elif (
        byte_order,
        nanosecond,
    ) == (
        ">",
        True,
    ):
        magic = (
            b"\xa1\xb2\x3c\x4d"
        )
    else:
        raise AssertionError(
            "unsupported fixture byte order"
        )

    global_header = (
        magic
        + struct.pack(
            byte_order
            + "HHiIII",
            2,
            4,
            0,
            0,
            snaplen,
            link_type,
        )
    )

    output = bytearray(
        global_header
    )

    for index, frame in enumerate(
        frames,
        start=1,
    ):
        output.extend(
            struct.pack(
                byte_order
                + "IIII",
                1_700_000_000
                + index,
                100
                * index,
                len(frame),
                len(frame),
            )
        )

        output.extend(
            frame
        )

    return bytes(
        output
    )


class PcapAdapterTests(
    unittest.TestCase
):
    def test_little_endian_tcp_packet_is_parsed(
        self,
    ) -> None:
        frame = ethernet_ipv4_tcp()

        raw = classic_pcap(
            (
                frame,
            )
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/capture.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.SUPPORTED_PROCESSED,
        )

        self.assertEqual(
            result.artifact.sha256,
            sha256(raw),
        )

        self.assertEqual(
            len(result.packets),
            1,
        )

        self.assertEqual(
            result.issues,
            (),
        )

        packet = (
            result.packets[0]
        )

        self.assertIs(
            packet.source_type,
            SourceType.PCAP,
        )

        self.assertEqual(
            packet.event_type,
            PCAP_PACKET_EVENT_TYPE,
        )

        self.assertEqual(
            packet.source_ip,
            "192.0.2.10",
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

    def test_big_endian_udp_packet_is_parsed(
        self,
    ) -> None:
        frame = ethernet_ipv4_udp()

        raw = classic_pcap(
            (
                frame,
            ),
            byte_order=">",
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/big-endian.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        header = (
            result.global_header
        )

        assert header is not None

        self.assertEqual(
            header.byte_order,
            ">",
        )

        packet = (
            result.packets[0]
        )

        self.assertEqual(
            packet.transport_protocol,
            "udp",
        )

        self.assertEqual(
            packet.destination_port,
            53,
        )

    def test_nanosecond_magic_is_preserved(
        self,
    ) -> None:
        raw = classic_pcap(
            (
                ethernet_ipv4_udp(),
            ),
            nanosecond=True,
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/nano.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        header = (
            result.global_header
        )

        assert header is not None

        self.assertEqual(
            header.timestamp_resolution,
            "nanosecond",
        )

        self.assertEqual(
            result.packets[0].timestamp_resolution,
            "nanosecond",
        )

    def test_packet_locator_hashes_exact_frame_bytes(
        self,
    ) -> None:
        frame = ethernet_ipv4_tcp()

        raw = classic_pcap(
            (
                frame,
            )
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/exact.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        locator = (
            result.packets[0].locator
        )

        self.assertIs(
            locator.locator_kind,
            LocatorKind.PCAP_PACKET,
        )

        self.assertEqual(
            locator.packet_number,
            1,
        )

        self.assertEqual(
            locator.byte_offset,
            24 + 16,
        )

        self.assertEqual(
            locator.byte_length,
            len(frame),
        )

        self.assertEqual(
            locator.raw_sha256,
            sha256(frame),
        )

        selected = raw[
            locator.byte_offset:
            locator.byte_offset
            + locator.byte_length
        ]

        self.assertEqual(
            selected,
            frame,
        )

    def test_multiple_packet_records_are_fully_accounted(
        self,
    ) -> None:
        raw = classic_pcap(
            (
                ethernet_ipv4_tcp(),
                ethernet_ipv4_udp(),
            )
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/two.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertEqual(
            len(result.packets),
            2,
        )

        self.assertEqual(
            len(result.issues),
            0,
        )

        self.assertEqual(
            result.accounted_packet_count,
            2,
        )

        self.assertEqual(
            [
                item.packet_number
                for item in result.packets
            ],
            [
                1,
                2,
            ],
        )

    def test_unsupported_link_type_is_explicit_issue(
        self,
    ) -> None:
        frame = ethernet_ipv4_tcp()

        raw = classic_pcap(
            (
                frame,
            ),
            link_type=101,
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/raw-ip.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.SUPPORTED_PARTIAL,
        )

        self.assertEqual(
            result.packets,
            (),
        )

        self.assertEqual(
            len(result.issues),
            1,
        )

        self.assertEqual(
            result.issues[0].reason_code,
            "unsupported_link_type:101",
        )

        self.assertEqual(
            result.accounted_packet_count,
            1,
        )

    def test_unsupported_ethertype_is_explicit_issue(
        self,
    ) -> None:
        frame = (
            b"\x00" * 12
            + struct.pack(
                "!H",
                0x86DD,
            )
            + b"\x00" * 40
        )

        raw = classic_pcap(
            (
                frame,
            )
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/ipv6.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertEqual(
            len(result.issues),
            1,
        )

        self.assertEqual(
            result.issues[0].reason_code,
            "unsupported_ethertype:0x86dd",
        )

        self.assertEqual(
            result.accounted_packet_count,
            1,
        )

    def test_unsupported_ip_protocol_is_explicit_issue(
        self,
    ) -> None:
        ethernet = (
            b"\x00" * 12
            + struct.pack(
                "!H",
                0x0800,
            )
        )

        source = (
            ipaddress.IPv4Address(
                "192.0.2.1"
            ).packed
        )

        destination = (
            ipaddress.IPv4Address(
                "192.0.2.2"
            ).packed
        )

        ipv4 = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20,
            1,
            0,
            64,
            1,
            0,
            source,
            destination,
        )

        raw = classic_pcap(
            (
                ethernet
                + ipv4,
            )
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/icmp.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertEqual(
            result.issues[0].reason_code,
            "unsupported_ip_protocol:1",
        )

        self.assertEqual(
            result.accounted_packet_count,
            1,
        )

    def test_truncated_global_header_is_quarantined(
        self,
    ) -> None:
        raw = (
            b"\xd4\xc3\xb2\xa1"
            + b"\x00" * 5
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/truncated-header.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.MALFORMED_QUARANTINED,
        )

        self.assertEqual(
            result.errors,
            (
                "pcap_global_header_truncated",
            ),
        )

    def test_unknown_magic_is_preserved_as_unsupported(
        self,
    ) -> None:
        raw = (
            b"\x0a\x0d\x0d\x0a"
            + b"\x00" * 40
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/not-classic.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.UNSUPPORTED_PRESERVED,
        )

        self.assertEqual(
            result.errors,
            (
                "unsupported_pcap_magic",
            ),
        )

    def test_truncated_packet_header_is_explicit_issue(
        self,
    ) -> None:
        raw = (
            classic_pcap(
                ()
            )
            + b"\x01\x02\x03"
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/truncated-record.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.SUPPORTED_PARTIAL,
        )

        self.assertEqual(
            len(result.issues),
            1,
        )

        issue = (
            result.issues[0]
        )

        self.assertEqual(
            issue.reason_code,
            "pcap_packet_header_truncated",
        )

        self.assertIs(
            issue.locator.locator_kind,
            LocatorKind.BYTE_RANGE,
        )

        self.assertEqual(
            issue.locator.raw_sha256,
            sha256(
                b"\x01\x02\x03"
            ),
        )

        self.assertEqual(
            result.accounted_packet_count,
            1,
        )

    def test_truncated_packet_data_is_explicit_issue(
        self,
    ) -> None:
        header = classic_pcap(
            ()
        )

        record_header = struct.pack(
            "<IIII",
            1_700_000_001,
            100,
            60,
            60,
        )

        available = (
            b"\x00" * 10
        )

        raw = (
            header
            + record_header
            + available
        )

        result = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/truncated-frame.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertEqual(
            len(result.issues),
            1,
        )

        issue = (
            result.issues[0]
        )

        self.assertEqual(
            issue.reason_code,
            "pcap_packet_data_truncated:declared=60:available=10",
        )

        self.assertIs(
            issue.locator.locator_kind,
            LocatorKind.PCAP_PACKET,
        )

        self.assertEqual(
            issue.locator.raw_sha256,
            sha256(
                available
            ),
        )

        self.assertEqual(
            result.accounted_packet_count,
            1,
        )

    def test_adapter_is_deterministic(
        self,
    ) -> None:
        raw = classic_pcap(
            (
                ethernet_ipv4_tcp(),
                ethernet_ipv4_udp(),
            )
        )

        first = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/deterministic.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        second = load_pcap_bytes(
            raw_bytes=raw,
            source_path_display="raw/deterministic.pcap",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertEqual(
            first,
            second,
        )

    def test_source_path_validation_is_inherited(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            load_pcap_bytes(
                raw_bytes=classic_pcap(
                    ()
                ),
                source_path_display="../escape.pcap",
                acquired_or_observed_utc=UTC_TIME,
            )

    def test_raw_input_must_be_bytes(
        self,
    ) -> None:
        with self.assertRaises(
            TypeError
        ):
            load_pcap_bytes(
                raw_bytes="not-bytes",
                source_path_display="raw/type.pcap",
                acquired_or_observed_utc=UTC_TIME,
            )


if __name__ == "__main__":
    unittest.main()
