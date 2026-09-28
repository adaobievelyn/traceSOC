from __future__ import annotations

import hashlib
import unittest
from datetime import (
    datetime,
    timezone,
)

from tracesoc.evidence.artifacts import (
    Artifact,
    ArtifactImmutabilityState,
    ArtifactProcessingState,
)
from tracesoc.evidence.intake import (
    AdapterFamily,
    EvidenceDirectoryIntake,
    EvidenceFileIntake,
)
from tracesoc.evidence.locators import (
    EvidenceLocator,
    LocatorKind,
)
from tracesoc.evidence.native_canonical import (
    NativeCanonicalizationError,
    canonicalize_native_observations,
)
from tracesoc.models import (
    ClockState,
    SourceType,
)
from tracesoc.parsers.eml import (
    EmailMessageObservation,
    EmailPartObservation,
)
from tracesoc.parsers.pcap import (
    PcapPacketObservation,
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


def digest(
    value: bytes,
) -> str:
    return hashlib.sha256(
        value
    ).hexdigest()


def artifact(
    *,
    path: str,
    raw: bytes,
    artifact_type: str,
) -> Artifact:
    return Artifact.create(
        artifact_type=artifact_type,
        source_path_display=path,
        sha256=digest(
            raw
        ),
        bytes=len(
            raw
        ),
        acquired_or_observed_utc=(
            UTC_TIME
        ),
        immutability_state=(
            ArtifactImmutabilityState.PRESERVED_SOURCE
        ),
        processing_state=(
            ArtifactProcessingState.SUPPORTED_PROCESSED
        ),
    )


class NativeCanonicalV04Tests(
    unittest.TestCase
):
    def test_email_message_preserves_headers_and_utc_time(
        self,
    ) -> None:
        raw = b"mail"

        source_artifact = artifact(
            path="mail/message.eml",
            raw=raw,
            artifact_type="message/rfc822",
        )

        locator = EvidenceLocator(
            artifact_id=(
                source_artifact.artifact_id
            ),
            artifact_type=(
                source_artifact.artifact_type
            ),
            locator_kind=(
                LocatorKind.BYTE_RANGE
            ),
            raw_sha256=digest(
                raw
            ),
            adapter_id=(
                "tracesoc-eml-v1"
            ),
            input_schema_version="1",
            byte_offset=0,
            byte_length=len(
                raw
            ),
        )

        observation = (
            EmailMessageObservation(
                artifact_id=(
                    source_artifact.artifact_id
                ),
                source_type=(
                    SourceType.EMAIL
                ),
                event_type=(
                    "email_message"
                ),
                locator=locator,
                message_id="<m1@example>",
                date=(
                    "Tue, 22 Sep 2026 "
                    "13:30:00 +0100"
                ),
                from_value="a@example.test",
                to_value="b@example.test",
                subject="Example",
                defects=(),
            )
        )

        intake = EvidenceDirectoryIntake(
            root_display_name="evidence",
            items=(
                EvidenceFileIntake(
                    artifact=source_artifact,
                    adapter_family=(
                        AdapterFamily.EMAIL
                    ),
                    native_observations=(
                        observation,
                    ),
                ),
            ),
        )

        events = (
            canonicalize_native_observations(
                intake
            )
        )

        self.assertEqual(
            len(events),
            1,
        )

        event = events[0]

        self.assertIs(
            event.source_type,
            SourceType.EMAIL,
        )

        self.assertEqual(
            event.event_type,
            "email_message",
        )

        self.assertIs(
            event.clock_state,
            ClockState.OBSERVED,
        )

        self.assertEqual(
            event.event_time_utc,
            UTC_TIME.replace(
                minute=30
            ),
        )

        self.assertEqual(
            event.event_time_raw,
            observation.date,
        )

        self.assertEqual(
            event.provenance.logical_source,
            "mail/message.eml",
        )

        self.assertEqual(
            event.provenance.record_index,
            0,
        )

        self.assertEqual(
            event.semantic_fields[
                "message_id"
            ],
            "<m1@example>",
        )

        self.assertEqual(
            event.source_context[
                "native_locator"
            ][
                "locator_kind"
            ],
            "BYTE_RANGE",
        )


    def test_email_missing_date_is_untimed(
        self,
    ) -> None:
        raw = b"mail"

        source_artifact = artifact(
            path="message.eml",
            raw=raw,
            artifact_type="message/rfc822",
        )

        locator = EvidenceLocator(
            artifact_id=(
                source_artifact.artifact_id
            ),
            artifact_type=(
                source_artifact.artifact_type
            ),
            locator_kind=(
                LocatorKind.BYTE_RANGE
            ),
            raw_sha256=digest(
                raw
            ),
            adapter_id="tracesoc-eml-v1",
            input_schema_version="1",
            byte_offset=0,
            byte_length=len(
                raw
            ),
        )

        observation = EmailMessageObservation(
            artifact_id=(
                source_artifact.artifact_id
            ),
            source_type=SourceType.EMAIL,
            event_type="email_message",
            locator=locator,
            message_id=None,
            date=None,
            from_value=None,
            to_value=None,
            subject=None,
            defects=(),
        )

        intake = EvidenceDirectoryIntake(
            root_display_name="evidence",
            items=(
                EvidenceFileIntake(
                    artifact=source_artifact,
                    adapter_family=(
                        AdapterFamily.EMAIL
                    ),
                    native_observations=(
                        observation,
                    ),
                ),
            ),
        )

        event = (
            canonicalize_native_observations(
                intake
            )[0]
        )

        self.assertIs(
            event.clock_state,
            ClockState.UNTIMED,
        )

        self.assertIsNone(
            event.event_time_utc
        )


    def test_email_timezone_unknown_is_unresolved(
        self,
    ) -> None:
        raw = b"mail"

        source_artifact = artifact(
            path="message.eml",
            raw=raw,
            artifact_type="message/rfc822",
        )

        locator = EvidenceLocator(
            artifact_id=(
                source_artifact.artifact_id
            ),
            artifact_type=(
                source_artifact.artifact_type
            ),
            locator_kind=(
                LocatorKind.BYTE_RANGE
            ),
            raw_sha256=digest(raw),
            adapter_id="tracesoc-eml-v1",
            input_schema_version="1",
            byte_offset=0,
            byte_length=len(raw),
        )

        observation = EmailMessageObservation(
            artifact_id=(
                source_artifact.artifact_id
            ),
            source_type=SourceType.EMAIL,
            event_type="email_message",
            locator=locator,
            message_id=None,
            date=(
                "Tue, 22 Sep 2026 13:30:00"
            ),
            from_value=None,
            to_value=None,
            subject=None,
            defects=(),
        )

        intake = EvidenceDirectoryIntake(
            root_display_name="evidence",
            items=(
                EvidenceFileIntake(
                    artifact=source_artifact,
                    adapter_family=(
                        AdapterFamily.EMAIL
                    ),
                    native_observations=(
                        observation,
                    ),
                ),
            ),
        )

        event = (
            canonicalize_native_observations(
                intake
            )[0]
        )

        self.assertIs(
            event.clock_state,
            ClockState.UNRESOLVED,
        )

        self.assertIsNone(
            event.event_time_utc
        )


    def test_email_part_preserves_mime_locator_and_hash(
        self,
    ) -> None:
        raw = b"mail"

        source_artifact = artifact(
            path="message.eml",
            raw=raw,
            artifact_type="message/rfc822",
        )

        decoded = b"attachment"

        locator = EvidenceLocator(
            artifact_id=(
                source_artifact.artifact_id
            ),
            artifact_type=(
                source_artifact.artifact_type
            ),
            locator_kind=(
                LocatorKind.MIME_PART
            ),
            raw_sha256=digest(
                decoded
            ),
            adapter_id="tracesoc-eml-v1",
            input_schema_version="1",
            mime_part_path=(
                1,
                2,
            ),
        )

        observation = EmailPartObservation(
            artifact_id=(
                source_artifact.artifact_id
            ),
            source_type=SourceType.EMAIL,
            event_type="email_part",
            locator=locator,
            content_type=(
                "application/octet-stream"
            ),
            content_disposition=(
                "attachment"
            ),
            filename="sample.bin",
            content_id=None,
            transfer_encoding="base64",
            decoded_sha256=digest(
                decoded
            ),
            decoded_bytes=len(
                decoded
            ),
            derived_artifact_id=(
                "art_derived_example"
            ),
        )

        intake = EvidenceDirectoryIntake(
            root_display_name="evidence",
            items=(
                EvidenceFileIntake(
                    artifact=source_artifact,
                    adapter_family=(
                        AdapterFamily.EMAIL
                    ),
                    native_observations=(
                        observation,
                    ),
                ),
            ),
        )

        event = (
            canonicalize_native_observations(
                intake
            )[0]
        )

        self.assertIs(
            event.clock_state,
            ClockState.UNTIMED,
        )

        self.assertEqual(
            event.source_context[
                "native_locator"
            ][
                "mime_part_path"
            ],
            [
                1,
                2,
            ],
        )

        self.assertEqual(
            event.semantic_fields[
                "decoded_sha256"
            ],
            digest(
                decoded
            ),
        )

        self.assertEqual(
            event.semantic_fields[
                "filename"
            ],
            "sample.bin",
        )


    def test_pcap_microsecond_packet_becomes_observed_event(
        self,
    ) -> None:
        raw = b"pcap-source"

        source_artifact = artifact(
            path="capture.pcap",
            raw=raw,
            artifact_type="pcap",
        )

        frame = b"frame"

        locator = EvidenceLocator(
            artifact_id=(
                source_artifact.artifact_id
            ),
            artifact_type=(
                source_artifact.artifact_type
            ),
            locator_kind=(
                LocatorKind.PCAP_PACKET
            ),
            raw_sha256=digest(
                frame
            ),
            adapter_id=(
                "tracesoc-classic-pcap-v1"
            ),
            input_schema_version="1",
            byte_offset=40,
            byte_length=len(
                frame
            ),
            packet_number=3,
        )

        observation = PcapPacketObservation(
            artifact_id=(
                source_artifact.artifact_id
            ),
            source_type=SourceType.PCAP,
            event_type="network_packet",
            locator=locator,
            packet_number=3,
            timestamp_seconds=0,
            timestamp_fraction=123456,
            timestamp_resolution=(
                "microsecond"
            ),
            captured_length=5,
            original_length=5,
            ethernet_type=0x0800,
            source_ip="10.0.0.5",
            destination_ip=(
                "198.51.100.20"
            ),
            transport_protocol="TCP",
            source_port=50000,
            destination_port=443,
        )

        intake = EvidenceDirectoryIntake(
            root_display_name="evidence",
            items=(
                EvidenceFileIntake(
                    artifact=source_artifact,
                    adapter_family=(
                        AdapterFamily.PCAP
                    ),
                    native_observations=(
                        observation,
                    ),
                ),
            ),
        )

        event = (
            canonicalize_native_observations(
                intake
            )[0]
        )

        self.assertIs(
            event.source_type,
            SourceType.PCAP,
        )

        self.assertIs(
            event.clock_state,
            ClockState.OBSERVED,
        )

        self.assertEqual(
            event.event_time_utc,
            datetime(
                1970,
                1,
                1,
                0,
                0,
                0,
                123456,
                tzinfo=timezone.utc,
            ),
        )

        self.assertEqual(
            event.provenance.record_index,
            2,
        )

        self.assertEqual(
            event.source_context[
                "native_locator"
            ][
                "packet_number"
            ],
            3,
        )

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
                    "TCP",
            },
        )


    def test_pcap_nanosecond_precision_is_not_silently_lost(
        self,
    ) -> None:
        raw = b"pcap-source"

        source_artifact = artifact(
            path="capture.pcap",
            raw=raw,
            artifact_type="pcap",
        )

        frame = b"frame"

        locator = EvidenceLocator(
            artifact_id=(
                source_artifact.artifact_id
            ),
            artifact_type=(
                source_artifact.artifact_type
            ),
            locator_kind=(
                LocatorKind.PCAP_PACKET
            ),
            raw_sha256=digest(frame),
            adapter_id=(
                "tracesoc-classic-pcap-v1"
            ),
            input_schema_version="1",
            byte_offset=40,
            byte_length=len(frame),
            packet_number=1,
        )

        observation = PcapPacketObservation(
            artifact_id=(
                source_artifact.artifact_id
            ),
            source_type=SourceType.PCAP,
            event_type="network_packet",
            locator=locator,
            packet_number=1,
            timestamp_seconds=0,
            timestamp_fraction=123456789,
            timestamp_resolution=(
                "nanosecond"
            ),
            captured_length=5,
            original_length=5,
            ethernet_type=0x0800,
            source_ip="10.0.0.5",
            destination_ip="10.0.0.6",
            transport_protocol="UDP",
            source_port=53,
            destination_port=53000,
        )

        intake = EvidenceDirectoryIntake(
            root_display_name="evidence",
            items=(
                EvidenceFileIntake(
                    artifact=source_artifact,
                    adapter_family=(
                        AdapterFamily.PCAP
                    ),
                    native_observations=(
                        observation,
                    ),
                ),
            ),
        )

        event = (
            canonicalize_native_observations(
                intake
            )[0]
        )

        self.assertEqual(
            event.event_time_raw,
            "0.123456789 nanosecond epoch",
        )

        self.assertEqual(
            event.event_time_utc.microsecond,
            123456,
        )

        self.assertEqual(
            event.source_context[
                "timestamp_fraction"
            ],
            123456789,
        )

        self.assertEqual(
            event.source_context[
                "submicrosecond_remainder_nanoseconds"
            ],
            789,
        )


    def test_artifact_mismatch_fails_closed(
        self,
    ) -> None:
        raw = b"mail"

        source_artifact = artifact(
            path="message.eml",
            raw=raw,
            artifact_type="message/rfc822",
        )

        locator = EvidenceLocator(
            artifact_id=(
                "art_"
                + "a" * 64
            ),
            artifact_type=(
                source_artifact.artifact_type
            ),
            locator_kind=(
                LocatorKind.BYTE_RANGE
            ),
            raw_sha256=digest(raw),
            adapter_id="tracesoc-eml-v1",
            input_schema_version="1",
            byte_offset=0,
            byte_length=len(raw),
        )

        observation = EmailMessageObservation(
            artifact_id=(
                source_artifact.artifact_id
            ),
            source_type=SourceType.EMAIL,
            event_type="email_message",
            locator=locator,
            message_id=None,
            date=None,
            from_value=None,
            to_value=None,
            subject=None,
            defects=(),
        )

        intake = EvidenceDirectoryIntake(
            root_display_name="evidence",
            items=(
                EvidenceFileIntake(
                    artifact=source_artifact,
                    adapter_family=(
                        AdapterFamily.EMAIL
                    ),
                    native_observations=(
                        observation,
                    ),
                ),
            ),
        )

        with self.assertRaises(
            NativeCanonicalizationError
        ):
            canonicalize_native_observations(
                intake
            )


    def test_unknown_native_observation_is_not_silently_dropped(
        self,
    ) -> None:
        raw = b"x"

        source_artifact = artifact(
            path="message.eml",
            raw=raw,
            artifact_type="message/rfc822",
        )

        intake = EvidenceDirectoryIntake(
            root_display_name="evidence",
            items=(
                EvidenceFileIntake(
                    artifact=source_artifact,
                    adapter_family=(
                        AdapterFamily.EMAIL
                    ),
                    native_observations=(
                        object(),
                    ),
                ),
            ),
        )

        with self.assertRaises(
            NativeCanonicalizationError
        ):
            canonicalize_native_observations(
                intake
            )


    def test_canonicalization_is_deterministic(
        self,
    ) -> None:
        raw = b"pcap-source"

        source_artifact = artifact(
            path="capture.pcap",
            raw=raw,
            artifact_type="pcap",
        )

        frame = b"frame"

        locator = EvidenceLocator(
            artifact_id=(
                source_artifact.artifact_id
            ),
            artifact_type=(
                source_artifact.artifact_type
            ),
            locator_kind=(
                LocatorKind.PCAP_PACKET
            ),
            raw_sha256=digest(frame),
            adapter_id=(
                "tracesoc-classic-pcap-v1"
            ),
            input_schema_version="1",
            byte_offset=40,
            byte_length=len(frame),
            packet_number=1,
        )

        observation = PcapPacketObservation(
            artifact_id=(
                source_artifact.artifact_id
            ),
            source_type=SourceType.PCAP,
            event_type="network_packet",
            locator=locator,
            packet_number=1,
            timestamp_seconds=1,
            timestamp_fraction=2,
            timestamp_resolution=(
                "microsecond"
            ),
            captured_length=5,
            original_length=5,
            ethernet_type=0x0800,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            transport_protocol="TCP",
            source_port=1,
            destination_port=2,
        )

        intake = EvidenceDirectoryIntake(
            root_display_name="evidence",
            items=(
                EvidenceFileIntake(
                    artifact=source_artifact,
                    adapter_family=(
                        AdapterFamily.PCAP
                    ),
                    native_observations=(
                        observation,
                    ),
                ),
            ),
        )

        first = (
            canonicalize_native_observations(
                intake
            )
        )

        second = (
            canonicalize_native_observations(
                intake
            )
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            first[0].event_id,
            second[0].event_id,
        )


if __name__ == "__main__":
    unittest.main()
