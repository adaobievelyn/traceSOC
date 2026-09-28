from __future__ import annotations

import hashlib
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

from tracesoc.evidence.artifacts import (
    Artifact,
    ArtifactImmutabilityState,
    ArtifactProcessingState,
)
from tracesoc.evidence.locators import (
    EvidenceLocator,
    LocatorKind,
)
from tracesoc.models import RawLocator


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
    data: bytes,
) -> str:
    return hashlib.sha256(
        data
    ).hexdigest()


def artifact(
    *,
    path: str = "raw/events.log",
    raw: bytes = b"artifact",
    artifact_type: str = "text/plain",
) -> Artifact:
    return Artifact.create(
        artifact_type=artifact_type,
        source_path_display=path,
        sha256=sha256(raw),
        bytes=len(raw),
        acquired_or_observed_utc=UTC_TIME,
        immutability_state=(
            ArtifactImmutabilityState.PRESERVED_SOURCE
        ),
        processing_state=(
            ArtifactProcessingState.SUPPORTED_PROCESSED
        ),
    )


class CaseLocatorContractTests(
    unittest.TestCase
):
    def test_locator_kind_contract_is_exact(
        self,
    ) -> None:
        self.assertEqual(
            {
                kind.value
                for kind in LocatorKind
            },
            {
                "RECORD",
                "BYTE_RANGE",
                "MIME_PART",
                "PCAP_PACKET",
            },
        )

    def test_record_locator_accepts_exact_record_coordinates(
        self,
    ) -> None:
        source = artifact()

        locator = EvidenceLocator(
            artifact_id=source.artifact_id,
            artifact_type=source.artifact_type,
            locator_kind=LocatorKind.RECORD,
            raw_sha256=sha256(b"record"),
            adapter_id="test-record-v1",
            input_schema_version="1",
            record_index=0,
            line_number=2,
            byte_offset=10,
            byte_length=25,
        )

        self.assertEqual(
            locator.record_index,
            0,
        )

        self.assertEqual(
            locator.byte_offset,
            10,
        )

        self.assertEqual(
            locator.byte_length,
            25,
        )

    def test_record_locator_may_exist_without_byte_range(
        self,
    ) -> None:
        source = artifact()

        locator = EvidenceLocator(
            artifact_id=source.artifact_id,
            artifact_type=source.artifact_type,
            locator_kind=LocatorKind.RECORD,
            raw_sha256=sha256(b"record"),
            adapter_id="test-record-v1",
            input_schema_version="1",
            record_index=3,
        )

        self.assertIsNone(
            locator.byte_offset
        )

        self.assertIsNone(
            locator.byte_length
        )

    def test_byte_range_locator_requires_complete_range(
        self,
    ) -> None:
        source = artifact()

        locator = EvidenceLocator(
            artifact_id=source.artifact_id,
            artifact_type=source.artifact_type,
            locator_kind=LocatorKind.BYTE_RANGE,
            raw_sha256=sha256(b"slice"),
            adapter_id="test-range-v1",
            input_schema_version="1",
            byte_offset=4,
            byte_length=5,
        )

        self.assertEqual(
            locator.byte_offset,
            4,
        )

        self.assertEqual(
            locator.byte_length,
            5,
        )

        with self.assertRaises(
            ValueError
        ):
            EvidenceLocator(
                artifact_id=source.artifact_id,
                artifact_type=source.artifact_type,
                locator_kind=LocatorKind.BYTE_RANGE,
                raw_sha256=sha256(b"slice"),
                adapter_id="test-range-v1",
                input_schema_version="1",
                byte_offset=4,
            )

    def test_mime_locator_uses_structural_part_path(
        self,
    ) -> None:
        source = artifact(
            path="raw/message.eml",
            artifact_type="message/rfc822",
        )

        locator = EvidenceLocator(
            artifact_id=source.artifact_id,
            artifact_type=source.artifact_type,
            locator_kind=LocatorKind.MIME_PART,
            raw_sha256=sha256(b"attachment"),
            adapter_id="test-eml-v1",
            input_schema_version="1",
            mime_part_path=(1, 0),
        )

        self.assertEqual(
            locator.mime_part_path,
            (1, 0),
        )

    def test_mime_locator_rejects_empty_or_mutable_path(
        self,
    ) -> None:
        source = artifact(
            path="raw/message.eml",
            artifact_type="message/rfc822",
        )

        with self.assertRaises(
            ValueError
        ):
            EvidenceLocator(
                artifact_id=source.artifact_id,
                artifact_type=source.artifact_type,
                locator_kind=LocatorKind.MIME_PART,
                raw_sha256=sha256(b"part"),
                adapter_id="test-eml-v1",
                input_schema_version="1",
                mime_part_path=(),
            )

        with self.assertRaises(
            TypeError
        ):
            EvidenceLocator(
                artifact_id=source.artifact_id,
                artifact_type=source.artifact_type,
                locator_kind=LocatorKind.MIME_PART,
                raw_sha256=sha256(b"part"),
                adapter_id="test-eml-v1",
                input_schema_version="1",
                mime_part_path=[1],
            )

    def test_pcap_locator_requires_packet_number_and_byte_range(
        self,
    ) -> None:
        source = artifact(
            path="raw/capture.pcap",
            artifact_type=(
                "application/vnd.tcpdump.pcap"
            ),
        )

        locator = EvidenceLocator(
            artifact_id=source.artifact_id,
            artifact_type=source.artifact_type,
            locator_kind=LocatorKind.PCAP_PACKET,
            raw_sha256=sha256(b"packet"),
            adapter_id="test-pcap-v1",
            input_schema_version="1",
            packet_number=1,
            byte_offset=24,
            byte_length=60,
        )

        self.assertEqual(
            locator.packet_number,
            1,
        )

        self.assertEqual(
            locator.byte_offset,
            24,
        )

        with self.assertRaises(
            ValueError
        ):
            EvidenceLocator(
                artifact_id=source.artifact_id,
                artifact_type=source.artifact_type,
                locator_kind=LocatorKind.PCAP_PACKET,
                raw_sha256=sha256(b"packet"),
                adapter_id="test-pcap-v1",
                input_schema_version="1",
                packet_number=0,
                byte_offset=24,
                byte_length=60,
            )

    def test_cross_kind_coordinates_are_rejected(
        self,
    ) -> None:
        source = artifact()

        with self.assertRaises(
            ValueError
        ):
            EvidenceLocator(
                artifact_id=source.artifact_id,
                artifact_type=source.artifact_type,
                locator_kind=LocatorKind.RECORD,
                raw_sha256=sha256(b"record"),
                adapter_id="test-record-v1",
                input_schema_version="1",
                record_index=0,
                packet_number=1,
            )

        with self.assertRaises(
            ValueError
        ):
            EvidenceLocator(
                artifact_id=source.artifact_id,
                artifact_type=source.artifact_type,
                locator_kind=LocatorKind.MIME_PART,
                raw_sha256=sha256(b"part"),
                adapter_id="test-eml-v1",
                input_schema_version="1",
                mime_part_path=(0,),
                byte_offset=1,
                byte_length=2,
            )

    def test_invalid_artifact_id_is_rejected(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            EvidenceLocator(
                artifact_id=(
                    "evt_"
                    + ("0" * 64)
                ),
                artifact_type="text/plain",
                locator_kind=LocatorKind.RECORD,
                raw_sha256=sha256(b"record"),
                adapter_id="test-record-v1",
                input_schema_version="1",
                record_index=0,
            )

    def test_invalid_raw_sha256_is_rejected(
        self,
    ) -> None:
        source = artifact()

        with self.assertRaises(
            ValueError
        ):
            EvidenceLocator(
                artifact_id=source.artifact_id,
                artifact_type=source.artifact_type,
                locator_kind=LocatorKind.RECORD,
                raw_sha256=(
                    sha256(
                        b"record"
                    ).upper()
                ),
                adapter_id="test-record-v1",
                input_schema_version="1",
                record_index=0,
            )

    def test_boolean_numeric_coordinates_are_rejected(
        self,
    ) -> None:
        source = artifact()

        with self.assertRaises(
            ValueError
        ):
            EvidenceLocator(
                artifact_id=source.artifact_id,
                artifact_type=source.artifact_type,
                locator_kind=LocatorKind.RECORD,
                raw_sha256=sha256(b"record"),
                adapter_id="test-record-v1",
                input_schema_version="1",
                record_index=True,
            )

    def test_from_raw_locator_preserves_legacy_coordinates(
        self,
    ) -> None:
        logical_source = (
            "tests/fixtures/example.log"
        )

        source = artifact(
            path=logical_source,
            raw=b"whole file",
            artifact_type="text/plain",
        )

        legacy = RawLocator(
            logical_source=logical_source,
            record_index=7,
            line_number=11,
            byte_offset=100,
            byte_length=42,
            raw_sha256=sha256(b"record"),
            adapter_id="legacy-test-v1",
            input_schema_version="1",
        )

        converted = (
            EvidenceLocator.from_raw_locator(
                artifact=source,
                locator=legacy,
            )
        )

        self.assertEqual(
            converted.artifact_id,
            source.artifact_id,
        )

        self.assertEqual(
            converted.artifact_type,
            source.artifact_type,
        )

        self.assertIs(
            converted.locator_kind,
            LocatorKind.RECORD,
        )

        self.assertEqual(
            converted.record_index,
            legacy.record_index,
        )

        self.assertEqual(
            converted.line_number,
            legacy.line_number,
        )

        self.assertEqual(
            converted.byte_offset,
            legacy.byte_offset,
        )

        self.assertEqual(
            converted.byte_length,
            legacy.byte_length,
        )

        self.assertEqual(
            converted.raw_sha256,
            legacy.raw_sha256,
        )

        self.assertEqual(
            converted.adapter_id,
            legacy.adapter_id,
        )

        self.assertEqual(
            converted.input_schema_version,
            legacy.input_schema_version,
        )

    def test_raw_locator_conversion_rejects_artifact_path_mismatch(
        self,
    ) -> None:
        source = artifact(
            path="raw/a.log",
        )

        legacy = RawLocator(
            logical_source="raw/b.log",
            record_index=0,
            raw_sha256=sha256(b"record"),
            adapter_id="legacy-test-v1",
            input_schema_version="1",
        )

        with self.assertRaises(
            ValueError
        ):
            EvidenceLocator.from_raw_locator(
                artifact=source,
                locator=legacy,
            )

    def test_raw_locator_conversion_is_deterministic_and_non_mutating(
        self,
    ) -> None:
        logical_source = "raw/events.log"

        source = artifact(
            path=logical_source,
        )

        legacy = RawLocator(
            logical_source=logical_source,
            record_index=2,
            line_number=3,
            byte_offset=9,
            byte_length=8,
            raw_sha256=sha256(b"record"),
            adapter_id="legacy-test-v1",
            input_schema_version="1",
        )

        before = (
            legacy.logical_source,
            legacy.record_index,
            legacy.line_number,
            legacy.byte_offset,
            legacy.byte_length,
            legacy.raw_sha256,
            legacy.adapter_id,
            legacy.input_schema_version,
        )

        first = (
            EvidenceLocator.from_raw_locator(
                artifact=source,
                locator=legacy,
            )
        )

        second = (
            EvidenceLocator.from_raw_locator(
                artifact=source,
                locator=legacy,
            )
        )

        after = (
            legacy.logical_source,
            legacy.record_index,
            legacy.line_number,
            legacy.byte_offset,
            legacy.byte_length,
            legacy.raw_sha256,
            legacy.adapter_id,
            legacy.input_schema_version,
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            before,
            after,
        )

    def test_locator_is_immutable(
        self,
    ) -> None:
        source = artifact()

        locator = EvidenceLocator(
            artifact_id=source.artifact_id,
            artifact_type=source.artifact_type,
            locator_kind=LocatorKind.RECORD,
            raw_sha256=sha256(b"record"),
            adapter_id="test-record-v1",
            input_schema_version="1",
            record_index=0,
        )

        with self.assertRaises(
            FrozenInstanceError
        ):
            locator.record_index = 9


if __name__ == "__main__":
    unittest.main()
