from __future__ import annotations

import hashlib
import ipaddress
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tracesoc.evidence.artifacts import (
    Artifact,
    ArtifactImmutabilityState,
    ArtifactProcessingState,
)
from tracesoc.evidence.identity import (
    compute_event_id,
)
from tracesoc.evidence.intake import (
    AdapterFamily,
    classify_evidence_bytes,
    ingest_evidence_directory,
    ingest_evidence_file,
)
from tracesoc.evidence.windows_event_bridge import (
    EvidenceMutationError,
    SourceNativeArtifactBatch,
)
from tracesoc.models import (
    CanonicalEvent,
    ClockState,
    RawLocator,
    SourceType,
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


def tcp_frame() -> bytes:
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
            "192.0.2.10"
        ).packed
    )

    destination = (
        ipaddress.IPv4Address(
            "198.51.100.20"
        ).packed
    )

    tcp = struct.pack(
        "!HHIIHHHH",
        50000,
        443,
        0,
        0,
        5 << 12,
        0,
        0,
        0,
    )

    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
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


def pcap_bytes() -> bytes:
    frame = tcp_frame()

    return (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack(
            "<HHiIII",
            2,
            4,
            0,
            0,
            65535,
            1,
        )
        + struct.pack(
            "<IIII",
            1700000000,
            100,
            len(frame),
            len(frame),
        )
        + frame
    )


def artifact(
    *,
    logical_source: str,
    raw: bytes,
    artifact_type: str,
    state: ArtifactProcessingState,
) -> Artifact:
    return Artifact.create(
        artifact_type=artifact_type,
        source_path_display=(
            logical_source
        ),
        sha256=sha256(
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
        processing_state=state,
    )


def raw_locator(
    *,
    logical_source: str,
    raw: bytes,
    source_label: str,
) -> RawLocator:
    return RawLocator(
        logical_source=(
            logical_source
        ),
        record_index=0,
        line_number=1,
        byte_offset=0,
        byte_length=len(
            raw
        ),
        raw_sha256=sha256(
            raw
        ),
        adapter_id=source_label,
        input_schema_version="1",
    )


def canonical_event(
    *,
    source_type: SourceType,
    locator: RawLocator,
    event_type: str,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=compute_event_id(
            locator=locator,
            source_type=(
                source_type
            ),
            event_type=(
                event_type
            ),
        ),
        source_type=(
            source_type
        ),
        event_type=(
            event_type
        ),
        clock_state=(
            ClockState.OBSERVED
        ),
        provenance=(
            locator
        ),
        event_time_raw=(
            "2026-09-22T12:00:00Z"
        ),
        event_time_utc=(
            UTC_TIME
        ),
        host="HOST-1",
        principal=None,
        semantic_fields={},
        source_context={},
    )


class EvidenceDirectoryIntakeTests(
    unittest.TestCase
):
    def test_classifier_detects_email_by_extension(
        self,
    ) -> None:
        classification = (
            classify_evidence_bytes(
                raw_bytes=(
                    b"Microsoft-Windows-Sysmon"
                ),
                logical_source=(
                    "mail/message.eml"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.EMAIL,
        )

    def test_classifier_detects_pcap_by_magic(
        self,
    ) -> None:
        classification = (
            classify_evidence_bytes(
                raw_bytes=(
                    pcap_bytes()
                ),
                logical_source=(
                    "capture.bin"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.PCAP,
        )

    def test_classifier_detects_powershell_provider(
        self,
    ) -> None:
        raw = (
            b'<Event><System><Provider '
            b'Name="Microsoft-Windows-PowerShell"/>'
            b"</System></Event>"
        )

        classification = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "events.xml"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.POWERSHELL_XML,
        )

    def test_classifier_detects_sysmon_provider(
        self,
    ) -> None:
        raw = (
            b'<Event><System><Provider '
            b'Name="Microsoft-Windows-Sysmon"/>'
            b"</System></Event>"
        )

        classification = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "events.xml"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.SYSMON_XML,
        )

    def test_classifier_detects_zeek_declared_header(
        self,
    ) -> None:
        raw = (
            b"#separator \\x09\n"
            b"#fields\tts\tid.orig_h\tid.resp_h\n"
        )

        classification = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "conn.log"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.ZEEK_ASCII,
        )

    def test_classifier_detects_windows_security_splunk(
        self,
    ) -> None:
        raw = (
            b"LogName=Security\n"
            b"EventCode=4688\n"
            b"ComputerName=HOST-1\n"
        )

        classification = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "security.log"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.WINDOWS_SECURITY_SPLUNK,
        )

    def test_ambiguous_windows_provider_is_not_guessed(
        self,
    ) -> None:
        raw = (
            b"Microsoft-Windows-PowerShell\n"
            b"Microsoft-Windows-Sysmon\n"
        )

        classification = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "ambiguous.xml"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.UNSUPPORTED,
        )

        self.assertEqual(
            classification.reason,
            "ambiguous_windows_event_provider",
        )

    def test_mixed_directory_is_fully_accounted_and_input_unchanged(
        self,
    ) -> None:
        eml = (
            b"From: a@example.com\r\n"
            b"To: b@example.com\r\n"
            b"Subject: hello\r\n"
            b"\r\n"
            b"body\r\n"
        )

        pcap = (
            pcap_bytes()
        )

        unknown = (
            b"not a supported evidence format\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            files = {
                "01-message.eml":
                    eml,
                "02-capture.pcap":
                    pcap,
                "03-unknown.bin":
                    unknown,
            }

            before: dict[
                str,
                str,
            ] = {}

            for name, raw in files.items():
                path = (
                    root
                    / name
                )

                path.write_bytes(
                    raw
                )

                before[
                    name
                ] = sha256(
                    raw
                )

            result = (
                ingest_evidence_directory(
                    root,
                    acquired_or_observed_utc=(
                        UTC_TIME
                    ),
                )
            )

            after = {
                name:
                    sha256(
                        (
                            root
                            / name
                        ).read_bytes()
                    )
                for name
                in files
            }

        self.assertEqual(
            before,
            after,
        )

        self.assertEqual(
            result.discovered_artifact_count,
            3,
        )

        self.assertEqual(
            result.accounted_artifact_count,
            3,
        )

        self.assertEqual(
            result.supported_processed_count,
            2,
        )

        self.assertEqual(
            result.unsupported_preserved_count,
            1,
        )

        self.assertEqual(
            result.supported_partial_count,
            0,
        )

        self.assertEqual(
            result.malformed_quarantined_count,
            0,
        )

        self.assertEqual(
            result.failed_explicit_count,
            0,
        )

        self.assertEqual(
            [
                item.logical_source
                for item
                in result.items
            ],
            [
                "01-message.eml",
                "02-capture.pcap",
                "03-unknown.bin",
            ],
        )

    def test_unsupported_file_is_preserved_with_hash(
        self,
    ) -> None:
        raw = (
            b"unknown evidence"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "unknown.bin"
            )

            path.write_bytes(
                raw
            )

            result = (
                ingest_evidence_file(
                    path,
                    root=root,
                    acquired_or_observed_utc=(
                        UTC_TIME
                    ),
                )
            )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.UNSUPPORTED,
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.UNSUPPORTED_PRESERVED,
        )

        self.assertEqual(
            result.artifact.sha256,
            sha256(
                raw
            ),
        )

        self.assertEqual(
            result.errors,
            (
                "no_supported_source_signature",
            ),
        )

    def test_powershell_dispatch_uses_existing_bridge(
        self,
    ) -> None:
        raw = (
            b'<Event><Provider '
            b'Name="Microsoft-Windows-PowerShell"/>'
            b"</Event>"
        )

        logical = (
            "powershell.xml"
        )

        source_artifact = artifact(
            logical_source=(
                logical
            ),
            raw=raw,
            artifact_type=(
                "windows_event_xml"
            ),
            state=(
                ArtifactProcessingState.SUPPORTED_PROCESSED
            ),
        )

        fake = (
            SourceNativeArtifactBatch(
                artifact=(
                    source_artifact
                ),
                source_type=(
                    SourceType.POWERSHELL
                ),
                adapter_id=(
                    "existing-powershell-loader"
                ),
                canonical_events=(),
                event_locators=(),
                quarantined_locators=(),
                errors=(),
            )
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / logical
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.intake."
                "load_powershell_xml_artifact",
                return_value=(
                    fake
                ),
            ) as mocked:
                result = (
                    ingest_evidence_file(
                        path,
                        root=root,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )
                )

        mocked.assert_called_once()

        self.assertIs(
            result.adapter_family,
            AdapterFamily.POWERSHELL_XML,
        )

        self.assertEqual(
            result.artifact.artifact_id,
            source_artifact.artifact_id,
        )

    def test_sysmon_dispatch_uses_existing_bridge(
        self,
    ) -> None:
        raw = (
            b'<Event><Provider '
            b'Name="Microsoft-Windows-Sysmon"/>'
            b"</Event>"
        )

        logical = (
            "sysmon.xml"
        )

        source_artifact = artifact(
            logical_source=(
                logical
            ),
            raw=raw,
            artifact_type=(
                "windows_event_xml"
            ),
            state=(
                ArtifactProcessingState.SUPPORTED_PROCESSED
            ),
        )

        fake = (
            SourceNativeArtifactBatch(
                artifact=(
                    source_artifact
                ),
                source_type=(
                    SourceType.SYSMON
                ),
                adapter_id=(
                    "existing-sysmon-loader"
                ),
                canonical_events=(),
                event_locators=(),
                quarantined_locators=(),
                errors=(),
            )
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / logical
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.intake."
                "load_sysmon_xml_artifact",
                return_value=(
                    fake
                ),
            ) as mocked:
                result = (
                    ingest_evidence_file(
                        path,
                        root=root,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )
                )

        mocked.assert_called_once()

        self.assertIs(
            result.adapter_family,
            AdapterFamily.SYSMON_XML,
        )

    def test_windows_security_batch_is_bound_to_artifact(
        self,
    ) -> None:
        raw = (
            b"LogName=Security\n"
            b"EventCode=4688\n"
            b"ComputerName=HOST-1\n"
        )

        logical = (
            "security.log"
        )

        locator = (
            raw_locator(
                logical_source=(
                    logical
                ),
                raw=raw,
                source_label=(
                    "windows-security-test"
                ),
            )
        )

        event = (
            canonical_event(
                source_type=(
                    SourceType.WINDOWS_SECURITY
                ),
                locator=locator,
                event_type=(
                    "windows_security_event"
                ),
            )
        )

        batch = SimpleNamespace(
            source_type=(
                SourceType.WINDOWS_SECURITY
            ),
            adapter_id=(
                "windows-security-test"
            ),
            accepted=(
                event,
            ),
            quarantined=(),
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / logical
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.intake."
                "load_windows_security_splunk",
                return_value=(
                    batch
                ),
            ):
                result = (
                    ingest_evidence_file(
                        path,
                        root=root,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )
                )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.WINDOWS_SECURITY_SPLUNK,
        )

        self.assertEqual(
            result.canonical_events,
            (
                event,
            ),
        )

        self.assertEqual(
            result.evidence_locators[
                0
            ].raw_sha256,
            sha256(
                raw
            ),
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.SUPPORTED_PROCESSED,
        )

    def test_zeek_batch_is_bound_to_artifact(
        self,
    ) -> None:
        raw = (
            b"#separator \\x09\n"
            b"#fields\tts\tid.orig_h\tid.resp_h\n"
        )

        logical = (
            "conn.log"
        )

        locator = (
            raw_locator(
                logical_source=(
                    logical
                ),
                raw=raw,
                source_label=(
                    "zeek-test"
                ),
            )
        )

        event = (
            canonical_event(
                source_type=(
                    SourceType.ZEEK
                ),
                locator=locator,
                event_type=(
                    "connection"
                ),
            )
        )

        batch = SimpleNamespace(
            source_type=(
                SourceType.ZEEK
            ),
            adapter_id=(
                "zeek-test"
            ),
            accepted=(
                event,
            ),
            quarantined=(),
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / logical
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.intake."
                "load_zeek_conn_ascii",
                return_value=(
                    batch
                ),
            ):
                result = (
                    ingest_evidence_file(
                        path,
                        root=root,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )
                )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.ZEEK_ASCII,
        )

        self.assertEqual(
            result.canonical_events,
            (
                event,
            ),
        )

        self.assertEqual(
            result.evidence_locators[
                0
            ].artifact_id,
            result.artifact.artifact_id,
        )

    def test_adapter_failure_becomes_failed_explicit(
        self,
    ) -> None:
        raw = (
            b"From: a@example.com\r\n"
            b"\r\n"
            b"body\r\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "failure.eml"
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.intake."
                "load_eml_bytes",
                side_effect=(
                    RuntimeError(
                        "synthetic adapter failure"
                    )
                ),
            ):
                result = (
                    ingest_evidence_file(
                        path,
                        root=root,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )
                )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.FAILED_EXPLICIT,
        )

        self.assertEqual(
            result.errors,
            (
                "adapter_error:EMAIL:RuntimeError",
            ),
        )

    def test_adapter_evidence_mutation_fails_closed(
        self,
    ) -> None:
        raw = (
            b"LogName=Security\n"
            b"EventCode=4688\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "security.log"
            )

            path.write_bytes(
                raw
            )

            def mutating_loader(
                received_path: Path,
                *,
                logical_source: str,
            ) -> object:
                received_path.write_bytes(
                    b"changed"
                )

                return SimpleNamespace(
                    source_type=(
                        SourceType.WINDOWS_SECURITY
                    ),
                    adapter_id="test",
                    accepted=(),
                    quarantined=(),
                )

            with patch(
                "tracesoc.evidence.intake."
                "load_windows_security_splunk",
                side_effect=(
                    mutating_loader
                ),
            ):
                with self.assertRaises(
                    EvidenceMutationError
                ):
                    ingest_evidence_file(
                        path,
                        root=root,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )

    def test_directory_order_is_deterministic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            (
                root
                / "z.bin"
            ).write_bytes(
                b"z"
            )

            (
                root
                / "a.bin"
            ).write_bytes(
                b"a"
            )

            nested = (
                root
                / "nested"
            )

            nested.mkdir()

            (
                nested
                / "m.bin"
            ).write_bytes(
                b"m"
            )

            result = (
                ingest_evidence_directory(
                    root,
                    acquired_or_observed_utc=(
                        UTC_TIME
                    ),
                )
            )

        self.assertEqual(
            [
                item.logical_source
                for item
                in result.items
            ],
            [
                "a.bin",
                "nested/m.bin",
                "z.bin",
            ],
        )

        self.assertEqual(
            result.accounted_artifact_count,
            3,
        )


if __name__ == "__main__":
    unittest.main()
