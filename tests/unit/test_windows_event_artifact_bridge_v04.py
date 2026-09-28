from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tracesoc.evidence.artifacts import (
    ArtifactProcessingState,
)
from tracesoc.evidence.locators import (
    LocatorKind,
)
from tracesoc.evidence.windows_event_bridge import (
    EvidenceBoundaryError,
    EvidenceMutationError,
    load_powershell_xml_artifact,
    load_sysmon_xml_artifact,
)
from tracesoc.evidence.identity import (
    compute_event_id,
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


def locator(
    *,
    logical_source: str,
    raw_bytes: bytes,
    byte_offset: int,
    record_index: int,
    source_label: str,
) -> RawLocator:
    return RawLocator(
        logical_source=logical_source,
        record_index=record_index,
        line_number=1,
        byte_offset=byte_offset,
        byte_length=len(
            raw_bytes
        ),
        raw_sha256=sha256(
            raw_bytes
        ),
        adapter_id=source_label,
        input_schema_version="1",
    )


def canonical(
    *,
    source_type: SourceType,
    raw_locator: RawLocator,
    event_type: str,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=compute_event_id(
            locator=raw_locator,
            source_type=source_type,
            event_type=event_type,
        ),
        source_type=source_type,
        event_type=event_type,
        clock_state=(
            ClockState.OBSERVED
        ),
        provenance=raw_locator,
        event_time_raw=(
            "2026-09-22T12:00:00Z"
        ),
        event_time_utc=UTC_TIME,
        host="HOST-1",
        principal=None,
        semantic_fields={},
        source_context={},
    )


class WindowsEventArtifactBridgeTests(
    unittest.TestCase
):
    def test_powershell_event_is_preserved_and_bound_to_artifact(
        self,
    ) -> None:
        raw = (
            b"<Event>PowerShell</Event>"
        )

        logical = (
            "raw/powershell.xml"
        )

        raw_locator = locator(
            logical_source=logical,
            raw_bytes=raw,
            byte_offset=0,
            record_index=0,
            source_label="powershell-real-v1",
        )

        event = canonical(
            source_type=(
                SourceType.POWERSHELL
            ),
            raw_locator=raw_locator,
            event_type=(
                "windows_event"
            ),
        )

        batch = SimpleNamespace(
            source_type=(
                SourceType.POWERSHELL
            ),
            adapter_id=(
                "powershell-real-v1"
            ),
            accepted=(
                event,
            ),
            quarantined=(),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "powershell.xml"
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.windows_event_bridge."
                "load_powershell_windows_event_xml",
                return_value=batch,
            ) as mocked:
                result = (
                    load_powershell_xml_artifact(
                        path,
                        logical_source=logical,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )
                )

        mocked.assert_called_once_with(
            path,
            logical_source=logical,
        )

        self.assertIs(
            result.canonical_events[0],
            event,
        )

        self.assertIs(
            result.source_type,
            SourceType.POWERSHELL,
        )

        self.assertEqual(
            result.artifact.sha256,
            sha256(raw),
        )

        self.assertEqual(
            result.artifact.bytes,
            len(raw),
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.SUPPORTED_PROCESSED,
        )

        self.assertEqual(
            result.accepted_count,
            1,
        )

        self.assertEqual(
            result.quarantined_count,
            0,
        )

        self.assertEqual(
            result.accounted_record_count,
            1,
        )

        evidence_locator = (
            result.event_locators[0]
        )

        self.assertIs(
            evidence_locator.locator_kind,
            LocatorKind.RECORD,
        )

        self.assertEqual(
            evidence_locator.artifact_id,
            result.artifact.artifact_id,
        )

        self.assertEqual(
            evidence_locator.byte_offset,
            0,
        )

        self.assertEqual(
            evidence_locator.byte_length,
            len(raw),
        )

        self.assertEqual(
            evidence_locator.raw_sha256,
            sha256(raw),
        )

        self.assertEqual(
            event.provenance,
            raw_locator,
        )

    def test_sysmon_partial_batch_accounts_for_quarantine(
        self,
    ) -> None:
        good = (
            b"<Event>Sysmon</Event>"
        )

        bad = (
            b"BROKEN"
        )

        raw = (
            good
            + bad
        )

        logical = (
            "raw/sysmon.xml"
        )

        good_locator = locator(
            logical_source=logical,
            raw_bytes=good,
            byte_offset=0,
            record_index=0,
            source_label="sysmon-real-v1",
        )

        bad_locator = locator(
            logical_source=logical,
            raw_bytes=bad,
            byte_offset=len(
                good
            ),
            record_index=1,
            source_label="sysmon-real-v1",
        )

        event = canonical(
            source_type=(
                SourceType.SYSMON
            ),
            raw_locator=good_locator,
            event_type=(
                "process_creation"
            ),
        )

        quarantined = (
            SimpleNamespace(
                locator=bad_locator
            )
        )

        batch = SimpleNamespace(
            source_type=(
                SourceType.SYSMON
            ),
            adapter_id=(
                "sysmon-real-v1"
            ),
            accepted=(
                event,
            ),
            quarantined=(
                quarantined,
            ),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "sysmon.xml"
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.windows_event_bridge."
                "load_sysmon_windows_event_xml",
                return_value=batch,
            ):
                result = (
                    load_sysmon_xml_artifact(
                        path,
                        logical_source=logical,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )
                )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.SUPPORTED_PARTIAL,
        )

        self.assertEqual(
            result.accepted_count,
            1,
        )

        self.assertEqual(
            result.quarantined_count,
            1,
        )

        self.assertEqual(
            result.accounted_record_count,
            2,
        )

        self.assertEqual(
            result.quarantined_locators[
                0
            ].byte_offset,
            len(
                good
            ),
        )

        self.assertEqual(
            result.quarantined_locators[
                0
            ].raw_sha256,
            sha256(
                bad
            ),
        )

    def test_all_quarantined_becomes_malformed_quarantined(
        self,
    ) -> None:
        raw = (
            b"BROKEN"
        )

        logical = (
            "raw/all-bad.xml"
        )

        bad_locator = locator(
            logical_source=logical,
            raw_bytes=raw,
            byte_offset=0,
            record_index=0,
            source_label="sysmon-real-v1",
        )

        batch = SimpleNamespace(
            source_type=(
                SourceType.SYSMON
            ),
            adapter_id=(
                "sysmon-real-v1"
            ),
            accepted=(),
            quarantined=(
                SimpleNamespace(
                    locator=bad_locator
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "all-bad.xml"
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.windows_event_bridge."
                "load_sysmon_windows_event_xml",
                return_value=batch,
            ):
                result = (
                    load_sysmon_xml_artifact(
                        path,
                        logical_source=logical,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )
                )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.MALFORMED_QUARANTINED,
        )

        self.assertEqual(
            result.accounted_record_count,
            1,
        )

    def test_zero_record_batch_is_failed_explicit(
        self,
    ) -> None:
        raw = b""

        logical = (
            "raw/empty.xml"
        )

        batch = SimpleNamespace(
            source_type=(
                SourceType.POWERSHELL
            ),
            adapter_id=(
                "powershell-real-v1"
            ),
            accepted=(),
            quarantined=(),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "empty.xml"
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.windows_event_bridge."
                "load_powershell_windows_event_xml",
                return_value=batch,
            ):
                result = (
                    load_powershell_xml_artifact(
                        path,
                        logical_source=logical,
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
                "no_records",
            ),
        )

        self.assertEqual(
            result.accounted_record_count,
            0,
        )

    def test_exact_locator_hash_mismatch_fails_closed(
        self,
    ) -> None:
        raw = (
            b"<Event>PowerShell</Event>"
        )

        logical = (
            "raw/hash-mismatch.xml"
        )

        bad_locator = RawLocator(
            logical_source=logical,
            record_index=0,
            line_number=1,
            byte_offset=0,
            byte_length=len(
                raw
            ),
            raw_sha256=sha256(
                b"different"
            ),
            adapter_id=(
                "powershell-real-v1"
            ),
            input_schema_version="1",
        )

        event = canonical(
            source_type=(
                SourceType.POWERSHELL
            ),
            raw_locator=bad_locator,
            event_type=(
                "windows_event"
            ),
        )

        batch = SimpleNamespace(
            source_type=(
                SourceType.POWERSHELL
            ),
            adapter_id=(
                "powershell-real-v1"
            ),
            accepted=(
                event,
            ),
            quarantined=(),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "mismatch.xml"
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.windows_event_bridge."
                "load_powershell_windows_event_xml",
                return_value=batch,
            ):
                with self.assertRaises(
                    EvidenceBoundaryError
                ):
                    load_powershell_xml_artifact(
                        path,
                        logical_source=logical,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )

    def test_out_of_bounds_locator_fails_closed(
        self,
    ) -> None:
        raw = (
            b"<Event>X</Event>"
        )

        logical = (
            "raw/out-of-bounds.xml"
        )

        bad_locator = RawLocator(
            logical_source=logical,
            record_index=0,
            line_number=1,
            byte_offset=999,
            byte_length=1,
            raw_sha256=sha256(
                b"X"
            ),
            adapter_id=(
                "sysmon-real-v1"
            ),
            input_schema_version="1",
        )

        event = canonical(
            source_type=(
                SourceType.SYSMON
            ),
            raw_locator=bad_locator,
            event_type=(
                "process_creation"
            ),
        )

        batch = SimpleNamespace(
            source_type=(
                SourceType.SYSMON
            ),
            adapter_id=(
                "sysmon-real-v1"
            ),
            accepted=(
                event,
            ),
            quarantined=(),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "out.xml"
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.windows_event_bridge."
                "load_sysmon_windows_event_xml",
                return_value=batch,
            ):
                with self.assertRaises(
                    EvidenceBoundaryError
                ):
                    load_sysmon_xml_artifact(
                        path,
                        logical_source=logical,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )

    def test_source_type_mismatch_fails_closed(
        self,
    ) -> None:
        raw = (
            b"<Event>X</Event>"
        )

        logical = (
            "raw/source-mismatch.xml"
        )

        batch = SimpleNamespace(
            source_type=(
                SourceType.SYSMON
            ),
            adapter_id=(
                "wrong-v1"
            ),
            accepted=(),
            quarantined=(),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "mismatch.xml"
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.windows_event_bridge."
                "load_powershell_windows_event_xml",
                return_value=batch,
            ):
                with self.assertRaises(
                    EvidenceBoundaryError
                ):
                    load_powershell_xml_artifact(
                        path,
                        logical_source=logical,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )

    def test_evidence_mutation_during_loader_fails_closed(
        self,
    ) -> None:
        original = (
            b"<Event>original</Event>"
        )

        logical = (
            "raw/mutation.xml"
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "mutation.xml"
            )

            path.write_bytes(
                original
            )

            def mutating_loader(
                received_path: Path,
                *,
                logical_source: str,
            ) -> object:
                self.assertEqual(
                    logical_source,
                    logical,
                )

                received_path.write_bytes(
                    b"<Event>changed</Event>"
                )

                return SimpleNamespace(
                    source_type=(
                        SourceType.POWERSHELL
                    ),
                    adapter_id=(
                        "powershell-real-v1"
                    ),
                    accepted=(),
                    quarantined=(),
                )

            with patch(
                "tracesoc.evidence.windows_event_bridge."
                "load_powershell_windows_event_xml",
                side_effect=(
                    mutating_loader
                ),
            ):
                with self.assertRaises(
                    EvidenceMutationError
                ):
                    load_powershell_xml_artifact(
                        path,
                        logical_source=logical,
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )

    def test_unsafe_logical_source_is_rejected_before_loader(
        self,
    ) -> None:
        raw = (
            b"<Event>X</Event>"
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "unsafe.xml"
            )

            path.write_bytes(
                raw
            )

            with patch(
                "tracesoc.evidence.windows_event_bridge."
                "load_powershell_windows_event_xml"
            ) as mocked:
                with self.assertRaises(
                    ValueError
                ):
                    load_powershell_xml_artifact(
                        path,
                        logical_source=(
                            "../escape.xml"
                        ),
                        acquired_or_observed_utc=(
                            UTC_TIME
                        ),
                    )

        mocked.assert_not_called()

    def test_physical_path_must_exist(
        self,
    ) -> None:
        missing = (
            Path(
                tempfile.gettempdir()
            )
            / "tracesoc-v04-definitely-missing.xml"
        )

        if missing.exists():
            missing.unlink()

        with self.assertRaises(
            FileNotFoundError
        ):
            load_sysmon_xml_artifact(
                missing,
                logical_source=(
                    "raw/missing.xml"
                ),
                acquired_or_observed_utc=(
                    UTC_TIME
                ),
            )


if __name__ == "__main__":
    unittest.main()
