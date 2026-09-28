from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tracesoc.models import (
    ClockState,
    SemanticEvent,
    SourceType,
)
from tracesoc.parsers.windows_security import (
    REAL_ADAPTER_ID,
    REAL_EVENT_TYPE,
    load_windows_security_splunk,
)


class WindowsSecurityRealMappingTests(
    unittest.TestCase
):
    def _temporary_file(
        self,
        data: bytes,
    ):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "windows-security.log"
        path.write_bytes(data)
        return directory, path

    def _record(
        self,
        *,
        timestamp: bytes = b"03/31/2021 10:48:23 AM",
        provider: bytes = (
            b"Microsoft Windows security auditing."
        ),
        event_code: bytes = b"4688",
        event_type: bytes = b"0",
        computer: bytes = b"HOST-01",
        task: bytes = b"Process Creation",
        record_number: bytes = b"123",
        keywords: bytes = b"Audit Success",
        message: bytes = (
            b"A new process has been created."
        ),
        newline: bytes = b"\n",
    ) -> bytes:
        return newline.join(
            (
                timestamp,
                b"LogName=Security",
                b"SourceName=" + provider,
                b"EventCode=" + event_code,
                b"EventType=" + event_type,
                b"Type=Information",
                b"ComputerName=" + computer,
                b"TaskCategory=" + task,
                b"OpCode=Info",
                b"RecordNumber=" + record_number,
                b"Keywords=" + keywords,
                b"Message=" + message,
                b"",
            )
        )

    def test_real_mapping_preserves_unresolved_raw_time_and_provenance(
        self,
    ) -> None:
        raw = self._record()

        directory, path = self._temporary_file(
            raw
        )

        try:
            batch = load_windows_security_splunk(
                path,
                logical_source=(
                    "tests/real/windows-security.log"
                ),
            )
        finally:
            directory.cleanup()

        self.assertEqual(
            batch.adapter_id,
            REAL_ADAPTER_ID,
        )

        self.assertEqual(
            batch.source_type,
            SourceType.WINDOWS_SECURITY,
        )

        self.assertEqual(
            batch.accepted_count,
            1,
        )

        self.assertEqual(
            batch.quarantined_count,
            0,
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            REAL_EVENT_TYPE,
        )

        self.assertEqual(
            event.clock_state,
            ClockState.UNRESOLVED,
        )

        self.assertEqual(
            event.event_time_raw,
            "03/31/2021 10:48:23 AM",
        )

        self.assertIsNone(
            event.event_time_utc
        )

        self.assertEqual(
            event.host,
            "HOST-01",
        )

        self.assertIsNone(
            event.principal
        )

        self.assertEqual(
            event.provenance.byte_offset,
            0,
        )

        self.assertEqual(
            event.provenance.byte_length,
            len(raw),
        )

    def test_real_mapping_retains_source_metadata_outside_semantic_fields(
        self,
    ) -> None:
        raw = self._record(
            event_code=b"1100",
            provider=b"Microsoft-Windows-Eventlog",
            event_type=b"4",
            task=b"Service shutdown",
            record_number=b"999",
            message=(
                b"The event logging service has shut down."
            ),
        )

        directory, path = self._temporary_file(
            raw
        )

        try:
            batch = load_windows_security_splunk(
                path,
                logical_source=(
                    "tests/real/source-context.log"
                ),
            )
        finally:
            directory.cleanup()

        event = batch.accepted[0]

        self.assertEqual(
            event.source_context["event_code"],
            1100,
        )

        self.assertEqual(
            event.source_context["provider"],
            "Microsoft-Windows-Eventlog",
        )

        self.assertEqual(
            event.source_context["record_number"],
            999,
        )

        self.assertEqual(
            dict(event.semantic_fields),
            {},
        )

        semantic = SemanticEvent.from_canonical(
            event
        )

        self.assertEqual(
            dict(semantic.fields),
            {},
        )

        self.assertFalse(
            hasattr(
                semantic,
                "source_context",
            )
        )

        self.assertFalse(
            hasattr(
                semantic,
                "provenance",
            )
        )

    def test_real_mapping_accepts_provider_and_event_code_variants_generically(
        self,
    ) -> None:
        first = self._record(
            provider=b"Provider-A",
            event_code=b"1234",
            computer=b"HOST-A",
            record_number=b"1",
        )

        second = self._record(
            timestamp=b"03/31/2021 10:48:24 AM",
            provider=b"Provider-B",
            event_code=b"9876",
            computer=b"HOST-B",
            record_number=b"2",
            newline=b"\r\n",
        )

        directory, path = self._temporary_file(
            first + second
        )

        try:
            batch = load_windows_security_splunk(
                path,
                logical_source=(
                    "tests/real/generic-security.log"
                ),
            )
        finally:
            directory.cleanup()

        self.assertEqual(
            batch.accepted_count,
            2,
        )

        self.assertEqual(
            batch.quarantined_count,
            0,
        )

        self.assertEqual(
            {
                event.source_context[
                    "event_code"
                ]
                for event in batch.accepted
            },
            {
                1234,
                9876,
            },
        )

        self.assertEqual(
            {
                event.event_type
                for event in batch.accepted
            },
            {
                REAL_EVENT_TYPE,
            },
        )

    def test_real_mapping_quarantines_invalid_required_numeric_metadata(
        self,
    ) -> None:
        raw = self._record(
            record_number=b"not-a-number",
        )

        directory, path = self._temporary_file(
            raw
        )

        try:
            batch = load_windows_security_splunk(
                path,
                logical_source=(
                    "tests/real/invalid-number.log"
                ),
            )
        finally:
            directory.cleanup()

        self.assertEqual(
            batch.accepted_count,
            0,
        )

        self.assertEqual(
            batch.quarantined_count,
            1,
        )

        self.assertEqual(
            batch.quarantined[0].reason_code,
            "invalid_field",
        )

    def test_real_mapping_is_deterministic(
        self,
    ) -> None:
        raw = (
            self._record(
                computer=b"HOST-A",
                record_number=b"1",
            )
            +
            self._record(
                timestamp=b"03/31/2021 10:48:24 AM",
                computer=b"HOST-B",
                event_code=b"4624",
                task=b"Logon",
                record_number=b"2",
                message=(
                    b"An account was successfully logged on."
                ),
            )
        )

        directory, path = self._temporary_file(
            raw
        )

        try:
            first = load_windows_security_splunk(
                path,
                logical_source=(
                    "tests/real/deterministic-security.log"
                ),
            )

            second = load_windows_security_splunk(
                path,
                logical_source=(
                    "tests/real/deterministic-security.log"
                ),
            )
        finally:
            directory.cleanup()

        first_state = [
            (
                event.event_id,
                event.event_type,
                event.clock_state,
                event.event_time_raw,
                event.event_time_utc,
                event.host,
                event.provenance.raw_sha256,
                dict(event.source_context),
                dict(event.semantic_fields),
            )
            for event in first.accepted
        ]

        second_state = [
            (
                event.event_id,
                event.event_type,
                event.clock_state,
                event.event_time_raw,
                event.event_time_utc,
                event.host,
                event.provenance.raw_sha256,
                dict(event.source_context),
                dict(event.semantic_fields),
            )
            for event in second.accepted
        ]

        self.assertEqual(
            first_state,
            second_state,
        )


if __name__ == "__main__":
    unittest.main()
