from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from tracesoc.models import SourceType
from tracesoc.parsers.real_records import (
    read_windows_event_xml_records,
    read_windows_security_splunk_records,
    read_zeek_ascii_records,
)


class RealFormatRawReaderTests(unittest.TestCase):
    def _temporary_file(
        self,
        data: bytes,
    ):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "input.log"
        path.write_bytes(data)
        return directory, path

    def test_xml_stream_preserves_exact_event_bytes_offsets_and_hashes(
        self,
    ) -> None:
        first = (
            b'<Event xmlns="urn:test">'
            b"<System><EventID>1</EventID></System>"
            b"</Event>"
        )

        second = (
            b'<Event xmlns="urn:test">'
            b"<System><EventID>2</EventID></System>"
            b"</Event>"
        )

        raw = (
            b"\xef\xbb\xbf\r\n"
            + first
            + b"\r\n"
            + second
            + b"\r\n"
        )

        directory, path = self._temporary_file(raw)

        try:
            batch = read_windows_event_xml_records(
                path,
                logical_source="tests/real/xml-stream.log",
                source_type=SourceType.SYSMON,
                adapter_id="test-windows-event-xml-v1",
                input_schema_version="1",
            )
        finally:
            directory.cleanup()

        self.assertEqual(batch.total_records, 2)
        self.assertEqual(batch.accepted_count, 2)
        self.assertEqual(batch.quarantined_count, 0)

        first_record = batch.accepted[0]
        second_record = batch.accepted[1]

        self.assertEqual(
            first_record.raw_bytes,
            first,
        )

        self.assertEqual(
            second_record.raw_bytes,
            second,
        )

        self.assertEqual(
            first_record.locator.byte_offset,
            raw.index(first),
        )

        self.assertEqual(
            second_record.locator.byte_offset,
            raw.index(second),
        )

        self.assertEqual(
            first_record.locator.byte_length,
            len(first),
        )

        self.assertEqual(
            first_record.locator.raw_sha256,
            hashlib.sha256(first).hexdigest(),
        )

        self.assertEqual(
            second_record.locator.raw_sha256,
            hashlib.sha256(second).hexdigest(),
        )

        self.assertEqual(
            first_record.locator.line_number,
            2,
        )

        self.assertEqual(
            second_record.locator.line_number,
            3,
        )

    def test_xml_stream_retains_unterminated_event_as_quarantine(
        self,
    ) -> None:
        raw = (
            b'<Event xmlns="urn:test">'
            b"<System><EventID>1</EventID></System>"
        )

        directory, path = self._temporary_file(raw)

        try:
            batch = read_windows_event_xml_records(
                path,
                logical_source="tests/real/broken-xml.log",
                source_type=SourceType.POWERSHELL,
                adapter_id="test-windows-event-xml-v1",
                input_schema_version="1",
            )
        finally:
            directory.cleanup()

        self.assertEqual(batch.accepted_count, 0)
        self.assertEqual(batch.quarantined_count, 1)
        self.assertEqual(
            batch.quarantined[0].reason_code,
            "xml_event_unterminated",
        )

        self.assertEqual(
            batch.quarantined[0].locator.raw_sha256,
            hashlib.sha256(raw).hexdigest(),
        )

    def test_zeek_reader_uses_declared_schema_and_preserves_exact_row(
        self,
    ) -> None:
        header = (
            b"#separator \\x09\n"
            b"#set_separator\t,\n"
            b"#empty_field\t(empty)\n"
            b"#unset_field\t-\n"
            b"#path\tconn\n"
            b"#fields\tts\tuid\tid.orig_h\tlabel\tdet_label\n"
            b"#types\ttime\tstring\taddr\tstring\tstring\n"
        )

        row = (
            b"1532103831.0\tC123\t192.0.2.10"
            b"\tMalicious\tPartOfAHorizontalPortScan"
        )

        raw = header + row + b"\n"

        directory, path = self._temporary_file(raw)

        try:
            batch = read_zeek_ascii_records(
                path,
                logical_source="tests/real/conn.log",
                adapter_id="test-zeek-ascii-v1",
                input_schema_version="1",
            )
        finally:
            directory.cleanup()

        self.assertEqual(batch.accepted_count, 1)
        self.assertEqual(batch.quarantined_count, 0)

        record = batch.accepted[0]

        self.assertEqual(
            record.raw_bytes,
            row,
        )

        self.assertEqual(
            record.locator.byte_offset,
            len(header),
        )

        self.assertEqual(
            record.locator.raw_sha256,
            hashlib.sha256(row).hexdigest(),
        )

        self.assertEqual(
            record.field_map["uid"],
            "C123",
        )

        # Raw schema values may be retained for later evaluation.
        # This reader makes no detection decision from them.
        self.assertEqual(
            record.field_map["label"],
            "Malicious",
        )

        self.assertEqual(
            record.field_map["det_label"],
            "PartOfAHorizontalPortScan",
        )

    def test_zeek_field_count_mismatch_is_quarantined(
        self,
    ) -> None:
        raw = (
            b"#separator \\x09\n"
            b"#fields\tts\tuid\tid.orig_h\n"
            b"#types\ttime\tstring\taddr\n"
            b"1532103831.0\tC123\n"
        )

        directory, path = self._temporary_file(raw)

        try:
            batch = read_zeek_ascii_records(
                path,
                logical_source="tests/real/broken-conn.log",
                adapter_id="test-zeek-ascii-v1",
                input_schema_version="1",
            )
        finally:
            directory.cleanup()

        self.assertEqual(batch.accepted_count, 0)
        self.assertEqual(batch.quarantined_count, 1)

        self.assertEqual(
            batch.quarantined[0].reason_code,
            "zeek_field_count_mismatch",
        )

    def test_windows_security_splunk_preserves_exact_records_offsets_hashes_and_mixed_line_endings(
        self,
    ) -> None:
        first = (
            b"03/31/2021 10:48:23 AM\r\n"
            b"LogName=Security\r\n"
            b"SourceName=Microsoft Windows security auditing.\r\n"
            b"EventCode=4688\r\n"
            b"Message=first\r\n"
        )

        second = (
            b"03/31/2021 10:49:39 AM\n"
            b"LogName=Security\n"
            b"SourceName=Microsoft-Windows-Eventlog\n"
            b"EventCode=1100\n"
            b"Message=second\n"
        )

        raw = first + second

        directory, path = self._temporary_file(
            raw
        )

        try:
            batch = read_windows_security_splunk_records(
                path,
                logical_source=(
                    "tests/real/windows-security.log"
                ),
                adapter_id=(
                    "test-windows-security-splunk-v1"
                ),
                input_schema_version="1",
            )
        finally:
            directory.cleanup()

        self.assertEqual(
            batch.source_type,
            SourceType.WINDOWS_SECURITY,
        )

        self.assertEqual(
            batch.accepted_count,
            2,
        )

        self.assertEqual(
            batch.quarantined_count,
            0,
        )

        first_record = batch.accepted[0]
        second_record = batch.accepted[1]

        self.assertEqual(
            first_record.raw_bytes,
            first,
        )

        self.assertEqual(
            second_record.raw_bytes,
            second,
        )

        self.assertEqual(
            first_record.locator.byte_offset,
            0,
        )

        self.assertEqual(
            second_record.locator.byte_offset,
            len(first),
        )

        self.assertEqual(
            first_record.locator.byte_length,
            len(first),
        )

        self.assertEqual(
            second_record.locator.byte_length,
            len(second),
        )

        self.assertEqual(
            first_record.locator.raw_sha256,
            hashlib.sha256(first).hexdigest(),
        )

        self.assertEqual(
            second_record.locator.raw_sha256,
            hashlib.sha256(second).hexdigest(),
        )

        self.assertEqual(
            first_record.locator.line_number,
            1,
        )

        self.assertEqual(
            second_record.locator.line_number,
            6,
        )

    def test_windows_security_splunk_does_not_hardcode_source_name(
        self,
    ) -> None:
        raw = (
            b"04/01/2021 01:02:03 PM\n"
            b"LogName=Security\n"
            b"SourceName=Future-Security-Provider\n"
            b"EventCode=9999\n"
            b"Message=test\n"
        )

        directory, path = self._temporary_file(
            raw
        )

        try:
            batch = read_windows_security_splunk_records(
                path,
                logical_source=(
                    "tests/real/provider-variant.log"
                ),
                adapter_id=(
                    "test-windows-security-splunk-v1"
                ),
                input_schema_version="1",
            )
        finally:
            directory.cleanup()

        self.assertEqual(
            batch.accepted_count,
            1,
        )

        self.assertEqual(
            batch.quarantined_count,
            0,
        )

        self.assertEqual(
            batch.accepted[0].raw_bytes,
            raw,
        )

    def test_windows_security_splunk_ignores_timestamp_text_without_security_header(
        self,
    ) -> None:
        first = (
            b"03/31/2021 10:00:00 AM\n"
            b"LogName=Security\n"
            b"SourceName=Provider-A\n"
            b"EventCode=1\n"
            b"Message=first\n"
            b"03/31/2021 10:00:01 AM\n"
            b"This is message text, not a header.\n"
        )

        second = (
            b"03/31/2021 10:00:02 AM\n"
            b"LogName=Security\n"
            b"SourceName=Provider-B\n"
            b"EventCode=2\n"
            b"Message=second\n"
        )

        raw = first + second

        directory, path = self._temporary_file(
            raw
        )

        try:
            batch = read_windows_security_splunk_records(
                path,
                logical_source=(
                    "tests/real/timestamp-message.log"
                ),
                adapter_id=(
                    "test-windows-security-splunk-v1"
                ),
                input_schema_version="1",
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
            batch.accepted[0].raw_bytes,
            first,
        )

        self.assertEqual(
            batch.accepted[1].raw_bytes,
            second,
        )

    def test_windows_security_splunk_quarantines_malformed_header_without_merging(
        self,
    ) -> None:
        malformed = (
            b"03/31/2021 10:00:00 AM\n"
            b"LogName=Security\n"
            b"SourceName=Provider-A\n"
            b"EventCode=not-numeric\n"
            b"Message=bad\n"
        )

        valid = (
            b"03/31/2021 10:00:01 AM\n"
            b"LogName=Security\n"
            b"SourceName=Provider-B\n"
            b"EventCode=2\n"
            b"Message=good\n"
        )

        directory, path = self._temporary_file(
            malformed + valid
        )

        try:
            batch = read_windows_security_splunk_records(
                path,
                logical_source=(
                    "tests/real/malformed-security.log"
                ),
                adapter_id=(
                    "test-windows-security-splunk-v1"
                ),
                input_schema_version="1",
            )
        finally:
            directory.cleanup()

        self.assertEqual(
            batch.accepted_count,
            1,
        )

        self.assertEqual(
            batch.quarantined_count,
            1,
        )

        self.assertEqual(
            batch.quarantined[0].reason_code,
            "windows_security_header_malformed",
        )

        self.assertEqual(
            batch.quarantined[0].locator.raw_sha256,
            hashlib.sha256(
                malformed
            ).hexdigest(),
        )

        self.assertEqual(
            batch.accepted[0].raw_bytes,
            valid,
        )

        self.assertEqual(
            batch.accepted[0].locator.record_index,
            1,
        )

    def test_windows_security_splunk_quarantines_truncated_header(
        self,
    ) -> None:
        raw = (
            b"03/31/2021 10:00:00 AM\n"
            b"LogName=Security\n"
        )

        directory, path = self._temporary_file(
            raw
        )

        try:
            batch = read_windows_security_splunk_records(
                path,
                logical_source=(
                    "tests/real/truncated-security.log"
                ),
                adapter_id=(
                    "test-windows-security-splunk-v1"
                ),
                input_schema_version="1",
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
            "windows_security_header_malformed",
        )

        self.assertEqual(
            batch.quarantined[0].locator.raw_sha256,
            hashlib.sha256(raw).hexdigest(),
        )

    def test_windows_security_splunk_reader_is_deterministic(
        self,
    ) -> None:
        raw = (
            b"03/31/2021 10:00:00 AM\n"
            b"LogName=Security\n"
            b"SourceName=Provider-A\n"
            b"EventCode=1\n"
            b"Message=first\n"
            b"03/31/2021 10:00:01 AM\r\n"
            b"LogName=Security\r\n"
            b"SourceName=Provider-B\r\n"
            b"EventCode=2\r\n"
            b"Message=second\r\n"
        )

        directory, path = self._temporary_file(
            raw
        )

        try:
            first = read_windows_security_splunk_records(
                path,
                logical_source=(
                    "tests/real/deterministic-security.log"
                ),
                adapter_id=(
                    "test-windows-security-splunk-v1"
                ),
                input_schema_version="1",
            )

            second = read_windows_security_splunk_records(
                path,
                logical_source=(
                    "tests/real/deterministic-security.log"
                ),
                adapter_id=(
                    "test-windows-security-splunk-v1"
                ),
                input_schema_version="1",
            )
        finally:
            directory.cleanup()

        def state(batch):
            return [
                (
                    record.locator.record_index,
                    record.locator.line_number,
                    record.locator.byte_offset,
                    record.locator.byte_length,
                    record.locator.raw_sha256,
                    record.raw_bytes,
                )
                for record in batch.accepted
            ]

        self.assertEqual(
            state(first),
            state(second),
        )


    def test_real_raw_readers_are_deterministic(
        self,
    ) -> None:
        raw = (
            b"#separator \\x09\n"
            b"#fields\tts\tuid\n"
            b"#types\ttime\tstring\n"
            b"1.0\tC1\n"
            b"2.0\tC2\n"
        )

        directory, path = self._temporary_file(raw)

        try:
            first = read_zeek_ascii_records(
                path,
                logical_source="tests/real/deterministic.log",
                adapter_id="test-zeek-ascii-v1",
                input_schema_version="1",
            )

            second = read_zeek_ascii_records(
                path,
                logical_source="tests/real/deterministic.log",
                adapter_id="test-zeek-ascii-v1",
                input_schema_version="1",
            )
        finally:
            directory.cleanup()

        first_state = [
            (
                record.locator.record_index,
                record.locator.line_number,
                record.locator.byte_offset,
                record.locator.byte_length,
                record.locator.raw_sha256,
                record.field_names,
                record.field_values,
            )
            for record in first.accepted
        ]

        second_state = [
            (
                record.locator.record_index,
                record.locator.line_number,
                record.locator.byte_offset,
                record.locator.byte_length,
                record.locator.raw_sha256,
                record.field_names,
                record.field_values,
            )
            for record in second.accepted
        ]

        self.assertEqual(
            first_state,
            second_state,
        )


if __name__ == "__main__":
    unittest.main()
