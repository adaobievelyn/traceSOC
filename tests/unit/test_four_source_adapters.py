from __future__ import annotations

import hashlib
import unittest
from datetime import timedelta
from pathlib import Path

from tracesoc.models import ClockState, SemanticEvent, SourceType
from tracesoc.parsers.powershell import load_powershell_jsonl
from tracesoc.parsers.sysmon import load_sysmon_jsonl
from tracesoc.parsers.windows_security import load_windows_security_jsonl
from tracesoc.parsers.zeek import load_zeek_jsonl


REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "tiny"


def load_all():
    return (
        load_sysmon_jsonl(
            FIXTURES / "sysmon.jsonl",
            logical_source="tests/fixtures/tiny/sysmon.jsonl",
        ),
        load_windows_security_jsonl(
            FIXTURES / "windows-security.jsonl",
            logical_source="tests/fixtures/tiny/windows-security.jsonl",
        ),
        load_powershell_jsonl(
            FIXTURES / "powershell.jsonl",
            logical_source="tests/fixtures/tiny/powershell.jsonl",
        ),
        load_zeek_jsonl(
            FIXTURES / "zeek.jsonl",
            logical_source="tests/fixtures/tiny/zeek.jsonl",
        ),
    )


class FourSourceAdapterTests(unittest.TestCase):
    def test_sysmon_adapter_accounting(self) -> None:
        batch = load_all()[0]

        self.assertEqual(batch.source_type, SourceType.SYSMON)
        self.assertEqual(batch.total_records, 4)
        self.assertEqual(batch.accepted_count, 3)
        self.assertEqual(batch.quarantined_count, 1)
        self.assertEqual(
            batch.quarantined[0].reason_code,
            "missing_field",
        )

    def test_windows_security_adapter_accounting(self) -> None:
        batch = load_all()[1]

        self.assertEqual(
            batch.source_type,
            SourceType.WINDOWS_SECURITY,
        )
        self.assertEqual(batch.total_records, 4)
        self.assertEqual(batch.accepted_count, 3)
        self.assertEqual(batch.quarantined_count, 1)
        self.assertEqual(
            batch.quarantined[0].reason_code,
            "invalid_field",
        )

    def test_powershell_adapter_accounting(self) -> None:
        batch = load_all()[2]

        self.assertEqual(
            batch.source_type,
            SourceType.POWERSHELL,
        )
        self.assertEqual(batch.total_records, 4)
        self.assertEqual(batch.accepted_count, 3)
        self.assertEqual(batch.quarantined_count, 1)
        self.assertEqual(
            batch.quarantined[0].reason_code,
            "invalid_timestamp",
        )

    def test_zeek_adapter_accounting(self) -> None:
        batch = load_all()[3]

        self.assertEqual(batch.source_type, SourceType.ZEEK)
        self.assertEqual(batch.total_records, 4)
        self.assertEqual(batch.accepted_count, 3)
        self.assertEqual(batch.quarantined_count, 1)
        self.assertEqual(
            batch.quarantined[0].reason_code,
            "record_not_object",
        )

    def test_total_accounting_and_source_coverage(self) -> None:
        batches = load_all()

        self.assertEqual(
            {batch.source_type for batch in batches},
            {
                SourceType.SYSMON,
                SourceType.WINDOWS_SECURITY,
                SourceType.POWERSHELL,
                SourceType.ZEEK,
            },
        )

        self.assertEqual(
            sum(batch.total_records for batch in batches),
            16,
        )

        self.assertEqual(
            sum(batch.accepted_count for batch in batches),
            12,
        )

        self.assertEqual(
            sum(batch.quarantined_count for batch in batches),
            4,
        )

        ids = [
            event.event_id
            for batch in batches
            for event in batch.accepted
        ]

        self.assertEqual(len(ids), len(set(ids)))

    def test_raw_locator_hash_and_offsets_match_exact_fixture_bytes(self) -> None:
        fixture = FIXTURES / "sysmon.jsonl"

        full_lines = fixture.read_bytes().splitlines(
            keepends=True
        )

        batch = load_all()[0]

        first = batch.accepted[0].provenance
        second = batch.accepted[1].provenance

        first_record = full_lines[0].rstrip(b"\r\n")

        self.assertEqual(
            first.raw_sha256,
            hashlib.sha256(first_record).hexdigest(),
        )

        self.assertEqual(first.byte_offset, 0)

        self.assertEqual(
            second.byte_offset,
            len(full_lines[0]),
        )

        self.assertEqual(first.line_number, 1)
        self.assertEqual(second.line_number, 2)

    def test_fixture_metadata_stays_out_of_semantic_events(self) -> None:
        for batch in load_all():
            for canonical in batch.accepted:
                semantic = SemanticEvent.from_canonical(
                    canonical
                )

                self.assertNotIn(
                    "fixture_id",
                    semantic.fields,
                )

                self.assertNotIn(
                    "expected_answer",
                    semantic.fields,
                )

                self.assertFalse(
                    hasattr(semantic, "source_context"),
                )

                self.assertFalse(
                    hasattr(semantic, "provenance"),
                )

    def test_all_accepted_times_are_observed_utc(self) -> None:
        for batch in load_all():
            for event in batch.accepted:
                self.assertEqual(
                    event.clock_state,
                    ClockState.OBSERVED,
                )

                self.assertIsNotNone(
                    event.event_time_utc
                )

                self.assertEqual(
                    event.event_time_utc.utcoffset(),
                    timedelta(0),
                )

    def test_all_malformed_records_are_retained_as_quarantine(self) -> None:
        quarantined = [
            record
            for batch in load_all()
            for record in batch.quarantined
        ]

        self.assertEqual(len(quarantined), 4)

        for record in quarantined:
            self.assertGreaterEqual(
                record.locator.record_index,
                0,
            )

            self.assertGreaterEqual(
                record.locator.line_number,
                1,
            )

            self.assertEqual(
                len(record.locator.raw_sha256),
                64,
            )

    def test_adapter_rerun_is_deterministic(self) -> None:
        first = load_all()
        second = load_all()

        first_state = [
            (
                batch.source_type,
                [
                    (
                        event.event_id,
                        event.provenance.raw_sha256,
                    )
                    for event in batch.accepted
                ],
                [
                    (
                        item.reason_code,
                        item.locator.raw_sha256,
                    )
                    for item in batch.quarantined
                ],
            )
            for batch in first
        ]

        second_state = [
            (
                batch.source_type,
                [
                    (
                        event.event_id,
                        event.provenance.raw_sha256,
                    )
                    for event in batch.accepted
                ],
                [
                    (
                        item.reason_code,
                        item.locator.raw_sha256,
                    )
                    for item in batch.quarantined
                ],
            )
            for batch in second
        ]

        self.assertEqual(first_state, second_state)


if __name__ == "__main__":
    unittest.main()