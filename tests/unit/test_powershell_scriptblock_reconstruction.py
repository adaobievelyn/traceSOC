from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from xml.sax.saxutils import escape

from tracesoc.normalization.powershell_scriptblock import (
    ScriptBlockReconstructionError,
    ScriptBlockState,
    reconstruct_powershell_scriptblocks,
)
from tracesoc.parsers.powershell import (
    load_powershell_windows_event_xml,
)


def xml_event(
    *,
    event_record_id: int,
    message_number: int,
    message_total: int,
    script_text: str,
    script_block_id: str = "block-1",
    process_id: str = "100",
    thread_id: str = "200",
    user_id: str = "S-1-5-21-test",
    host: str = "HOST-01",
    path: str = "",
    event_code: int = 4104,
    microsecond: int = 1,
) -> bytes:
    values = {
        "MessageNumber":
            str(message_number),

        "MessageTotal":
            str(message_total),

        "ScriptBlockText":
            script_text,

        "ScriptBlockId":
            script_block_id,

        "Path":
            path,
    }

    rendered_data = "".join(
        (
            f'<Data Name="{escape(name)}">'
            f'{escape(value)}'
            f'</Data>'
        )
        for name, value in values.items()
    )

    rendered = (
        '<Event '
        'xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System>'
        '<Provider Name="Microsoft-Windows-PowerShell"/>'
        f'<EventID>{event_code}</EventID>'
        '<Version>1</Version>'
        '<Level>3</Level>'
        '<Task>2</Task>'
        '<Opcode>15</Opcode>'
        '<Keywords>0x0</Keywords>'
        f'<TimeCreated SystemTime="2026-01-01T00:00:00.{microsecond:06d}Z"/>'
        f'<EventRecordID>{event_record_id}</EventRecordID>'
        '<Correlation ActivityID="{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"/>'
        f'<Execution ProcessID="{escape(process_id)}" '
        f'ThreadID="{escape(thread_id)}"/>'
        '<Channel>Microsoft-Windows-PowerShell/Operational</Channel>'
        f'<Computer>{escape(host)}</Computer>'
        f'<Security UserID="{escape(user_id)}"/>'
        '</System>'
        '<EventData>'
        f'{rendered_data}'
        '</EventData>'
        '</Event>'
    )

    return rendered.encode(
        "utf-8"
    )


def canonical_events(
    *records: bytes,
):
    with tempfile.TemporaryDirectory() as directory:
        path = (
            Path(directory)
            / "powershell.xml"
        )

        path.write_bytes(
            b"".join(records)
        )

        batch = load_powershell_windows_event_xml(
            path,
            logical_source="tests/powershell.xml",
        )

        if batch.quarantined_count:
            raise AssertionError(
                (
                    "test fixture unexpectedly quarantined "
                    f"{batch.quarantined_count} records"
                )
            )

        return batch.accepted


class PowerShellScriptBlockReconstructionTests(
    unittest.TestCase
):
    def test_complete_group_reassembles_in_message_number_order(
        self,
    ) -> None:
        events = canonical_events(
            xml_event(
                event_record_id=2,
                message_number=2,
                message_total=3,
                script_text="B",
                microsecond=2,
            ),
            xml_event(
                event_record_id=1,
                message_number=1,
                message_total=3,
                script_text="A",
                microsecond=1,
            ),
            xml_event(
                event_record_id=3,
                message_number=3,
                message_total=3,
                script_text="C",
                microsecond=3,
            ),
        )

        group = (
            reconstruct_powershell_scriptblocks(
                events
            )[0]
        )

        self.assertIs(
            group.state,
            ScriptBlockState.COMPLETE,
        )

        self.assertEqual(
            group.observed_message_numbers,
            (1, 2, 3),
        )

        self.assertEqual(
            group.missing_message_numbers,
            (),
        )

        self.assertEqual(
            group.script_text,
            "ABC",
        )

        self.assertEqual(
            group.script_text_sha256,
            hashlib.sha256(
                b"ABC"
            ).hexdigest(),
        )

    def test_incomplete_group_does_not_assert_complete_script_text(
        self,
    ) -> None:
        events = canonical_events(
            xml_event(
                event_record_id=1,
                message_number=1,
                message_total=4,
                script_text="A",
            ),
            xml_event(
                event_record_id=3,
                message_number=3,
                message_total=4,
                script_text="C",
                microsecond=3,
            ),
        )

        group = (
            reconstruct_powershell_scriptblocks(
                events
            )[0]
        )

        self.assertIs(
            group.state,
            ScriptBlockState.INCOMPLETE,
        )

        self.assertEqual(
            group.observed_message_numbers,
            (1, 3),
        )

        self.assertEqual(
            group.missing_message_numbers,
            (2, 4),
        )

        self.assertIsNone(
            group.script_text,
        )

        self.assertIsNone(
            group.script_text_sha256,
        )

        self.assertEqual(
            tuple(
                fragment.script_text
                for fragment in group.fragments
            ),
            ("A", "C"),
        )

    def test_identical_duplicate_preserves_lineage_without_duplicate_text(
        self,
    ) -> None:
        events = canonical_events(
            xml_event(
                event_record_id=1,
                message_number=1,
                message_total=1,
                script_text="Get-Date",
                microsecond=1,
            ),
            xml_event(
                event_record_id=2,
                message_number=1,
                message_total=1,
                script_text="Get-Date",
                microsecond=2,
            ),
        )

        group = (
            reconstruct_powershell_scriptblocks(
                events
            )[0]
        )

        self.assertIs(
            group.state,
            ScriptBlockState.COMPLETE,
        )

        self.assertEqual(
            group.script_text,
            "Get-Date",
        )

        self.assertEqual(
            len(group.parent_event_ids),
            2,
        )

        self.assertEqual(
            len(group.fragments),
            2,
        )

    def test_conflicting_duplicate_is_rejected(
        self,
    ) -> None:
        events = canonical_events(
            xml_event(
                event_record_id=1,
                message_number=1,
                message_total=1,
                script_text="A",
            ),
            xml_event(
                event_record_id=2,
                message_number=1,
                message_total=1,
                script_text="B",
                microsecond=2,
            ),
        )

        with self.assertRaises(
            ScriptBlockReconstructionError
        ):
            reconstruct_powershell_scriptblocks(
                events
            )

    def test_inconsistent_message_total_is_rejected(
        self,
    ) -> None:
        events = canonical_events(
            xml_event(
                event_record_id=1,
                message_number=1,
                message_total=2,
                script_text="A",
            ),
            xml_event(
                event_record_id=2,
                message_number=2,
                message_total=3,
                script_text="B",
                microsecond=2,
            ),
        )

        with self.assertRaises(
            ScriptBlockReconstructionError
        ):
            reconstruct_powershell_scriptblocks(
                events
            )

    def test_inconsistent_process_identity_is_rejected(
        self,
    ) -> None:
        events = canonical_events(
            xml_event(
                event_record_id=1,
                message_number=1,
                message_total=2,
                script_text="A",
                process_id="100",
            ),
            xml_event(
                event_record_id=2,
                message_number=2,
                message_total=2,
                script_text="B",
                process_id="999",
                microsecond=2,
            ),
        )

        with self.assertRaises(
            ScriptBlockReconstructionError
        ):
            reconstruct_powershell_scriptblocks(
                events
            )

    def test_non_4104_event_is_ignored(
        self,
    ) -> None:
        events = canonical_events(
            xml_event(
                event_record_id=1,
                message_number=1,
                message_total=1,
                script_text="ignored",
                event_code=4103,
            ),
        )

        self.assertEqual(
            reconstruct_powershell_scriptblocks(
                events
            ),
            (),
        )

    def test_reconstruction_is_input_order_deterministic(
        self,
    ) -> None:
        events = canonical_events(
            xml_event(
                event_record_id=2,
                message_number=2,
                message_total=2,
                script_text="B",
                microsecond=2,
            ),
            xml_event(
                event_record_id=1,
                message_number=1,
                message_total=2,
                script_text="A",
                microsecond=1,
            ),
        )

        first = (
            reconstruct_powershell_scriptblocks(
                events
            )
        )

        second = (
            reconstruct_powershell_scriptblocks(
                reversed(events)
            )
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertTrue(
            first[0].reconstruction_id.startswith(
                "psb_"
            )
        )


if __name__ == "__main__":
    unittest.main()