from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tracesoc.models import (
    ClockState,
    SemanticEvent,
)
from tracesoc.parsers.windows_security import (
    load_windows_security_splunk,
)


def security_record(
    *,
    event_code: int,
    body: bytes,
    source_name: bytes = b"Any-Security-Provider",
) -> bytes:
    return (
        b"03/31/2021 10:48:23 AM\n"
        b"LogName=Security\n"
        + b"SourceName=" + source_name + b"\n"
        + b"EventCode="
        + str(event_code).encode("ascii")
        + b"\n"
        b"EventType=0\n"
        b"Type=Information\n"
        b"ComputerName=HOST-01\n"
        b"TaskCategory=Process Creation\n"
        b"OpCode=Info\n"
        b"RecordNumber=100\n"
        b"Keywords=Audit Success\n"
        b"Message=A source message.\n"
        + body
    )


def process_body(
    *,
    security_id: str = r"DOMAIN\User",
    new_pid: str = "0x123",
    process_name: str = r"C:\Windows\System32\example.exe",
    parent_pid: str = "0x100",
    parent_process: str = r"C:\Windows\System32\parent.exe",
    command_line: str = "",
) -> bytes:
    rendered = (
        "Creator Subject:\n"
        f"    Security ID:            {security_id}\n"
        "    Account Name:           -\n"
        "    Account Domain:         -\n"
        "    Logon ID:               0x3E7\n"
        "\n"
        "Target Subject:\n"
        "    Security ID:            NULL SID\n"
        "    Account Name:           -\n"
        "    Account Domain:         -\n"
        "    Logon ID:               0x0\n"
        "\n"
        "Process Information:\n"
        f"    New Process ID:         {new_pid}\n"
        f"    New Process Name:       {process_name}\n"
        "    Token Elevation Type:   %%1936\n"
        "    Mandatory Label:        Mandatory Label\\System Mandatory Level\n"
        f"    Creator Process ID:     {parent_pid}\n"
        f"    Creator Process Name:   {parent_process}\n"
        f"    Process Command Line:   {command_line}\n"
    )

    return rendered.encode(
        "utf-8"
    )


class WindowsSecurity4688PromotionTests(
    unittest.TestCase
):
    def _map(
        self,
        raw: bytes,
    ):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "windows-security.log"
        path.write_bytes(raw)

        try:
            return load_windows_security_splunk(
                path,
                logical_source=(
                    "tests/windows-security.log"
                ),
            )
        finally:
            directory.cleanup()

    def test_4688_promotes_to_established_process_create_vocabulary(
        self,
    ) -> None:
        batch = self._map(
            security_record(
                event_code=4688,
                body=process_body(),
            )
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
            "process_create",
        )
        self.assertEqual(
            event.principal,
            r"DOMAIN\User",
        )
        self.assertEqual(
            event.semantic_fields["process_name"],
            r"C:\Windows\System32\example.exe",
        )
        self.assertEqual(
            event.semantic_fields["process_id"],
            "0x123",
        )
        self.assertEqual(
            event.semantic_fields["parent_process_id"],
            "0x100",
        )
        self.assertEqual(
            event.semantic_fields["parent_process"],
            r"C:\Windows\System32\parent.exe",
        )

    def test_4688_omits_empty_command_line_and_parent_process(
        self,
    ) -> None:
        batch = self._map(
            security_record(
                event_code=4688,
                body=process_body(
                    parent_process="",
                    command_line="",
                ),
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "process_create",
        )
        self.assertNotIn(
            "parent_process",
            event.semantic_fields,
        )
        self.assertNotIn(
            "command_line",
            event.semantic_fields,
        )

    def test_4688_preserves_nonempty_command_line_when_source_supplies_it(
        self,
    ) -> None:
        batch = self._map(
            security_record(
                event_code=4688,
                body=process_body(
                    command_line=(
                        r"C:\Windows\System32\example.exe /test"
                    ),
                ),
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.semantic_fields["command_line"],
            r"C:\Windows\System32\example.exe /test",
        )

    def test_incomplete_4688_remains_generic_instead_of_fabricating_semantics(
        self,
    ) -> None:
        body = (
            b"Process Information:\n"
            b"    New Process ID:         0x123\n"
        )

        batch = self._map(
            security_record(
                event_code=4688,
                body=body,
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "windows_security_event",
        )
        self.assertIsNone(
            event.principal,
        )
        self.assertEqual(
            dict(event.semantic_fields),
            {},
        )

    def test_non_4688_remains_generic_even_with_process_like_body(
        self,
    ) -> None:
        batch = self._map(
            security_record(
                event_code=4624,
                body=process_body(),
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "windows_security_event",
        )
        self.assertIsNone(
            event.principal,
        )
        self.assertEqual(
            dict(event.semantic_fields),
            {},
        )

    def test_promotion_preserves_unresolved_clock_and_semantic_separation(
        self,
    ) -> None:
        batch = self._map(
            security_record(
                event_code=4688,
                body=process_body(),
            )
        )

        event = batch.accepted[0]

        self.assertIs(
            event.clock_state,
            ClockState.UNRESOLVED,
        )
        self.assertIsNone(
            event.event_time_utc,
        )

        semantic = SemanticEvent.from_canonical(
            event
        )

        self.assertEqual(
            semantic.event_type,
            "process_create",
        )
        self.assertEqual(
            semantic.principal,
            r"DOMAIN\User",
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


if __name__ == "__main__":
    unittest.main()
