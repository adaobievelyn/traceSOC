from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tracesoc.models import (
    ClockState,
    SemanticEvent,
)
from tracesoc.parsers.sysmon import (
    load_sysmon_windows_event_xml,
)


def sysmon_event(
    *,
    event_id: int,
    event_record_id: int = 123,
    utc_time: str = "2021-03-31 12:00:39.018",
    system_time: str = "2021-03-31T12:00:39.021000000Z",
    fields: dict[str, str] | None = None,
) -> bytes:

    if fields is None:
        fields = {}

    event_data = {
        "UtcTime":
            utc_time,
        "RuleName":
            "-",
    }

    event_data.update(
        fields
    )

    rendered_data = "".join(
        (
            f'<Data Name="{name}">'
            f'{value}'
            f'</Data>'
        )
        for name, value in event_data.items()
    )

    rendered = (
        '<Event '
        'xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System>'
        '<Provider Name="Microsoft-Windows-Sysmon"/>'
        f'<EventID>{event_id}</EventID>'
        '<Version>5</Version>'
        '<Level>4</Level>'
        '<Task>1</Task>'
        '<Opcode>0</Opcode>'
        '<Keywords>0x8000000000000000</Keywords>'
        f'<TimeCreated SystemTime="{system_time}"/>'
        f'<EventRecordID>{event_record_id}</EventRecordID>'
        '<Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
        '<Computer>HOST-01</Computer>'
        '</System>'
        '<EventData>'
        f'{rendered_data}'
        '</EventData>'
        '</Event>'
    )

    return rendered.encode(
        "utf-8"
    )


def process_fields() -> dict[str, str]:
    return {
        "ProcessGuid":
            "{11111111-1111-1111-1111-111111111111}",

        "ProcessId":
            "1234",

        "Image":
            r"C:\Windows\System32\cmd.exe",

        "CommandLine":
            r'C:\Windows\System32\cmd.exe /c whoami',

        "User":
            r"DOMAIN\User",

        "ParentProcessGuid":
            "{22222222-2222-2222-2222-222222222222}",

        "ParentProcessId":
            "500",

        "ParentImage":
            r"C:\Windows\explorer.exe",

        "ParentCommandLine":
            r"C:\Windows\Explorer.EXE",
    }


class SysmonEvent1PromotionTests(
    unittest.TestCase
):
    def _map(
        self,
        raw: bytes,
    ):
        directory = tempfile.TemporaryDirectory()

        path = (
            Path(directory.name)
            / "windows-sysmon.log"
        )

        path.write_bytes(
            raw
        )

        try:
            return load_sysmon_windows_event_xml(
                path,
                logical_source="tests/windows-sysmon.log",
            )
        finally:
            directory.cleanup()

    def test_event_id_1_promotes_to_process_create(
        self,
    ) -> None:
        batch = self._map(
            sysmon_event(
                event_id=1,
                fields=process_fields(),
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
            r"C:\Windows\System32\cmd.exe",
        )

        self.assertEqual(
            event.semantic_fields["process_id"],
            "1234",
        )

        self.assertEqual(
            event.semantic_fields["process_guid"],
            "{11111111-1111-1111-1111-111111111111}",
        )

        self.assertEqual(
            event.semantic_fields["command_line"],
            r"C:\Windows\System32\cmd.exe /c whoami",
        )

        self.assertEqual(
            event.semantic_fields["parent_process"],
            r"C:\Windows\explorer.exe",
        )

        self.assertEqual(
            event.semantic_fields["parent_process_id"],
            "500",
        )

        self.assertEqual(
            event.semantic_fields["parent_process_guid"],
            "{22222222-2222-2222-2222-222222222222}",
        )

        self.assertEqual(
            event.semantic_fields["parent_command_line"],
            r"C:\Windows\Explorer.EXE",
        )

    def test_event_id_1_omits_only_missing_optional_source_fields(
        self,
    ) -> None:
        fields = process_fields()

        fields["ParentCommandLine"] = ""
        fields["CommandLine"] = ""

        batch = self._map(
            sysmon_event(
                event_id=1,
                fields=fields,
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "process_create",
        )

        self.assertNotIn(
            "command_line",
            event.semantic_fields,
        )

        self.assertNotIn(
            "parent_command_line",
            event.semantic_fields,
        )

        self.assertIn(
            "process_name",
            event.semantic_fields,
        )

    def test_event_id_1_without_user_does_not_fabricate_principal(
        self,
    ) -> None:
        fields = process_fields()

        fields["User"] = "-"

        batch = self._map(
            sysmon_event(
                event_id=1,
                fields=fields,
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "process_create",
        )

        self.assertIsNone(
            event.principal,
        )

    def test_non_event_id_1_remains_generic(
        self,
    ) -> None:
        batch = self._map(
            sysmon_event(
                event_id=25,
                fields=process_fields(),
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "sysmon_event",
        )

        self.assertIsNone(
            event.principal,
        )

        self.assertEqual(
            dict(event.semantic_fields),
            {},
        )

    def test_promotion_preserves_observed_clock_contract(
        self,
    ) -> None:
        batch = self._map(
            sysmon_event(
                event_id=1,
                fields=process_fields(),
            )
        )

        event = batch.accepted[0]

        self.assertIs(
            event.clock_state,
            ClockState.OBSERVED,
        )

        self.assertEqual(
            event.event_time_raw,
            "2021-03-31 12:00:39.018",
        )

        self.assertIsNotNone(
            event.event_time_utc,
        )

        self.assertEqual(
            event.source_context[
                "event_log_system_time"
            ],
            "2021-03-31T12:00:39.021000000Z",
        )

    def test_promotion_is_deterministic_and_semantically_separated(
        self,
    ) -> None:
        raw = sysmon_event(
            event_id=1,
            fields=process_fields(),
        )

        first = self._map(
            raw
        )

        second = self._map(
            raw
        )

        self.assertEqual(
            first.accepted[0],
            second.accepted[0],
        )

        semantic = SemanticEvent.from_canonical(
            first.accepted[0]
        )

        self.assertEqual(
            semantic.event_type,
            "process_create",
        )

        self.assertFalse(
            hasattr(
                semantic,
                "provenance",
            )
        )

        self.assertFalse(
            hasattr(
                semantic,
                "source_context",
            )
        )


if __name__ == "__main__":
    unittest.main()
