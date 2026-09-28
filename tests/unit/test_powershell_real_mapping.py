from __future__ import annotations

from datetime import timezone
import tempfile
import unittest
from pathlib import Path

from tracesoc.models import (
    ClockState,
    SemanticEvent,
)
from tracesoc.parsers.powershell import (
    load_powershell_windows_event_xml,
)


def powershell_event(
    *,
    event_id: int = 4104,
    provider: str = "Microsoft-Windows-PowerShell",
    system_time: str = "2022-03-29T13:37:43.316129Z",
    event_record_id: int = 100,
    process_id: str = "2404",
    thread_id: str = "5688",
    user_id: str = "S-1-5-21-1-2-3-500",
    event_data: dict[str, str] | None = None,
) -> bytes:

    if event_data is None:
        event_data = {
            "MessageNumber":
                "1",
            "MessageTotal":
                "1",
            "ScriptBlockText":
                "Get-Date",
            "ScriptBlockId":
                "11111111-1111-1111-1111-111111111111",
            "Path":
                "",
        }

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
        f'<Provider Name="{provider}"/>'
        f'<EventID>{event_id}</EventID>'
        '<Version>1</Version>'
        '<Level>3</Level>'
        '<Task>2</Task>'
        '<Opcode>15</Opcode>'
        '<Keywords>0x0</Keywords>'
        f'<TimeCreated SystemTime="{system_time}"/>'
        f'<EventRecordID>{event_record_id}</EventRecordID>'
        '<Correlation ActivityID="{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"/>'
        f'<Execution ProcessID="{process_id}" ThreadID="{thread_id}"/>'
        '<Channel>Microsoft-Windows-PowerShell/Operational</Channel>'
        '<Computer>HOST-01</Computer>'
        f'<Security UserID="{user_id}"/>'
        '</System>'
        '<EventData>'
        f'{rendered_data}'
        '</EventData>'
        '</Event>'
    )

    return rendered.encode(
        "utf-8"
    )


class PowerShellRealMappingTests(
    unittest.TestCase
):
    def _map(
        self,
        raw: bytes,
    ):
        directory = tempfile.TemporaryDirectory()

        path = (
            Path(directory.name)
            / "powershell.xml"
        )

        path.write_bytes(
            raw
        )

        try:
            return load_powershell_windows_event_xml(
                path,
                logical_source="tests/powershell.xml",
            )
        finally:
            directory.cleanup()

    def test_real_mapping_is_generic_and_observed_utc(
        self,
    ) -> None:
        batch = self._map(
            powershell_event()
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
            "powershell_event",
        )

        self.assertIs(
            event.clock_state,
            ClockState.OBSERVED,
        )

        self.assertEqual(
            event.event_time_raw,
            "2022-03-29T13:37:43.316129Z",
        )

        self.assertEqual(
            event.event_time_utc.tzinfo,
            timezone.utc,
        )

    def test_4104_fragment_metadata_is_preserved_in_source_context(
        self,
    ) -> None:
        batch = self._map(
            powershell_event()
        )

        event = batch.accepted[0]

        context = event.source_context

        self.assertEqual(
            context["event_code"],
            4104,
        )

        self.assertEqual(
            context["execution_process_id"],
            "2404",
        )

        self.assertEqual(
            context["execution_thread_id"],
            "5688",
        )

        self.assertEqual(
            context["security_user_id"],
            "S-1-5-21-1-2-3-500",
        )

        event_data = context[
            "event_data"
        ]

        self.assertEqual(
            event_data["MessageNumber"],
            "1",
        )

        self.assertEqual(
            event_data["MessageTotal"],
            "1",
        )

        self.assertEqual(
            event_data["ScriptBlockText"],
            "Get-Date",
        )

        self.assertEqual(
            event_data["ScriptBlockId"],
            "11111111-1111-1111-1111-111111111111",
        )

        self.assertEqual(
            event_data["Path"],
            "",
        )

    def test_generic_mapping_does_not_call_4104_script_execution(
        self,
    ) -> None:
        batch = self._map(
            powershell_event(
                event_id=4104,
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "powershell_event",
        )

        self.assertIsNone(
            event.principal,
        )

        self.assertEqual(
            dict(event.semantic_fields),
            {},
        )

    def test_explicit_utc_z_is_required(
        self,
    ) -> None:
        batch = self._map(
            powershell_event(
                system_time=(
                    "2022-03-29T13:37:43.316129"
                ),
            )
        )

        self.assertEqual(
            batch.accepted_count,
            0,
        )

        self.assertEqual(
            batch.quarantined_count,
            1,
        )

    def test_wrong_provider_is_quarantined(
        self,
    ) -> None:
        batch = self._map(
            powershell_event(
                provider="Another-Provider",
            )
        )

        self.assertEqual(
            batch.accepted_count,
            0,
        )

        self.assertEqual(
            batch.quarantined_count,
            1,
        )

    def test_mapping_is_deterministic_and_semantically_separated(
        self,
    ) -> None:
        raw = powershell_event()

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
            "powershell_event",
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


if __name__ == "__main__":
    unittest.main()
