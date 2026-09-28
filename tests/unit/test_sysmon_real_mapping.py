from __future__ import annotations

from datetime import timezone
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
    event_id: int = 25,
    provider: str = "Microsoft-Windows-Sysmon",
    computer: str = "HOST-01",
    channel: str = "Microsoft-Windows-Sysmon/Operational",
    event_record_id: int = 123,
    system_time: str = "2021-03-31T12:01:01.431749000Z",
    utc_time: str | None = "2021-03-31 12:00:39.018",
) -> bytes:

    if utc_time is None:
        event_data = (
            '<Data Name="RuleName">-</Data>'
        )
    else:
        event_data = (
            '<Data Name="UtcTime">'
            + utc_time
            + '</Data>'
            '<Data Name="RuleName">-</Data>'
        )

    rendered = (
        '<Event '
        'xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System>'
        f'<Provider Name="{provider}"/>'
        f'<EventID>{event_id}</EventID>'
        '<Version>3</Version>'
        '<Level>4</Level>'
        '<Task>10</Task>'
        '<Opcode>0</Opcode>'
        '<Keywords>0x8000000000000000</Keywords>'
        f'<TimeCreated SystemTime="{system_time}"/>'
        f'<EventRecordID>{event_record_id}</EventRecordID>'
        f'<Channel>{channel}</Channel>'
        f'<Computer>{computer}</Computer>'
        '</System>'
        '<EventData>'
        f'{event_data}'
        '</EventData>'
        '</Event>'
    )

    return rendered.encode(
        "utf-8"
    )


class SysmonRealMappingTests(
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
                logical_source=(
                    "tests/windows-sysmon.log"
                ),
            )
        finally:
            directory.cleanup()

    def test_real_mapping_uses_source_utc_time_as_observed_clock(
        self,
    ) -> None:
        batch = self._map(
            sysmon_event()
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
            "sysmon_event",
        )

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
            event.event_time_utc.tzinfo,
            timezone.utc,
        )

        self.assertEqual(
            event.event_time_utc.isoformat(),
            "2021-03-31T12:00:39.018000+00:00",
        )

    def test_event_log_system_time_is_retained_separately(
        self,
    ) -> None:
        batch = self._map(
            sysmon_event(
                event_id=23,
                system_time=(
                    "2021-03-31T12:00:40.000000000Z"
                ),
                utc_time=(
                    "2021-03-31 12:00:39.500"
                ),
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.source_context[
                "event_log_system_time"
            ],
            "2021-03-31T12:00:40.000000000Z",
        )

        self.assertEqual(
            event.source_context[
                "event_code"
            ],
            23,
        )

        self.assertEqual(
            event.source_context[
                "event_record_id"
            ],
            123,
        )

    def test_event_id_1_promotes_while_other_event_ids_remain_generic(
        self,
    ) -> None:
        raw = (
            sysmon_event(
                event_id=1,
                event_record_id=1,
            )
            +
            sysmon_event(
                event_id=25,
                event_record_id=2,
                utc_time="2021-03-31 12:00:40.000",
                system_time=(
                    "2021-03-31T12:00:40.010000000Z"
                ),
            )
        )

        batch = self._map(
            raw
        )

        self.assertEqual(
            batch.accepted_count,
            2,
        )

        self.assertEqual(
            batch.quarantined_count,
            0,
        )

        process_event = batch.accepted[0]
        generic_event = batch.accepted[1]

        # Event ID 1 is itself the source-defined Sysmon process
        # creation family. Promotion does not depend on fixture data
        # or on optional process attributes being present.
        self.assertEqual(
            process_event.source_context["event_code"],
            1,
        )

        self.assertEqual(
            process_event.event_type,
            "process_create",
        )

        self.assertIsNone(
            process_event.principal,
        )

        self.assertEqual(
            dict(process_event.semantic_fields),
            {},
        )

        # A different Sysmon EventID remains at the bounded generic
        # layer until separately evidence-adjudicated.
        self.assertEqual(
            generic_event.source_context["event_code"],
            25,
        )

        self.assertEqual(
            generic_event.event_type,
            "sysmon_event",
        )

        self.assertIsNone(
            generic_event.principal,
        )

        self.assertEqual(
            dict(generic_event.semantic_fields),
            {},
        )

    def test_missing_eventdata_utctime_is_quarantined(
        self,
    ) -> None:
        batch = self._map(
            sysmon_event(
                utc_time=None,
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
            sysmon_event(
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
        raw = sysmon_event(
            event_id=3,
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

        event = first.accepted[0]

        semantic = SemanticEvent.from_canonical(
            event
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

        self.assertEqual(
            dict(semantic.fields),
            {},
        )


if __name__ == "__main__":
    unittest.main()
