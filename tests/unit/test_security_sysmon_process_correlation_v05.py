from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from tracesoc.correlation.security_sysmon_process import (
    CORRELATION_ID,
    correlate_windows_security_process_with_sysmon,
    normalize_windows_process_id,
)
from tracesoc.models import (
    ClockState,
    SemanticEvent,
    SourceType,
)


BASE_TIME = datetime(
    2026,
    9,
    24,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def security_event(
    *,
    host: str = "HOST-01",
    process_id: object = "0x4d2",
    process_name: str = r"C:\Windows\System32\cmd.exe",
    parent_process_id: object = "0x1f4",
    parent_process: str | None = r"C:\Windows\explorer.exe",
    event_time: datetime = BASE_TIME,
) -> SemanticEvent:
    fields: dict[str, object] = {
        "process_id": process_id,
        "process_name": process_name,
        "parent_process_id": parent_process_id,
    }

    if parent_process is not None:
        fields["parent_process"] = parent_process

    return SemanticEvent(
        event_id="security-4688-1",
        source_type=SourceType.WINDOWS_SECURITY,
        event_type="process_create",
        clock_state=ClockState.OBSERVED,
        event_time_utc=event_time,
        host=host,
        principal=None,
        fields=fields,
    )


def sysmon_event(
    *,
    host: str = "host-01",
    process_id: object = "1234",
    process_name: str = r"c:\windows\system32\CMD.EXE",
    parent_process_id: object = "500",
    parent_process: str | None = r"c:\windows\EXPLORER.EXE",
    event_time: datetime = BASE_TIME + timedelta(milliseconds=750),
) -> SemanticEvent:
    fields: dict[str, object] = {
        "process_id": process_id,
        "process_name": process_name,
        "parent_process_id": parent_process_id,
    }

    if parent_process is not None:
        fields["parent_process"] = parent_process

    return SemanticEvent(
        event_id="sysmon-event1-1",
        source_type=SourceType.SYSMON,
        event_type="process_create",
        clock_state=ClockState.OBSERVED,
        event_time_utc=event_time,
        host=host,
        principal=r"DOMAIN\User",
        fields=fields,
    )


class SecuritySysmonProcessCorrelationTests(
    unittest.TestCase
):
    def test_hex_security_pid_and_decimal_sysmon_pid_match(
        self,
    ) -> None:
        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=security_event(),
                sysmon_event=sysmon_event(),
            )
        )

        self.assertTrue(
            result.matched
        )
        self.assertEqual(
            result.correlation_id,
            CORRELATION_ID,
        )
        self.assertEqual(
            result.reason_code,
            "windows_process_creation_corroborated",
        )
        self.assertEqual(
            result.edge.process_id,
            "1234",
        )
        self.assertEqual(
            set(result.edge.matched_dimensions),
            {
                "host",
                "process_id",
                "process_name",
                "parent_process_id",
                "parent_process",
                "bounded_absolute_time_window",
            },
        )

    def test_pid_normalizer_handles_hex_and_decimal(
        self,
    ) -> None:
        self.assertEqual(
            normalize_windows_process_id(
                "0x4d2"
            ),
            "1234",
        )
        self.assertEqual(
            normalize_windows_process_id(
                "1234"
            ),
            "1234",
        )

    def test_time_only_near_match_does_not_correlate(
        self,
    ) -> None:
        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=security_event(),
                sysmon_event=sysmon_event(
                    process_id="9876",
                    process_name=(
                        r"C:\Windows\System32\notepad.exe"
                    ),
                ),
            )
        )

        self.assertFalse(
            result.matched
        )
        self.assertEqual(
            result.reason_code,
            "process_id_mismatch",
        )

    def test_same_pid_on_different_host_does_not_correlate(
        self,
    ) -> None:
        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=security_event(),
                sysmon_event=sysmon_event(
                    host="HOST-02"
                ),
            )
        )

        self.assertFalse(
            result.matched
        )
        self.assertEqual(
            result.reason_code,
            "host_mismatch",
        )

    def test_same_pid_different_process_image_does_not_correlate(
        self,
    ) -> None:
        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=security_event(),
                sysmon_event=sysmon_event(
                    process_name=(
                        r"C:\Windows\System32\powershell.exe"
                    ),
                ),
            )
        )

        self.assertFalse(
            result.matched
        )
        self.assertEqual(
            result.reason_code,
            "process_name_mismatch",
        )

    def test_parent_process_id_mismatch_breaks_otherwise_strong_match(
        self,
    ) -> None:
        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=security_event(),
                sysmon_event=sysmon_event(
                    parent_process_id="501"
                ),
            )
        )

        self.assertFalse(
            result.matched
        )
        self.assertEqual(
            result.reason_code,
            "parent_process_id_mismatch",
        )

    def test_missing_parent_process_name_does_not_fabricate_anchor(
        self,
    ) -> None:
        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=security_event(
                    parent_process=None
                ),
                sysmon_event=sysmon_event(),
            )
        )

        self.assertTrue(
            result.matched
        )
        self.assertNotIn(
            "parent_process",
            result.edge.matched_dimensions,
        )
        self.assertIn(
            "parent_process_id",
            result.edge.matched_dimensions,
        )

    def test_missing_critical_process_id_fails_closed(
        self,
    ) -> None:
        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=security_event(
                    process_id=""
                ),
                sysmon_event=sysmon_event(),
            )
        )

        self.assertFalse(
            result.matched
        )
        self.assertEqual(
            result.reason_code,
            "process_id_unavailable",
        )

    def test_outside_bounded_time_window_does_not_correlate(
        self,
    ) -> None:
        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=security_event(),
                sysmon_event=sysmon_event(
                    event_time=(
                        BASE_TIME
                        + timedelta(seconds=6)
                    )
                ),
            )
        )

        self.assertFalse(
            result.matched
        )
        self.assertEqual(
            result.reason_code,
            "outside_time_window",
        )

    def test_wrong_source_family_fails_closed(
        self,
    ) -> None:
        source = replace(
            security_event(),
            source_type=SourceType.POWERSHELL,
        )

        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=source,
                sysmon_event=sysmon_event(),
            )
        )

        self.assertFalse(
            result.matched
        )
        self.assertEqual(
            result.reason_code,
            "source_type_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
