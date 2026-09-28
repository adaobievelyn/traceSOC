from __future__ import annotations

from types import SimpleNamespace
import unittest

from tracesoc.detection.models import DetectionState
from tracesoc.detection.sysmon_powershell_behavior import (
    detect_powershell_cross_process_access,
    detect_powershell_initiated_network_connection,
    detect_powershell_process_creation,
)
from tracesoc.models import SourceType


EVENT_ID = "evt_" + ("a" * 64)


def event(
    *,
    event_type: str,
    fields: dict[str, str],
):
    return SimpleNamespace(
        source_type=SourceType.SYSMON,
        event_type=event_type,
        fields=fields,
        event_id=EVENT_ID,
    )


class SysmonPowerShellBehaviorDetectionTests(
    unittest.TestCase
):
    def test_det006_positive(
        self,
    ) -> None:
        result = detect_powershell_process_creation(
            event(
                event_type="process_create",
                fields={
                    "process_name":
                        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "command_line":
                        "powershell.exe -NoProfile -File task.ps1",
                },
            )
        )

        self.assertEqual(
            result.state,
            DetectionState.MATCH,
        )

        self.assertEqual(
            result.detection_id,
            "TRC-DET-006",
        )


    def test_det006_negative(
        self,
    ) -> None:
        result = detect_powershell_process_creation(
            event(
                event_type="process_create",
                fields={
                    "process_name":
                        r"C:\Windows\System32\cmd.exe",
                    "command_line":
                        "cmd.exe /c whoami",
                },
            )
        )

        self.assertEqual(
            result.state,
            DetectionState.NO_MATCH,
        )

        self.assertEqual(
            result.reason_code,
            "process_family_mismatch",
        )


    def test_det006_malformed(
        self,
    ) -> None:
        result = detect_powershell_process_creation(
            event(
                event_type="process_create",
                fields={
                    "process_name":
                        "powershell.exe",
                },
            )
        )

        self.assertEqual(
            result.state,
            DetectionState.NO_MATCH,
        )

        self.assertEqual(
            result.reason_code,
            "missing_command_line",
        )


    def test_det007_positive(
        self,
    ) -> None:
        result = detect_powershell_initiated_network_connection(
            event(
                event_type="network_connection",
                fields={
                    "process_name":
                        "powershell.exe",
                    "initiated":
                        "true",
                    "dst_ip":
                        "203.0.113.25",
                    "dst_port":
                        "443",
                },
            )
        )

        self.assertEqual(
            result.state,
            DetectionState.MATCH,
        )

        self.assertEqual(
            result.detection_id,
            "TRC-DET-007",
        )


    def test_det007_negative(
        self,
    ) -> None:
        result = detect_powershell_initiated_network_connection(
            event(
                event_type="network_connection",
                fields={
                    "process_name":
                        r"C:\Program Files\Example\client.exe",
                    "initiated":
                        "true",
                    "dst_ip":
                        "203.0.113.25",
                    "dst_port":
                        "443",
                },
            )
        )

        self.assertEqual(
            result.state,
            DetectionState.NO_MATCH,
        )

        self.assertEqual(
            result.reason_code,
            "process_family_mismatch",
        )


    def test_det007_malformed(
        self,
    ) -> None:
        result = detect_powershell_initiated_network_connection(
            event(
                event_type="network_connection",
                fields={
                    "process_name":
                        "powershell.exe",
                    "initiated":
                        "true",
                    "dst_port":
                        "443",
                },
            )
        )

        self.assertEqual(
            result.state,
            DetectionState.NO_MATCH,
        )

        self.assertEqual(
            result.reason_code,
            "missing_destination",
        )


    def test_det008_positive(
        self,
    ) -> None:
        result = detect_powershell_cross_process_access(
            event(
                event_type="process_access",
                fields={
                    "source_process":
                        "powershell.exe",
                    "source_process_id":
                        "100",
                    "target_process":
                        r"C:\Windows\System32\notepad.exe",
                    "target_process_id":
                        "200",
                    "granted_access":
                        "0x1010",
                },
            )
        )

        self.assertEqual(
            result.state,
            DetectionState.MATCH,
        )

        self.assertEqual(
            result.detection_id,
            "TRC-DET-008",
        )


    def test_det008_negative(
        self,
    ) -> None:
        result = detect_powershell_cross_process_access(
            event(
                event_type="process_access",
                fields={
                    "source_process":
                        r"C:\Program Files\Example\backup-agent.exe",
                    "source_process_id":
                        "100",
                    "target_process":
                        r"C:\Windows\System32\notepad.exe",
                    "target_process_id":
                        "200",
                    "granted_access":
                        "0x1010",
                },
            )
        )

        self.assertEqual(
            result.state,
            DetectionState.NO_MATCH,
        )

        self.assertEqual(
            result.reason_code,
            "source_process_family_mismatch",
        )


    def test_det008_malformed(
        self,
    ) -> None:
        result = detect_powershell_cross_process_access(
            event(
                event_type="process_access",
                fields={
                    "source_process":
                        "powershell.exe",
                    "source_process_id":
                        "100",
                    "target_process":
                        r"C:\Windows\System32\notepad.exe",
                    "target_process_id":
                        "200",
                },
            )
        )

        self.assertEqual(
            result.state,
            DetectionState.NO_MATCH,
        )

        self.assertEqual(
            result.reason_code,
            "missing_granted_access",
        )