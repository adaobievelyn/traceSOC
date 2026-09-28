from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tracesoc.cli.case import (
    _evaluate_case_correlations,
)
from tracesoc.parsers.sysmon import (
    load_sysmon_windows_event_xml,
)
from tracesoc.parsers.windows_security import (
    load_windows_security_windows_event_xml,
)


SECURITY_XML = br'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-09-24T12:00:00.0000000Z"/><EventRecordID>100</EventRecordID><Channel>Security</Channel><Computer>HOST-01</Computer></System><EventData><Data Name="SubjectUserSid">S-1-5-18</Data><Data Name="NewProcessId">0x123</Data><Data Name="NewProcessName">C:\Windows\System32\example.exe</Data><Data Name="ProcessId">0x100</Data><Data Name="ParentProcessName">C:\Windows\System32\parent.exe</Data><Data Name="CommandLine">C:\Windows\System32\example.exe /test</Data></EventData></Event>'''

SYSMON_XML = br'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="2026-09-24T12:00:00.6000000Z"/><EventRecordID>200</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>HOST-01</Computer></System><EventData><Data Name="UtcTime">2026-09-24 12:00:00.600</Data><Data Name="ProcessGuid">{11111111-1111-1111-1111-111111111111}</Data><Data Name="ProcessId">291</Data><Data Name="Image">C:\Windows\System32\example.exe</Data><Data Name="CommandLine">C:\Windows\System32\example.exe /test</Data><Data Name="User">NT AUTHORITY\SYSTEM</Data><Data Name="ParentProcessGuid">{22222222-2222-2222-2222-222222222222}</Data><Data Name="ParentProcessId">256</Data><Data Name="ParentImage">C:\Windows\System32\parent.exe</Data></EventData></Event>'''


class SecuritySysmonCaseIntegrationTests(
    unittest.TestCase
):
    def test_case_correlation_pipeline_emits_corr004_relationship(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            security_path = root / "security.xml"
            sysmon_path = root / "sysmon.xml"
            security_path.write_bytes(
                SECURITY_XML
            )
            sysmon_path.write_bytes(
                SYSMON_XML
            )

            security_batch = (
                load_windows_security_windows_event_xml(
                    security_path,
                    logical_source=(
                        "evidence/security.xml"
                    ),
                )
            )
            sysmon_batch = (
                load_sysmon_windows_event_xml(
                    sysmon_path,
                    logical_source=(
                        "evidence/sysmon.xml"
                    ),
                )
            )

        canonical_events = (
            tuple(security_batch.accepted)
            + tuple(sysmon_batch.accepted)
        )

        records, projections, candidates = (
            _evaluate_case_correlations(
                canonical_events
            )
        )

        corr004_records = [
            record
            for record in records
            if record["correlation_id"]
            == "TRC-CORR-004"
        ]

        self.assertEqual(
            len(corr004_records),
            1,
        )
        self.assertTrue(
            corr004_records[0]["matched"]
        )
        self.assertEqual(
            corr004_records[0]["source_kind"],
            "windows_security_process",
        )
        self.assertEqual(
            corr004_records[0]["candidate_kind"],
            "sysmon_process",
        )

        corr004_projections = [
            projection
            for projection in projections
            if projection.legacy_correlation_id
            == "TRC-CORR-004"
        ]

        self.assertEqual(
            len(corr004_projections),
            1,
        )

        # CORR004 is evidence corroboration, not a maliciousness detector,
        # so it does not manufacture a hypothesis candidate by itself.
        self.assertEqual(
            candidates,
            (),
        )


if __name__ == "__main__":
    unittest.main()
