from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from tracesoc.correlation.security_sysmon_process import (
    correlate_windows_security_process_with_sysmon,
)
from tracesoc.evidence.correlation_bridge import (
    bridge_security_sysmon_process_correlation,
)
from tracesoc.evidence.graph import (
    RelationshipType,
)
from tracesoc.evidence.states import (
    EvidenceState,
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


def security() -> SemanticEvent:
    return SemanticEvent(
        event_id="security-1",
        source_type=SourceType.WINDOWS_SECURITY,
        event_type="process_create",
        clock_state=ClockState.OBSERVED,
        event_time_utc=BASE_TIME,
        host="HOST-01",
        principal=None,
        fields={
            "process_id": "0x4d2",
            "process_name": r"C:\Windows\System32\cmd.exe",
            "parent_process_id": "0x1f4",
            "parent_process": r"C:\Windows\explorer.exe",
        },
    )


def sysmon() -> SemanticEvent:
    return SemanticEvent(
        event_id="sysmon-1",
        source_type=SourceType.SYSMON,
        event_type="process_create",
        clock_state=ClockState.OBSERVED,
        event_time_utc=(
            BASE_TIME
            + timedelta(milliseconds=500)
        ),
        host="host-01",
        principal=r"DOMAIN\User",
        fields={
            "process_id": "1234",
            "process_name": r"c:\windows\system32\CMD.EXE",
            "parent_process_id": "500",
            "parent_process": r"c:\windows\EXPLORER.EXE",
        },
    )


class SecuritySysmonProcessBridgeTests(
    unittest.TestCase
):
    def test_match_projects_to_corroborates_relationship(
        self,
    ) -> None:
        security_event = security()
        sysmon_event = sysmon()

        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=security_event,
                sysmon_event=sysmon_event,
            )
        )

        projection = (
            bridge_security_sysmon_process_correlation(
                result=result,
                security_event=security_event,
                sysmon_event=sysmon_event,
            )
        )

        self.assertIsNotNone(
            projection
        )
        assert projection is not None

        relationship = (
            projection.relationship
        )

        self.assertEqual(
            relationship.relationship_type,
            RelationshipType.CORROBORATES,
        )
        self.assertEqual(
            relationship.evidence_state,
            EvidenceState.CORROBORATED,
        )
        self.assertEqual(
            relationship.predicate_version,
            "TRC-CORR-004@1.0.0",
        )

        anchors = {
            (
                anchor.anchor_type,
                anchor.value,
                anchor.temporal,
            )
            for anchor
            in relationship.anchors
        }

        self.assertIn(
            ("host", "host-01", False),
            anchors,
        )
        self.assertIn(
            ("process_id", "1234", False),
            anchors,
        )
        self.assertIn(
            (
                "process_name",
                r"c:\windows\system32\cmd.exe",
                False,
            ),
            anchors,
        )
        self.assertIn(
            ("parent_process_id", "500", False),
            anchors,
        )
        self.assertIn(
            (
                "absolute_delta_seconds",
                "0.500000",
                True,
            ),
            anchors,
        )

    def test_no_match_creates_no_graph_relationship(
        self,
    ) -> None:
        security_event = security()
        sysmon_event = SemanticEvent(
            event_id="sysmon-2",
            source_type=SourceType.SYSMON,
            event_type="process_create",
            clock_state=ClockState.OBSERVED,
            event_time_utc=BASE_TIME,
            host="HOST-01",
            principal=None,
            fields={
                "process_id": "9999",
                "process_name": r"C:\Windows\System32\cmd.exe",
            },
        )

        result = (
            correlate_windows_security_process_with_sysmon(
                security_event=security_event,
                sysmon_event=sysmon_event,
            )
        )

        projection = (
            bridge_security_sysmon_process_correlation(
                result=result,
                security_event=security_event,
                sysmon_event=sysmon_event,
            )
        )

        self.assertIsNone(
            projection
        )


if __name__ == "__main__":
    unittest.main()
