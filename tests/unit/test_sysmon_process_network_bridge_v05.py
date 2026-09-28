from dataclasses import replace
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from types import SimpleNamespace
import unittest

from tracesoc.correlation.sysmon_process_network import (
    correlate_sysmon_process_with_network_activity,
)
from tracesoc.evidence.correlation_bridge import (
    CorrelationBridgeError,
    bridge_sysmon_process_network_correlation,
)
from tracesoc.evidence.graph import (
    RelationshipType,
)
from tracesoc.models import (
    SourceType,
)


GUID = (
    "{851f2de6-143d-6ab5-4b08-000000005d00}"
)

IMAGE = (
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)

BASE = datetime(
    2026,
    9,
    24,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


class SysmonProcessNetworkBridgeTests(
    unittest.TestCase
):
    def pair(
        self,
    ):
        process = SimpleNamespace(
            event_id="evt_process",
            source_type=SourceType.SYSMON,
            event_type="process_create",
            host="HOST-01",
            event_time_utc=BASE,
            fields={
                "process_guid":
                    GUID,
                "process_id":
                    "7156",
                "process_name":
                    IMAGE,
            },
        )

        network = SimpleNamespace(
            event_id="evt_network",
            source_type=SourceType.SYSMON,
            event_type="network_connection",
            host="HOST-01",
            event_time_utc=(
                BASE
                + timedelta(
                    seconds=2
                )
            ),
            fields={
                "process_guid":
                    GUID,
                "process_id":
                    "7156",
                "process_name":
                    IMAGE,
            },
        )

        return (
            process,
            network,
        )

    def test_match_projects_relationship(
        self,
    ):
        process, network = self.pair()

        result = (
            correlate_sysmon_process_with_network_activity(
                process_event=process,
                network_event=network,
            )
        )

        projection = (
            bridge_sysmon_process_network_correlation(
                result=result,
                process_event=process,
                network_event=network,
            )
        )

        self.assertIsNotNone(
            projection
        )

        assert projection is not None

        self.assertEqual(
            projection.legacy_correlation_id,
            "TRC-CORR-006",
        )

        self.assertIs(
            projection
            .relationship
            .relationship_type,
            RelationshipType.CORROBORATES,
        )

        anchors = {
            anchor.anchor_type:
                anchor.value
            for anchor
            in projection
            .relationship
            .anchors
        }

        self.assertEqual(
            anchors["process_guid"],
            GUID,
        )

        self.assertEqual(
            anchors["process_id"],
            "7156",
        )

        self.assertTrue(
            all(
                not anchor.temporal
                for anchor
                in projection
                .relationship
                .anchors
            )
        )

    def test_nonmatch_projects_nothing(
        self,
    ):
        process, network = self.pair()

        network.fields[
            "process_guid"
        ] = (
            "{11111111-2222-3333-4444-555555555555}"
        )

        result = (
            correlate_sysmon_process_with_network_activity(
                process_event=process,
                network_event=network,
            )
        )

        projection = (
            bridge_sysmon_process_network_correlation(
                result=result,
                process_event=process,
                network_event=network,
            )
        )

        self.assertIsNone(
            projection
        )

    def test_bridge_rejects_tampered_guid(
        self,
    ):
        process, network = self.pair()

        result = (
            correlate_sysmon_process_with_network_activity(
                process_event=process,
                network_event=network,
            )
        )

        self.assertIsNotNone(
            result.edge
        )

        assert result.edge is not None

        tampered = replace(
            result,
            edge=replace(
                result.edge,
                process_guid=(
                    "{11111111-2222-3333-4444-555555555555}"
                ),
            ),
        )

        with self.assertRaises(
            CorrelationBridgeError
        ):
            bridge_sysmon_process_network_correlation(
                result=tampered,
                process_event=process,
                network_event=network,
            )


if __name__ == "__main__":
    unittest.main()
