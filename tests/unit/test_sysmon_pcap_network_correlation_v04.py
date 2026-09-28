from __future__ import annotations

import unittest
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from types import (
    SimpleNamespace,
)

from tracesoc.correlation.sysmon_pcap_network import (
    CORRELATION_ID,
    NetworkTupleCorrelationResult,
    correlate_sysmon_network_with_pcap,
)
from tracesoc.detection.sysmon_powershell_behavior import (
    detect_powershell_initiated_network_connection,
)
from tracesoc.evidence.correlation_bridge import (
    bridge_sysmon_pcap_network_correlation,
)
from tracesoc.evidence.graph import (
    RelationshipType,
)
from tracesoc.evidence.states import (
    EvidenceState,
)
from tracesoc.models import (
    SourceType,
)


BASE_TIME = datetime(
    2026,
    9,
    22,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def sysmon_event(
    *,
    event_id: str = "sysmon-network",
    destination_port: object = "443",
    event_time_utc: datetime = BASE_TIME,
) -> object:
    return SimpleNamespace(
        event_id=event_id,
        source_type=(
            SourceType.SYSMON
        ),
        event_type=(
            "network_connection"
        ),
        event_time_utc=(
            event_time_utc
        ),
        host="HOST-1",
        principal=r"DOMAIN\alice",
        fields={
            "process_name":
                "powershell.exe",

            "initiated":
                "true",

            "src_ip":
                "10.0.0.5",

            "src_port":
                "50000",

            "dst_ip":
                "198.51.100.20",

            "dst_port":
                destination_port,

            "proto":
                "tcp",
        },
    )


def pcap_event(
    *,
    event_id: str = "pcap-packet",
    destination_port: object = 443,
    event_time_utc: datetime = (
        BASE_TIME
        + timedelta(
            milliseconds=500
        )
    ),
) -> object:
    return SimpleNamespace(
        event_id=event_id,
        source_type=(
            SourceType.PCAP
        ),
        event_type=(
            "network_packet"
        ),
        event_time_utc=(
            event_time_utc
        ),
        host=None,
        principal=None,
        fields={
            "src_ip":
                "10.0.0.5",

            "src_port":
                50000,

            "dst_ip":
                "198.51.100.20",

            "dst_port":
                destination_port,

            "protocol":
                "tcp",
        },
    )


def detection_for(
    event: object,
):
    return (
        detect_powershell_initiated_network_connection(
            event
        )
    )


class SysmonPcapNetworkCorrelationV04Tests(
    unittest.TestCase
):
    def test_exact_tuple_and_bounded_time_match(
        self,
    ) -> None:
        sysmon = sysmon_event()
        pcap = pcap_event()

        result = (
            correlate_sysmon_network_with_pcap(
                detection=(
                    detection_for(
                        sysmon
                    )
                ),
                sysmon_event=sysmon,
                pcap_event=pcap,
            )
        )

        self.assertIsInstance(
            result,
            NetworkTupleCorrelationResult,
        )

        self.assertTrue(
            result.matched
        )

        self.assertEqual(
            result.correlation_id,
            "TRC-CORR-003",
        )

        edge = result.edge

        assert edge is not None

        self.assertEqual(
            edge.source_ip,
            "10.0.0.5",
        )

        self.assertEqual(
            edge.source_port,
            50000,
        )

        self.assertEqual(
            edge.destination_ip,
            "198.51.100.20",
        )

        self.assertEqual(
            edge.destination_port,
            443,
        )

        self.assertEqual(
            edge.protocol,
            "tcp",
        )

        self.assertEqual(
            set(
                edge.matched_dimensions
            ),
            {
                "source_ip",
                "source_port",
                "destination_ip",
                "destination_port",
                "protocol",
                "bounded_absolute_time_window",
            },
        )


    def test_tuple_mismatch_does_not_match(
        self,
    ) -> None:
        sysmon = sysmon_event()

        result = (
            correlate_sysmon_network_with_pcap(
                detection=(
                    detection_for(
                        sysmon
                    )
                ),
                sysmon_event=sysmon,
                pcap_event=(
                    pcap_event(
                        destination_port=8443
                    )
                ),
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "destination_port_mismatch",
        )

        self.assertIsNone(
            result.edge
        )


    def test_timestamp_proximity_without_tuple_match_is_insufficient(
        self,
    ) -> None:
        sysmon = sysmon_event()

        result = (
            correlate_sysmon_network_with_pcap(
                detection=(
                    detection_for(
                        sysmon
                    )
                ),
                sysmon_event=sysmon,
                pcap_event=(
                    pcap_event(
                        destination_port=8443,
                        event_time_utc=(
                            BASE_TIME
                        ),
                    )
                ),
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "destination_port_mismatch",
        )


    def test_matching_tuple_outside_time_window_does_not_match(
        self,
    ) -> None:
        sysmon = sysmon_event()

        result = (
            correlate_sysmon_network_with_pcap(
                detection=(
                    detection_for(
                        sysmon
                    )
                ),
                sysmon_event=sysmon,
                pcap_event=(
                    pcap_event(
                        event_time_utc=(
                            BASE_TIME
                            + timedelta(
                                seconds=6
                            )
                        ),
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


    def test_edge_identity_is_deterministic(
        self,
    ) -> None:
        sysmon = sysmon_event()
        pcap = pcap_event()

        first = (
            correlate_sysmon_network_with_pcap(
                detection=(
                    detection_for(
                        sysmon
                    )
                ),
                sysmon_event=sysmon,
                pcap_event=pcap,
            )
        )

        second = (
            correlate_sysmon_network_with_pcap(
                detection=(
                    detection_for(
                        sysmon
                    )
                ),
                sysmon_event=sysmon,
                pcap_event=pcap,
            )
        )

        assert first.edge is not None
        assert second.edge is not None

        self.assertEqual(
            first.edge.edge_id,
            second.edge.edge_id,
        )


    def test_bridge_creates_corroborates_relationship_with_tuple_anchors(
        self,
    ) -> None:
        sysmon = sysmon_event()
        pcap = pcap_event()

        result = (
            correlate_sysmon_network_with_pcap(
                detection=(
                    detection_for(
                        sysmon
                    )
                ),
                sysmon_event=sysmon,
                pcap_event=pcap,
            )
        )

        projection = (
            bridge_sysmon_pcap_network_correlation(
                result=result,
                sysmon_event=sysmon,
                pcap_event=pcap,
            )
        )

        assert projection is not None

        self.assertEqual(
            projection.legacy_correlation_id,
            CORRELATION_ID,
        )

        relationship = (
            projection.relationship
        )

        self.assertIs(
            relationship.relationship_type,
            RelationshipType.CORROBORATES,
        )

        self.assertIs(
            relationship.evidence_state,
            EvidenceState.CORROBORATED,
        )

        anchors = {
            (
                item.anchor_type,
                item.value,
                item.temporal,
            )
            for item
            in relationship.anchors
        }

        self.assertIn(
            (
                "source_ip",
                "10.0.0.5",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "source_port",
                "50000",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "destination_ip",
                "198.51.100.20",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "destination_port",
                "443",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "protocol",
                "tcp",
                False,
            ),
            anchors,
        )

        self.assertTrue(
            any(
                anchor_type
                == "absolute_delta_seconds"
                and temporal
                for (
                    anchor_type,
                    _value,
                    temporal,
                )
                in anchors
            )
        )


    def test_no_match_creates_no_relationship(
        self,
    ) -> None:
        sysmon = sysmon_event()

        result = (
            correlate_sysmon_network_with_pcap(
                detection=(
                    detection_for(
                        sysmon
                    )
                ),
                sysmon_event=sysmon,
                pcap_event=(
                    pcap_event(
                        destination_port=8443
                    )
                ),
            )
        )

        projection = (
            bridge_sysmon_pcap_network_correlation(
                result=result,
                sysmon_event=sysmon,
                pcap_event=(
                    pcap_event(
                        destination_port=8443
                    )
                ),
            )
        )

        self.assertIsNone(
            projection
        )


if __name__ == "__main__":
    unittest.main()
