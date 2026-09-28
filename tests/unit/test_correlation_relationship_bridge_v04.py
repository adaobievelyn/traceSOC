from __future__ import annotations

import unittest
from types import SimpleNamespace

from tracesoc.evidence.correlation_bridge import (
    CorrelationBridgeError,
    bridge_powershell_process_correlation,
    bridge_web_retrieval_correlation,
)
from tracesoc.evidence.graph import (
    EntityKind,
    RelationshipType,
)
from tracesoc.evidence.states import (
    EvidenceState,
)
from tracesoc.models import (
    SourceType,
)


def event(
    *,
    event_id: str,
    source_type: SourceType,
    host: str = "HOST-1",
    principal: str | None = None,
    fields: dict[str, object] | None = None,
) -> object:
    return SimpleNamespace(
        event_id=event_id,
        source_type=source_type,
        host=host,
        principal=principal,
        fields=(
            {}
            if fields is None
            else fields
        ),
    )


def network_match() -> object:
    edge = SimpleNamespace(
        correlation_id="TRC-CORR-001",
        correlation_version="1.0.0",
        edge_id="edge_network_1",
        relationship=(
            "powershell_web_retrieval_network_corroboration"
        ),
        source_event_id="ps-event",
        target_event_id="zeek-event",
        delta_seconds=2.5,
        destination_ip="198.51.100.20",
        destination_port=443,
        matched_dimensions=(
            "host",
            "source_ip",
            "destination_ip",
            "destination_port",
            "directional_time_window",
        ),
    )

    return SimpleNamespace(
        correlation_id="TRC-CORR-001",
        correlation_version="1.0.0",
        matched=True,
        rationale=(
            "PowerShell retrieval behavior and "
            "Zeek telemetry corroborate one another."
        ),
        edge=edge,
    )


def process_match() -> object:
    edge = SimpleNamespace(
        correlation_id="TRC-CORR-002",
        correlation_version="1.0.0",
        edge_id="edge_process_1",
        relationship=(
            "powershell_process_corroborates_powershell_behavior"
        ),
        source_event_id="sysmon-event",
        target_event_id="ps-event",
        delta_seconds=5.0,
        process_name="powershell.exe",
        local_ip="192.0.2.10",
        principal="DOMAIN\\alice",
        matched_dimensions=(
            "host",
            "principal",
            "local_ip",
            "powershell_process_family",
            "directional_time_window",
        ),
    )

    return SimpleNamespace(
        correlation_id="TRC-CORR-002",
        correlation_version="1.0.0",
        matched=True,
        rationale=(
            "Sysmon process creation corroborates "
            "PowerShell behavior."
        ),
        edge=edge,
    )


class CorrelationRelationshipBridgeTests(
    unittest.TestCase
):
    def test_network_match_becomes_corroborates_relationship(
        self,
    ) -> None:
        ps = event(
            event_id="ps-event",
            source_type=(
                SourceType.POWERSHELL
            ),
            host="HOST-1",
            fields={
                "local_ip":
                    "192.0.2.10",
            },
        )

        zeek = event(
            event_id="zeek-event",
            source_type=(
                SourceType.ZEEK
            ),
            host="host-1",
            fields={
                "src_ip":
                    "192.0.2.10",
                "dst_ip":
                    "198.51.100.20",
                "dst_port":
                    443,
            },
        )

        projection = (
            bridge_web_retrieval_correlation(
                result=network_match(),
                powershell_event=ps,
                zeek_event=zeek,
            )
        )

        assert projection is not None

        self.assertEqual(
            projection.legacy_correlation_id,
            "TRC-CORR-001",
        )

        self.assertEqual(
            projection.legacy_correlation_version,
            "1.0.0",
        )

        self.assertEqual(
            projection.legacy_edge_id,
            "edge_network_1",
        )

        self.assertIs(
            projection.source_entity.kind,
            EntityKind.OBSERVATION,
        )

        self.assertIs(
            projection.target_entity.kind,
            EntityKind.OBSERVATION,
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

        self.assertEqual(
            relationship.predicate_version,
            "TRC-CORR-001@1.0.0",
        )

        self.assertEqual(
            set(
                relationship.supporting_ids
            ),
            {
                "edge_network_1",
                "ps-event",
                "zeek-event",
            },
        )

    def test_network_relationship_preserves_concrete_non_temporal_anchors(
        self,
    ) -> None:
        ps = event(
            event_id="ps-event",
            source_type=(
                SourceType.POWERSHELL
            ),
            host="HOST-1",
            fields={
                "local_ip":
                    "192.0.2.10",
            },
        )

        zeek = event(
            event_id="zeek-event",
            source_type=(
                SourceType.ZEEK
            ),
            host="host-1",
            fields={
                "src_ip":
                    "192.0.2.10",
                "dst_ip":
                    "198.51.100.20",
                "dst_port":
                    443,
            },
        )

        projection = (
            bridge_web_retrieval_correlation(
                result=network_match(),
                powershell_event=ps,
                zeek_event=zeek,
            )
        )

        assert projection is not None

        anchors = {
            (
                item.anchor_type,
                item.value,
                item.temporal,
            )
            for item
            in projection.relationship.anchors
        }

        self.assertIn(
            (
                "host",
                "host-1",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "source_ip",
                "192.0.2.10",
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
                "directional_delta_seconds",
                "2.500000",
                True,
            ),
            anchors,
        )

    def test_process_match_preserves_existing_orientation(
        self,
    ) -> None:
        sysmon = event(
            event_id="sysmon-event",
            source_type=(
                SourceType.SYSMON
            ),
            host="HOST-1",
            principal=(
                "DOMAIN\\Alice"
            ),
            fields={
                "local_ip":
                    "192.0.2.10",
            },
        )

        ps = event(
            event_id="ps-event",
            source_type=(
                SourceType.POWERSHELL
            ),
            host="host-1",
            principal=(
                "domain\\alice"
            ),
            fields={
                "local_ip":
                    "192.0.2.10",
            },
        )

        projection = (
            bridge_powershell_process_correlation(
                result=process_match(),
                sysmon_event=sysmon,
                powershell_event=ps,
            )
        )

        assert projection is not None

        source_attrs = dict(
            projection.source_entity.identity_attributes
        )

        target_attrs = dict(
            projection.target_entity.identity_attributes
        )

        self.assertEqual(
            source_attrs[
                "event_id"
            ],
            "sysmon-event",
        )

        self.assertEqual(
            target_attrs[
                "event_id"
            ],
            "ps-event",
        )

        self.assertEqual(
            projection.relationship.predicate_version,
            "TRC-CORR-002@1.0.0",
        )

    def test_process_relationship_preserves_concrete_anchors(
        self,
    ) -> None:
        sysmon = event(
            event_id="sysmon-event",
            source_type=(
                SourceType.SYSMON
            ),
            host="HOST-1",
            principal=(
                "DOMAIN\\Alice"
            ),
            fields={
                "local_ip":
                    "192.0.2.10",
            },
        )

        ps = event(
            event_id="ps-event",
            source_type=(
                SourceType.POWERSHELL
            ),
            host="host-1",
            principal=(
                "domain\\alice"
            ),
            fields={
                "local_ip":
                    "192.0.2.10",
            },
        )

        projection = (
            bridge_powershell_process_correlation(
                result=process_match(),
                sysmon_event=sysmon,
                powershell_event=ps,
            )
        )

        assert projection is not None

        anchors = {
            (
                item.anchor_type,
                item.value,
                item.temporal,
            )
            for item
            in projection.relationship.anchors
        }

        self.assertIn(
            (
                "host",
                "host-1",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "principal",
                "domain\\alice",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "local_ip",
                "192.0.2.10",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "powershell_process_family",
                "powershell.exe",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "directional_delta_seconds",
                "5.000000",
                True,
            ),
            anchors,
        )

    def test_network_no_match_creates_no_graph_edge(
        self,
    ) -> None:
        result = SimpleNamespace(
            correlation_id=(
                "TRC-CORR-001"
            ),
            correlation_version=(
                "1.0.0"
            ),
            matched=False,
            rationale="no match",
            edge=None,
        )

        projection = (
            bridge_web_retrieval_correlation(
                result=result,
                powershell_event=event(
                    event_id="ps-event",
                    source_type=(
                        SourceType.POWERSHELL
                    ),
                ),
                zeek_event=event(
                    event_id="zeek-event",
                    source_type=(
                        SourceType.ZEEK
                    ),
                ),
            )
        )

        self.assertIsNone(
            projection
        )

    def test_process_no_match_creates_no_graph_edge(
        self,
    ) -> None:
        result = SimpleNamespace(
            correlation_id=(
                "TRC-CORR-002"
            ),
            correlation_version=(
                "1.0.0"
            ),
            matched=False,
            rationale="no match",
            edge=None,
        )

        projection = (
            bridge_powershell_process_correlation(
                result=result,
                sysmon_event=event(
                    event_id=(
                        "sysmon-event"
                    ),
                    source_type=(
                        SourceType.SYSMON
                    ),
                ),
                powershell_event=event(
                    event_id="ps-event",
                    source_type=(
                        SourceType.POWERSHELL
                    ),
                ),
            )
        )

        self.assertIsNone(
            projection
        )

    def test_network_wrong_legacy_version_fails_closed(
        self,
    ) -> None:
        result = (
            network_match()
        )

        result.correlation_version = (
            "2.0.0"
        )

        with self.assertRaises(
            CorrelationBridgeError
        ):
            bridge_web_retrieval_correlation(
                result=result,
                powershell_event=event(
                    event_id="ps-event",
                    source_type=(
                        SourceType.POWERSHELL
                    ),
                ),
                zeek_event=event(
                    event_id="zeek-event",
                    source_type=(
                        SourceType.ZEEK
                    ),
                ),
            )

    def test_changed_matched_dimensions_fail_closed(
        self,
    ) -> None:
        result = (
            network_match()
        )

        result.edge.matched_dimensions = (
            "directional_time_window",
        )

        with self.assertRaises(
            CorrelationBridgeError
        ):
            bridge_web_retrieval_correlation(
                result=result,
                powershell_event=event(
                    event_id="ps-event",
                    source_type=(
                        SourceType.POWERSHELL
                    ),
                    host="HOST-1",
                    fields={
                        "local_ip":
                            "192.0.2.10",
                    },
                ),
                zeek_event=event(
                    event_id="zeek-event",
                    source_type=(
                        SourceType.ZEEK
                    ),
                    host="HOST-1",
                    fields={
                        "src_ip":
                            "192.0.2.10",
                        "dst_ip":
                            "198.51.100.20",
                        "dst_port":
                            443,
                    },
                ),
            )

    def test_edge_event_orientation_mismatch_fails_closed(
        self,
    ) -> None:
        result = (
            process_match()
        )

        result.edge.source_event_id = (
            "wrong-event"
        )

        with self.assertRaises(
            CorrelationBridgeError
        ):
            bridge_powershell_process_correlation(
                result=result,
                sysmon_event=event(
                    event_id=(
                        "sysmon-event"
                    ),
                    source_type=(
                        SourceType.SYSMON
                    ),
                ),
                powershell_event=event(
                    event_id="ps-event",
                    source_type=(
                        SourceType.POWERSHELL
                    ),
                ),
            )

    def test_relationship_identity_is_deterministic(
        self,
    ) -> None:
        ps = event(
            event_id="ps-event",
            source_type=(
                SourceType.POWERSHELL
            ),
            host="HOST-1",
            fields={
                "local_ip":
                    "192.0.2.10",
            },
        )

        zeek = event(
            event_id="zeek-event",
            source_type=(
                SourceType.ZEEK
            ),
            host="HOST-1",
            fields={
                "src_ip":
                    "192.0.2.10",
                "dst_ip":
                    "198.51.100.20",
                "dst_port":
                    443,
            },
        )

        first = (
            bridge_web_retrieval_correlation(
                result=network_match(),
                powershell_event=ps,
                zeek_event=zeek,
            )
        )

        second = (
            bridge_web_retrieval_correlation(
                result=network_match(),
                powershell_event=ps,
                zeek_event=zeek,
            )
        )

        assert first is not None
        assert second is not None

        self.assertEqual(
            first,
            second,
        )

    def test_bridge_does_not_assert_malicious_intent(
        self,
    ) -> None:
        ps = event(
            event_id="ps-event",
            source_type=(
                SourceType.POWERSHELL
            ),
            host="HOST-1",
            fields={
                "local_ip":
                    "192.0.2.10",
            },
        )

        zeek = event(
            event_id="zeek-event",
            source_type=(
                SourceType.ZEEK
            ),
            host="HOST-1",
            fields={
                "src_ip":
                    "192.0.2.10",
                "dst_ip":
                    "198.51.100.20",
                "dst_port":
                    443,
            },
        )

        projection = (
            bridge_web_retrieval_correlation(
                result=network_match(),
                powershell_event=ps,
                zeek_event=zeek,
            )
        )

        assert projection is not None

        serialized = str(
            projection.relationship.to_dict()
        ).casefold()

        self.assertNotIn(
            "malicious",
            serialized,
        )

        self.assertNotIn(
            "caused",
            serialized,
        )


if __name__ == "__main__":
    unittest.main()
