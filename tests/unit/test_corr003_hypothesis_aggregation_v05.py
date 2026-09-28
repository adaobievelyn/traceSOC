
from __future__ import annotations

import unittest
from types import SimpleNamespace

from tracesoc.cli.case import (
    _build_case_hypotheses,
)
from tracesoc.detection.models import (
    DetectionResult,
    DetectionState,
)
from tracesoc.evidence.graph import (
    Entity,
    EntityKind,
    Relationship,
    RelationshipAnchor,
    RelationshipType,
)
from tracesoc.evidence.states import (
    EvidenceState,
)


def entity(
    event_id: str,
) -> Entity:
    return Entity.create(
        kind=EntityKind.OBSERVATION,
        identity_attributes=(
            (
                "event_id",
                event_id,
            ),
        ),
    )


def relation(
    source: Entity,
    target: Entity,
    edge_id: str,
) -> Relationship:
    source_id = dict(
        source.identity_attributes
    )[
        "event_id"
    ]

    target_id = dict(
        target.identity_attributes
    )[
        "event_id"
    ]

    return Relationship.create(
        relationship_type=(
            RelationshipType.CORROBORATES
        ),
        source_entity_id=(
            source.entity_id
        ),
        target_entity_id=(
            target.entity_id
        ),
        predicate_version=(
            "TRC-CORR-003@1.0.0"
        ),
        supporting_ids=(
            edge_id,
            source_id,
            target_id,
        ),
        anchors=(
            RelationshipAnchor(
                anchor_type="source_ip",
                value="10.0.0.5",
                temporal=False,
            ),
            RelationshipAnchor(
                anchor_type="source_port",
                value="50000",
                temporal=False,
            ),
            RelationshipAnchor(
                anchor_type="destination_ip",
                value="198.51.100.20",
                temporal=False,
            ),
            RelationshipAnchor(
                anchor_type="destination_port",
                value="443",
                temporal=False,
            ),
            RelationshipAnchor(
                anchor_type="protocol",
                value="tcp",
                temporal=False,
            ),
            RelationshipAnchor(
                anchor_type=(
                    "absolute_delta_seconds"
                ),
                value="0.100000",
                temporal=True,
            ),
        ),
        evidence_state=(
            EvidenceState.CORROBORATED
        ),
        rationale=(
            "Bounded tuple match."
        ),
        alternative_or_falsifier=(
            "A mismatch in source IP, source port, "
            "destination IP, destination port, "
            "transport protocol, or the bounded "
            "timestamp tolerance falsifies this "
            "cross-source correlation."
        ),
    )


def detection(
    source_event_id: str,
) -> DetectionResult:
    return DetectionResult(
        detection_id="TRC-DET-007",
        detection_version="1.0.0",
        title="Test network detector",
        state=DetectionState.MATCH,
        reason_code="test_match",
        rationale=(
            "Synthetic bounded network match."
        ),
        contributing_event_ids=(
            source_event_id,
        ),
    )


class Corr003HypothesisAggregationV05Tests(
    unittest.TestCase
):
    def test_multiple_packets_become_one_source_hypothesis(
        self,
    ) -> None:
        source = entity(
            "sysmon-network-1"
        )

        packet1 = entity(
            "pcap-1"
        )

        packet2 = entity(
            "pcap-2"
        )

        detected = detection(
            "sysmon-network-1"
        )

        rel1 = relation(
            source,
            packet1,
            "edge-1",
        )

        rel2 = relation(
            source,
            packet2,
            "edge-2",
        )

        projection1 = SimpleNamespace(
            legacy_correlation_id=(
                "TRC-CORR-003"
            ),
            legacy_correlation_version=(
                "1.0.0"
            ),
            source_entity=source,
            target_entity=packet1,
            relationship=rel1,
        )

        projection2 = SimpleNamespace(
            legacy_correlation_id=(
                "TRC-CORR-003"
            ),
            legacy_correlation_version=(
                "1.0.0"
            ),
            source_entity=source,
            target_entity=packet2,
            relationship=rel2,
        )

        hypotheses = (
            _build_case_hypotheses(
                (
                    (
                        "TRC-CORR-003",
                        detected,
                        projection1,
                        "sysmon-network-1",
                        "pcap-1",
                    ),
                    (
                        "TRC-CORR-003",
                        detected,
                        projection2,
                        "sysmon-network-1",
                        "pcap-2",
                    ),
                ),
                relationship_projections=(
                    projection1,
                    projection2,
                ),
            )
        )

        self.assertEqual(
            len(hypotheses),
            1,
        )

        hypothesis = hypotheses[0]

        self.assertEqual(
            hypothesis.hypothesis_key,
            (
                "sysmon-pcap-network-corroboration:"
                "sysmon-network-1"
            ),
        )

        self.assertEqual(
            hypothesis.supporting_relationship_ids,
            tuple(
                sorted(
                    (
                        rel1.relationship_id,
                        rel2.relationship_id,
                    )
                )
            ),
        )

        self.assertEqual(
            hypothesis.observation_ids,
            (
                "pcap-1",
                "pcap-2",
                "sysmon-network-1",
            ),
        )

        self.assertIn(
            (
                "capture multiplicity is not promoted "
                "into multiple analytical conclusions"
            ),
            hypothesis.rationale,
        )

    def test_distinct_sysmon_sources_remain_distinct(
        self,
    ) -> None:
        source1 = entity(
            "sysmon-network-1"
        )

        source2 = entity(
            "sysmon-network-2"
        )

        packet1 = entity(
            "pcap-1"
        )

        packet2 = entity(
            "pcap-2"
        )

        rel1 = relation(
            source1,
            packet1,
            "edge-1",
        )

        rel2 = relation(
            source2,
            packet2,
            "edge-2",
        )

        projection1 = SimpleNamespace(
            legacy_correlation_id=(
                "TRC-CORR-003"
            ),
            legacy_correlation_version=(
                "1.0.0"
            ),
            source_entity=source1,
            target_entity=packet1,
            relationship=rel1,
        )

        projection2 = SimpleNamespace(
            legacy_correlation_id=(
                "TRC-CORR-003"
            ),
            legacy_correlation_version=(
                "1.0.0"
            ),
            source_entity=source2,
            target_entity=packet2,
            relationship=rel2,
        )

        hypotheses = (
            _build_case_hypotheses(
                (
                    (
                        "TRC-CORR-003",
                        detection(
                            "sysmon-network-1"
                        ),
                        projection1,
                        "sysmon-network-1",
                        "pcap-1",
                    ),
                    (
                        "TRC-CORR-003",
                        detection(
                            "sysmon-network-2"
                        ),
                        projection2,
                        "sysmon-network-2",
                        "pcap-2",
                    ),
                ),
                relationship_projections=(
                    projection1,
                    projection2,
                ),
            )
        )

        self.assertEqual(
            len(hypotheses),
            2,
        )

        self.assertEqual(
            {
                item.hypothesis_key
                for item in hypotheses
            },
            {
                (
                    "sysmon-pcap-network-corroboration:"
                    "sysmon-network-1"
                ),
                (
                    "sysmon-pcap-network-corroboration:"
                    "sysmon-network-2"
                ),
            },
        )


if __name__ == "__main__":
    unittest.main()
