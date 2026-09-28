from __future__ import annotations

import dataclasses
import unittest

from tracesoc.evidence.graph import (
    ENTITY_IDENTITY_VERSION,
    RELATIONSHIP_IDENTITY_VERSION,
    Entity,
    EntityKind,
    Relationship,
    RelationshipAnchor,
    RelationshipTimeSupport,
    RelationshipType,
)
from tracesoc.evidence.states import (
    EvidenceState,
)
from tracesoc.models import (
    ClockState,
)


def host_entity(
    value: str = "HOST-1",
) -> Entity:
    return Entity.create(
        kind=EntityKind.HOST,
        identity_attributes=(
            (
                "hostname",
                value,
            ),
        ),
        display_name=value,
    )


def process_entity(
    guid: str = "{ABC}",
) -> Entity:
    return Entity.create(
        kind=EntityKind.PROCESS,
        identity_attributes=(
            (
                "process_guid",
                guid,
            ),
        ),
    )


def anchor() -> RelationshipAnchor:
    return RelationshipAnchor(
        anchor_type=(
            "process_guid"
        ),
        value="{ABC}",
        temporal=False,
    )


class EvidenceGraphContractTests(
    unittest.TestCase
):
    def test_identity_versions_are_explicit(
        self,
    ) -> None:
        self.assertEqual(
            ENTITY_IDENTITY_VERSION,
            1,
        )

        self.assertEqual(
            RELATIONSHIP_IDENTITY_VERSION,
            1,
        )

    def test_entity_kind_contract_is_exact(
        self,
    ) -> None:
        self.assertEqual(
            {
                item.value
                for item
                in EntityKind
            },
            {
                "ARTIFACT",
                "OBSERVATION",
                "HOST",
                "PRINCIPAL",
                "PROCESS",
                "SCRIPT",
                "FILE",
                "MESSAGE",
                "HASH",
                "IP",
                "DOMAIN",
                "ENDPOINT",
                "FLOW",
                "REGISTRY",
                "CONFIG",
                "DETECTION",
                "HYPOTHESIS",
                "FINDING",
                "RESPONSE_ACTION",
            },
        )

    def test_relationship_type_contract_is_exact(
        self,
    ) -> None:
        self.assertEqual(
            {
                item.value
                for item
                in RelationshipType
            },
            {
                "DERIVED_FROM",
                "OBSERVED_ON",
                "SENT_TO",
                "CONTAINS_ATTACHMENT",
                "IDENTIFIED_BY_HASH",
                "EXECUTED",
                "PARENT_OF",
                "INITIATED_CONNECTION",
                "CONNECTED_TO",
                "RESOLVED_TO",
                "MODIFIED",
                "CORROBORATES",
                "CONTRADICTS",
                "SUPPORTS_HYPOTHESIS",
                "FALSIFIES_HYPOTHESIS",
            },
        )

    def test_entity_identity_is_deterministic_and_order_independent(
        self,
    ) -> None:
        first = Entity.create(
            kind=(
                EntityKind.PROCESS
            ),
            identity_attributes=(
                (
                    "host",
                    "HOST-1",
                ),
                (
                    "process_guid",
                    "{ABC}",
                ),
            ),
        )

        second = Entity.create(
            kind=(
                EntityKind.PROCESS
            ),
            identity_attributes=(
                (
                    "process_guid",
                    "{ABC}",
                ),
                (
                    "host",
                    "HOST-1",
                ),
            ),
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertTrue(
            first.entity_id.startswith(
                "ent_"
            )
        )

    def test_entity_identity_changes_when_identity_changes(
        self,
    ) -> None:
        self.assertNotEqual(
            host_entity(
                "HOST-1"
            ).entity_id,
            host_entity(
                "HOST-2"
            ).entity_id,
        )

    def test_entity_requires_nonempty_identity_attributes(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            Entity.create(
                kind=EntityKind.HOST,
                identity_attributes=(),
            )

    def test_entity_rejects_duplicate_identity_keys(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            Entity.create(
                kind=EntityKind.HOST,
                identity_attributes=(
                    (
                        "hostname",
                        "HOST-1",
                    ),
                    (
                        "hostname",
                        "HOST-2",
                    ),
                ),
            )

    def test_entity_is_immutable(
        self,
    ) -> None:
        entity = host_entity()

        with self.assertRaises(
            dataclasses.FrozenInstanceError
        ):
            entity.display_name = (
                "changed"
            )

    def test_relationship_is_deterministic(
        self,
    ) -> None:
        host = host_entity()
        process = process_entity()

        first = Relationship.create(
            relationship_type=(
                RelationshipType.OBSERVED_ON
            ),
            source_entity_id=(
                process.entity_id
            ),
            target_entity_id=(
                host.entity_id
            ),
            predicate_version="1",
            supporting_ids=(
                "evt-2",
                "evt-1",
            ),
            anchors=(
                anchor(),
            ),
            evidence_state=(
                EvidenceState.OBSERVED
            ),
        )

        second = Relationship.create(
            relationship_type=(
                RelationshipType.OBSERVED_ON
            ),
            source_entity_id=(
                process.entity_id
            ),
            target_entity_id=(
                host.entity_id
            ),
            predicate_version="1",
            supporting_ids=(
                "evt-1",
                "evt-2",
            ),
            anchors=(
                anchor(),
            ),
            evidence_state=(
                EvidenceState.OBSERVED
            ),
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertTrue(
            first.relationship_id.startswith(
                "rel_"
            )
        )

    def test_relationship_id_is_semantic_not_confidence_identity(
        self,
    ) -> None:
        host = host_entity()
        process = process_entity()

        observed = Relationship.create(
            relationship_type=(
                RelationshipType.OBSERVED_ON
            ),
            source_entity_id=(
                process.entity_id
            ),
            target_entity_id=(
                host.entity_id
            ),
            predicate_version="1",
            supporting_ids=(
                "evt-1",
            ),
            anchors=(
                anchor(),
            ),
            evidence_state=(
                EvidenceState.OBSERVED
            ),
        )

        corroborated = Relationship.create(
            relationship_type=(
                RelationshipType.OBSERVED_ON
            ),
            source_entity_id=(
                process.entity_id
            ),
            target_entity_id=(
                host.entity_id
            ),
            predicate_version="1",
            supporting_ids=(
                "evt-1",
                "evt-2",
            ),
            anchors=(
                anchor(),
            ),
            evidence_state=(
                EvidenceState.CORROBORATED
            ),
        )

        self.assertEqual(
            observed.relationship_id,
            corroborated.relationship_id,
        )

    def test_relationship_requires_supporting_evidence(
        self,
    ) -> None:
        host = host_entity()
        process = process_entity()

        with self.assertRaises(
            ValueError
        ):
            Relationship.create(
                relationship_type=(
                    RelationshipType.OBSERVED_ON
                ),
                source_entity_id=(
                    process.entity_id
                ),
                target_entity_id=(
                    host.entity_id
                ),
                predicate_version="1",
                supporting_ids=(),
                anchors=(
                    anchor(),
                ),
                evidence_state=(
                    EvidenceState.OBSERVED
                ),
            )

    def test_relationship_supporting_ids_are_unique(
        self,
    ) -> None:
        host = host_entity()
        process = process_entity()

        with self.assertRaises(
            ValueError
        ):
            Relationship.create(
                relationship_type=(
                    RelationshipType.OBSERVED_ON
                ),
                source_entity_id=(
                    process.entity_id
                ),
                target_entity_id=(
                    host.entity_id
                ),
                predicate_version="1",
                supporting_ids=(
                    "evt-1",
                    "evt-1",
                ),
                anchors=(
                    anchor(),
                ),
                evidence_state=(
                    EvidenceState.OBSERVED
                ),
            )

    def test_timestamp_only_relationship_is_rejected(
        self,
    ) -> None:
        host = host_entity()
        process = process_entity()

        temporal = (
            RelationshipAnchor(
                anchor_type=(
                    "timestamp_proximity"
                ),
                value="2.0s",
                temporal=True,
            )
        )

        with self.assertRaises(
            ValueError
        ):
            Relationship.create(
                relationship_type=(
                    RelationshipType.CORROBORATES
                ),
                source_entity_id=(
                    process.entity_id
                ),
                target_entity_id=(
                    host.entity_id
                ),
                predicate_version="1",
                supporting_ids=(
                    "evt-1",
                    "evt-2",
                ),
                anchors=(
                    temporal,
                ),
                evidence_state=(
                    EvidenceState.CORROBORATED
                ),
            )

    def test_time_support_may_supplement_non_temporal_anchor(
        self,
    ) -> None:
        host = host_entity()
        process = process_entity()

        time_support = (
            RelationshipTimeSupport(
                source_clock_state=(
                    ClockState.OBSERVED
                ),
                target_clock_state=(
                    ClockState.OBSERVED
                ),
                delta_seconds=2.5,
                tolerance_seconds=30.0,
                method=(
                    "observed_utc_delta"
                ),
            )
        )

        relationship = (
            Relationship.create(
                relationship_type=(
                    RelationshipType.CORROBORATES
                ),
                source_entity_id=(
                    process.entity_id
                ),
                target_entity_id=(
                    host.entity_id
                ),
                predicate_version="1",
                supporting_ids=(
                    "evt-1",
                    "evt-2",
                ),
                anchors=(
                    anchor(),
                    RelationshipAnchor(
                        anchor_type=(
                            "timestamp_proximity"
                        ),
                        value="2.5s",
                        temporal=True,
                    ),
                ),
                evidence_state=(
                    EvidenceState.CORROBORATED
                ),
                time_support=(
                    time_support
                ),
            )
        )

        self.assertEqual(
            relationship.time_support,
            time_support,
        )

    def test_negative_time_tolerance_is_rejected(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            RelationshipTimeSupport(
                source_clock_state=(
                    ClockState.OBSERVED
                ),
                target_clock_state=(
                    ClockState.OBSERVED
                ),
                delta_seconds=1.0,
                tolerance_seconds=-1.0,
                method="test",
            )

    def test_inferred_relationship_requires_rationale(
        self,
    ) -> None:
        host = host_entity()
        process = process_entity()

        with self.assertRaises(
            ValueError
        ):
            Relationship.create(
                relationship_type=(
                    RelationshipType.CORROBORATES
                ),
                source_entity_id=(
                    process.entity_id
                ),
                target_entity_id=(
                    host.entity_id
                ),
                predicate_version="1",
                supporting_ids=(
                    "evt-1",
                ),
                anchors=(
                    anchor(),
                ),
                evidence_state=(
                    EvidenceState.INFERRED
                ),
            )

    def test_non_assertion_states_do_not_create_edges(
        self,
    ) -> None:
        host = host_entity()
        process = process_entity()

        for state in (
            EvidenceState.SEARCH_NOT_CLOSED,
            EvidenceState.NOT_ESTABLISHED,
        ):
            with self.subTest(
                state=state
            ):
                with self.assertRaises(
                    ValueError
                ):
                    Relationship.create(
                        relationship_type=(
                            RelationshipType.CORROBORATES
                        ),
                        source_entity_id=(
                            process.entity_id
                        ),
                        target_entity_id=(
                            host.entity_id
                        ),
                        predicate_version="1",
                        supporting_ids=(
                            "evt-1",
                        ),
                        anchors=(
                            anchor(),
                        ),
                        evidence_state=state,
                        rationale=(
                            "not asserted"
                        ),
                    )

    def test_self_relationship_is_rejected(
        self,
    ) -> None:
        host = host_entity()

        with self.assertRaises(
            ValueError
        ):
            Relationship.create(
                relationship_type=(
                    RelationshipType.OBSERVED_ON
                ),
                source_entity_id=(
                    host.entity_id
                ),
                target_entity_id=(
                    host.entity_id
                ),
                predicate_version="1",
                supporting_ids=(
                    "evt-1",
                ),
                anchors=(
                    anchor(),
                ),
                evidence_state=(
                    EvidenceState.OBSERVED
                ),
            )

    def test_relationship_is_immutable(
        self,
    ) -> None:
        host = host_entity()
        process = process_entity()

        relationship = (
            Relationship.create(
                relationship_type=(
                    RelationshipType.OBSERVED_ON
                ),
                source_entity_id=(
                    process.entity_id
                ),
                target_entity_id=(
                    host.entity_id
                ),
                predicate_version="1",
                supporting_ids=(
                    "evt-1",
                ),
                anchors=(
                    anchor(),
                ),
                evidence_state=(
                    EvidenceState.OBSERVED
                ),
            )
        )

        with self.assertRaises(
            dataclasses.FrozenInstanceError
        ):
            relationship.rationale = (
                "changed"
            )

    def test_serialization_has_no_numeric_confidence(
        self,
    ) -> None:
        host = host_entity()
        process = process_entity()

        relationship = (
            Relationship.create(
                relationship_type=(
                    RelationshipType.OBSERVED_ON
                ),
                source_entity_id=(
                    process.entity_id
                ),
                target_entity_id=(
                    host.entity_id
                ),
                predicate_version="1",
                supporting_ids=(
                    "evt-1",
                ),
                anchors=(
                    anchor(),
                ),
                evidence_state=(
                    EvidenceState.OBSERVED
                ),
                alternative_or_falsifier=(
                    "Process identity mismatch "
                    "would falsify this relation."
                ),
            )
        )

        serialized = (
            relationship.to_dict()
        )

        self.assertNotIn(
            "confidence",
            serialized,
        )

        self.assertNotIn(
            "score",
            serialized,
        )

        self.assertEqual(
            serialized[
                "evidence_state"
            ],
            "OBSERVED",
        )

        self.assertEqual(
            serialized[
                "alternative_or_falsifier"
            ],
            (
                "Process identity mismatch "
                "would falsify this relation."
            ),
        )


if __name__ == "__main__":
    unittest.main()
