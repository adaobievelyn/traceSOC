from __future__ import annotations

import dataclasses
import unittest

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
from tracesoc.evidence.hypotheses import (
    DETECTION_RESULT_REFERENCE_VERSION,
    HYPOTHESIS_IDENTITY_VERSION,
    Hypothesis,
    HypothesisContractError,
    detection_result_reference,
)
from tracesoc.evidence.states import (
    EvidenceState,
)


def matched_detection(
    *,
    detection_id: str = "TRC-DET-001",
    event_ids: tuple[
        str,
        ...,
    ] = (
        "evt-1",
    ),
) -> DetectionResult:
    return DetectionResult(
        detection_id=detection_id,
        detection_version="1.0.0",
        title="Test detector",
        state=DetectionState.MATCH,
        reason_code="test_match",
        rationale=(
            "A bounded test behavior matched."
        ),
        contributing_event_ids=(
            event_ids
        ),
    )


def nonmatch_detection() -> DetectionResult:
    return DetectionResult(
        detection_id="TRC-DET-001",
        detection_version="1.0.0",
        title="Test detector",
        state=DetectionState.NO_MATCH,
        reason_code="test_no_match",
        rationale=(
            "The bounded behavior did not match."
        ),
        contributing_event_ids=(),
    )


def entities() -> tuple[
    Entity,
    Entity,
]:
    first = Entity.create(
        kind=EntityKind.OBSERVATION,
        identity_attributes=(
            (
                "event_id",
                "evt-1",
            ),
        ),
    )

    second = Entity.create(
        kind=EntityKind.OBSERVATION,
        identity_attributes=(
            (
                "event_id",
                "evt-2",
            ),
        ),
    )

    return (
        first,
        second,
    )


def supporting_relationship() -> Relationship:
    first, second = entities()

    return Relationship.create(
        relationship_type=(
            RelationshipType.CORROBORATES
        ),
        source_entity_id=(
            first.entity_id
        ),
        target_entity_id=(
            second.entity_id
        ),
        predicate_version=(
            "TRC-CORR-001@1.0.0"
        ),
        supporting_ids=(
            "evt-1",
            "evt-2",
        ),
        anchors=(
            RelationshipAnchor(
                anchor_type="host",
                value="host-1",
                temporal=False,
            ),
        ),
        evidence_state=(
            EvidenceState.CORROBORATED
        ),
        rationale=(
            "Two telemetry observations agree "
            "on a non-temporal host anchor."
        ),
    )


def contradiction_relationship() -> Relationship:
    first, second = entities()

    return Relationship.create(
        relationship_type=(
            RelationshipType.CONTRADICTS
        ),
        source_entity_id=(
            first.entity_id
        ),
        target_entity_id=(
            second.entity_id
        ),
        predicate_version="test@1",
        supporting_ids=(
            "evt-1",
            "evt-2",
        ),
        anchors=(
            RelationshipAnchor(
                anchor_type=(
                    "process_identity"
                ),
                value="mismatch",
                temporal=False,
            ),
        ),
        evidence_state=(
            EvidenceState.OBSERVED
        ),
        rationale=(
            "Observed identities contradict "
            "the proposed relationship."
        ),
    )


class HypothesisAggregationV04Tests(
    unittest.TestCase
):
    def test_identity_versions_are_explicit(
        self,
    ) -> None:
        self.assertEqual(
            HYPOTHESIS_IDENTITY_VERSION,
            1,
        )

        self.assertEqual(
            DETECTION_RESULT_REFERENCE_VERSION,
            1,
        )

    def test_detection_result_reference_is_deterministic(
        self,
    ) -> None:
        first = matched_detection(
            event_ids=(
                "evt-2",
                "evt-1",
            )
        )

        second = matched_detection(
            event_ids=(
                "evt-1",
                "evt-2",
            )
        )

        self.assertEqual(
            detection_result_reference(
                first
            ),
            detection_result_reference(
                second
            ),
        )

    def test_detection_result_reference_changes_with_lineage(
        self,
    ) -> None:
        first = matched_detection(
            event_ids=(
                "evt-1",
            )
        )

        second = matched_detection(
            event_ids=(
                "evt-2",
            )
        )

        self.assertNotEqual(
            detection_result_reference(
                first
            ),
            detection_result_reference(
                second
            ),
        )

    def test_nonmatch_detection_cannot_support_hypothesis(
        self,
    ) -> None:
        with self.assertRaises(
            HypothesisContractError
        ):
            Hypothesis.create(
                hypothesis_key=(
                    "test-hypothesis"
                ),
                statement=(
                    "A bounded behavior occurred."
                ),
                evidence_state=(
                    EvidenceState.INFERRED
                ),
                detections=(
                    nonmatch_detection(),
                ),
                rationale=(
                    "Test rationale."
                ),
                alternative_or_falsifier=(
                    "A benign explanation may exist."
                ),
            )

    def test_corroborated_requires_detection_and_relationship(
        self,
    ) -> None:
        with self.assertRaises(
            HypothesisContractError
        ):
            Hypothesis.create(
                hypothesis_key="test",
                statement="Test statement.",
                evidence_state=(
                    EvidenceState.CORROBORATED
                ),
                detections=(
                    matched_detection(),
                ),
            )

        with self.assertRaises(
            HypothesisContractError
        ):
            Hypothesis.create(
                hypothesis_key="test",
                statement="Test statement.",
                evidence_state=(
                    EvidenceState.CORROBORATED
                ),
                supporting_relationships=(
                    supporting_relationship(),
                ),
            )

    def test_corroborated_hypothesis_preserves_support(
        self,
    ) -> None:
        detection = (
            matched_detection()
        )

        relationship = (
            supporting_relationship()
        )

        hypothesis = (
            Hypothesis.create(
                hypothesis_key=(
                    "powershell-network"
                ),
                statement=(
                    "PowerShell retrieval behavior "
                    "is corroborated by network telemetry."
                ),
                evidence_state=(
                    EvidenceState.CORROBORATED
                ),
                detections=(
                    detection,
                ),
                supporting_relationships=(
                    relationship,
                ),
                observation_ids=(
                    "evt-2",
                    "evt-1",
                ),
                rationale=(
                    "Detector behavior and a bounded "
                    "cross-source relationship agree."
                ),
                alternative_or_falsifier=(
                    "Identity or destination mismatch "
                    "would falsify the relationship."
                ),
            )
        )

        self.assertEqual(
            hypothesis.detection_result_ids,
            (
                detection_result_reference(
                    detection
                ),
            ),
        )

        self.assertEqual(
            hypothesis.supporting_relationship_ids,
            (
                relationship.relationship_id,
            ),
        )

        self.assertEqual(
            hypothesis.observation_ids,
            (
                "evt-1",
                "evt-2",
            ),
        )

    def test_inferred_requires_support_rationale_and_falsifier(
        self,
    ) -> None:
        with self.assertRaises(
            HypothesisContractError
        ):
            Hypothesis.create(
                hypothesis_key="test",
                statement="Test statement.",
                evidence_state=(
                    EvidenceState.INFERRED
                ),
                rationale=(
                    "Rationale."
                ),
                alternative_or_falsifier=(
                    "Alternative."
                ),
            )

        with self.assertRaises(
            HypothesisContractError
        ):
            Hypothesis.create(
                hypothesis_key="test",
                statement="Test statement.",
                evidence_state=(
                    EvidenceState.INFERRED
                ),
                detections=(
                    matched_detection(),
                ),
                alternative_or_falsifier=(
                    "Alternative."
                ),
            )

        with self.assertRaises(
            HypothesisContractError
        ):
            Hypothesis.create(
                hypothesis_key="test",
                statement="Test statement.",
                evidence_state=(
                    EvidenceState.INFERRED
                ),
                detections=(
                    matched_detection(),
                ),
                rationale=(
                    "Rationale."
                ),
            )

    def test_search_not_closed_preserves_uncertainty(
        self,
    ) -> None:
        hypothesis = (
            Hypothesis.create(
                hypothesis_key=(
                    "open-search"
                ),
                statement=(
                    "Additional evidence may establish "
                    "or falsify this sequence."
                ),
                evidence_state=(
                    EvidenceState.SEARCH_NOT_CLOSED
                ),
                rationale=(
                    "The available evidence does not "
                    "close the search."
                ),
            )
        )

        self.assertIs(
            hypothesis.evidence_state,
            EvidenceState.SEARCH_NOT_CLOSED,
        )

        self.assertEqual(
            hypothesis.positive_support_ids,
            (),
        )

    def test_not_established_is_explicit(
        self,
    ) -> None:
        hypothesis = (
            Hypothesis.create(
                hypothesis_key=(
                    "not-established"
                ),
                statement=(
                    "The proposed behavior is established."
                ),
                evidence_state=(
                    EvidenceState.NOT_ESTABLISHED
                ),
                rationale=(
                    "Required supporting evidence "
                    "is absent."
                ),
            )
        )

        self.assertIs(
            hypothesis.evidence_state,
            EvidenceState.NOT_ESTABLISHED,
        )

    def test_observed_and_confirmed_are_not_hypothesis_states(
        self,
    ) -> None:
        for state in (
            EvidenceState.OBSERVED,
            EvidenceState.CONFIRMED,
        ):
            with self.subTest(
                state=state
            ):
                with self.assertRaises(
                    HypothesisContractError
                ):
                    Hypothesis.create(
                        hypothesis_key=(
                            "invalid-state"
                        ),
                        statement=(
                            "This is a hypothesis."
                        ),
                        evidence_state=state,
                        rationale=(
                            "Test."
                        ),
                    )

    def test_contradictory_relationship_is_retained(
        self,
    ) -> None:
        contradiction = (
            contradiction_relationship()
        )

        hypothesis = (
            Hypothesis.create(
                hypothesis_key=(
                    "contradicted"
                ),
                statement=(
                    "A proposed sequence occurred."
                ),
                evidence_state=(
                    EvidenceState.SEARCH_NOT_CLOSED
                ),
                contradicting_relationships=(
                    contradiction,
                ),
                rationale=(
                    "Evidence conflicts and the "
                    "search remains open."
                ),
                alternative_or_falsifier=(
                    "The contradictory identity may "
                    "represent a separate process."
                ),
            )
        )

        self.assertTrue(
            hypothesis.has_contradiction
        )

        self.assertEqual(
            hypothesis.contradicting_relationship_ids,
            (
                contradiction.relationship_id,
            ),
        )

    def test_normal_relationship_cannot_be_called_contradiction(
        self,
    ) -> None:
        with self.assertRaises(
            HypothesisContractError
        ):
            Hypothesis.create(
                hypothesis_key="test",
                statement="Test.",
                evidence_state=(
                    EvidenceState.SEARCH_NOT_CLOSED
                ),
                contradicting_relationships=(
                    supporting_relationship(),
                ),
                rationale=(
                    "Search remains open."
                ),
            )

    def test_contradiction_relationship_cannot_be_positive_support(
        self,
    ) -> None:
        with self.assertRaises(
            HypothesisContractError
        ):
            Hypothesis.create(
                hypothesis_key="test",
                statement="Test.",
                evidence_state=(
                    EvidenceState.CORROBORATED
                ),
                detections=(
                    matched_detection(),
                ),
                supporting_relationships=(
                    contradiction_relationship(),
                ),
                rationale=(
                    "Invalid support."
                ),
            )

    def test_hypothesis_identity_does_not_change_with_evidence_state(
        self,
    ) -> None:
        first = (
            Hypothesis.create(
                hypothesis_key=(
                    "same-proposition"
                ),
                statement=(
                    "The same bounded proposition."
                ),
                evidence_state=(
                    EvidenceState.INFERRED
                ),
                detections=(
                    matched_detection(),
                ),
                rationale=(
                    "One detector supports it."
                ),
                alternative_or_falsifier=(
                    "Alternative explanation."
                ),
            )
        )

        second = (
            Hypothesis.create(
                hypothesis_key=(
                    "same-proposition"
                ),
                statement=(
                    "The same bounded proposition."
                ),
                evidence_state=(
                    EvidenceState.SEARCH_NOT_CLOSED
                ),
                rationale=(
                    "The evidence search is incomplete."
                ),
            )
        )

        self.assertEqual(
            first.hypothesis_id,
            second.hypothesis_id,
        )

    def test_hypothesis_is_immutable(
        self,
    ) -> None:
        hypothesis = (
            Hypothesis.create(
                hypothesis_key="immutable",
                statement=(
                    "A bounded proposition."
                ),
                evidence_state=(
                    EvidenceState.NOT_ESTABLISHED
                ),
                rationale=(
                    "No sufficient evidence."
                ),
            )
        )

        with self.assertRaises(
            dataclasses.FrozenInstanceError
        ):
            hypothesis.statement = (
                "changed"
            )

    def test_serialization_contains_no_incident_verdict_or_score(
        self,
    ) -> None:
        hypothesis = (
            Hypothesis.create(
                hypothesis_key=(
                    "bounded"
                ),
                statement=(
                    "A bounded proposition."
                ),
                evidence_state=(
                    EvidenceState.INFERRED
                ),
                observation_ids=(
                    "evt-1",
                ),
                rationale=(
                    "One observation supports "
                    "the inference."
                ),
                alternative_or_falsifier=(
                    "Another mechanism could "
                    "produce the same observation."
                ),
            )
        )

        serialized = (
            hypothesis.to_dict()
        )

        forbidden = {
            "incident",
            "incident_id",
            "incident_verdict",
            "malicious",
            "confidence",
            "confidence_score",
            "score",
            "probability",
        }

        self.assertTrue(
            set(
                serialized
            ).isdisjoint(
                forbidden
            )
        )

        self.assertEqual(
            serialized[
                "evidence_state"
            ],
            "INFERRED",
        )


if __name__ == "__main__":
    unittest.main()
