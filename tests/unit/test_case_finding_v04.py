from __future__ import annotations

import unittest

from tracesoc.evidence.findings_v04 import (
    CaseFinding,
    CaseFindingContractError,
    create_case_findings,
)
from tracesoc.evidence.hypotheses import (
    Hypothesis,
)
from tracesoc.evidence.states import (
    EvidenceState,
)


def hypothesis(
    *,
    state: EvidenceState = (
        EvidenceState.CORROBORATED
    ),
    detection_ids: tuple[
        str,
        ...,
    ] = (
        "detres_001",
    ),
    relationship_ids: tuple[
        str,
        ...,
    ] = (
        "rel_001",
    ),
    contradiction_ids: tuple[
        str,
        ...,
    ] = (),
    observation_ids: tuple[
        str,
        ...,
    ] = (
        "evt_001",
        "evt_002",
    ),
    rationale: str | None = (
        "Independent evidence agrees on "
        "the bounded observed behavior."
    ),
    alternative: str | None = (
        "A mismatch in the documented anchors "
        "would falsify this relationship."
    ),
) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=(
            "hyp_001"
        ),
        hypothesis_key=(
            "test-hypothesis"
        ),
        statement=(
            "Observed behavior is corroborated "
            "by an independent source."
        ),
        evidence_state=(
            state
        ),
        detection_result_ids=(
            detection_ids
        ),
        supporting_relationship_ids=(
            relationship_ids
        ),
        contradicting_relationship_ids=(
            contradiction_ids
        ),
        observation_ids=(
            observation_ids
        ),
        rationale=rationale,
        alternative_or_falsifier=(
            alternative
        ),
    )


class CaseFindingV04Tests(
    unittest.TestCase
):
    def test_corroborated_hypothesis_becomes_finding(
        self,
    ) -> None:
        finding = (
            CaseFinding.from_hypothesis(
                hypothesis()
            )
        )

        self.assertTrue(
            finding.finding_id.startswith(
                "fnd_"
            )
        )

        self.assertEqual(
            finding.hypothesis_id,
            "hyp_001",
        )

        self.assertEqual(
            finding.evidence_state,
            EvidenceState.CORROBORATED,
        )

        self.assertEqual(
            finding.detection_result_ids,
            (
                "detres_001",
            ),
        )

        self.assertEqual(
            finding.supporting_relationship_ids,
            (
                "rel_001",
            ),
        )

        self.assertEqual(
            finding.observation_ids,
            (
                "evt_001",
                "evt_002",
            ),
        )

    def test_finding_identity_is_deterministic(
        self,
    ) -> None:
        first = (
            CaseFinding.from_hypothesis(
                hypothesis()
            )
        )

        second = (
            CaseFinding.from_hypothesis(
                hypothesis()
            )
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            first.finding_id,
            second.finding_id,
        )

    def test_finding_requires_concrete_detection_reference(
        self,
    ) -> None:
        with self.assertRaises(
            CaseFindingContractError
        ):
            CaseFinding.from_hypothesis(
                hypothesis(
                    detection_ids=(),
                )
            )

    def test_finding_requires_relationship_support(
        self,
    ) -> None:
        with self.assertRaises(
            CaseFindingContractError
        ):
            CaseFinding.from_hypothesis(
                hypothesis(
                    relationship_ids=(),
                )
            )

    def test_finding_requires_observation_lineage(
        self,
    ) -> None:
        with self.assertRaises(
            CaseFindingContractError
        ):
            CaseFinding.from_hypothesis(
                hypothesis(
                    observation_ids=(),
                )
            )

    def test_finding_requires_rationale_and_falsifier(
        self,
    ) -> None:
        with self.assertRaises(
            CaseFindingContractError
        ):
            CaseFinding.from_hypothesis(
                hypothesis(
                    rationale=None,
                )
            )

        with self.assertRaises(
            CaseFindingContractError
        ):
            CaseFinding.from_hypothesis(
                hypothesis(
                    alternative=None,
                )
            )

    def test_non_corroborated_hypothesis_is_not_promoted(
        self,
    ) -> None:
        source = hypothesis(
            state=(
                EvidenceState.NOT_ESTABLISHED
            ),
        )

        findings = (
            create_case_findings(
                (
                    source,
                )
            )
        )

        self.assertEqual(
            findings,
            (),
        )

    def test_finding_does_not_declare_incident_or_intent(
        self,
    ) -> None:
        finding = (
            CaseFinding.from_hypothesis(
                hypothesis()
            )
        )

        self.assertEqual(
            finding.incident_status,
            EvidenceState.NOT_ESTABLISHED,
        )

        self.assertEqual(
            finding.malicious_intent_status,
            EvidenceState.NOT_ESTABLISHED,
        )

    def test_serialization_has_no_numeric_confidence(
        self,
    ) -> None:
        payload = (
            CaseFinding.from_hypothesis(
                hypothesis()
            ).to_dict()
        )

        forbidden = {
            "confidence",
            "confidence_score",
            "probability",
            "score",
        }

        self.assertTrue(
            forbidden.isdisjoint(
                payload
            )
        )

        self.assertEqual(
            payload[
                "incident_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            payload[
                "malicious_intent_status"
            ],
            "NOT_ESTABLISHED",
        )


if __name__ == "__main__":
    unittest.main()
