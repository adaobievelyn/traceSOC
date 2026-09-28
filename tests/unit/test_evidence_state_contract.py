from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from tracesoc.detection.models import (
    DetectionState,
)
from tracesoc.evidence.states import (
    EvidenceAssertion,
    EvidenceState,
)


class EvidenceStateContractTests(
    unittest.TestCase
):
    def test_state_contract_is_exact(
        self,
    ) -> None:
        self.assertEqual(
            {
                state.value
                for state in EvidenceState
            },
            {
                "OBSERVED",
                "CONFIRMED",
                "CORROBORATED",
                "INFERRED",
                "SEARCH_NOT_CLOSED",
                "NOT_ESTABLISHED",
            },
        )

    def test_detection_state_contract_is_unchanged(
        self,
    ) -> None:
        self.assertEqual(
            {
                state.name
                for state in DetectionState
            },
            {
                "MATCH",
                "NO_MATCH",
            },
        )

        self.assertEqual(
            {
                state.value
                for state in DetectionState
            },
            {
                "match",
                "no_match",
            },
        )

    def test_observed_requires_support(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            EvidenceAssertion(
                statement=(
                    "A process execution was observed."
                ),
                state=EvidenceState.OBSERVED,
            )

        assertion = EvidenceAssertion(
            statement=(
                "A process execution was observed."
            ),
            state=EvidenceState.OBSERVED,
            supporting_ids=(
                "evt_001",
            ),
        )

        self.assertEqual(
            assertion.supporting_ids,
            (
                "evt_001",
            ),
        )

    def test_confirmed_requires_support(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            EvidenceAssertion(
                statement=(
                    "The file hash is confirmed."
                ),
                state=EvidenceState.CONFIRMED,
            )

    def test_corroborated_requires_support(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            EvidenceAssertion(
                statement=(
                    "Independent telemetry corroborates the activity."
                ),
                state=(
                    EvidenceState.CORROBORATED
                ),
            )

    def test_inferred_requires_support_and_rationale(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            EvidenceAssertion(
                statement=(
                    "The activity may represent one execution chain."
                ),
                state=EvidenceState.INFERRED,
                supporting_ids=(
                    "rel_001",
                ),
            )

        assertion = EvidenceAssertion(
            statement=(
                "The activity may represent one execution chain."
            ),
            state=EvidenceState.INFERRED,
            supporting_ids=(
                "rel_001",
            ),
            rationale=(
                "The relationship is supported by "
                "non-temporal identity anchors."
            ),
        )

        self.assertIs(
            assertion.state,
            EvidenceState.INFERRED,
        )

    def test_search_not_closed_requires_rationale_but_not_support(
        self,
    ) -> None:
        assertion = EvidenceAssertion(
            statement=(
                "No additional matching activity "
                "has been established."
            ),
            state=(
                EvidenceState.SEARCH_NOT_CLOSED
            ),
            rationale=(
                "The available evidence does not "
                "close the full search denominator."
            ),
        )

        self.assertEqual(
            assertion.supporting_ids,
            (),
        )

        self.assertEqual(
            assertion.state.value,
            "SEARCH_NOT_CLOSED",
        )

    def test_not_established_requires_rationale_but_not_support(
        self,
    ) -> None:
        assertion = EvidenceAssertion(
            statement=(
                "Malicious intent is not established."
            ),
            state=(
                EvidenceState.NOT_ESTABLISHED
            ),
            rationale=(
                "Observed behavior is compatible "
                "with legitimate administration."
            ),
        )

        payload = assertion.to_dict()

        self.assertEqual(
            payload["state"],
            "NOT_ESTABLISHED",
        )

        self.assertNotEqual(
            payload["state"],
            "CONFIRMED",
        )

    def test_supporting_ids_are_unique(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            EvidenceAssertion(
                statement=(
                    "Duplicate support must fail."
                ),
                state=EvidenceState.OBSERVED,
                supporting_ids=(
                    "evt_001",
                    "evt_001",
                ),
            )

    def test_supporting_ids_are_deterministically_sorted(
        self,
    ) -> None:
        assertion = EvidenceAssertion(
            statement=(
                "Two observations support this claim."
            ),
            state=(
                EvidenceState.CORROBORATED
            ),
            supporting_ids=(
                "evt_b",
                "evt_a",
            ),
        )

        self.assertEqual(
            assertion.supporting_ids,
            (
                "evt_a",
                "evt_b",
            ),
        )

    def test_supporting_ids_must_be_immutable_tuple(
        self,
    ) -> None:
        with self.assertRaises(
            TypeError
        ):
            EvidenceAssertion(
                statement=(
                    "Mutable support collections are rejected."
                ),
                state=EvidenceState.OBSERVED,
                supporting_ids=[
                    "evt_001",
                ],
            )

    def test_free_form_state_string_is_rejected(
        self,
    ) -> None:
        with self.assertRaises(
            TypeError
        ):
            EvidenceAssertion(
                statement=(
                    "Free-form state must not cross the contract."
                ),
                state="CONFIRMED",
                supporting_ids=(
                    "evt_001",
                ),
            )

    def test_statement_and_rationale_are_normalized(
        self,
    ) -> None:
        assertion = EvidenceAssertion(
            statement=(
                "  Malicious intent is not established.  "
            ),
            state=(
                EvidenceState.NOT_ESTABLISHED
            ),
            rationale=(
                "  Evidence remains insufficient.  "
            ),
        )

        self.assertEqual(
            assertion.statement,
            "Malicious intent is not established.",
        )

        self.assertEqual(
            assertion.rationale,
            "Evidence remains insufficient.",
        )

    def test_serialization_has_no_numeric_confidence_field(
        self,
    ) -> None:
        assertion = EvidenceAssertion(
            statement=(
                "A network connection was observed."
            ),
            state=EvidenceState.OBSERVED,
            supporting_ids=(
                "evt_001",
            ),
        )

        payload = assertion.to_dict()

        self.assertEqual(
            set(payload),
            {
                "statement",
                "state",
                "supporting_ids",
                "rationale",
            },
        )

        self.assertNotIn(
            "confidence",
            payload,
        )

        self.assertNotIn(
            "score",
            payload,
        )

    def test_assertion_is_immutable(
        self,
    ) -> None:
        assertion = EvidenceAssertion(
            statement=(
                "A process was observed."
            ),
            state=EvidenceState.OBSERVED,
            supporting_ids=(
                "evt_001",
            ),
        )

        with self.assertRaises(
            FrozenInstanceError
        ):
            assertion.statement = "changed"


if __name__ == "__main__":
    unittest.main()
