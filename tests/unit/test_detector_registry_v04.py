from __future__ import annotations

import dataclasses
import unittest
from unittest.mock import patch

import tracesoc.detection.registry as registry

from tracesoc.detection.models import (
    DetectionResult,
    DetectionState,
)
from tracesoc.detection.registry import (
    ALL_DETECTORS,
    POWERSHELL_SCRIPT_BLOCK_DETECTORS,
    SEMANTIC_EVENT_DETECTORS,
    DetectorInputKind,
    DetectorRegistryError,
    DetectorSpec,
    evaluate_powershell_script_block,
    evaluate_semantic_event,
    get_detector_spec,
)


def no_match(
    *,
    detection_id: str,
    detection_version: str,
) -> DetectionResult:
    return DetectionResult(
        detection_id=(
            detection_id
        ),
        detection_version=(
            detection_version
        ),
        title=(
            "Synthetic registry test detector"
        ),
        state=(
            DetectionState.NO_MATCH
        ),
        reason_code=(
            "synthetic_no_match"
        ),
        rationale=(
            "Synthetic registry dispatch proof."
        ),
        contributing_event_ids=(),
    )


class DetectorRegistryV04Tests(
    unittest.TestCase
):
    def test_registry_contains_exactly_eight_detectors(
        self,
    ) -> None:
        self.assertEqual(
            len(
                ALL_DETECTORS
            ),
            8,
        )

        self.assertEqual(
            tuple(
                item.detection_id
                for item
                in ALL_DETECTORS
            ),
            (
                "TRC-DET-001",
                "TRC-DET-002",
                "TRC-DET-003",
                "TRC-DET-004",
                "TRC-DET-005",
                "TRC-DET-006",
                "TRC-DET-007",
                "TRC-DET-008",
            ),
        )

    def test_detector_ids_are_unique(
        self,
    ) -> None:
        values = tuple(
            item.detection_id
            for item
            in ALL_DETECTORS
        )

        self.assertEqual(
            len(values),
            len(
                set(values)
            ),
        )

    def test_registry_order_is_deterministic(
        self,
    ) -> None:
        self.assertEqual(
            tuple(
                item.detection_id
                for item
                in ALL_DETECTORS
            ),
            tuple(
                sorted(
                    item.detection_id
                    for item
                    in ALL_DETECTORS
                )
            ),
        )

    def test_input_family_contract_is_exact(
        self,
    ) -> None:
        self.assertEqual(
            {
                item.value
                for item
                in DetectorInputKind
            },
            {
                "semantic_event",
                "powershell_script_block",
            },
        )

    def test_event_detector_family_is_exact(
        self,
    ) -> None:
        self.assertEqual(
            tuple(
                item.detection_id
                for item
                in SEMANTIC_EVENT_DETECTORS
            ),
            (
                "TRC-DET-001",
                "TRC-DET-004",
                "TRC-DET-005",
                "TRC-DET-006",
                "TRC-DET-007",
                "TRC-DET-008",
            ),
        )

    def test_scriptblock_detector_family_is_exact(
        self,
    ) -> None:
        self.assertEqual(
            tuple(
                item.detection_id
                for item
                in POWERSHELL_SCRIPT_BLOCK_DETECTORS
            ),
            (
                "TRC-DET-002",
                "TRC-DET-003",
            ),
        )

    def test_get_detector_spec_is_exact(
        self,
    ) -> None:
        for spec in ALL_DETECTORS:
            self.assertIs(
                get_detector_spec(
                    spec.detection_id
                ),
                spec,
            )

        with self.assertRaises(
            KeyError
        ):
            get_detector_spec(
                "TRC-DET-999"
            )

    def test_specs_are_immutable(
        self,
    ) -> None:
        with self.assertRaises(
            dataclasses.FrozenInstanceError
        ):
            ALL_DETECTORS[
                0
            ].detection_id = (
                "changed"
            )

    def test_semantic_dispatch_runs_only_event_family(
        self,
    ) -> None:
        calls: list[
            str
        ] = []

        first = DetectorSpec(
            detection_id=(
                "TEST-EVENT-001"
            ),
            detection_version="1",
            input_kind=(
                DetectorInputKind.SEMANTIC_EVENT
            ),
            evaluator=lambda value: (
                calls.append(
                    "first"
                )
                or no_match(
                    detection_id=(
                        "TEST-EVENT-001"
                    ),
                    detection_version="1",
                )
            ),
        )

        second = DetectorSpec(
            detection_id=(
                "TEST-EVENT-002"
            ),
            detection_version="1",
            input_kind=(
                DetectorInputKind.SEMANTIC_EVENT
            ),
            evaluator=lambda value: (
                calls.append(
                    "second"
                )
                or no_match(
                    detection_id=(
                        "TEST-EVENT-002"
                    ),
                    detection_version="1",
                )
            ),
        )

        with patch.object(
            registry,
            "SEMANTIC_EVENT_DETECTORS",
            (
                first,
                second,
            ),
        ):
            results = (
                evaluate_semantic_event(
                    object()
                )
            )

        self.assertEqual(
            calls,
            [
                "first",
                "second",
            ],
        )

        self.assertEqual(
            tuple(
                item.detection_id
                for item
                in results
            ),
            (
                "TEST-EVENT-001",
                "TEST-EVENT-002",
            ),
        )

    def test_scriptblock_dispatch_runs_only_scriptblock_family(
        self,
    ) -> None:
        calls: list[
            str
        ] = []

        first = DetectorSpec(
            detection_id=(
                "TEST-SCRIPT-001"
            ),
            detection_version="1",
            input_kind=(
                DetectorInputKind.POWERSHELL_SCRIPT_BLOCK
            ),
            evaluator=lambda value: (
                calls.append(
                    "first"
                )
                or no_match(
                    detection_id=(
                        "TEST-SCRIPT-001"
                    ),
                    detection_version="1",
                )
            ),
        )

        with patch.object(
            registry,
            "POWERSHELL_SCRIPT_BLOCK_DETECTORS",
            (
                first,
            ),
        ):
            results = (
                evaluate_powershell_script_block(
                    object()
                )
            )

        self.assertEqual(
            calls,
            [
                "first",
            ],
        )

        self.assertEqual(
            tuple(
                item.detection_id
                for item
                in results
            ),
            (
                "TEST-SCRIPT-001",
            ),
        )

    def test_wrong_returned_detector_id_fails_closed(
        self,
    ) -> None:
        spec = DetectorSpec(
            detection_id=(
                "TRC-TEST-001"
            ),
            detection_version="1",
            input_kind=(
                DetectorInputKind.SEMANTIC_EVENT
            ),
            evaluator=lambda value: (
                no_match(
                    detection_id=(
                        "TRC-TEST-WRONG"
                    ),
                    detection_version="1",
                )
            ),
        )

        with self.assertRaises(
            DetectorRegistryError
        ):
            spec.evaluate(
                object()
            )

    def test_wrong_returned_detector_version_fails_closed(
        self,
    ) -> None:
        spec = DetectorSpec(
            detection_id=(
                "TRC-TEST-001"
            ),
            detection_version="1",
            input_kind=(
                DetectorInputKind.SEMANTIC_EVENT
            ),
            evaluator=lambda value: (
                no_match(
                    detection_id=(
                        "TRC-TEST-001"
                    ),
                    detection_version="2",
                )
            ),
        )

        with self.assertRaises(
            DetectorRegistryError
        ):
            spec.evaluate(
                object()
            )

    def test_non_detection_result_fails_closed(
        self,
    ) -> None:
        spec = DetectorSpec(
            detection_id=(
                "TRC-TEST-001"
            ),
            detection_version="1",
            input_kind=(
                DetectorInputKind.SEMANTIC_EVENT
            ),
            evaluator=lambda value: (
                object()
            ),
        )

        with self.assertRaises(
            DetectorRegistryError
        ):
            spec.evaluate(
                object()
            )

    def test_registry_has_no_case_selection_fields(
        self,
    ) -> None:
        fields = {
            field.name
            for field
            in dataclasses.fields(
                DetectorSpec
            )
        }

        forbidden = {
            "fixture",
            "fixture_id",
            "expected_answer",
            "expected_outcome",
            "case",
            "case_name",
            "source_path",
            "filename",
            "label",
        }

        self.assertTrue(
            fields.isdisjoint(
                forbidden
            )
        )

    def test_registry_does_not_change_detection_state_contract(
        self,
    ) -> None:
        self.assertEqual(
            DetectionState.MATCH.value,
            "match",
        )

        self.assertEqual(
            DetectionState.NO_MATCH.value,
            "no_match",
        )


if __name__ == "__main__":
    unittest.main()
