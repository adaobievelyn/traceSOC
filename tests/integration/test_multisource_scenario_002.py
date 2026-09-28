from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from tracesoc.correlation.powershell_process import (
    CORRELATION_ID,
    correlate_powershell_detection_with_sysmon_process,
)
from tracesoc.multisource_scenario_002 import (
    evaluate_scenario,
    load_scenario_components,
    write_scenario_result,
)


REPO = Path(
    __file__
).resolve().parents[2]


class MultiSourceScenario002Tests(
    unittest.TestCase
):
    def test_positive_distinct_correlation_matches(
        self,
    ) -> None:
        result = evaluate_scenario(
            REPO
        )

        self.assertEqual(
            result["validation_status"],
            "PASS",
        )

        self.assertEqual(
            result["correlation"][
                "correlation_id"
            ],
            CORRELATION_ID,
        )

        self.assertEqual(
            result["telemetry_families"],
            [
                "sysmon",
                "powershell",
            ],
        )

        self.assertTrue(
            result["detection"]["matched"]
        )

        self.assertTrue(
            result["correlation"]["matched"]
        )

        self.assertFalse(
            result[
                "exact_pid_ancestry_established"
            ]
        )

        self.assertFalse(
            result["causality_established"]
        )

        self.assertFalse(
            result["real_incident_claim"]
        )

    def test_test_metadata_does_not_cross_semantic_boundary(
        self,
    ) -> None:
        components = load_scenario_components(
            REPO
        )

        for semantic in (
            components.powershell_semantic,
            components.sysmon_semantic,
        ):
            self.assertNotIn(
                "fixture_id",
                semantic.fields,
            )

            self.assertNotIn(
                "expected_answer",
                semantic.fields,
            )

    def test_detection_event_mismatch_falsifies_correlation(
        self,
    ) -> None:
        components = load_scenario_components(
            REPO
        )

        self.assertTrue(
            components.detection.matched
        )

        self.assertIn(
            components.powershell_semantic.event_id,
            components.detection.contributing_event_ids,
        )

        self.assertNotEqual(
            components.sysmon_semantic.event_id,
            components.powershell_semantic.event_id,
        )

        mismatched_detection = replace(
            components.detection,
            contributing_event_ids=(
                components.sysmon_semantic.event_id,
            ),
        )

        self.assertNotIn(
            components.powershell_semantic.event_id,
            mismatched_detection.contributing_event_ids,
        )

        result = (
            correlate_powershell_detection_with_sysmon_process(
                detection=mismatched_detection,
                powershell_event=(
                    components.powershell_semantic
                ),
                sysmon_event=(
                    components.sysmon_semantic
                ),
            )
        )

        self.assertFalse(
            result.matched,
            "CORR002_BINDING_FALSIFIER_EXPECTED_NO_MATCH",
        )

        self.assertEqual(
            result.reason_code,
            "detection_event_mismatch",
        )
    def test_principal_mismatch_falsifies_correlation(
        self,
    ) -> None:
        components = load_scenario_components(
            REPO
        )

        mutated = replace(
            components.sysmon_semantic,
            principal="LAB\\different-user",
        )

        result = (
            correlate_powershell_detection_with_sysmon_process(
                detection=components.detection,
                powershell_event=(
                    components
                    .powershell_semantic
                ),
                sysmon_event=mutated,
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "principal_mismatch",
        )

    def test_local_ip_mismatch_falsifies_correlation(
        self,
    ) -> None:
        components = load_scenario_components(
            REPO
        )

        fields = dict(
            components.sysmon_semantic.fields
        )

        fields["local_ip"] = (
            "10.88.5.99"
        )

        mutated = replace(
            components.sysmon_semantic,
            fields=fields,
        )

        result = (
            correlate_powershell_detection_with_sysmon_process(
                detection=components.detection,
                powershell_event=(
                    components
                    .powershell_semantic
                ),
                sysmon_event=mutated,
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "local_ip_mismatch",
        )

    def test_non_powershell_process_falsifies_correlation(
        self,
    ) -> None:
        components = load_scenario_components(
            REPO
        )

        fields = dict(
            components.sysmon_semantic.fields
        )

        fields["process_name"] = (
            r"C:\Windows\System32\cmd.exe"
        )

        mutated = replace(
            components.sysmon_semantic,
            fields=fields,
        )

        result = (
            correlate_powershell_detection_with_sysmon_process(
                detection=components.detection,
                powershell_event=(
                    components
                    .powershell_semantic
                ),
                sysmon_event=mutated,
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "process_family_mismatch",
        )

    def test_direction_and_window_are_bounded(
        self,
    ) -> None:
        components = load_scenario_components(
            REPO
        )

        after_behavior = replace(
            components.sysmon_semantic,
            event_time_utc=(
                components
                .powershell_semantic
                .event_time_utc
                + timedelta(
                    seconds=1
                )
            ),
        )

        result = (
            correlate_powershell_detection_with_sysmon_process(
                detection=components.detection,
                powershell_event=(
                    components
                    .powershell_semantic
                ),
                sysmon_event=after_behavior,
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "process_creation_after_behavior",
        )

        too_early = replace(
            components.sysmon_semantic,
            event_time_utc=(
                components
                .powershell_semantic
                .event_time_utc
                - timedelta(
                    seconds=31
                )
            ),
        )

        result = (
            correlate_powershell_detection_with_sysmon_process(
                detection=components.detection,
                powershell_event=(
                    components
                    .powershell_semantic
                ),
                sysmon_event=too_early,
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "outside_time_window",
        )

    def test_result_is_deterministic_and_exclusive_create(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            first = root / "first.json"
            second = root / "second.json"

            write_scenario_result(
                REPO,
                first,
            )

            write_scenario_result(
                REPO,
                second,
            )

            self.assertEqual(
                first.read_bytes(),
                second.read_bytes(),
            )

            original = first.read_bytes()

            with self.assertRaises(
                FileExistsError
            ):
                write_scenario_result(
                    REPO,
                    first,
                )

            self.assertEqual(
                first.read_bytes(),
                original,
            )


if __name__ == "__main__":
    unittest.main()
