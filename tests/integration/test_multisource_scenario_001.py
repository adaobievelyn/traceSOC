from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from tracesoc.correlation.web_retrieval_network import (
    correlate_web_retrieval_with_zeek,
)
from tracesoc.multisource_scenarios import (
    evaluate_scenario,
    load_scenario_components,
    write_scenario_result,
)


REPO = Path(
    __file__
).resolve().parents[2]


class MultiSourceScenario001Tests(
    unittest.TestCase
):
    def test_scenario_matches_production_contract(
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
            result["telemetry_families"],
            [
                "powershell",
                "zeek",
            ],
        )

        self.assertTrue(
            result["detection"]["matched"]
        )

        self.assertTrue(
            result["correlation"]["matched"]
        )

        self.assertEqual(
            result["correlation"][
                "matched_dimensions"
            ],
            [
                "host",
                "source_ip",
                "destination_ip",
                "destination_port",
                "directional_time_window",
            ],
        )

        self.assertFalse(
            result["real_incident_claim"]
        )

        self.assertFalse(
            result[
                "malicious_intent_established"
            ]
        )

    def test_fixture_metadata_does_not_cross_semantic_boundary(
        self,
    ) -> None:
        components = load_scenario_components(
            REPO
        )

        for semantic in (
            components.powershell_semantic,
            components.zeek_semantic,
        ):
            self.assertNotIn(
                "fixture_id",
                semantic.fields,
            )

            self.assertNotIn(
                "expected_answer",
                semantic.fields,
            )

    def test_wrong_host_falsifies_correlation(
        self,
    ) -> None:
        components = load_scenario_components(
            REPO
        )

        wrong_host = replace(
            components.zeek_semantic,
            host="SYN-WKS-DIFFERENT",
        )

        result = (
            correlate_web_retrieval_with_zeek(
                detection=components.detection,
                powershell_event=(
                    components
                    .powershell_semantic
                ),
                zeek_event=wrong_host,
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "host_mismatch",
        )

    def test_outside_window_falsifies_correlation(
        self,
    ) -> None:
        components = load_scenario_components(
            REPO
        )

        outside = replace(
            components.zeek_semantic,
            event_time_utc=(
                components
                .powershell_semantic
                .event_time_utc
                + timedelta(
                    seconds=61
                )
            ),
        )

        result = (
            correlate_web_retrieval_with_zeek(
                detection=components.detection,
                powershell_event=(
                    components
                    .powershell_semantic
                ),
                zeek_event=outside,
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
