from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from tracesoc.correlation.powershell_process import (
    correlate_powershell_detection_with_sysmon_process,
)
from tracesoc.correlation.web_retrieval_network import (
    correlate_web_retrieval_with_zeek,
)
from tracesoc.multisource_scenario_003 import (
    evaluate_scenario,
    load_components,
    write_scenario_result,
)


REPO = Path(
    __file__
).resolve().parents[2]


class MultiSourceScenario003Tests(
    unittest.TestCase
):
    def test_three_source_graph_matches(
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
                "sysmon",
                "powershell",
                "zeek",
            ],
        )

        self.assertEqual(
            result["graph"][
                "node_count"
            ],
            3,
        )

        self.assertEqual(
            result["graph"][
                "edge_count"
            ],
            2,
        )

        correlation_ids = {
            edge["correlation_id"]
            for edge in result["graph"][
                "edges"
            ]
        }

        self.assertEqual(
            correlation_ids,
            {
                "TRC-CORR-001",
                "TRC-CORR-002",
            },
        )

        self.assertFalse(
            result[
                "real_incident_claim"
            ]
        )

        self.assertFalse(
            result[
                "causality_established"
            ]
        )

    def test_metadata_does_not_cross_semantic_boundary(
        self,
    ) -> None:
        components = load_components(
            REPO
        )

        for name in (
            "powershell_semantic",
            "sysmon_semantic",
            "zeek_semantic",
        ):
            semantic = components[
                name
            ]

            self.assertNotIn(
                "fixture_id",
                semantic.fields,
            )

            self.assertNotIn(
                "expected_answer",
                semantic.fields,
            )

    def test_breaking_process_edge_invalidates_chain(
        self,
    ) -> None:
        components = load_components(
            REPO
        )

        mutated_sysmon = replace(
            components[
                "sysmon_semantic"
            ],
            principal=(
                "LAB\\different-user"
            ),
        )

        process_result = (
            correlate_powershell_detection_with_sysmon_process(
                detection=components[
                    "detection"
                ],
                powershell_event=components[
                    "powershell_semantic"
                ],
                sysmon_event=mutated_sysmon,
            )
        )

        self.assertFalse(
            process_result.matched
        )

        self.assertEqual(
            process_result.reason_code,
            "principal_mismatch",
        )

    def test_breaking_network_edge_invalidates_chain(
        self,
    ) -> None:
        components = load_components(
            REPO
        )

        zeek_fields = dict(
            components[
                "zeek_semantic"
            ].fields
        )

        zeek_fields["dst_ip"] = (
            "198.51.100.200"
        )

        mutated_zeek = replace(
            components[
                "zeek_semantic"
            ],
            fields=zeek_fields,
        )

        network_result = (
            correlate_web_retrieval_with_zeek(
                detection=components[
                    "detection"
                ],
                powershell_event=components[
                    "powershell_semantic"
                ],
                zeek_event=mutated_zeek,
            )
        )

        self.assertFalse(
            network_result.matched
        )

        self.assertEqual(
            network_result.reason_code,
            "destination_ip_mismatch",
        )

    def test_network_time_falsifier_invalidates_chain(
        self,
    ) -> None:
        components = load_components(
            REPO
        )

        late_zeek = replace(
            components[
                "zeek_semantic"
            ],
            event_time_utc=(
                components[
                    "powershell_semantic"
                ].event_time_utc
                + timedelta(
                    seconds=61
                )
            ),
        )

        network_result = (
            correlate_web_retrieval_with_zeek(
                detection=components[
                    "detection"
                ],
                powershell_event=components[
                    "powershell_semantic"
                ],
                zeek_event=late_zeek,
            )
        )

        self.assertFalse(
            network_result.matched
        )

        self.assertEqual(
            network_result.reason_code,
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
