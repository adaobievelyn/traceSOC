from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from tracesoc.correlation.web_retrieval_network import (
    CORRELATION_ID,
    correlate_web_retrieval_with_zeek,
)
from tracesoc.detection.powershell_web_retrieval import (
    DETECTION_ID,
    detect_powershell_web_retrieval,
)
from tracesoc.findings.builders import FINDING_ID
from tracesoc.models import SemanticEvent
from tracesoc.parsers.powershell import load_powershell_jsonl
from tracesoc.parsers.zeek import load_zeek_jsonl
from tracesoc.vertical_slice import build_fixture_finding_001


REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "tiny"


def canonical_batches():
    powershell = load_powershell_jsonl(
        FIXTURES / "powershell.jsonl",
        logical_source="tests/fixtures/tiny/powershell.jsonl",
    )

    zeek = load_zeek_jsonl(
        FIXTURES / "zeek.jsonl",
        logical_source="tests/fixtures/tiny/zeek.jsonl",
    )

    return powershell, zeek


def candidate_pair():
    powershell_batch, zeek_batch = canonical_batches()

    for powershell_canonical in powershell_batch.accepted:
        powershell_semantic = SemanticEvent.from_canonical(
            powershell_canonical
        )

        detection = detect_powershell_web_retrieval(
            powershell_semantic
        )

        if not detection.matched:
            continue

        for zeek_canonical in zeek_batch.accepted:
            zeek_semantic = SemanticEvent.from_canonical(
                zeek_canonical
            )

            correlation = correlate_web_retrieval_with_zeek(
                detection=detection,
                powershell_event=powershell_semantic,
                zeek_event=zeek_semantic,
            )

            if correlation.matched:
                return (
                    powershell_canonical,
                    powershell_semantic,
                    detection,
                    zeek_canonical,
                    zeek_semantic,
                    correlation,
                )

    raise AssertionError(
        "No valid fixture correlation was found"
    )


class FirstBoundedCorrelationTests(unittest.TestCase):
    def test_positive_bounded_correlation_matches(self) -> None:
        (
            _,
            _,
            _,
            _,
            _,
            correlation,
        ) = candidate_pair()

        self.assertTrue(correlation.matched)
        self.assertEqual(
            correlation.correlation_id,
            CORRELATION_ID,
        )
        self.assertEqual(
            correlation.reason_code,
            "cross_source_retrieval_corroborated",
        )

        self.assertEqual(
            correlation.edge.matched_dimensions,
            (
                "host",
                "source_ip",
                "destination_ip",
                "destination_port",
                "directional_time_window",
            ),
        )

    def test_destination_mismatch_breaks_correlation(self) -> None:
        (
            _,
            powershell,
            detection,
            _,
            zeek,
            _,
        ) = candidate_pair()

        fields = dict(zeek.fields)
        fields["dst_ip"] = "203.0.113.77"

        mutated = replace(
            zeek,
            fields=fields,
        )

        result = correlate_web_retrieval_with_zeek(
            detection=detection,
            powershell_event=powershell,
            zeek_event=mutated,
        )

        self.assertFalse(result.matched)
        self.assertEqual(
            result.reason_code,
            "destination_ip_mismatch",
        )

    def test_source_ip_mismatch_breaks_correlation(self) -> None:
        (
            _,
            powershell,
            detection,
            _,
            zeek,
            _,
        ) = candidate_pair()

        fields = dict(zeek.fields)
        fields["src_ip"] = "10.10.20.99"

        mutated = replace(
            zeek,
            fields=fields,
        )

        result = correlate_web_retrieval_with_zeek(
            detection=detection,
            powershell_event=powershell,
            zeek_event=mutated,
        )

        self.assertFalse(result.matched)
        self.assertEqual(
            result.reason_code,
            "source_ip_mismatch",
        )

    def test_host_mismatch_breaks_correlation(self) -> None:
        (
            _,
            powershell,
            detection,
            _,
            zeek,
            _,
        ) = candidate_pair()

        mutated = replace(
            zeek,
            host="OTHER-HOST",
        )

        result = correlate_web_retrieval_with_zeek(
            detection=detection,
            powershell_event=powershell,
            zeek_event=mutated,
        )

        self.assertFalse(result.matched)
        self.assertEqual(
            result.reason_code,
            "host_mismatch",
        )

    def test_outside_time_window_breaks_correlation(self) -> None:
        (
            _,
            powershell,
            detection,
            _,
            zeek,
            _,
        ) = candidate_pair()

        mutated = replace(
            zeek,
            event_time_utc=(
                powershell.event_time_utc
                + timedelta(seconds=61)
            ),
        )

        result = correlate_web_retrieval_with_zeek(
            detection=detection,
            powershell_event=powershell,
            zeek_event=mutated,
        )

        self.assertFalse(result.matched)
        self.assertEqual(
            result.reason_code,
            "outside_time_window",
        )

    def test_network_before_behavior_breaks_correlation(self) -> None:
        (
            _,
            powershell,
            detection,
            _,
            zeek,
            _,
        ) = candidate_pair()

        mutated = replace(
            zeek,
            event_time_utc=(
                powershell.event_time_utc
                - timedelta(seconds=1)
            ),
        )

        result = correlate_web_retrieval_with_zeek(
            detection=detection,
            powershell_event=powershell,
            zeek_event=mutated,
        )

        self.assertFalse(result.matched)
        self.assertEqual(
            result.reason_code,
            "network_precedes_behavior",
        )

    def test_detection_nonmatch_prevents_correlation(self) -> None:
        powershell_batch, zeek_batch = canonical_batches()

        benign_semantic = SemanticEvent.from_canonical(
            powershell_batch.accepted[1]
        )

        detection = detect_powershell_web_retrieval(
            benign_semantic
        )

        zeek_semantic = SemanticEvent.from_canonical(
            zeek_batch.accepted[0]
        )

        result = correlate_web_retrieval_with_zeek(
            detection=detection,
            powershell_event=benign_semantic,
            zeek_event=zeek_semantic,
        )

        self.assertFalse(result.matched)
        self.assertEqual(
            result.reason_code,
            "detection_not_matched",
        )

    def test_finding_contains_exact_detection_correlation_and_evidence(self) -> None:
        finding = build_fixture_finding_001(
            REPO
        )

        self.assertEqual(
            finding.finding_id,
            FINDING_ID,
        )

        self.assertEqual(
            finding.detection_ids,
            (DETECTION_ID,),
        )

        self.assertEqual(
            finding.correlation_ids,
            (CORRELATION_ID,),
        )

        self.assertEqual(
            len(finding.correlation_edge_ids),
            1,
        )

        self.assertEqual(
            len(finding.evidence),
            2,
        )

        self.assertEqual(
            {
                item.source_type
                for item in finding.evidence
            },
            {
                "powershell",
                "zeek",
            },
        )

        for item in finding.evidence:
            self.assertEqual(
                len(item.raw_sha256),
                64,
            )

            self.assertTrue(
                item.logical_source.startswith(
                    "tests/fixtures/tiny/"
                )
            )

    def test_finding_claims_remain_bounded(self) -> None:
        finding = build_fixture_finding_001(
            REPO
        )

        self.assertFalse(
            finding.malicious_intent_established
        )

        self.assertTrue(
            finding.synthetic_fixture
        )

        self.assertIn(
            "not established",
            finding.residual_risk.lower(),
        )

        self.assertIn(
            "legitimate",
            finding.alternative_explanation.lower(),
        )

        self.assertIn(
            "must not form",
            finding.falsifier.lower(),
        )

        self.assertIn(
            "unknown",
            finding.business_impact.lower(),
        )

    def test_vertical_slice_is_deterministic(self) -> None:
        first = build_fixture_finding_001(
            REPO
        ).to_dict()

        second = build_fixture_finding_001(
            REPO
        ).to_dict()

        self.assertEqual(
            first,
            second,
        )


if __name__ == "__main__":
    unittest.main()