from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path

from tracesoc.detection.models import (
    DetectionResult,
    DetectionState,
)
from tracesoc.detection.powershell_web_retrieval import (
    DETECTION_ID,
    detect_powershell_web_retrieval,
)
from tracesoc.models import SemanticEvent
from tracesoc.parsers.powershell import load_powershell_jsonl
from tracesoc.parsers.sysmon import load_sysmon_jsonl


REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "tiny"


def powershell_events() -> tuple[SemanticEvent, ...]:
    batch = load_powershell_jsonl(
        FIXTURES / "powershell.jsonl",
        logical_source="tests/fixtures/tiny/powershell.jsonl",
    )

    return tuple(
        SemanticEvent.from_canonical(event)
        for event in batch.accepted
    )


class FirstBehavioralDetectionTests(unittest.TestCase):
    def test_positive_web_retrieval_behavior_matches(self) -> None:
        candidate = powershell_events()[0]

        result = detect_powershell_web_retrieval(
            candidate
        )

        self.assertTrue(result.matched)
        self.assertEqual(
            result.detection_id,
            DETECTION_ID,
        )
        self.assertEqual(
            result.reason_code,
            "powershell_web_retrieval_observed",
        )

    def test_benign_and_archive_controls_do_not_match(self) -> None:
        events = powershell_events()

        inventory = detect_powershell_web_retrieval(
            events[1]
        )

        archive = detect_powershell_web_retrieval(
            events[2]
        )

        self.assertFalse(inventory.matched)
        self.assertFalse(archive.matched)

    def test_non_powershell_source_does_not_match(self) -> None:
        batch = load_sysmon_jsonl(
            FIXTURES / "sysmon.jsonl",
            logical_source="tests/fixtures/tiny/sysmon.jsonl",
        )

        semantic = SemanticEvent.from_canonical(
            batch.accepted[0]
        )

        result = detect_powershell_web_retrieval(
            semantic
        )

        self.assertFalse(result.matched)
        self.assertEqual(
            result.reason_code,
            "wrong_source",
        )

    def test_command_family_label_alone_does_not_trigger(self) -> None:
        benign = powershell_events()[1]

        mutated_fields = dict(benign.fields)
        mutated_fields["command_family"] = "download"
        mutated_fields["script_text"] = (
            "Get-Process | Select-Object -First 5"
        )

        mutated = replace(
            benign,
            fields=mutated_fields,
        )

        result = detect_powershell_web_retrieval(
            mutated
        )

        self.assertFalse(result.matched)
        self.assertEqual(
            result.reason_code,
            "no_retrieval_primitive",
        )

    def test_url_without_retrieval_primitive_does_not_trigger(self) -> None:
        benign = powershell_events()[1]

        mutated_fields = dict(benign.fields)
        mutated_fields["script_text"] = (
            'Write-Output "https://example.test/file.txt"'
        )

        mutated = replace(
            benign,
            fields=mutated_fields,
        )

        result = detect_powershell_web_retrieval(
            mutated
        )

        self.assertFalse(result.matched)
        self.assertEqual(
            result.reason_code,
            "no_retrieval_primitive",
        )

    def test_case_insensitive_behavior_matches(self) -> None:
        candidate = powershell_events()[0]

        mutated_fields = dict(candidate.fields)
        mutated_fields["script_text"] = (
            "invoke-webrequest HTTPS://example.test/tool.txt "
            "-OutFile C:\\Temp\\tool.txt"
        )

        mutated = replace(
            candidate,
            fields=mutated_fields,
        )

        result = detect_powershell_web_retrieval(
            mutated
        )

        self.assertTrue(result.matched)

    def test_match_carries_exact_contributing_event(self) -> None:
        candidate = powershell_events()[0]

        result = detect_powershell_web_retrieval(
            candidate
        )

        self.assertEqual(
            result.contributing_event_ids,
            (candidate.event_id,),
        )

    def test_detection_claim_is_explicitly_bounded(self) -> None:
        candidate = powershell_events()[0]

        result = detect_powershell_web_retrieval(
            candidate
        )

        self.assertIn(
            "does not establish malicious intent",
            result.rationale.lower(),
        )

        with self.assertRaises(ValueError):
            DetectionResult(
                detection_id="TEST",
                detection_version="1",
                title="Invalid match",
                state=DetectionState.MATCH,
                reason_code="invalid",
                rationale="Invalid.",
                contributing_event_ids=(),
            )


if __name__ == "__main__":
    unittest.main()