from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from tracesoc.evidence.identity import compute_event_id
from tracesoc.models import (
    CanonicalEvent,
    ClockState,
    RawLocator,
    SemanticEvent,
    SourceType,
)


RAW_A = "a" * 64
RAW_B = "b" * 64


def locator(**overrides: object) -> RawLocator:
    values = {
        "logical_source": "fixtures/tiny/sysmon.jsonl",
        "record_index": 0,
        "line_number": 1,
        "byte_offset": 0,
        "byte_length": 128,
        "raw_sha256": RAW_A,
        "adapter_id": "sysmon-json-v1",
        "input_schema_version": "1",
    }
    values.update(overrides)
    return RawLocator(**values)


class RawLocatorTests(unittest.TestCase):
    def test_raw_locator_rejects_absolute_path(self) -> None:
        with self.assertRaises(ValueError):
            locator(logical_source=r"C:\evidence\sysmon.jsonl")

    def test_raw_locator_normalizes_sha256(self) -> None:
        item = locator(raw_sha256=("A" * 64))
        self.assertEqual(item.raw_sha256, RAW_A)
        self.assertEqual(
            item.logical_source,
            "fixtures/tiny/sysmon.jsonl",
        )


class EventIdentityTests(unittest.TestCase):
    def test_event_id_is_deterministic(self) -> None:
        item = locator()

        first = compute_event_id(
            locator=item,
            source_type=SourceType.SYSMON,
            event_type="process_create",
        )

        second = compute_event_id(
            locator=item,
            source_type=SourceType.SYSMON,
            event_type="process_create",
        )

        self.assertEqual(first, second)
        self.assertTrue(first.startswith("evt_"))
        self.assertEqual(len(first), 68)

    def test_event_id_changes_when_raw_evidence_changes(self) -> None:
        first = compute_event_id(
            locator=locator(raw_sha256=RAW_A),
            source_type=SourceType.SYSMON,
            event_type="process_create",
        )

        second = compute_event_id(
            locator=locator(raw_sha256=RAW_B),
            source_type=SourceType.SYSMON,
            event_type="process_create",
        )

        self.assertNotEqual(first, second)


class CanonicalEventTests(unittest.TestCase):
    def test_observed_event_requires_utc_time(self) -> None:
        event_id = compute_event_id(
            locator=locator(),
            source_type=SourceType.SYSMON,
            event_type="process_create",
        )

        with self.assertRaises(ValueError):
            CanonicalEvent(
                event_id=event_id,
                source_type=SourceType.SYSMON,
                event_type="process_create",
                clock_state=ClockState.OBSERVED,
                provenance=locator(),
                event_time_utc=None,
            )

        with self.assertRaises(ValueError):
            CanonicalEvent(
                event_id=event_id,
                source_type=SourceType.SYSMON,
                event_type="process_create",
                clock_state=ClockState.OBSERVED,
                provenance=locator(),
                event_time_utc=datetime(
                    2026,
                    9,
                    14,
                    10,
                    0,
                    tzinfo=timezone(timedelta(hours=1)),
                ),
            )

    def test_untimed_event_rejects_utc_time(self) -> None:
        event_id = compute_event_id(
            locator=locator(),
            source_type=SourceType.ZEEK,
            event_type="network_observation",
        )

        with self.assertRaises(ValueError):
            CanonicalEvent(
                event_id=event_id,
                source_type=SourceType.ZEEK,
                event_type="network_observation",
                clock_state=ClockState.UNTIMED,
                provenance=locator(),
                event_time_utc=datetime(
                    2026,
                    9,
                    14,
                    10,
                    0,
                    tzinfo=timezone.utc,
                ),
            )

    def test_semantic_event_excludes_source_context_and_provenance(self) -> None:
        raw_locator = locator()

        event_id = compute_event_id(
            locator=raw_locator,
            source_type=SourceType.POWERSHELL,
            event_type="script_execution",
        )

        canonical = CanonicalEvent(
            event_id=event_id,
            source_type=SourceType.POWERSHELL,
            event_type="script_execution",
            clock_state=ClockState.OBSERVED,
            provenance=raw_locator,
            event_time_raw="2026-09-14T10:00:00Z",
            event_time_utc=datetime(
                2026,
                9,
                14,
                10,
                0,
                tzinfo=timezone.utc,
            ),
            host="LAB-WKS-01",
            principal=r"LAB\analyst",
            semantic_fields={
                "process_name": "powershell.exe",
                "command_family": "archive",
            },
            source_context={
                "fixture_id": "FX-001",
                "expected_answer": "alert",
                "raw_provider": "PowerShell",
            },
        )

        semantic = SemanticEvent.from_canonical(canonical)

        self.assertEqual(
            semantic.fields["process_name"],
            "powershell.exe",
        )

        self.assertNotIn(
            "fixture_id",
            semantic.fields,
        )

        self.assertNotIn(
            "expected_answer",
            semantic.fields,
        )

        self.assertFalse(
            hasattr(semantic, "provenance"),
        )

        self.assertFalse(
            hasattr(semantic, "source_context"),
        )

    def test_mapping_inputs_are_snapshotted(self) -> None:
        semantic_input = {
            "process_name": "cmd.exe",
        }

        context_input = {
            "provider": "Sysmon",
        }

        raw_locator = locator()

        event_id = compute_event_id(
            locator=raw_locator,
            source_type=SourceType.SYSMON,
            event_type="process_create",
        )

        canonical = CanonicalEvent(
            event_id=event_id,
            source_type=SourceType.SYSMON,
            event_type="process_create",
            clock_state=ClockState.OBSERVED,
            provenance=raw_locator,
            event_time_utc=datetime(
                2026,
                9,
                14,
                10,
                0,
                tzinfo=timezone.utc,
            ),
            semantic_fields=semantic_input,
            source_context=context_input,
        )

        semantic_input["process_name"] = "changed.exe"
        context_input["provider"] = "changed"

        self.assertEqual(
            canonical.semantic_fields["process_name"],
            "cmd.exe",
        )

        self.assertEqual(
            canonical.source_context["provider"],
            "Sysmon",
        )

        with self.assertRaises(TypeError):
            canonical.semantic_fields["new"] = "value"


if __name__ == "__main__":
    unittest.main()