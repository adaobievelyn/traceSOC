from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tracesoc.evidence.intake import (
    AdapterFamily,
    classify_evidence_bytes,
    ingest_evidence_file,
)
from tracesoc.models import SourceType
from tracesoc.parsers.powershell import (
    JSON_ADAPTER_ID,
    REAL_ADAPTER_ID,
    REAL_EVENT_TYPE,
    load_powershell_windows_event_json,
    load_powershell_windows_event_xml,
)


UTC_TIME = datetime(
    2026,
    9,
    23,
    16,
    1,
    tzinfo=timezone.utc,
)


def event_data() -> dict[str, str]:
    return {
        "MessageNumber":
            "1",
        "MessageTotal":
            "1",
        "ScriptBlockText":
            "Write-Output 'RC2B representation test'",
        "ScriptBlockId":
            "11111111-2222-3333-4444-555555555555",
        "Path":
            "",
    }


def powershell_payload() -> dict[str, object]:
    return {
        "System": {
            "Provider": {
                "Name":
                    "Microsoft-Windows-PowerShell",
            },
            "EventID":
                4104,
            "EventRecordID":
                7001,
            "TimeCreated": {
                "SystemTime":
                    "2026-09-23T16:00:00.0000000Z",
            },
            "Execution": {
                "ProcessID":
                    "500",
                "ThreadID":
                    "600",
            },
            "Channel":
                "Microsoft-Windows-PowerShell/Operational",
            "Computer":
                "HOST-RC2B",
            "Security": {
                "UserID":
                    "S-1-5-21-1000",
            },
        },
        "EventData":
            event_data(),
    }


def powershell_xml() -> bytes:
    return (
        b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        b"<System>"
        b'<Provider Name="Microsoft-Windows-PowerShell"/>'
        b"<EventID>4104</EventID>"
        b"<EventRecordID>7001</EventRecordID>"
        b'<TimeCreated SystemTime="2026-09-23T16:00:00.0000000Z"/>'
        b'<Execution ProcessID="500" ThreadID="600"/>'
        b"<Channel>Microsoft-Windows-PowerShell/Operational</Channel>"
        b"<Computer>HOST-RC2B</Computer>"
        b'<Security UserID="S-1-5-21-1000"/>'
        b"</System>"
        b"<EventData>"
        b'<Data Name="MessageNumber">1</Data>'
        b'<Data Name="MessageTotal">1</Data>'
        b"<Data Name=\"ScriptBlockText\">Write-Output 'RC2B representation test'</Data>"
        b'<Data Name="ScriptBlockId">11111111-2222-3333-4444-555555555555</Data>'
        b'<Data Name="Path"></Data>'
        b"</EventData>"
        b"</Event>"
    )


class PowerShellWindowsEventJsonTests(
    unittest.TestCase
):
    def test_classifier_recognizes_powershell_windows_event_jsonl(
        self,
    ) -> None:
        raw = (
            json.dumps(
                powershell_payload(),
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        classification = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "powershell.jsonl"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.POWERSHELL_JSON,
        )

        self.assertEqual(
            classification.reason,
            "powershell_windows_event_json_profile",
        )

    def test_xml_and_json_emit_same_pre_reconstruction_event(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            xml_path = (
                root
                / "powershell.xml"
            )

            json_path = (
                root
                / "powershell.jsonl"
            )

            xml_path.write_bytes(
                powershell_xml()
            )

            json_path.write_bytes(
                json.dumps(
                    powershell_payload(),
                    separators=(",", ":"),
                ).encode(
                    "utf-8"
                )
                + b"\n"
            )

            xml_batch = (
                load_powershell_windows_event_xml(
                    xml_path,
                    logical_source=(
                        "powershell.xml"
                    ),
                )
            )

            json_batch = (
                load_powershell_windows_event_json(
                    json_path,
                    logical_source=(
                        "powershell.jsonl"
                    ),
                )
            )

        self.assertEqual(
            xml_batch.accepted_count,
            1,
        )

        self.assertEqual(
            json_batch.accepted_count,
            1,
        )

        self.assertEqual(
            xml_batch.quarantined_count,
            0,
        )

        self.assertEqual(
            json_batch.quarantined_count,
            0,
        )

        xml_event = (
            xml_batch.accepted[0]
        )

        json_event = (
            json_batch.accepted[0]
        )

        self.assertIs(
            xml_event.source_type,
            SourceType.POWERSHELL,
        )

        self.assertIs(
            json_event.source_type,
            SourceType.POWERSHELL,
        )

        self.assertEqual(
            xml_event.event_type,
            REAL_EVENT_TYPE,
        )

        self.assertEqual(
            json_event.event_type,
            REAL_EVENT_TYPE,
        )

        self.assertEqual(
            xml_event.event_type,
            json_event.event_type,
        )

        self.assertEqual(
            xml_event.clock_state,
            json_event.clock_state,
        )

        self.assertEqual(
            xml_event.event_time_raw,
            json_event.event_time_raw,
        )

        self.assertEqual(
            xml_event.event_time_utc,
            json_event.event_time_utc,
        )

        self.assertEqual(
            xml_event.host,
            json_event.host,
        )

        self.assertEqual(
            xml_event.principal,
            json_event.principal,
        )

        self.assertEqual(
            xml_event.semantic_fields,
            json_event.semantic_fields,
        )

        self.assertEqual(
            xml_event.source_context,
            json_event.source_context,
        )

        self.assertNotEqual(
            xml_event.event_id,
            json_event.event_id,
        )

        self.assertNotEqual(
            xml_event.provenance.raw_sha256,
            json_event.provenance.raw_sha256,
        )

        self.assertEqual(
            xml_event.provenance.adapter_id,
            REAL_ADAPTER_ID,
        )

        self.assertEqual(
            json_event.provenance.adapter_id,
            JSON_ADAPTER_ID,
        )

        self.assertEqual(
            json_event.semantic_fields,
            {},
        )

        self.assertIsNone(
            json_event.principal
        )

        self.assertEqual(
            json_event.source_context[
                "event_code"
            ],
            4104,
        )

        self.assertEqual(
            json_event.source_context[
                "execution_process_id"
            ],
            "500",
        )

        self.assertEqual(
            json_event.source_context[
                "execution_thread_id"
            ],
            "600",
        )

        self.assertEqual(
            json_event.source_context[
                "security_user_id"
            ],
            "S-1-5-21-1000",
        )

    def test_generic_intake_routes_powershell_jsonl_without_mutating_source(
        self,
    ) -> None:
        raw = (
            json.dumps(
                powershell_payload(),
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "powershell.jsonl"
            )

            path.write_bytes(
                raw
            )

            before = (
                path.read_bytes()
            )

            result = (
                ingest_evidence_file(
                    path,
                    root=root,
                    acquired_or_observed_utc=(
                        UTC_TIME
                    ),
                )
            )

            after = (
                path.read_bytes()
            )

        self.assertEqual(
            before,
            after,
        )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.POWERSHELL_JSON,
        )

        self.assertEqual(
            len(
                result.canonical_events
            ),
            1,
        )

        self.assertEqual(
            result.canonical_events[
                0
            ].event_type,
            REAL_EVENT_TYPE,
        )

        self.assertEqual(
            len(
                result.evidence_locators
            ),
            1,
        )

    def test_single_json_object_uses_same_powershell_profile(
        self,
    ) -> None:
        raw = json.dumps(
            powershell_payload(),
            separators=(",", ":"),
        ).encode(
            "utf-8"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "powershell.json"
            )

            path.write_bytes(
                raw
            )

            result = (
                ingest_evidence_file(
                    path,
                    root=root,
                    acquired_or_observed_utc=(
                        UTC_TIME
                    ),
                )
            )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.POWERSHELL_JSON,
        )

        self.assertEqual(
            len(
                result.canonical_events
            ),
            1,
        )

    def test_4104_missing_execution_identity_is_quarantined(
        self,
    ) -> None:
        payload = (
            powershell_payload()
        )

        system = payload[
            "System"
        ]

        assert isinstance(
            system,
            dict,
        )

        execution = system[
            "Execution"
        ]

        assert isinstance(
            execution,
            dict,
        )

        del execution[
            "ThreadID"
        ]

        raw = (
            json.dumps(
                payload,
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "powershell.jsonl"
            )

            path.write_bytes(
                raw
            )

            result = (
                ingest_evidence_file(
                    path,
                    root=root,
                    acquired_or_observed_utc=(
                        UTC_TIME
                    ),
                )
            )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.POWERSHELL_JSON,
        )

        self.assertEqual(
            len(
                result.canonical_events
            ),
            0,
        )

        self.assertEqual(
            result.issue_count,
            1,
        )

    def test_old_compatibility_jsonl_is_not_native_profile(
        self,
    ) -> None:
        old = {
            "provider":
                "Microsoft-Windows-PowerShell",
            "event_code":
                4104,
            "event_type":
                "script_execution",
            "timestamp":
                "2026-09-23T16:00:00Z",
            "host":
                "HOST-RC2B",
            "principal":
                r"DOMAIN\User1",
            "engine":
                "powershell",
            "command_family":
                "web",
            "script_text":
                "Write-Output legacy",
            "local_ip":
                "10.0.0.5",
        }

        raw = (
            json.dumps(
                old,
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        classification = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "legacy-powershell.jsonl"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.UNSUPPORTED,
        )

        self.assertEqual(
            classification.reason,
            "no_supported_json_profile",
        )


if __name__ == "__main__":
    unittest.main()
