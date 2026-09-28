from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tracesoc.evidence.artifacts import (
    ArtifactProcessingState,
)
from tracesoc.evidence.intake import (
    AdapterFamily,
    classify_evidence_bytes,
    ingest_evidence_file,
)
from tracesoc.models import SourceType
from tracesoc.parsers.sysmon import (
    JSON_ADAPTER_ID,
    REAL_ADAPTER_ID,
    load_sysmon_windows_event_json,
    load_sysmon_windows_event_xml,
)


UTC_TIME = datetime(
    2026,
    9,
    23,
    12,
    30,
    tzinfo=timezone.utc,
)


def sysmon_event_payload() -> dict[str, object]:
    return {
        "System": {
            "Provider": {
                "Name":
                    "Microsoft-Windows-Sysmon",
            },
            "EventID": 1,
            "EventRecordID": 4242,
            "TimeCreated": {
                "SystemTime":
                    "2026-09-23T12:00:00.1234567Z",
            },
            "Computer":
                "HOST-RC2A",
            "Channel":
                "Microsoft-Windows-Sysmon/Operational",
        },
        "EventData": {
            "UtcTime":
                "2026-09-23 12:00:00.123",
            "ProcessGuid":
                "{11111111-2222-3333-4444-555555555555}",
            "ProcessId":
                "500",
            "Image":
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine":
                "powershell.exe -NoProfile",
            "User":
                r"DOMAIN\User1",
            "ParentProcessGuid":
                "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
            "ParentProcessId":
                "100",
            "ParentImage":
                r"C:\Windows\explorer.exe",
            "ParentCommandLine":
                "C:\\Windows\\explorer.exe",
        },
    }


def equivalent_sysmon_xml() -> bytes:
    return (
        b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        b"<System>"
        b'<Provider Name="Microsoft-Windows-Sysmon"/>'
        b"<EventID>1</EventID>"
        b"<EventRecordID>4242</EventRecordID>"
        b'<TimeCreated SystemTime="2026-09-23T12:00:00.1234567Z"/>'
        b"<Computer>HOST-RC2A</Computer>"
        b"<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
        b"</System>"
        b"<EventData>"
        b'<Data Name="UtcTime">2026-09-23 12:00:00.123</Data>'
        b'<Data Name="ProcessGuid">{11111111-2222-3333-4444-555555555555}</Data>'
        b'<Data Name="ProcessId">500</Data>'
        b'<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>'
        b'<Data Name="CommandLine">powershell.exe -NoProfile</Data>'
        b'<Data Name="User">DOMAIN\\User1</Data>'
        b'<Data Name="ParentProcessGuid">{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}</Data>'
        b'<Data Name="ParentProcessId">100</Data>'
        b'<Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>'
        b'<Data Name="ParentCommandLine">C:\\Windows\\explorer.exe</Data>'
        b"</EventData>"
        b"</Event>"
    )


class WindowsEventJsonSysmonTests(
    unittest.TestCase
):
    def test_classifier_recognizes_structured_sysmon_jsonl(
        self,
    ) -> None:
        raw = (
            json.dumps(
                sysmon_event_payload(),
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

        classification = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "sysmon.jsonl"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.SYSMON_JSON,
        )

        self.assertEqual(
            classification.reason,
            "sysmon_windows_event_json_profile",
        )

    def test_legacy_tracesoc_jsonl_is_not_misrepresented_as_native(
        self,
    ) -> None:
        legacy = {
            "provider":
                "Microsoft-Windows-Sysmon",
            "event_type":
                "process_create",
            "timestamp":
                "2026-09-23T12:00:00Z",
            "host":
                "HOST-RC2A",
            "principal":
                r"DOMAIN\User1",
            "process_name":
                "powershell.exe",
            "parent_process":
                "explorer.exe",
            "command_line":
                "powershell.exe",
            "local_ip":
                "10.0.0.5",
        }

        raw = (
            json.dumps(
                legacy
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        classification = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "legacy.jsonl"
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

    def test_xml_and_json_have_equivalent_sysmon_semantics(
        self,
    ) -> None:
        payload = (
            sysmon_event_payload()
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            xml_path = (
                root
                / "sysmon.xml"
            )

            json_path = (
                root
                / "sysmon.jsonl"
            )

            xml_path.write_bytes(
                equivalent_sysmon_xml()
            )

            json_path.write_bytes(
                json.dumps(
                    payload,
                    separators=(",", ":"),
                ).encode(
                    "utf-8"
                )
                + b"\n"
            )

            xml_batch = (
                load_sysmon_windows_event_xml(
                    xml_path,
                    logical_source=(
                        "sysmon.xml"
                    ),
                )
            )

            json_batch = (
                load_sysmon_windows_event_json(
                    json_path,
                    logical_source=(
                        "sysmon.jsonl"
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
            SourceType.SYSMON,
        )

        self.assertIs(
            json_event.source_type,
            SourceType.SYSMON,
        )

        self.assertEqual(
            xml_event.event_type,
            json_event.event_type,
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

    def test_generic_intake_routes_sysmon_jsonl_and_preserves_bytes(
        self,
    ) -> None:
        raw = (
            json.dumps(
                sysmon_event_payload(),
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
                / "sysmon.jsonl"
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

            after = (
                path.read_bytes()
            )

        self.assertEqual(
            after,
            raw,
        )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.SYSMON_JSON,
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.SUPPORTED_PROCESSED,
        )

        self.assertEqual(
            len(
                result.canonical_events
            ),
            1,
        )

        self.assertEqual(
            len(
                result.evidence_locators
            ),
            1,
        )

    def test_single_json_object_uses_same_profile(
        self,
    ) -> None:
        raw = json.dumps(
            sysmon_event_payload(),
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
                / "sysmon.json"
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
            AdapterFamily.SYSMON_JSON,
        )

        self.assertEqual(
            len(
                result.canonical_events
            ),
            1,
        )

    def test_recognized_sysmon_json_with_missing_required_field_quarantines(
        self,
    ) -> None:
        payload = (
            sysmon_event_payload()
        )

        system = payload[
            "System"
        ]

        assert isinstance(
            system,
            dict,
        )

        del system[
            "EventID"
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
                / "malformed-sysmon.jsonl"
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

            after = (
                path.read_bytes()
            )

        self.assertEqual(
            after,
            raw,
        )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.SYSMON_JSON,
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

    def test_mixed_windows_event_json_providers_fail_closed(
        self,
    ) -> None:
        sysmon = (
            sysmon_event_payload()
        )

        powershell = (
            sysmon_event_payload()
        )

        system = powershell[
            "System"
        ]

        assert isinstance(
            system,
            dict,
        )

        provider = system[
            "Provider"
        ]

        assert isinstance(
            provider,
            dict,
        )

        provider[
            "Name"
        ] = (
            "Microsoft-Windows-PowerShell"
        )

        raw = (
            json.dumps(
                sysmon,
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
            + json.dumps(
                powershell,
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
                    "mixed.jsonl"
                ),
            )
        )

        self.assertIs(
            classification.family,
            AdapterFamily.UNSUPPORTED,
        )

        self.assertEqual(
            classification.reason,
            "ambiguous_windows_event_json_provider",
        )


if __name__ == "__main__":
    unittest.main()
