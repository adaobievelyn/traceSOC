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
from tracesoc.models import (
    ClockState,
    SourceType,
)
from tracesoc.parsers.windows_security import (
    REAL_ADAPTER_ID,
    WINDOWS_EVENT_JSON_ADAPTER_ID,
    WINDOWS_SECURITY_PROVIDER,
    XML_ADAPTER_ID,
    load_windows_security_splunk,
    load_windows_security_windows_event_json,
    load_windows_security_windows_event_xml,
)


ACQUIRED = datetime(
    2026,
    9,
    23,
    19,
    1,
    tzinfo=timezone.utc,
)

SYSTEM_TIME = (
    "2026-09-23T19:00:00.0000000Z"
)

SECURITY_ID = "S-1-5-18"

PROCESS_FIELDS = {
    "SubjectUserSid":
        SECURITY_ID,
    "SubjectUserName":
        "SYSTEM",
    "SubjectDomainName":
        "NT AUTHORITY",
    "SubjectLogonId":
        "0x3e7",
    "NewProcessId":
        "0x123",
    "NewProcessName":
        r"C:\Windows\System32\example.exe",
    "TokenElevationType":
        "%%1936",
    "ProcessId":
        "0x100",
    "CommandLine":
        r"C:\Windows\System32\example.exe /test",
    "ParentProcessName":
        r"C:\Windows\System32\parent.exe",
}


def windows_event_payload(
    *,
    event_code: int = 4688,
    record_id: int = 100,
    event_data: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "System": {
            "Provider": {
                "Name":
                    WINDOWS_SECURITY_PROVIDER,
            },
            "EventID":
                event_code,
            "EventRecordID":
                record_id,
            "TimeCreated": {
                "SystemTime":
                    SYSTEM_TIME,
            },
            "Computer":
                "HOST-01",
            "Channel":
                "Security",
        },
        "EventData": (
            dict(
                PROCESS_FIELDS
                if event_data is None
                else event_data
            )
        ),
    }


def windows_event_xml(
    *,
    event_code: int = 4688,
    record_id: int = 100,
    event_data: dict[str, str] | None = None,
) -> bytes:
    fields = (
        PROCESS_FIELDS
        if event_data is None
        else event_data
    )

    rendered_fields = []

    for name, value in fields.items():
        if value == "":
            rendered_fields.append(
                f'<Data Name="{name}"></Data>'
            )
        else:
            rendered_fields.append(
                f'<Data Name="{name}">{value}</Data>'
            )

    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        f'<Provider Name="{WINDOWS_SECURITY_PROVIDER}"/>'
        f"<EventID>{event_code}</EventID>"
        "<Version>2</Version>"
        "<Level>0</Level>"
        "<Task>13312</Task>"
        "<Opcode>0</Opcode>"
        "<Keywords>0x8020000000000000</Keywords>"
        f'<TimeCreated SystemTime="{SYSTEM_TIME}"/>'
        f"<EventRecordID>{record_id}</EventRecordID>"
        "<Execution ProcessID=\"4\" ThreadID=\"400\"/>"
        "<Channel>Security</Channel>"
        "<Computer>HOST-01</Computer>"
        "<Security/>"
        "</System>"
        "<EventData>"
        + "".join(
            rendered_fields
        )
        + "</EventData>"
        "</Event>"
    )

    return xml.encode(
        "utf-8"
    )


def splunk_4688() -> bytes:
    body = (
        "Creator Subject:\n"
        f"    Security ID:            {SECURITY_ID}\n"
        "    Account Name:           SYSTEM\n"
        "    Account Domain:         NT AUTHORITY\n"
        "    Logon ID:               0x3E7\n"
        "\n"
        "Target Subject:\n"
        "    Security ID:            NULL SID\n"
        "    Account Name:           -\n"
        "    Account Domain:         -\n"
        "    Logon ID:               0x0\n"
        "\n"
        "Process Information:\n"
        "    New Process ID:         0x123\n"
        r"    New Process Name:       C:\Windows\System32\example.exe"
        "\n"
        "    Token Elevation Type:   %%1936\n"
        "    Mandatory Label:        Mandatory Label\\System Mandatory Level\n"
        "    Creator Process ID:     0x100\n"
        r"    Creator Process Name:   C:\Windows\System32\parent.exe"
        "\n"
        r"    Process Command Line:   C:\Windows\System32\example.exe /test"
        "\n"
    ).encode(
        "utf-8"
    )

    return (
        b"03/31/2021 10:48:23 AM\n"
        b"LogName=Security\n"
        + (
            "SourceName="
            + WINDOWS_SECURITY_PROVIDER
            + "\n"
        ).encode(
            "ascii"
        )
        + b"EventCode=4688\n"
        b"EventType=0\n"
        b"Type=Information\n"
        b"ComputerName=HOST-01\n"
        b"TaskCategory=Process Creation\n"
        b"OpCode=Info\n"
        b"RecordNumber=100\n"
        b"Keywords=Audit Success\n"
        b"Message=A new process has been created.\n"
        + body
    )


class WindowsSecurityWindowsEventTests(
    unittest.TestCase
):
    def test_classifier_recognizes_security_xml(
        self,
    ) -> None:
        result = (
            classify_evidence_bytes(
                raw_bytes=(
                    windows_event_xml()
                ),
                logical_source=(
                    "security.xml"
                ),
            )
        )

        self.assertIs(
            result.family,
            AdapterFamily.WINDOWS_SECURITY_XML,
        )

        self.assertEqual(
            result.reason,
            "windows_security_provider",
        )

    def test_classifier_recognizes_security_jsonl(
        self,
    ) -> None:
        raw = (
            json.dumps(
                windows_event_payload(),
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        result = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "security.jsonl"
                ),
            )
        )

        self.assertIs(
            result.family,
            AdapterFamily.WINDOWS_SECURITY_JSON,
        )

        self.assertEqual(
            result.reason,
            "windows_security_windows_event_json_profile",
        )

    def test_xml_and_json_have_equivalent_4688_semantics(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            xml_path = (
                root
                / "security.xml"
            )

            json_path = (
                root
                / "security.jsonl"
            )

            xml_path.write_bytes(
                windows_event_xml()
            )

            json_path.write_bytes(
                json.dumps(
                    windows_event_payload(),
                    separators=(",", ":"),
                ).encode(
                    "utf-8"
                )
                + b"\n"
            )

            xml_batch = (
                load_windows_security_windows_event_xml(
                    xml_path,
                    logical_source=(
                        "security.xml"
                    ),
                )
            )

            json_batch = (
                load_windows_security_windows_event_json(
                    json_path,
                    logical_source=(
                        "security.jsonl"
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
            SourceType.WINDOWS_SECURITY,
        )

        self.assertIs(
            json_event.source_type,
            SourceType.WINDOWS_SECURITY,
        )

        self.assertEqual(
            xml_event.event_type,
            "process_create",
        )

        self.assertEqual(
            xml_event.event_type,
            json_event.event_type,
        )

        self.assertIs(
            xml_event.clock_state,
            ClockState.OBSERVED,
        )

        self.assertIs(
            json_event.clock_state,
            ClockState.OBSERVED,
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
            XML_ADAPTER_ID,
        )

        self.assertEqual(
            json_event.provenance.adapter_id,
            WINDOWS_EVENT_JSON_ADAPTER_ID,
        )

    def test_splunk_xml_json_converge_on_4688_semantics_but_not_clock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            splunk_path = (
                root
                / "security.log"
            )

            xml_path = (
                root
                / "security.xml"
            )

            json_path = (
                root
                / "security.jsonl"
            )

            splunk_path.write_bytes(
                splunk_4688()
            )

            xml_path.write_bytes(
                windows_event_xml()
            )

            json_path.write_bytes(
                json.dumps(
                    windows_event_payload(),
                    separators=(",", ":"),
                ).encode(
                    "utf-8"
                )
                + b"\n"
            )

            splunk_event = (
                load_windows_security_splunk(
                    splunk_path,
                    logical_source=(
                        "security.log"
                    ),
                ).accepted[0]
            )

            xml_event = (
                load_windows_security_windows_event_xml(
                    xml_path,
                    logical_source=(
                        "security.xml"
                    ),
                ).accepted[0]
            )

            json_event = (
                load_windows_security_windows_event_json(
                    json_path,
                    logical_source=(
                        "security.jsonl"
                    ),
                ).accepted[0]
            )

        for event in (
            xml_event,
            json_event,
        ):
            self.assertEqual(
                splunk_event.event_type,
                event.event_type,
            )

            self.assertEqual(
                splunk_event.host,
                event.host,
            )

            self.assertEqual(
                splunk_event.principal,
                event.principal,
            )

            self.assertEqual(
                splunk_event.semantic_fields,
                event.semantic_fields,
            )

        self.assertIs(
            splunk_event.clock_state,
            ClockState.UNRESOLVED,
        )

        self.assertIsNone(
            splunk_event.event_time_utc
        )

        self.assertIs(
            xml_event.clock_state,
            ClockState.OBSERVED,
        )

        self.assertIs(
            json_event.clock_state,
            ClockState.OBSERVED,
        )

        self.assertIsNotNone(
            xml_event.event_time_utc
        )

        self.assertIsNotNone(
            json_event.event_time_utc
        )

        self.assertEqual(
            splunk_event.provenance.adapter_id,
            REAL_ADAPTER_ID,
        )

    def test_incomplete_4688_remains_generic_in_xml_and_json(
        self,
    ) -> None:
        incomplete = {
            "NewProcessId":
                "0x123",
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            xml_path = (
                root
                / "security.xml"
            )

            json_path = (
                root
                / "security.jsonl"
            )

            xml_path.write_bytes(
                windows_event_xml(
                    event_data=incomplete,
                )
            )

            json_path.write_bytes(
                json.dumps(
                    windows_event_payload(
                        event_data=incomplete,
                    ),
                    separators=(",", ":"),
                ).encode(
                    "utf-8"
                )
                + b"\n"
            )

            xml_event = (
                load_windows_security_windows_event_xml(
                    xml_path,
                    logical_source=(
                        "security.xml"
                    ),
                ).accepted[0]
            )

            json_event = (
                load_windows_security_windows_event_json(
                    json_path,
                    logical_source=(
                        "security.jsonl"
                    ),
                ).accepted[0]
            )

        for event in (
            xml_event,
            json_event,
        ):
            self.assertEqual(
                event.event_type,
                "windows_security_event",
            )

            self.assertIsNone(
                event.principal
            )

            self.assertEqual(
                dict(
                    event.semantic_fields
                ),
                {},
            )

    def test_non_4688_remains_generic_even_with_process_fields(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            json_path = (
                root
                / "security.jsonl"
            )

            json_path.write_bytes(
                json.dumps(
                    windows_event_payload(
                        event_code=4624,
                    ),
                    separators=(",", ":"),
                ).encode(
                    "utf-8"
                )
                + b"\n"
            )

            event = (
                load_windows_security_windows_event_json(
                    json_path,
                    logical_source=(
                        "security.jsonl"
                    ),
                ).accepted[0]
            )

        self.assertEqual(
            event.source_context[
                "event_code"
            ],
            4624,
        )

        self.assertEqual(
            event.event_type,
            "windows_security_event",
        )

        self.assertIsNone(
            event.principal
        )

        self.assertEqual(
            dict(
                event.semantic_fields
            ),
            {},
        )

    def test_generic_intake_routes_xml_and_json_and_preserves_bytes(
        self,
    ) -> None:
        xml_raw = (
            windows_event_xml()
        )

        json_raw = (
            json.dumps(
                windows_event_payload(),
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

            xml_path = (
                root
                / "security.xml"
            )

            json_path = (
                root
                / "security.jsonl"
            )

            xml_path.write_bytes(
                xml_raw
            )

            json_path.write_bytes(
                json_raw
            )

            xml_result = (
                ingest_evidence_file(
                    xml_path,
                    root=root,
                    acquired_or_observed_utc=(
                        ACQUIRED
                    ),
                )
            )

            json_result = (
                ingest_evidence_file(
                    json_path,
                    root=root,
                    acquired_or_observed_utc=(
                        ACQUIRED
                    ),
                )
            )

            self.assertEqual(
                xml_path.read_bytes(),
                xml_raw,
            )

            self.assertEqual(
                json_path.read_bytes(),
                json_raw,
            )

        self.assertIs(
            xml_result.adapter_family,
            AdapterFamily.WINDOWS_SECURITY_XML,
        )

        self.assertIs(
            json_result.adapter_family,
            AdapterFamily.WINDOWS_SECURITY_JSON,
        )

        self.assertEqual(
            len(
                xml_result.canonical_events
            ),
            1,
        )

        self.assertEqual(
            len(
                json_result.canonical_events
            ),
            1,
        )

        self.assertEqual(
            len(
                xml_result.evidence_locators
            ),
            1,
        )

        self.assertEqual(
            len(
                json_result.evidence_locators
            ),
            1,
        )

    def test_single_json_object_is_supported(
        self,
    ) -> None:
        raw = json.dumps(
            windows_event_payload(),
            indent=2,
        ).encode(
            "utf-8"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "security.json"
            )

            path.write_bytes(
                raw
            )

            result = (
                ingest_evidence_file(
                    path,
                    root=root,
                    acquired_or_observed_utc=(
                        ACQUIRED
                    ),
                )
            )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.WINDOWS_SECURITY_JSON,
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
            ].provenance.byte_offset,
            0,
        )

    def test_legacy_compatibility_jsonl_is_not_native_profile(
        self,
    ) -> None:
        legacy = {
            "provider":
                WINDOWS_SECURITY_PROVIDER,
            "event_code":
                4624,
            "event_type":
                "logon",
            "timestamp":
                "2026-09-23T19:00:00Z",
            "host":
                "HOST-01",
            "principal":
                r"DOMAIN\User",
            "logon_type":
                3,
            "status":
                "success",
            "source_ip":
                "198.51.100.20",
            "local_ip":
                "10.0.0.5",
        }

        raw = (
            json.dumps(
                legacy,
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        result = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "legacy-security.jsonl"
                ),
            )
        )

        self.assertIs(
            result.family,
            AdapterFamily.UNSUPPORTED,
        )

        self.assertEqual(
            result.reason,
            "no_supported_json_profile",
        )

    def test_wrong_channel_is_accounted_as_quarantine(
        self,
    ) -> None:
        payload = (
            windows_event_payload()
        )

        system = payload[
            "System"
        ]

        assert isinstance(
            system,
            dict,
        )

        system[
            "Channel"
        ] = "System"

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
                / "security.jsonl"
            )

            path.write_bytes(
                raw
            )

            result = (
                ingest_evidence_file(
                    path,
                    root=root,
                    acquired_or_observed_utc=(
                        ACQUIRED
                    ),
                )
            )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.WINDOWS_SECURITY_JSON,
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


    def test_security_splunk_native_provider_is_not_misclassified_as_xml(
        self,
    ) -> None:
        raw = (
            splunk_4688()
        )

        result = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "security.log"
                ),
            )
        )

        self.assertIs(
            result.family,
            AdapterFamily.WINDOWS_SECURITY_SPLUNK,
        )


if __name__ == "__main__":
    unittest.main()
