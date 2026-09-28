from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from tracesoc.models import (
    SemanticEvent,
)
from tracesoc.parsers.sysmon import (
    load_sysmon_windows_event_xml,
)


def sysmon_event(
    *,
    event_id: int,
    fields: dict[str, str],
    record_id: int = 1,
    utc_time: str = "2021-03-31 12:00:39.123",
) -> bytes:
    data = {
        "UtcTime":
            utc_time,

        "RuleName":
            "-",
    }

    data.update(
        fields
    )

    rendered_data = "".join(
        (
            "<Data Name="
            + quoteattr(name)
            + ">"
            + escape(value)
            + "</Data>"
        )
        for name, value
        in data.items()
    )

    rendered = (
        '<Event '
        'xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System>'
        '<Provider Name="Microsoft-Windows-Sysmon"/>'
        f'<EventID>{event_id}</EventID>'
        '<Version>3</Version>'
        '<Level>4</Level>'
        '<Task>10</Task>'
        '<Opcode>0</Opcode>'
        '<Keywords>0x8000000000000000</Keywords>'
        '<TimeCreated SystemTime="2021-03-31T12:00:39.150000000Z"/>'
        f'<EventRecordID>{record_id}</EventRecordID>'
        '<Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
        '<Computer>HOST-01</Computer>'
        '</System>'
        '<EventData>'
        + rendered_data
        + '</EventData>'
        '</Event>'
    )

    return rendered.encode(
        "utf-8"
    )


class SysmonBehavioralPromotionTests(
    unittest.TestCase
):
    def _map(
        self,
        raw: bytes,
    ):
        directory = (
            tempfile.TemporaryDirectory()
        )

        path = (
            Path(
                directory.name
            )
            /
            "windows-sysmon.log"
        )

        path.write_bytes(
            raw
        )

        try:
            return (
                load_sysmon_windows_event_xml(
                    path,
                    logical_source=
                        "tests/windows-sysmon.log",
                )
            )
        finally:
            directory.cleanup()

    def test_event3_promotes_network_connection(
        self,
    ) -> None:
        batch = self._map(
            sysmon_event(
                event_id=3,
                fields={
                    "Image":
                        r"C:\Windows\System32\app.exe",

                    "ProcessId":
                        "123",

                    "ProcessGuid":
                        "{GUID-3}",

                    "SourceIp":
                        "10.0.0.1",

                    "SourcePort":
                        "50000",

                    "DestinationIp":
                        "10.0.0.2",

                    "DestinationHostname":
                        "server.example",

                    "DestinationPort":
                        "443",

                    "Protocol":
                        "tcp",

                    "Initiated":
                        "true",

                    "User":
                        r"DOMAIN\alice",
                },
            )
        )

        self.assertEqual(
            batch.accepted_count,
            1,
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "network_connection",
        )

        self.assertEqual(
            event.principal,
            r"DOMAIN\alice",
        )

        self.assertEqual(
            dict(
                event.semantic_fields
            ),
            {
                "process_name":
                    r"C:\Windows\System32\app.exe",

                "process_id":
                    "123",

                "process_guid":
                    "{GUID-3}",

                "src_ip":
                    "10.0.0.1",

                "src_port":
                    "50000",

                "dst_ip":
                    "10.0.0.2",

                "dst_hostname":
                    "server.example",

                "dst_port":
                    "443",

                "proto":
                    "tcp",

                "initiated":
                    "true",
            },
        )

    def test_event10_promotes_process_access(
        self,
    ) -> None:
        batch = self._map(
            sysmon_event(
                event_id=10,
                fields={
                    "SourceImage":
                        r"C:\source.exe",

                    "SourceProcessId":
                        "100",

                    "SourceProcessGUID":
                        "{SOURCE-GUID}",

                    "SourceThreadId":
                        "101",

                    "TargetImage":
                        r"C:\target.exe",

                    "TargetProcessId":
                        "200",

                    "TargetProcessGUID":
                        "{TARGET-GUID}",

                    "GrantedAccess":
                        "0x1010",

                    "CallTrace":
                        r"C:\Windows\SYSTEM32\ntdll.dll+1234",
                },
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "process_access",
        )

        self.assertEqual(
            dict(
                event.semantic_fields
            ),
            {
                "source_process":
                    r"C:\source.exe",

                "source_process_id":
                    "100",

                "source_process_guid":
                    "{SOURCE-GUID}",

                "source_thread_id":
                    "101",

                "target_process":
                    r"C:\target.exe",

                "target_process_id":
                    "200",

                "target_process_guid":
                    "{TARGET-GUID}",

                "granted_access":
                    "0x1010",

                "call_trace":
                    r"C:\Windows\SYSTEM32\ntdll.dll+1234",
            },
        )

    def test_file_create_and_file_delete_promote(
        self,
    ) -> None:
        create = self._map(
            sysmon_event(
                event_id=11,
                fields={
                    "Image":
                        r"C:\creator.exe",

                    "ProcessId":
                        "300",

                    "ProcessGuid":
                        "{CREATE-GUID}",

                    "TargetFilename":
                        r"C:\Temp\created.bin",

                    "CreationUtcTime":
                        "2021-03-31 12:00:00.000",
                },
            )
        ).accepted[0]

        self.assertEqual(
            create.event_type,
            "file_create",
        )

        self.assertEqual(
            create.semantic_fields[
                "file_path"
            ],
            r"C:\Temp\created.bin",
        )

        delete = self._map(
            sysmon_event(
                event_id=23,
                fields={
                    "Image":
                        r"C:\deleter.exe",

                    "ProcessId":
                        "301",

                    "ProcessGuid":
                        "{DELETE-GUID}",

                    "TargetFilename":
                        r"C:\Temp\deleted.bin",

                    "Hashes":
                        "SHA256=ABC",

                    "Archived":
                        "true",

                    "IsExecutable":
                        "true",

                    "User":
                        r"DOMAIN\bob",
                },
            )
        ).accepted[0]

        self.assertEqual(
            delete.event_type,
            "file_delete",
        )

        self.assertEqual(
            delete.principal,
            r"DOMAIN\bob",
        )

        self.assertEqual(
            delete.semantic_fields[
                "file_path"
            ],
            r"C:\Temp\deleted.bin",
        )

        self.assertEqual(
            delete.semantic_fields[
                "hashes"
            ],
            "SHA256=ABC",
        )

    def test_registry_delete_and_set_value_promote(
        self,
    ) -> None:
        deleted = self._map(
            sysmon_event(
                event_id=12,
                fields={
                    "Image":
                        r"C:\reg.exe",

                    "ProcessId":
                        "400",

                    "ProcessGuid":
                        "{REG-DELETE}",

                    "TargetObject":
                        r"HKLM\Software\Test",

                    "EventType":
                        "DeleteValue",
                },
            )
        ).accepted[0]

        self.assertEqual(
            deleted.event_type,
            "registry_delete",
        )

        self.assertEqual(
            deleted.semantic_fields[
                "registry_operation"
            ],
            "DeleteValue",
        )

        changed = self._map(
            sysmon_event(
                event_id=13,
                fields={
                    "Image":
                        r"C:\reg.exe",

                    "ProcessId":
                        "401",

                    "ProcessGuid":
                        "{REG-SET}",

                    "TargetObject":
                        r"HKLM\Software\Test\Value",

                    "Details":
                        "DWORD (0x00000000)",

                    "EventType":
                        "SetValue",
                },
            )
        ).accepted[0]

        self.assertEqual(
            changed.event_type,
            "registry_set_value",
        )

        self.assertEqual(
            changed.semantic_fields[
                "registry_details"
            ],
            "DWORD (0x00000000)",
        )

    def test_named_pipe_create_and_connect_promote(
        self,
    ) -> None:
        created = self._map(
            sysmon_event(
                event_id=17,
                fields={
                    "Image":
                        r"C:\server.exe",

                    "ProcessId":
                        "500",

                    "ProcessGuid":
                        "{PIPE-CREATE}",

                    "PipeName":
                        r"\example-pipe",

                    "EventType":
                        "CreatePipe",
                },
            )
        ).accepted[0]

        self.assertEqual(
            created.event_type,
            "named_pipe_create",
        )

        self.assertEqual(
            created.semantic_fields[
                "pipe_name"
            ],
            r"\example-pipe",
        )

        connected = self._map(
            sysmon_event(
                event_id=18,
                fields={
                    "Image":
                        r"C:\client.exe",

                    "ProcessId":
                        "501",

                    "ProcessGuid":
                        "{PIPE-CONNECT}",

                    "PipeName":
                        r"\example-pipe",

                    "EventType":
                        "ConnectPipe",
                },
            )
        ).accepted[0]

        self.assertEqual(
            connected.event_type,
            "named_pipe_connect",
        )

    def test_event22_promotes_dns_query(
        self,
    ) -> None:
        batch = self._map(
            sysmon_event(
                event_id=22,
                fields={
                    "Image":
                        r"C:\resolver.exe",

                    "ProcessId":
                        "600",

                    "ProcessGuid":
                        "{DNS-GUID}",

                    "QueryName":
                        "example.test.",

                    "QueryStatus":
                        "0",

                    "QueryResults":
                        "10.0.0.10;",
                },
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "dns_query",
        )

        self.assertEqual(
            event.semantic_fields[
                "query_name"
            ],
            "example.test.",
        )

        self.assertEqual(
            event.semantic_fields[
                "query_results"
            ],
            "10.0.0.10;",
        )

    def test_unadjudicated_event25_remains_generic(
        self,
    ) -> None:
        batch = self._map(
            sysmon_event(
                event_id=25,
                fields={
                    "Image":
                        r"C:\example.exe",

                    "ProcessId":
                        "700",

                    "ProcessGuid":
                        "{GENERIC-GUID}",

                    "Type":
                        "Image is locked for access",
                },
            )
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.event_type,
            "sysmon_event",
        )

        self.assertIsNone(
            event.principal,
        )

        self.assertEqual(
            dict(
                event.semantic_fields
            ),
            {},
        )

    def test_promotion_is_deterministic_and_placeholders_do_not_leak(
        self,
    ) -> None:
        raw = sysmon_event(
            event_id=3,
            fields={
                "Image":
                    r"C:\example.exe",

                "ProcessId":
                    "800",

                "ProcessGuid":
                    "{NETWORK-GUID}",

                "SourceIp":
                    "10.0.0.1",

                "SourcePort":
                    "50000",

                "DestinationIp":
                    "10.0.0.2",

                "DestinationHostname":
                    "-",

                "DestinationPort":
                    "443",

                "Protocol":
                    "tcp",

                "Initiated":
                    "true",

                "User":
                    "NULL SID",
            },
        )

        first = self._map(
            raw
        )

        second = self._map(
            raw
        )

        self.assertEqual(
            first.accepted[0],
            second.accepted[0],
        )

        event = first.accepted[0]

        self.assertIsNone(
            event.principal,
        )

        self.assertNotIn(
            "dst_hostname",
            event.semantic_fields,
        )

        self.assertNotIn(
            "rule_name",
            event.semantic_fields,
        )

        semantic = (
            SemanticEvent.from_canonical(
                event
            )
        )

        self.assertFalse(
            hasattr(
                semantic,
                "source_context",
            )
        )

        self.assertFalse(
            hasattr(
                semantic,
                "provenance",
            )
        )

        self.assertEqual(
            dict(
                semantic.fields
            ),
            dict(
                event.semantic_fields
            ),
        )


if __name__ == "__main__":
    unittest.main()