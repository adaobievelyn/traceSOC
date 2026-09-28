from __future__ import annotations

import hashlib
import tempfile
import unittest

from datetime import (
    datetime,
    timezone,
)

from email.message import (
    EmailMessage,
)

from pathlib import Path

from tracesoc.cli.case import (
    _collect_canonical_events,
    _evaluate_case_correlations,
)

from tracesoc.evidence.intake import (
    ingest_evidence_directory,
)


ATTACHMENT = (
    b"harmless-reference-executable-bytes"
)

SHA = hashlib.sha256(
    ATTACHMENT
).hexdigest()


class EmailSysmonCaseIntegrationTests(
    unittest.TestCase
):
    def test_real_eml_and_sysmon_xml_emit_corr005_relationship(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            message = EmailMessage()

            message[
                "From"
            ] = (
                "sender@example.invalid"
            )

            message[
                "To"
            ] = (
                "analyst@example.invalid"
            )

            message[
                "Subject"
            ] = (
                "Reference attachment"
            )

            message[
                "Date"
            ] = (
                "Thu, 24 Sep 2026 "
                "12:00:00 +0000"
            )

            message.set_content(
                "Controlled reference message"
            )

            message.add_attachment(
                ATTACHMENT,
                maintype="application",
                subtype="octet-stream",
                filename=(
                    "original-name.exe"
                ),
            )

            (
                root
                / "message.eml"
            ).write_bytes(
                message.as_bytes()
            )

            sysmon_xml = (
                '<Event xmlns="http://schemas.microsoft.com/'
                'win/2004/08/events/event">'
                '<System>'
                '<Provider Name="Microsoft-Windows-Sysmon"/>'
                '<EventID>1</EventID>'
                '<Version>5</Version>'
                '<Level>4</Level>'
                '<Task>1</Task>'
                '<Opcode>0</Opcode>'
                '<Keywords>0x8000000000000000</Keywords>'
                '<TimeCreated SystemTime='
                '"2026-09-24T12:00:01.0000000Z"/>'
                '<EventRecordID>200</EventRecordID>'
                '<Channel>'
                'Microsoft-Windows-Sysmon/Operational'
                '</Channel>'
                '<Computer>HOST-01</Computer>'
                '</System>'
                '<EventData>'
                '<Data Name="UtcTime">'
                '2026-09-24 12:00:01.000'
                '</Data>'
                '<Data Name="ProcessGuid">'
                '{11111111-1111-1111-1111-111111111111}'
                '</Data>'
                '<Data Name="ProcessId">291</Data>'
                '<Data Name="Image">'
                r'C:\Temp\renamed.exe'
                '</Data>'
                '<Data Name="CommandLine">'
                r'C:\Temp\renamed.exe'
                '</Data>'
                '<Data Name="Hashes">'
                'MD5='
                + (
                    "c" * 32
                )
                + ',SHA256='
                + SHA.upper()
                + '</Data>'
                '<Data Name="User">'
                r'NT AUTHORITY\SYSTEM'
                '</Data>'
                '<Data Name="ParentProcessGuid">'
                '{22222222-2222-2222-2222-222222222222}'
                '</Data>'
                '<Data Name="ParentProcessId">256</Data>'
                '<Data Name="ParentImage">'
                r'C:\Windows\explorer.exe'
                '</Data>'
                '</EventData>'
                '</Event>'
            )

            (
                root
                / "sysmon.xml"
            ).write_bytes(
                sysmon_xml.encode(
                    "utf-8"
                )
            )

            intake = (
                ingest_evidence_directory(
                    root,
                    acquired_or_observed_utc=(
                        datetime(
                            2026,
                            9,
                            24,
                            12,
                            5,
                            tzinfo=timezone.utc,
                        )
                    ),
                )
            )

            events = (
                _collect_canonical_events(
                    intake
                )
            )

        sysmon_processes = [
            event
            for event
            in events
            if (
                event.source_type.value
                == "sysmon"
                and event.event_type
                == "process_create"
            )
        ]

        self.assertEqual(
            len(
                sysmon_processes
            ),
            1,
        )

        self.assertEqual(
            sysmon_processes[
                0
            ].semantic_fields[
                "hashes"
            ],
            (
                "MD5="
                + "c" * 32
                + ",SHA256="
                + SHA.upper()
            ),
        )

        (
            records,
            projections,
            candidates,
        ) = (
            _evaluate_case_correlations(
                events
            )
        )

        corr005 = [
            record
            for record
            in records
            if (
                record[
                    "correlation_id"
                ]
                == "TRC-CORR-005"
            )
        ]

        self.assertEqual(
            len(
                corr005
            ),
            1,
        )

        self.assertTrue(
            corr005[
                0
            ][
                "matched"
            ]
        )

        self.assertEqual(
            corr005[
                0
            ][
                "source_kind"
            ],
            "email_attachment",
        )

        self.assertEqual(
            corr005[
                0
            ][
                "candidate_kind"
            ],
            "sysmon_hashed_process",
        )

        projected = [
            projection
            for projection
            in projections
            if (
                projection
                .legacy_correlation_id
                == "TRC-CORR-005"
            )
        ]

        self.assertEqual(
            len(
                projected
            ),
            1,
        )

        # Exact byte identity is evidence corroboration.
        # It does not manufacture a maliciousness hypothesis.
        self.assertEqual(
            candidates,
            (),
        )


if __name__ == "__main__":
    unittest.main()
