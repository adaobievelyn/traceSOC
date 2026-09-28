from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tracesoc.cli.case import analyze_case


MISSING_SCRIPTBLOCK_TEXT_XML = (
    '<Event '
    'xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    '<System>'
    '<Provider Name="Microsoft-Windows-PowerShell" '
    'Guid="{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"/>'
    '<EventID>4104</EventID>'
    '<Version>1</Version>'
    '<Level>5</Level>'
    '<Task>2</Task>'
    '<Opcode>15</Opcode>'
    '<Keywords>0x0</Keywords>'
    '<TimeCreated '
    'SystemTime="2022-03-29T13:45:39.141147800Z"/>'
    '<EventRecordID>124406</EventRecordID>'
    '<Correlation '
    'ActivityID="{243103BA-434B-0006-0933-31244B43D801}"/>'
    '<Execution ProcessID="5364" ThreadID="4896"/>'
    '<Channel>'
    'Microsoft-Windows-PowerShell/Operational'
    '</Channel>'
    '<Computer>'
    'win-dc-tcontreras-attack-range-677.attackrange.local'
    '</Computer>'
    '<Security '
    'UserID="S-1-5-21-2858367438-1356187604-3090371563-500"/>'
    '</System>'
    '<EventData>'
    '<Data Name="MessageNumber">1</Data>'
    '<Data Name="MessageTotal">1</Data>'
    '<Data Name="ScriptBlockId">'
    'c124adea-145e-4e3f-99e5-871d5a8cc289'
    '</Data>'
    '<Data Name="Path"/>'
    '</EventData>'
    '</Event>'
)


class PowerShell4104QuarantineV04Tests(
    unittest.TestCase
):
    def test_missing_scriptblocktext_is_quarantined_and_case_sealed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(
                temp
            )

            evidence = (
                root
                / "evidence"
            )

            output = (
                root
                / "case-output"
            )

            evidence.mkdir()

            (
                evidence
                / "powershell.xml"
            ).write_text(
                MISSING_SCRIPTBLOCK_TEXT_XML,
                encoding="utf-8",
            )

            result = analyze_case(
                evidence_directory=evidence,
                output_directory=output,
            )

            artifact_index = json.loads(
                (
                    output
                    / "artifact-index.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            normalized = json.loads(
                (
                    output
                    / "normalized-events.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            manifest = json.loads(
                (
                    output
                    / "case-manifest.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            raw_index = json.loads(
                (
                    output
                    / "raw-evidence-index.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(
                result[
                    "artifact_count"
                ],
                1,
            )

            self.assertEqual(
                result[
                    "canonical_event_count"
                ],
                0,
            )

            self.assertEqual(
                result[
                    "scriptblock_count"
                ],
                0,
            )

            self.assertTrue(
                result[
                    "raw_evidence_embedded"
                ]
            )

            self.assertTrue(
                result[
                    "seal_verified"
                ]
            )

            self.assertEqual(
                len(
                    artifact_index[
                        "artifacts"
                    ]
                ),
                1,
            )

            artifact = (
                artifact_index[
                    "artifacts"
                ][0]
            )

            self.assertEqual(
                artifact[
                    "processing_state"
                ],
                "MALFORMED_QUARANTINED",
            )

            self.assertGreaterEqual(
                artifact[
                    "issue_count"
                ],
                1,
            )

            self.assertEqual(
                normalized[
                    "events"
                ],
                [],
            )

            accounting = (
                manifest[
                    "artifact_accounting"
                ]
            )

            self.assertEqual(
                accounting[
                    "discovered"
                ],
                1,
            )

            self.assertEqual(
                accounting[
                    "malformed_quarantined"
                ],
                1,
            )

            self.assertEqual(
                accounting[
                    "accounted"
                ],
                1,
            )

            self.assertTrue(
                accounting[
                    "zero_silent_loss"
                ]
            )

            self.assertEqual(
                manifest[
                    "analysis_counts"
                ][
                    "canonical_events"
                ],
                0,
            )

            self.assertEqual(
                len(
                    raw_index[
                        "raw_evidence_files"
                    ]
                ),
                1,
            )


if __name__ == "__main__":
    unittest.main()
