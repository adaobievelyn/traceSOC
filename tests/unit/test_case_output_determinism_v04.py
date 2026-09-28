from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tracesoc.cli.case import analyze_case


def file_snapshot(
    root: Path,
) -> dict[str, bytes]:
    return {
        path.relative_to(
            root
        ).as_posix():
            path.read_bytes()

        for path in sorted(
            root.rglob("*")
        )

        if path.is_file()
    }


class CaseOutputDeterminismV04Tests(
    unittest.TestCase
):
    def test_identical_evidence_produces_identical_sealed_case(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            evidence = root / "evidence"
            first_output = root / "case-1"
            second_output = root / "case-2"

            evidence.mkdir()

            (
                evidence
                / "unknown.bin"
            ).write_bytes(
                b"deterministic unsupported evidence\n"
            )

            first = analyze_case(
                evidence_directory=evidence,
                output_directory=first_output,
            )

            second = analyze_case(
                evidence_directory=evidence,
                output_directory=second_output,
            )

            self.assertEqual(
                first["case_id"],
                second["case_id"],
            )

            self.assertEqual(
                file_snapshot(
                    first_output
                ),
                file_snapshot(
                    second_output
                ),
            )

            artifact_index = json.loads(
                (
                    first_output
                    / "artifact-index.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            manifest = json.loads(
                (
                    first_output
                    / "case-manifest.json"
                ).read_text(
                    encoding="utf-8"
                )
            )

            artifact = (
                artifact_index[
                    "artifacts"
                ][0]
            )

            self.assertIsNone(
                artifact[
                    "acquired_or_observed_utc"
                ]
            )

            self.assertEqual(
                artifact[
                    "acquired_or_observed_time_status"
                ],
                "NOT_ESTABLISHED",
            )

            self.assertFalse(
                artifact[
                    "runtime_intake_time_in_sealed_truth"
                ]
            )

            self.assertIsNone(
                manifest[
                    "analysis_observed_utc"
                ]
            )

            self.assertEqual(
                manifest[
                    "analysis_observed_time_status"
                ],
                "VOLATILE_RUNTIME_EXCLUDED",
            )

            self.assertFalse(
                manifest[
                    "runtime_analysis_time_in_sealed_truth"
                ]
            )


if __name__ == "__main__":
    unittest.main()
