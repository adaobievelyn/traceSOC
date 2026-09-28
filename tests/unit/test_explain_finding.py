from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tracesoc.cli.explain import (
    EvidenceIntegrityError,
    accepted_finding_contract,
    explain_finding,
    render_text,
    resolve_evidence_reference,
)
from tracesoc.vertical_slice import (
    build_fixture_finding_001,
)


REPO = Path(__file__).resolve().parents[2]


class ExplainFindingTests(unittest.TestCase):
    def test_canonical_contract_is_authoritative(self) -> None:
        serialization_id, digest = (
            accepted_finding_contract(
                REPO
            )
        )

        self.assertEqual(
            serialization_id,
            "tracesoc-finding-json-v1",
        )

        self.assertEqual(
            digest,
            "fbb56699bb3f1dd5f75f5ccf153d10f0956be3940ed55a9edf3c9667e89e3c90",
        )

    def test_regenerated_finding_matches_canonical_hash(self) -> None:
        explanation = explain_finding(
            repo=REPO,
            finding_id="FINDING-001",
        )

        self.assertTrue(
            explanation[
                "finding_hash_verified"
            ]
        )

        self.assertEqual(
            explanation[
                "finding_sha256"
            ],
            explanation[
                "expected_finding_sha256"
            ],
        )

    def test_two_raw_evidence_references_verify(self) -> None:
        explanation = explain_finding(
            repo=REPO,
            finding_id="FINDING-001",
        )

        self.assertEqual(
            explanation[
                "raw_evidence_reference_count"
            ],
            2,
        )

        self.assertEqual(
            explanation[
                "raw_evidence_hashes_verified"
            ],
            2,
        )

        for item in explanation[
            "evidence"
        ]:
            self.assertTrue(
                item[
                    "raw_sha256_verified"
                ]
            )

    def test_raw_locator_resolves_exact_record(self) -> None:
        finding = build_fixture_finding_001(
            REPO
        )

        verified = resolve_evidence_reference(
            repo=REPO,
            reference=finding.evidence[0],
        )

        self.assertTrue(
            verified.raw_sha256_verified
        )

        parsed = json.loads(
            verified.raw_text
        )

        self.assertIn(
            "timestamp",
            parsed,
        )

    def test_tampered_raw_record_fails_integrity(self) -> None:
        finding = build_fixture_finding_001(
            REPO
        )

        reference = finding.evidence[0]

        original = (
            REPO
            / reference.logical_source
        ).read_bytes()

        with tempfile.TemporaryDirectory() as temp:
            root = Path(
                temp
            )

            destination = (
                root
                / reference.logical_source
            )

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            mutated = bytearray(
                original
            )

            index = (
                reference.byte_offset
            )

            mutated[index] = (
                mutated[index] + 1
            ) % 256

            destination.write_bytes(
                bytes(mutated)
            )

            with self.assertRaises(
                EvidenceIntegrityError
            ):
                resolve_evidence_reference(
                    repo=root,
                    reference=reference,
                )

    def test_path_escape_is_rejected(self) -> None:
        finding = build_fixture_finding_001(
            REPO
        )

        escaped = replace(
            finding.evidence[0],
            logical_source="../outside.jsonl",
        )

        with self.assertRaises(
            EvidenceIntegrityError
        ):
            resolve_evidence_reference(
                repo=REPO,
                reference=escaped,
            )

    def test_human_render_contains_defense_sections(self) -> None:
        explanation = explain_finding(
            repo=REPO,
            finding_id="FINDING-001",
        )

        rendered = render_text(
            explanation
        )

        for required in (
            "OBSERVED FACTS",
            "INFERENCE:",
            "ALTERNATIVE EXPLANATION:",
            "FALSIFIER:",
            "RESIDUAL RISK:",
            "BUSINESS IMPACT:",
            "DECISION REQUIRED:",
            "RAW EVIDENCE",
            "RAW_HASH_VERIFIED=PASS",
            "FINDING_HASH_VERIFIED=PASS",
            "SERIALIZATION: tracesoc-finding-json-v1",
        ):
            self.assertIn(
                required,
                rendered,
            )

    def test_cli_json_output_is_machine_readable(self) -> None:
        env = dict(
            os.environ
        )

        src = str(
            REPO / "src"
        )

        env["PYTHONPATH"] = (
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
                "explain",
                "FINDING-001",
                "--json",
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
            msg=process.stderr,
        )

        payload = json.loads(
            process.stdout
        )

        self.assertEqual(
            payload[
                "finding"
            ][
                "finding_id"
            ],
            "FINDING-001",
        )

        self.assertEqual(
            payload[
                "serialization_id"
            ],
            "tracesoc-finding-json-v1",
        )

        self.assertTrue(
            payload[
                "finding_hash_verified"
            ]
        )

        self.assertEqual(
            payload[
                "raw_evidence_hashes_verified"
            ],
            2,
        )


if __name__ == "__main__":
    unittest.main()