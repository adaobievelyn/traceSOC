from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from tracesoc.findings.serialization import (
    finding_json_bytes,
    finding_sha256,
    write_finding,
)
from tracesoc.vertical_slice import build_fixture_finding_001


REPO = Path(__file__).resolve().parents[2]


class FindingSerializationTests(unittest.TestCase):
    def test_canonical_bytes_use_lf_only(self) -> None:
        finding = build_fixture_finding_001(
            REPO
        )

        payload = finding_json_bytes(
            finding
        )

        self.assertTrue(
            payload.endswith(b"\n")
        )

        self.assertNotIn(
            b"\r\n",
            payload,
        )

        self.assertFalse(
            payload.startswith(
                b"\xef\xbb\xbf"
            )
        )

    def test_hash_is_hash_of_exact_canonical_bytes(self) -> None:
        finding = build_fixture_finding_001(
            REPO
        )

        payload = finding_json_bytes(
            finding
        )

        expected = hashlib.sha256(
            payload
        ).hexdigest()

        self.assertEqual(
            finding_sha256(finding),
            expected,
        )

    def test_binary_write_matches_canonical_bytes_exactly(self) -> None:
        finding = build_fixture_finding_001(
            REPO
        )

        with tempfile.TemporaryDirectory() as temp:
            path = (
                Path(temp)
                / "FINDING-001.json"
            )

            digest = write_finding(
                path=path,
                finding=finding,
            )

            payload = path.read_bytes()

            self.assertEqual(
                payload,
                finding_json_bytes(finding),
            )

            self.assertEqual(
                digest,
                hashlib.sha256(payload).hexdigest(),
            )

    def test_serialization_is_deterministic(self) -> None:
        first = build_fixture_finding_001(
            REPO
        )

        second = build_fixture_finding_001(
            REPO
        )

        self.assertEqual(
            finding_json_bytes(first),
            finding_json_bytes(second),
        )

        self.assertEqual(
            finding_sha256(first),
            finding_sha256(second),
        )


if __name__ == "__main__":
    unittest.main()