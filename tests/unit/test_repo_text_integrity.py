from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = (
    REPO
    / "scripts"
    / "validate_repo_text_integrity.py"
)

SPEC = importlib.util.spec_from_file_location(
    "validate_repo_text_integrity",
    SCRIPT,
)

MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class RepositoryTextIntegrityTests(unittest.TestCase):

    def _write(self, root, name, data):
        path = root / name
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_bytes(data)
        return path

    def test_valid_utf8_structured_files_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            samples = {
                "a.json":
                    b'{"ok":true}\n',

                "b.jsonl":
                    b'{"a":1}\n{"b":2}\n',

                "c.csv":
                    b"id,value\n1,test\n",

                "d.md":
                    "TraceSOC - evidence\n".encode("utf-8"),
            }

            for name, data in samples.items():
                path = self._write(
                    root,
                    name,
                    data,
                )

                issues, _ = MODULE.validate_file(
                    path,
                    name,
                )

                self.assertEqual(
                    issues,
                    [],
                )

    def test_invalid_utf8_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            path = self._write(
                root,
                "bad.md",
                b"\xff\xfe\xfa",
            )

            issues, _ = MODULE.validate_file(
                path,
                "bad.md",
            )

            self.assertTrue(
                any(
                    item[0] == "INVALID_UTF8"
                    for item in issues
                )
            )

    def test_mojibake_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            path = self._write(
                root,
                "bad.md",
                ("Broken " + "".join(chr(cp) for cp in (0x00C3, 0x0192)) + " text\n").encode("utf-8"),
            )

            issues, _ = MODULE.validate_file(
                path,
                "bad.md",
            )

            self.assertTrue(
                any(
                    item[0] == "MOJIBAKE"
                    for item in issues
                )
            )

    def test_giant_line_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            path = self._write(
                root,
                "bad.txt",
                b"A" * 101,
            )

            issues, _ = MODULE.validate_file(
                path,
                "bad.txt",
                max_line_bytes=100,
            )

            self.assertTrue(
                any(
                    item[0] == "GIANT_LINE"
                    for item in issues
                )
            )

    def test_oversize_text_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            path = self._write(
                root,
                "bad.txt",
                b"A" * 101,
            )

            issues, _ = MODULE.validate_file(
                path,
                "bad.txt",
                max_text_bytes=100,
            )

            self.assertTrue(
                any(
                    item[0] == "TEXT_FILE_OVERSIZE"
                    for item in issues
                )
            )

    def test_malformed_structured_data_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            cases = {
                "bad.json":
                    b'{"broken":\n',

                "bad.jsonl":
                    b'{"ok":1}\nnot-json\n',
            }

            for name, data in cases.items():
                with self.subTest(name=name):
                    path = self._write(
                        root,
                        name,
                        data,
                    )

                    issues, _ = MODULE.validate_file(
                        path,
                        name,
                    )

                    self.assertTrue(
                        any(
                            item[0]
                            == "STRUCTURED_PARSE_FAILURE"
                            for item in issues
                        )
                    )


if __name__ == "__main__":
    unittest.main()
