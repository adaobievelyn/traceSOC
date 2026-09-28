from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path
import subprocess
import sys


MAX_TEXT_BYTES = 10 * 1024 * 1024
MAX_LINE_BYTES = 1 * 1024 * 1024

TEXT_EXTENSIONS = {
    ".py",
    ".md",
    ".json",
    ".jsonl",
    ".csv",
    ".txt",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".ps1",
    ".psm1",
    ".psd1",
    ".bat",
    ".cmd",
}

TEXT_FILENAMES = {
    ".gitattributes",
    ".gitignore",
}

MOJIBAKE_MARKERS = tuple(
    "".join(chr(codepoint) for codepoint in codepoints)
    for codepoints in (
        (0x00C3, 0x0192),
        (0x00C3, 0x201A),
        (0x00C3, 0x00A2),
        (0x00E2, 0x20AC),
        (0x00EF, 0x00BB, 0x00BF),
    )
)

def is_text_path(path: Path) -> bool:
    return (
        path.suffix.lower() in TEXT_EXTENSIONS
        or path.name in TEXT_FILENAMES
    )


def validate_file(
    path: Path,
    relative_path: str,
    *,
    max_text_bytes: int = MAX_TEXT_BYTES,
    max_line_bytes: int = MAX_LINE_BYTES,
):
    issues = []
    structured = False

    data = path.read_bytes()

    if len(data) > max_text_bytes:
        issues.append(
            (
                "TEXT_FILE_OVERSIZE",
                relative_path,
                f"bytes={len(data)} limit={max_text_bytes}",
            )
        )

    if b"\x00" in data:
        issues.append(
            (
                "NUL_BYTE",
                relative_path,
                "NUL byte found in tracked text file",
            )
        )

    try:
        # utf-8-sig accepts an existing UTF-8 BOM while still
        # rejecting invalid UTF-8 byte sequences.
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        issues.append(
            (
                "INVALID_UTF8",
                relative_path,
                str(exc),
            )
        )
        return issues, structured

    for marker in MOJIBAKE_MARKERS:
        if marker in text:
            issues.append(
                (
                    "MOJIBAKE",
                    relative_path,
                    f"marker={marker!r}",
                )
            )

    for number, raw_line in enumerate(
        data.split(b"\n"),
        1,
    ):
        if len(raw_line) > max_line_bytes:
            issues.append(
                (
                    "GIANT_LINE",
                    relative_path,
                    f"line={number} bytes={len(raw_line)} "
                    f"limit={max_line_bytes}",
                )
            )

    suffix = path.suffix.lower()

    try:
        if suffix == ".json":
            structured = True
            json.loads(text)

        elif suffix == ".jsonl":
            structured = True

            for number, line in enumerate(
                text.splitlines(),
                1,
            ):
                if not line.strip():
                    continue

                try:
                    json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"line {number}: {exc}"
                    ) from exc

        elif suffix == ".csv":
            structured = True

            stream = io.StringIO(
                text,
                newline="",
            )

            for _ in csv.reader(stream):
                pass

    except Exception as exc:
        issues.append(
            (
                "STRUCTURED_PARSE_FAILURE",
                relative_path,
                str(exc),
            )
        )

    return issues, structured


def tracked_text_paths(repo: Path):
    process = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "ls-files",
            "-z",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    names = (
        process.stdout
        .decode("utf-8")
        .split("\x00")
    )

    result = []

    for name in names:
        if not name:
            continue

        relative = Path(name)

        if not is_text_path(relative):
            continue

        result.append(
            (
                name,
                repo / relative,
            )
        )

    return result


def validate_repository(repo: Path):
    issues = []
    text_files = 0
    structured_files = 0

    for relative, path in tracked_text_paths(repo):
        text_files += 1

        if not path.is_file():
            issues.append(
                (
                    "TRACKED_TEXT_MISSING",
                    relative,
                    "tracked path is not a file",
                )
            )
            continue

        file_issues, structured = validate_file(
            path,
            relative,
        )

        issues.extend(file_issues)

        if structured:
            structured_files += 1

    return {
        "text_files": text_files,
        "structured_files": structured_files,
        "issues": issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate tracked TraceSOC text files for UTF-8 "
            "integrity, mojibake, abnormal growth, giant lines "
            "and structured-file parse failures."
        )
    )

    parser.add_argument(
        "--repo",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    repo = args.repo.resolve()

    result = validate_repository(repo)

    print(
        f"TEXT_FILES_SCANNED={result['text_files']}"
    )
    print(
        "STRUCTURED_FILES_PARSED="
        f"{result['structured_files']}"
    )
    print(
        f"INTEGRITY_ISSUES={len(result['issues'])}"
    )

    for index, issue in enumerate(
        result["issues"],
        1,
    ):
        code, path, detail = issue

        print(
            f"ISSUE={index} "
            f"CODE={code} "
            f"PATH={path} "
            f"DETAIL={detail}"
        )

    if result["issues"]:
        print("REPOSITORY_TEXT_INTEGRITY=FAIL")
        return 1

    print("REPOSITORY_TEXT_INTEGRITY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())