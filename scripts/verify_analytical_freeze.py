from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def sha256_path(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--repo",
        required=True,
    )

    parser.add_argument(
        "--freeze-record",
        required=True,
    )

    args = parser.parse_args()

    repo = Path(
        args.repo
    ).resolve()

    record_path = Path(
        args.freeze_record
    ).resolve()

    record = json.loads(
        record_path.read_text(
            encoding="utf-8"
        )
    )

    if record.get(
        "schema_version"
    ) != "tracesoc-analytical-freeze-v1":
        raise SystemExit(
            "STOP: unsupported analytical freeze schema."
        )

    if record.get(
        "freeze_status"
    ) != "FROZEN":
        raise SystemExit(
            "STOP: analytical freeze record is not FROZEN."
        )

    files = record.get(
        "frozen_files"
    )

    if (
        not isinstance(
            files,
            list,
        )
        or not files
    ):
        raise SystemExit(
            "STOP: freeze record contains no frozen files."
        )

    observed_paths = []

    canonical_records = []

    for item in files:
        relative = item.get(
            "path"
        )

        expected_sha = item.get(
            "sha256"
        )

        expected_bytes = item.get(
            "bytes"
        )

        if not isinstance(
            relative,
            str,
        ):
            raise SystemExit(
                "STOP: malformed freeze path."
            )

        path = (
            repo
            / relative
        ).resolve()

        try:
            path.relative_to(
                repo
            )
        except ValueError:
            raise SystemExit(
                "STOP: frozen path escapes repository: "
                + relative
            )

        if not path.is_file():
            raise SystemExit(
                "STOP: frozen file missing: "
                + relative
            )

        actual_bytes = path.stat().st_size
        actual_sha = sha256_path(
            path
        )

        if actual_bytes != expected_bytes:
            raise SystemExit(
                "STOP: frozen byte-size mismatch: "
                + relative
            )

        if actual_sha != expected_sha:
            raise SystemExit(
                "STOP: frozen SHA-256 mismatch: "
                + relative
            )

        observed_paths.append(
            relative
        )

        canonical_records.append(
            {
                "path":
                    relative,

                "bytes":
                    actual_bytes,

                "sha256":
                    actual_sha,
            }
        )

    if len(
        observed_paths
    ) != len(
        set(
            observed_paths
        )
    ):
        raise SystemExit(
            "STOP: duplicate frozen path in manifest."
        )

    canonical_bytes = (
        json.dumps(
            canonical_records,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode(
        "utf-8"
    )

    fingerprint = hashlib.sha256(
        canonical_bytes
    ).hexdigest()

    if fingerprint != record.get(
        "analytical_candidate_sha256"
    ):
        raise SystemExit(
            "STOP: analytical candidate fingerprint mismatch."
        )

    head = subprocess.run(
        [
            "git",
            "-C",
            str(
                repo
            ),
            "rev-parse",
            "HEAD",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()

    source_commit = str(
        record.get(
            "source_commit",
            "",
        )
    )

    if not source_commit:
        raise SystemExit(
            "STOP: analytical freeze source_commit is missing."
        )

    ancestry = subprocess.run(
        [
            "git",
            "-C",
            str(
                repo
            ),
            "merge-base",
            "--is-ancestor",
            source_commit,
            head,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if ancestry.returncode == 1:
        raise SystemExit(
            "STOP: analytical freeze source commit is not an ancestor of repository HEAD."
        )

    if ancestry.returncode != 0:
        raise SystemExit(
            "STOP: unable to verify analytical freeze ancestry: "
            + ancestry.stderr.strip()
        )

    print(
        "ANALYTICAL_FREEZE_FILE_COUNT="
        + str(
            len(
                canonical_records
            )
        )
    )

    print(
        "ANALYTICAL_CANDIDATE_SHA256="
        + fingerprint
    )

    print(
        "ANALYTICAL_FREEZE_VERIFY=PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )