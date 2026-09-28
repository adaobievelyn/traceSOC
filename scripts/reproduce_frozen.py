from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "tracesoc-clean-reproduction-v1"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)

            if not block:
                break

            digest.update(block)

    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    return sha256_bytes(encoded)


def run_git_text(
    repo: Path,
    *arguments: str,
) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            *arguments,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "git command failed: "
            + " ".join(arguments)
            + "\n"
            + result.stderr
        )

    return result.stdout


def run_git_bytes(
    repo: Path,
    *arguments: str,
) -> bytes:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            *arguments,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "git command failed: "
            + " ".join(arguments)
            + "\n"
            + result.stderr.decode(
                "utf-8",
                errors="replace",
            )
        )

    return result.stdout


def run_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None,
    label: str,
) -> str:
    print()
    print("=== " + label + " ===")
    print(
        "COMMAND="
        + " ".join(command)
    )

    result = subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    output = result.stdout or ""

    if output:
        print(
            output,
            end="" if output.endswith("\n") else "\n",
        )

    print(
        label.upper()
        .replace(" ", "_")
        .replace("/", "_")
        + "_EXIT_CODE="
        + str(result.returncode)
    )

    if result.returncode != 0:
        raise RuntimeError(
            label + " failed"
        )

    return output


def file_inventory(
    root: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for path in sorted(
        item
        for item in root.rglob("*")
        if item.is_file()
    ):
        relative = (
            path.relative_to(root)
            .as_posix()
        )

        rows.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )

    return rows


def raw_snapshot(
    root: Path,
) -> dict[str, Any]:
    files = file_inventory(root)

    legacy_rows = [
        (
            item["path"]
            + "|"
            + str(item["bytes"])
            + "|"
            + item["sha256"]
        )
        for item in files
    ]

    payload = (
        "\n".join(legacy_rows)
        + "\n"
    ).encode("utf-8")

    return {
        "file_count": len(files),
        "total_bytes": sum(
            int(item["bytes"])
            for item in files
        ),
        "corpus_sha256":
            sha256_bytes(payload),
        "files": files,
    }


def verify_prior_proof(
    proof_path: Path,
    *,
    freeze_sha256: str,
    source_commit: str,
) -> dict[str, Any]:
    if not proof_path.is_file():
        raise RuntimeError(
            "preserved real-evidence proof is missing"
        )

    raw = proof_path.read_bytes()

    record = json.loads(
        raw.decode("utf-8")
    )

    if record.get(
        "schema_version"
    ) != "tracesoc-frozen-real-evidence-reproduction-v1":
        raise RuntimeError(
            "unexpected preserved reproduction-proof schema"
        )

    if record.get(
        "acceptance",
        {},
    ).get(
        "overall"
    ) != "PASS":
        raise RuntimeError(
            "preserved reproduction proof is not PASS"
        )

    implementation = record.get(
        "implementation",
        {},
    )

    if implementation.get(
        "source_commit"
    ) != source_commit:
        raise RuntimeError(
            "preserved proof source commit differs from freeze"
        )

    if implementation.get(
        "implementation_freeze_record_sha256"
    ) != freeze_sha256:
        raise RuntimeError(
            "preserved proof does not bind current freeze record"
        )

    return {
        "record_sha256":
            sha256_bytes(raw),

        "benchmark_raw_corpus_sha256":
            record.get(
                "raw_evidence",
                {},
            ).get(
                "corpus_sha256"
            ),

        "benchmark_case_id":
            record.get(
                "case_reproduction",
                {},
            ).get(
                "case_id"
            ),

        "benchmark_comparison_sha256":
            record.get(
                "case_reproduction",
                {},
            ).get(
                "two_clean_run_comparison_sha256"
            ),
    }


def verify_freeze(
    repo: Path,
    freeze_path: Path,
) -> dict[str, Any]:
    if not freeze_path.is_file():
        raise RuntimeError(
            "implementation freeze record is missing"
        )

    freeze_raw = freeze_path.read_bytes()

    record = json.loads(
        freeze_raw.decode("utf-8")
    )

    if record.get(
        "schema_version"
    ) != "tracesoc-analytical-freeze-v1":
        raise RuntimeError(
            "unexpected freeze schema"
        )

    if record.get(
        "freeze_status"
    ) != "FROZEN":
        raise RuntimeError(
            "implementation is not frozen"
        )

    source_commit = str(
        record.get(
            "source_commit",
            "",
        )
    )

    if not source_commit:
        raise RuntimeError(
            "freeze source_commit is missing"
        )

    current_head = run_git_text(
        repo,
        "rev-parse",
        "HEAD",
    ).strip()

    ancestor = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "merge-base",
            "--is-ancestor",
            source_commit,
            current_head,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if ancestor.returncode != 0:
        raise RuntimeError(
            "implementation source commit is not an ancestor of current HEAD"
        )

    frozen_files = record.get(
        "frozen_files"
    )

    if (
        not isinstance(
            frozen_files,
            list,
        )
        or not frozen_files
    ):
        raise RuntimeError(
            "freeze frozen_files is invalid"
        )

    paths = [
        str(item["path"])
        for item in frozen_files
    ]

    if len(paths) != len(set(paths)):
        raise RuntimeError(
            "freeze contains duplicate paths"
        )

    if paths != sorted(paths):
        raise RuntimeError(
            "freeze paths are not canonically sorted"
        )

    for item in frozen_files:
        relative = str(
            item["path"]
        )

        expected_bytes = int(
            item["bytes"]
        )

        expected_sha = str(
            item["sha256"]
        )

        worktree_path = (
            repo
            / relative
        )

        if not worktree_path.is_file():
            raise RuntimeError(
                "frozen worktree file missing: "
                + relative
            )

        if (
            worktree_path.stat().st_size
            != expected_bytes
        ):
            raise RuntimeError(
                "frozen worktree byte count changed: "
                + relative
            )

        if (
            sha256_file(worktree_path)
            != expected_sha
        ):
            raise RuntimeError(
                "frozen worktree bytes changed: "
                + relative
            )

        committed = run_git_bytes(
            repo,
            "show",
            source_commit
            + ":"
            + relative,
        )

        if len(committed) != expected_bytes:
            raise RuntimeError(
                "source-commit byte count differs: "
                + relative
            )

        if sha256_bytes(
            committed
        ) != expected_sha:
            raise RuntimeError(
                "source-commit blob differs: "
                + relative
            )

    canonical = (
        json.dumps(
            frozen_files,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    candidate_sha = sha256_bytes(
        canonical
    )

    if candidate_sha != record.get(
        "analytical_candidate_sha256"
    ):
        raise RuntimeError(
            "freeze analytical candidate fingerprint mismatch"
        )

    return {
        "current_head":
            current_head,

        "source_commit":
            source_commit,

        "freeze_record_sha256":
            sha256_bytes(
                freeze_raw
            ),

        "frozen_file_count":
            len(frozen_files),

        "analytical_candidate_sha256":
            candidate_sha,
    }


def copy_build_context(
    repo: Path,
    destination: Path,
) -> None:
    destination.mkdir(
        parents=True,
        exist_ok=False,
    )

    pyproject = (
        repo
        / "pyproject.toml"
    )

    if not pyproject.is_file():
        raise RuntimeError(
            "pyproject.toml is missing"
        )

    shutil.copy2(
        pyproject,
        destination
        / "pyproject.toml",
    )

    shutil.copytree(
        repo / "src",
        destination / "src",
        ignore=shutil.ignore_patterns(
            "__pycache__",
            "*.pyc",
            ".pytest_cache",
            "*.egg-info",
        ),
    )


def python_tree(
    root: Path,
) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}

    for path in sorted(
        root.rglob("*.py")
    ):
        if "__pycache__" in path.parts:
            continue

        relative = (
            path.relative_to(root)
            .as_posix()
        )

        rows[relative] = {
            "bytes":
                path.stat().st_size,

            "sha256":
                sha256_file(path),
        }

    return rows


def prove_install_equivalence(
    repo: Path,
    install_root: Path,
) -> dict[str, Any]:
    source_root = (
        repo
        / "src"
        / "tracesoc"
    )

    installed_root = (
        install_root
        / "tracesoc"
    )

    if not installed_root.is_dir():
        raise RuntimeError(
            "isolated install has no tracesoc package"
        )

    source = python_tree(
        source_root
    )

    installed = python_tree(
        installed_root
    )

    if not source:
        raise RuntimeError(
            "frozen source package contains no Python files"
        )

    missing = sorted(
        set(source)
        - set(installed)
    )

    extra = sorted(
        set(installed)
        - set(source)
    )

    different = sorted(
        relative
        for relative in (
            set(source)
            & set(installed)
        )
        if source[relative]
        != installed[relative]
    )

    if missing or extra or different:
        raise RuntimeError(
            "installed package differs from frozen source; "
            + "missing="
            + repr(missing)
            + " extra="
            + repr(extra)
            + " different="
            + repr(different)
        )

    canonical = [
        {
            "path":
                relative,

            "bytes":
                source[
                    relative
                ][
                    "bytes"
                ],

            "sha256":
                source[
                    relative
                ][
                    "sha256"
                ],
        }
        for relative in sorted(
            source
        )
    ]

    return {
        "python_file_count":
            len(source),

        "source_install_fingerprint":
            canonical_sha256(
                canonical
            ),
    }


def parse_test_count(
    output: str,
) -> int:
    matches = re.findall(
        r"Ran\s+(\d+)\s+tests?",
        output,
    )

    if not matches:
        raise RuntimeError(
            "unable to determine unittest denominator"
        )

    return int(
        matches[-1]
    )


def validate_public_report(
    report: dict[str, Any],
) -> dict[str, Any]:
    if report.get(
        "result"
    ) != "PASS":
        raise RuntimeError(
            "public acceptance result is not PASS"
        )

    regression = report.get(
        "full_regression"
    )

    if not isinstance(
        regression,
        dict,
    ):
        raise RuntimeError(
            "public acceptance full_regression missing"
        )

    discovered = int(
        regression.get(
            "discovered",
            0,
        )
    )

    tests_run = int(
        regression.get(
            "tests_run",
            -1,
        )
    )

    passed = int(
        regression.get(
            "passed",
            -1,
        )
    )

    if discovered <= 0:
        raise RuntimeError(
            "public regression discovered no tests"
        )

    if (
        tests_run != discovered
        or passed != discovered
    ):
        raise RuntimeError(
            "public regression did not completely pass"
        )

    for field in (
        "failed",
        "errors",
        "skipped",
        "expected_failures",
        "unexpected_successes",
    ):
        if int(
            regression.get(
                field,
                -1,
            )
        ) != 0:
            raise RuntimeError(
                "nonzero public regression field: "
                + field
            )

    classes = report.get(
        "public_acceptance"
    )

    if (
        not isinstance(
            classes,
            dict,
        )
        or not classes
    ):
        raise RuntimeError(
            "public acceptance classes missing"
        )

    for name, value in classes.items():
        if (
            not isinstance(
                value,
                dict,
            )
            or value.get(
                "result"
            )
            != "PASS"
        ):
            raise RuntimeError(
                "public acceptance class failed: "
                + str(name)
            )

    return {
        "regression_tests":
            discovered,

        "acceptance_classes":
            len(classes),
    }


def run_validation(
    *,
    repo: Path,
    install_root: Path,
    run_root: Path,
    source_commit: str,
) -> dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(
        install_root
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    unit_output = run_command(
        [
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            str(
                repo
                / "tests"
                / "unit"
            ),
            "-p",
            "test_*.py",
        ],
        cwd=run_root,
        env=env,
        label="unit regression",
    )

    integration_output = run_command(
        [
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            str(
                repo
                / "tests"
                / "integration"
            ),
            "-p",
            "test_*.py",
        ],
        cwd=run_root,
        env=env,
        label="integration regression",
    )

    public_runner = (
        repo
        / "scripts"
        / "run_public_acceptance.py"
    )

    if not public_runner.is_file():
        raise RuntimeError(
            "public acceptance runner is missing"
        )

    public_report_path = (
        run_root
        / "public-acceptance.json"
    )

    run_command(
        [
            sys.executable,
            "-B",
            str(public_runner),
            "--repo",
            str(repo),
            "--commit",
            source_commit,
            "--output",
            str(
                public_report_path
            ),
        ],
        cwd=run_root,
        env=env,
        label="public acceptance",
    )

    public_raw = (
        public_report_path.read_bytes()
    )

    public_report = json.loads(
        public_raw.decode(
            "utf-8"
        )
    )

    public_counts = validate_public_report(
        public_report
    )

    return {
        "unit_tests":
            parse_test_count(
                unit_output
            ),

        "integration_tests":
            parse_test_count(
                integration_output
            ),

        "public_regression_tests":
            public_counts[
                "regression_tests"
            ],

        "public_acceptance_classes":
            public_counts[
                "acceptance_classes"
            ],

        "public_report_sha256":
            sha256_bytes(
                public_raw
            ),

        "public_report":
            public_report,
    }


def worker_analyze(
    *,
    install_root: Path,
    evidence: Path,
    output: Path,
    manifest: Path,
) -> int:
    sys.path.insert(
        0,
        str(install_root)
    )

    import tracesoc
    from tracesoc.cli.case import analyze_case

    module_path = Path(
        tracesoc.__file__
    ).resolve()

    try:
        module_path.relative_to(
            install_root.resolve()
        )
    except ValueError as exc:
        raise RuntimeError(
            "analysis import escaped isolated installation"
        ) from exc

    raw_files = [
        item
        for item in evidence.rglob("*")
        if item.is_file()
    ]

    result = analyze_case(
        evidence_directory=evidence,
        output_directory=output,
    )

    if not isinstance(
        result,
        dict,
    ):
        raise RuntimeError(
            "analyze_case returned a non-dictionary result"
        )

    raw_count = len(
        raw_files
    )

    required_true = (
        "all_registered_detectors_integrated",
        "raw_evidence_embedded",
        "seal_verified",
    )

    for key in required_true:
        if result.get(
            key
        ) is not True:
            raise RuntimeError(
                "case execution property failed: "
                + key
            )

    if result.get(
        "artifact_count"
    ) != raw_count:
        raise RuntimeError(
            "not every raw file became an artifact"
        )

    if result.get(
        "raw_evidence_file_count"
    ) != raw_count:
        raise RuntimeError(
            "raw evidence file accounting mismatch"
        )

    if result.get(
        "raw_evidence_hashes_verified"
    ) != raw_count:
        raise RuntimeError(
            "not every raw evidence hash verified"
        )

    stable_result = {
        key: value
        for key, value in result.items()
        if key != "output_directory"
    }

    derived_files = file_inventory(
        output
    )

    manifest_record = {
        "stable_case_result":
            stable_result,

        "derived_files":
            derived_files,

        "derived_inventory_sha256":
            canonical_sha256(
                derived_files
            ),
    }

    manifest.write_text(
        json.dumps(
            manifest_record,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(
        "CASE_ID="
        + str(
            stable_result.get(
                "case_id"
            )
        )
    )

    print(
        "RAW_FILE_COUNT="
        + str(raw_count)
    )

    print(
        "CANONICAL_EVENT_COUNT="
        + str(
            stable_result.get(
                "canonical_event_count"
            )
        )
    )

    print(
        "MATCHED_DETECTION_COUNT="
        + str(
            stable_result.get(
                "matched_detection_count"
            )
        )
    )

    print(
        "MATCHED_CORRELATION_COUNT="
        + str(
            stable_result.get(
                "matched_correlation_count"
            )
        )
    )

    print(
        "RELATIONSHIP_COUNT="
        + str(
            stable_result.get(
                "relationship_count"
            )
        )
    )

    print(
        "FINDING_COUNT="
        + str(
            stable_result.get(
                "finding_count"
            )
        )
    )

    print(
        "DERIVED_FILE_COUNT="
        + str(
            len(
                derived_files
            )
        )
    )

    print(
        "SEAL_SHA256="
        + str(
            stable_result.get(
                "seal_sha256"
            )
        )
    )

    return 0


def run_clean_build(
    *,
    label: str,
    repo: Path,
    evidence: Path,
    case_output: Path,
    outer_root: Path,
    source_commit: str,
) -> dict[str, Any]:
    run_root = (
        outer_root
        / (
            "run-"
            + label
        )
    )

    build_context = (
        run_root
        / "build-context"
    )

    install_root = (
        run_root
        / "isolated-install"
    )

    case_manifest_path = (
        outer_root
        / (
            "case-manifest-"
            + label
            + ".json"
        )
    )

    run_root.mkdir(
        parents=True,
        exist_ok=False,
    )

    copy_build_context(
        repo,
        build_context,
    )

    install_root.mkdir(
        parents=True,
        exist_ok=False,
    )

    run_command(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            "--no-build-isolation",
            "--no-cache-dir",
            "--no-compile",
            "--target",
            str(
                install_root
            ),
            str(
                build_context
            ),
        ],
        cwd=run_root,
        env=None,
        label=(
            "clean build "
            + label
        ),
    )

    equivalence = prove_install_equivalence(
        repo,
        install_root,
    )

    print(
        "BUILD_"
        + label
        + "_PYTHON_FILE_COUNT="
        + str(
            equivalence[
                "python_file_count"
            ]
        )
    )

    print(
        "BUILD_"
        + label
        + "_SOURCE_INSTALL_EQUIVALENCE=PASS"
    )

    validation = run_validation(
        repo=repo,
        install_root=install_root,
        run_root=run_root,
        source_commit=source_commit,
    )

    worker_env = os.environ.copy()
    worker_env[
        "PYTHONDONTWRITEBYTECODE"
    ] = "1"

    run_command(
        [
            sys.executable,
            "-B",
            str(
                Path(__file__).resolve()
            ),
            "--worker-analyze",
            "--install-root",
            str(
                install_root
            ),
            "--evidence",
            str(
                evidence
            ),
            "--output",
            str(
                case_output
            ),
            "--worker-manifest",
            str(
                case_manifest_path
            ),
        ],
        cwd=run_root,
        env=worker_env,
        label=(
            "real evidence run "
            + label
        ),
    )

    case_raw = (
        case_manifest_path.read_bytes()
    )

    case_manifest = json.loads(
        case_raw.decode(
            "utf-8"
        )
    )

    return {
        "label":
            label,

        "run_root":
            str(
                run_root
            ),

        "equivalence":
            equivalence,

        "validation":
            validation,

        "case_manifest_sha256":
            sha256_bytes(
                case_raw
            ),

        "case_manifest":
            case_manifest,
    }


def compare_runs(
    run_a: dict[str, Any],
    run_b: dict[str, Any],
) -> dict[str, Any]:
    eq_a = run_a[
        "equivalence"
    ]

    eq_b = run_b[
        "equivalence"
    ]

    if (
        eq_a[
            "source_install_fingerprint"
        ]
        != eq_b[
            "source_install_fingerprint"
        ]
    ):
        raise RuntimeError(
            "installed-product fingerprints differ between builds"
        )

    val_a = run_a[
        "validation"
    ]

    val_b = run_b[
        "validation"
    ]

    for key in (
        "unit_tests",
        "integration_tests",
        "public_regression_tests",
        "public_acceptance_classes",
    ):
        if val_a[key] != val_b[key]:
            raise RuntimeError(
                "validation denominator differs between runs: "
                + key
            )

    if (
        val_a[
            "public_report"
        ]
        != val_b[
            "public_report"
        ]
    ):
        raise RuntimeError(
            "public acceptance reports differ"
        )

    case_a = run_a[
        "case_manifest"
    ]

    case_b = run_b[
        "case_manifest"
    ]

    if (
        case_a[
            "stable_case_result"
        ]
        != case_b[
            "stable_case_result"
        ]
    ):
        raise RuntimeError(
            "stable case results differ"
        )

    if (
        case_a[
            "derived_files"
        ]
        != case_b[
            "derived_files"
        ]
    ):
        index_a = {
            item["path"]: item
            for item in case_a[
                "derived_files"
            ]
        }

        index_b = {
            item["path"]: item
            for item in case_b[
                "derived_files"
            ]
        }

        for relative in sorted(
            set(index_a)
            | set(index_b)
        ):
            if (
                index_a.get(
                    relative
                )
                != index_b.get(
                    relative
                )
            ):
                print(
                    "DERIVED_DIFFERENCE|"
                    + relative
                    + "|A="
                    + repr(
                        index_a.get(
                            relative
                        )
                    )
                    + "|B="
                    + repr(
                        index_b.get(
                            relative
                        )
                    )
                )

        raise RuntimeError(
            "derived outputs differ"
        )

    comparison_material = {
        "source_install_fingerprint":
            eq_a[
                "source_install_fingerprint"
            ],

        "validation": {
            "unit_tests":
                val_a[
                    "unit_tests"
                ],

            "integration_tests":
                val_a[
                    "integration_tests"
                ],

            "public_regression_tests":
                val_a[
                    "public_regression_tests"
                ],

            "public_acceptance_classes":
                val_a[
                    "public_acceptance_classes"
                ],

            "public_report":
                val_a[
                    "public_report"
                ],
        },

        "stable_case_result":
            case_a[
                "stable_case_result"
            ],

        "derived_files":
            case_a[
                "derived_files"
            ],
    }

    return {
        "comparison_sha256":
            canonical_sha256(
                comparison_material
            ),

        "source_install_fingerprint":
            eq_a[
                "source_install_fingerprint"
            ],

        "unit_tests":
            val_a[
                "unit_tests"
            ],

        "integration_tests":
            val_a[
                "integration_tests"
            ],

        "public_regression_tests":
            val_a[
                "public_regression_tests"
            ],

        "public_acceptance_classes":
            val_a[
                "public_acceptance_classes"
            ],

        "public_report_sha256":
            val_a[
                "public_report_sha256"
            ],

        "stable_case_result":
            case_a[
                "stable_case_result"
            ],

        "derived_files":
            case_a[
                "derived_files"
            ],

        "derived_inventory_sha256":
            case_a[
                "derived_inventory_sha256"
            ],
    }


def is_relative_to(
    candidate: Path,
    parent: Path,
) -> bool:
    try:
        candidate.relative_to(
            parent
        )
        return True
    except ValueError:
        return False


def orchestrate(
    *,
    repo: Path,
    evidence: Path,
    output: Path,
) -> int:
    if sys.version_info < (3, 11):
        raise RuntimeError(
            "TraceSOC reproduction requires Python 3.11+"
        )

    if not evidence.is_dir():
        raise RuntimeError(
            "evidence directory does not exist: "
            + str(evidence)
        )

    if output.exists():
        raise RuntimeError(
            "output directory already exists: "
            + str(output)
        )

    if is_relative_to(
        output,
        repo,
    ):
        raise RuntimeError(
            "final reproduction output must be outside the repository"
        )

    if (
        output == evidence
        or is_relative_to(
            output,
            evidence,
        )
    ):
        raise RuntimeError(
            "final output must not be inside the evidence directory"
        )

    validation_path = (
        output.parent
        / (
            output.name
            + "-reproduction-validation.json"
        )
    )

    if validation_path.exists():
        raise RuntimeError(
            "validation record already exists: "
            + str(
                validation_path
            )
        )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    freeze_path = (
        repo
        / "project-control"
        / "v04-implementation-freeze.json"
    )

    proof_path = (
        repo
        / "project-control"
        / "frozen-real-evidence-reproduction.json"
    )

    print("=" * 78)
    print("TRACESOC v0.4 CLEAN REPRODUCTION")
    print("=" * 78)
    print(
        "REPOSITORY="
        + str(repo)
    )
    print(
        "EVIDENCE_DIRECTORY="
        + str(evidence)
    )
    print(
        "FINAL_CASE_OUTPUT="
        + str(output)
    )
    print(
        "VALIDATION_RECORD="
        + str(
            validation_path
        )
    )
    print(
        "PYTHON_VERSION="
        + sys.version.replace(
            "\n",
            " "
        )
    )

    freeze = verify_freeze(
        repo,
        freeze_path,
    )

    prior = verify_prior_proof(
        proof_path,
        freeze_sha256=freeze[
            "freeze_record_sha256"
        ],
        source_commit=freeze[
            "source_commit"
        ],
    )

    raw_before = raw_snapshot(
        evidence
    )

    if raw_before[
        "file_count"
    ] <= 0:
        raise RuntimeError(
            "evidence directory contains no files"
        )

    print(
        "CURRENT_HEAD="
        + freeze[
            "current_head"
        ]
    )
    print(
        "IMPLEMENTATION_SOURCE_COMMIT="
        + freeze[
            "source_commit"
        ]
    )
    print(
        "FROZEN_FILE_COUNT="
        + str(
            freeze[
                "frozen_file_count"
            ]
        )
    )
    print(
        "ANALYTICAL_CANDIDATE_SHA256="
        + freeze[
            "analytical_candidate_sha256"
        ]
    )
    print(
        "PRIOR_REPRODUCTION_PROOF_SHA256="
        + prior[
            "record_sha256"
        ]
    )
    print(
        "RAW_FILE_COUNT="
        + str(
            raw_before[
                "file_count"
            ]
        )
    )
    print(
        "RAW_TOTAL_BYTES="
        + str(
            raw_before[
                "total_bytes"
            ]
        )
    )
    print(
        "RAW_CORPUS_SHA256="
        + raw_before[
            "corpus_sha256"
        ]
    )

    benchmark_match = (
        raw_before[
            "corpus_sha256"
        ]
        == prior[
            "benchmark_raw_corpus_sha256"
        ]
    )

    print(
        "MATCHES_PRESERVED_REAL_EVIDENCE_BENCHMARK="
        + str(
            benchmark_match
        ).upper()
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="tracesoc-reproduce-"
        ) as temporary:
            outer_root = Path(
                temporary
            )

            case_a = (
                outer_root
                / "case-A"
            )

            print()
            print("=" * 78)
            print("INDEPENDENT CLEAN BUILD / RUN A")
            print("=" * 78)

            run_a = run_clean_build(
                label="A",
                repo=repo,
                evidence=evidence,
                case_output=case_a,
                outer_root=outer_root,
                source_commit=freeze[
                    "source_commit"
                ],
            )

            raw_between = raw_snapshot(
                evidence
            )

            if raw_between != raw_before:
                raise RuntimeError(
                    "raw evidence changed during run A"
                )

            shutil.rmtree(
                Path(
                    run_a[
                        "run_root"
                    ]
                ),
                ignore_errors=False,
            )

            shutil.rmtree(
                case_a,
                ignore_errors=False,
            )

            print(
                "RUN_A_HEAVY_OUTPUT_REMOVED=TRUE"
            )

            print()
            print("=" * 78)
            print("INDEPENDENT CLEAN BUILD / RUN B")
            print("=" * 78)

            run_b = run_clean_build(
                label="B",
                repo=repo,
                evidence=evidence,
                case_output=output,
                outer_root=outer_root,
                source_commit=freeze[
                    "source_commit"
                ],
            )

            raw_after = raw_snapshot(
                evidence
            )

            if raw_after != raw_before:
                raise RuntimeError(
                    "raw evidence changed during run B"
                )

            comparison = compare_runs(
                run_a,
                run_b,
            )

            freeze_after = verify_freeze(
                repo,
                freeze_path,
            )

            if freeze_after != freeze:
                raise RuntimeError(
                    "frozen implementation state changed during reproduction"
                )

            validation_record = {
                "schema_version":
                    SCHEMA_VERSION,

                "status":
                    "PASS",

                "implementation":
                    freeze,

                "preserved_real_evidence_proof":
                    prior,

                "benchmark_corpus_match":
                    benchmark_match,

                "python": {
                    "version":
                        sys.version.replace(
                            "\n",
                            " "
                        ),

                    "executable":
                        sys.executable,
                },

                "raw_evidence":
                    raw_before,

                "run_a": {
                    "source_install":
                        run_a[
                            "equivalence"
                        ],

                    "unit_tests":
                        run_a[
                            "validation"
                        ][
                            "unit_tests"
                        ],

                    "integration_tests":
                        run_a[
                            "validation"
                        ][
                            "integration_tests"
                        ],

                    "public_regression_tests":
                        run_a[
                            "validation"
                        ][
                            "public_regression_tests"
                        ],

                    "public_acceptance_classes":
                        run_a[
                            "validation"
                        ][
                            "public_acceptance_classes"
                        ],

                    "public_report_sha256":
                        run_a[
                            "validation"
                        ][
                            "public_report_sha256"
                        ],

                    "case_manifest_sha256":
                        run_a[
                            "case_manifest_sha256"
                        ],
                },

                "run_b": {
                    "source_install":
                        run_b[
                            "equivalence"
                        ],

                    "unit_tests":
                        run_b[
                            "validation"
                        ][
                            "unit_tests"
                        ],

                    "integration_tests":
                        run_b[
                            "validation"
                        ][
                            "integration_tests"
                        ],

                    "public_regression_tests":
                        run_b[
                            "validation"
                        ][
                            "public_regression_tests"
                        ],

                    "public_acceptance_classes":
                        run_b[
                            "validation"
                        ][
                            "public_acceptance_classes"
                        ],

                    "public_report_sha256":
                        run_b[
                            "validation"
                        ][
                            "public_report_sha256"
                        ],

                    "case_manifest_sha256":
                        run_b[
                            "case_manifest_sha256"
                        ],
                },

                "determinism": {
                    "source_install_match":
                        True,

                    "validation_denominators_match":
                        True,

                    "public_acceptance_match":
                        True,

                    "stable_case_result_match":
                        True,

                    "derived_path_byte_hash_match":
                        True,

                    "comparison_sha256":
                        comparison[
                            "comparison_sha256"
                        ],

                    "derived_inventory_sha256":
                        comparison[
                            "derived_inventory_sha256"
                        ],
                },

                "final_case": {
                    "output_directory":
                        str(output),

                    "stable_case_result":
                        comparison[
                            "stable_case_result"
                        ],

                    "derived_file_count":
                        len(
                            comparison[
                                "derived_files"
                            ]
                        ),
                },

                "packaging_boundary": {
                    "installed_product_byte_equivalence":
                        True,

                    "wheel_container_byte_reproducibility":
                        "not asserted",

                    "note":
                        (
                            "TraceSOC validates installed package content "
                            "and deterministic analysis outputs. Wheel "
                            "container byte reproducibility is not claimed."
                        ),
                },
            }

            validation_path.write_text(
                json.dumps(
                    validation_record,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )

            validation_sha = sha256_file(
                validation_path
            )

            shutil.rmtree(
                Path(
                    run_b[
                        "run_root"
                    ]
                ),
                ignore_errors=False,
            )

            print()
            print("=" * 78)
            print("REPRODUCTION RESULT")
            print("=" * 78)
            print(
                "REPRODUCTION_STATUS=PASS"
            )
            print(
                "IMPLEMENTATION_SOURCE_COMMIT="
                + freeze[
                    "source_commit"
                ]
            )
            print(
                "CURRENT_HEAD="
                + freeze[
                    "current_head"
                ]
            )
            print(
                "RAW_FILE_COUNT="
                + str(
                    raw_before[
                        "file_count"
                    ]
                )
            )
            print(
                "RAW_CORPUS_SHA256="
                + raw_before[
                    "corpus_sha256"
                ]
            )
            print(
                "UNIT_TESTS="
                + str(
                    comparison[
                        "unit_tests"
                    ]
                )
            )
            print(
                "INTEGRATION_TESTS="
                + str(
                    comparison[
                        "integration_tests"
                    ]
                )
            )
            print(
                "PUBLIC_REGRESSION_TESTS="
                + str(
                    comparison[
                        "public_regression_tests"
                    ]
                )
            )
            print(
                "PUBLIC_ACCEPTANCE_CLASSES="
                + str(
                    comparison[
                        "public_acceptance_classes"
                    ]
                )
            )
            print(
                "SOURCE_INSTALL_EQUIVALENCE_A=PASS"
            )
            print(
                "SOURCE_INSTALL_EQUIVALENCE_B=PASS"
            )
            print(
                "TWO_CLEAN_CASE_RUNS=PASS"
            )
            print(
                "DERIVED_BYTE_HASH_COMPARISON=PASS"
            )
            print(
                "RAW_EVIDENCE_IMMUTABILITY=PASS"
            )
            print(
                "TWO_RUN_COMPARISON_SHA256="
                + comparison[
                    "comparison_sha256"
                ]
            )
            print(
                "FINAL_CASE_OUTPUT="
                + str(output)
            )
            print(
                "VALIDATION_RECORD="
                + str(
                    validation_path
                )
            )
            print(
                "VALIDATION_RECORD_SHA256="
                + validation_sha
            )

    except Exception:
        if output.exists():
            shutil.rmtree(
                output,
                ignore_errors=True,
            )

        if validation_path.exists():
            validation_path.unlink()

        raise

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "TraceSOC frozen two-build clean reproduction "
            "and real-evidence deterministic validation"
        )
    )

    parser.add_argument(
        "--repo",
        type=Path,
    )

    parser.add_argument(
        "--evidence",
        type=Path,
    )

    parser.add_argument(
        "--output",
        type=Path,
    )

    parser.add_argument(
        "--worker-analyze",
        action="store_true",
    )

    parser.add_argument(
        "--install-root",
        type=Path,
    )

    parser.add_argument(
        "--worker-manifest",
        type=Path,
    )

    args = parser.parse_args()

    if args.worker_analyze:
        if (
            args.install_root is None
            or args.evidence is None
            or args.output is None
            or args.worker_manifest is None
        ):
            raise RuntimeError(
                "worker analysis arguments are incomplete"
            )

        return worker_analyze(
            install_root=args.install_root.resolve(),
            evidence=args.evidence.resolve(),
            output=args.output.resolve(),
            manifest=args.worker_manifest.resolve(),
        )

    repo = (
        args.repo.resolve()
        if args.repo is not None
        else Path(
            __file__
        ).resolve().parents[1]
    )

    if args.evidence is None:
        raise RuntimeError(
            "--evidence is required"
        )

    if args.output is None:
        raise RuntimeError(
            "--output is required"
        )

    return orchestrate(
        repo=repo,
        evidence=args.evidence.resolve(),
        output=args.output.resolve(),
    )


if __name__ == "__main__":
    try:
        raise SystemExit(
            main()
        )
    except Exception as exc:
        print(
            "REPRODUCTION_STATUS=FAIL",
            file=sys.stderr,
        )

        print(
            type(exc).__name__
            + ": "
            + str(exc),
            file=sys.stderr,
        )

        raise