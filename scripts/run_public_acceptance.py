from __future__ import annotations

import argparse
import importlib.metadata
import io
import json
import os
import platform
import sys
import unittest
from pathlib import Path


SCHEMA_VERSION = "1.0"
SUITE_ID = "tracesoc-public-acceptance-v1"

REPRESENTATIVE_METHODS = {
    "positive": "test_positive_distinct_correlation_matches",
    "negative": "test_wrong_host_falsifies_correlation",
    "malformed_input": (
        "test_windows_security_splunk_"
        "quarantines_malformed_header_without_merging"
    ),
    "clean_state": "test_benign_and_archive_controls_do_not_match",
}


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.success_ids: list[str] = []

    def addSuccess(self, test):
        self.success_ids.append(test.id())
        super().addSuccess(test)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--repo",
        required=True,
    )

    parser.add_argument(
        "--commit",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()

    os.chdir(repo)

    repo_src = (repo / "src").resolve()

    for entry in sys.path:
        if not entry:
            continue

        try:
            resolved = Path(entry).resolve()
        except OSError:
            continue

        if resolved == repo_src:
            raise SystemExit(
                "source-tree PYTHONPATH injection is not allowed"
            )

    import tracesoc

    module_path = Path(tracesoc.__file__).resolve()

    try:
        module_path.relative_to(repo_src)
    except ValueError:
        pass
    else:
        raise SystemExit(
            "TraceSOC imported from repository src instead of installed package"
        )

    unit = unittest.defaultTestLoader.discover(
        start_dir="tests/unit",
        pattern="test_*.py",
    )

    integration = unittest.defaultTestLoader.discover(
        start_dir="tests/integration",
        pattern="test_*.py",
    )

    combined = unittest.TestSuite(
        [
            unit,
            integration,
        ]
    )

    tests = list(flatten(combined))

    test_ids = sorted(
        test.id()
        for test in tests
    )

    if len(test_ids) <= 0:
        raise SystemExit(
            "expected at least one discovered test; observed "
            + str(len(test_ids))
        )

    if len(test_ids) != len(set(test_ids)):
        raise SystemExit(
            "duplicate unittest IDs discovered"
        )

    representatives = {}

    for category, method in REPRESENTATIVE_METHODS.items():
        matches = [
            test_id
            for test_id in test_ids
            if test_id.endswith("." + method)
        ]

        if len(matches) != 1:
            raise SystemExit(
                "acceptance representative not unique: "
                + category
                + " "
                + repr(matches)
            )

        representatives[category] = matches[0]

    suite = unittest.TestSuite(tests)

    stream = io.StringIO()

    runner = unittest.TextTestRunner(
        stream=stream,
        verbosity=0,
        resultclass=RecordingResult,
    )

    result = runner.run(suite)

    success_ids = set(result.success_ids)

    public_acceptance = {}

    for category in sorted(representatives):
        test_id = representatives[category]

        public_acceptance[category] = {
            "test_id": test_id,
            "result": (
                "PASS"
                if test_id in success_ids
                else "FAIL"
            ),
        }

    failures = sorted(
        test.id()
        for test, _ in result.failures
    )

    errors = sorted(
        test.id()
        for test, _ in result.errors
    )

    skipped = sorted(
        test.id()
        for test, _ in result.skipped
    )

    expected_failures = sorted(
        test.id()
        for test, _ in result.expectedFailures
    )

    unexpected_successes = sorted(
        test.id()
        for test in result.unexpectedSuccesses
    )

    overall_pass = (
        result.wasSuccessful()
        and result.testsRun == len(test_ids)
        and len(failures) == 0
        and len(errors) == 0
        and len(skipped) == 0
        and len(expected_failures) == 0
        and len(unexpected_successes) == 0
        and all(
            item["result"] == "PASS"
            for item in public_acceptance.values()
        )
    )

    report = {
        "schema_version": SCHEMA_VERSION,
        "suite_id": SUITE_ID,
        "commit": args.commit,
        "result": (
            "PASS"
            if overall_pass
            else "FAIL"
        ),
        "environment": {
            "python": platform.python_version(),
            "tracesoc": importlib.metadata.version("tracesoc"),
        },
        "public_acceptance": public_acceptance,
        "full_regression": {
            "discovered": len(test_ids),
            "tests_run": result.testsRun,
            "passed": len(success_ids),
            "failed": len(failures),
            "errors": len(errors),
            "skipped": len(skipped),
            "expected_failures": len(expected_failures),
            "unexpected_successes": len(unexpected_successes),
            "failure_test_ids": failures,
            "error_test_ids": errors,
            "skipped_test_ids": skipped,
            "expected_failure_test_ids": expected_failures,
            "unexpected_success_test_ids": unexpected_successes,
        },
        "determinism": {
            "timestamps_in_report": False,
            "runtime_duration_in_report": False,
            "test_ids_sorted": True,
            "source_tree_pythonpath_injection": False,
        },
        "all_test_ids": test_ids,
    }

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(
        "PUBLIC_ACCEPTANCE_REPORT="
        + str(output)
    )

    print(
        "PUBLIC_ACCEPTANCE_RESULT="
        + report["result"]
    )

    print(
        "PUBLIC_ACCEPTANCE_CLASSES="
        + str(len(public_acceptance))
    )

    print(
        "FULL_REGRESSION="
        + str(result.testsRun)
        + "/" + str(len(test_ids))
    )

    return 0 if overall_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
