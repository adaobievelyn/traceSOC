from __future__ import annotations

import argparse
import ctypes
import gc
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


from tracesoc.models import SemanticEvent
from tracesoc.parsers.powershell import load_powershell_windows_event_xml
from tracesoc.parsers.sysmon import load_sysmon_windows_event_xml
from tracesoc.parsers.windows_security import load_windows_security_splunk
from tracesoc.parsers.zeek import load_zeek_conn_ascii


EXPECTED_PROTOCOL_SHA256 = (
    "bb646a390afe794fa631d8527cabe1f84cca4b3f9e9ab3fafdc8a4e1d3fcaa61"
)

EXPECTED_RESOLUTION_SHA256 = "d895c95f2eef964c11b65512b0021aa94983f319974bbb0e4433279cbd34e57a"

PROTOCOL_RELATIVE = (
    "project-control/phase4j-cov011-benchmark-protocol-v1.json"
)

RESOLUTION_RELATIVE = (
    "project-control/phase4j-cov011-source-resolution-v1.json"
)

RESULT_RELATIVE = (
    "project-control/phase4j-cov011-benchmark-result-v1.json"
)

EXPECTED_RECORDS = 198463
MEMORY_THRESHOLD_BYTES = 4000000000


PARSER_MAP = {
    (
        "tracesoc.parsers.powershell."
        "load_powershell_windows_event_xml"
    ):
        load_powershell_windows_event_xml,

    (
        "tracesoc.parsers.sysmon."
        "load_sysmon_windows_event_xml"
    ):
        load_sysmon_windows_event_xml,

    (
        "tracesoc.parsers.windows_security."
        "load_windows_security_splunk"
    ):
        load_windows_security_splunk,

    (
        "tracesoc.parsers.zeek."
        "load_zeek_conn_ascii"
    ):
        load_zeek_conn_ascii,
}


def sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as handle:
        while True:
            block = handle.read(
                8 * 1024 * 1024
            )

            if not block:
                break

            digest.update(
                block
            )

    return digest.hexdigest()


def sha256_repo_file(
    path: Path,
) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


class PROCESS_MEMORY_COUNTERS_EX(
    ctypes.Structure
):
    _fields_ = [
        (
            "cb",
            ctypes.c_ulong,
        ),
        (
            "PageFaultCount",
            ctypes.c_ulong,
        ),
        (
            "PeakWorkingSetSize",
            ctypes.c_size_t,
        ),
        (
            "WorkingSetSize",
            ctypes.c_size_t,
        ),
        (
            "QuotaPeakPagedPoolUsage",
            ctypes.c_size_t,
        ),
        (
            "QuotaPagedPoolUsage",
            ctypes.c_size_t,
        ),
        (
            "QuotaPeakNonPagedPoolUsage",
            ctypes.c_size_t,
        ),
        (
            "QuotaNonPagedPoolUsage",
            ctypes.c_size_t,
        ),
        (
            "PagefileUsage",
            ctypes.c_size_t,
        ),
        (
            "PeakPagefileUsage",
            ctypes.c_size_t,
        ),
        (
            "PrivateUsage",
            ctypes.c_size_t,
        ),
    ]


def process_memory() -> dict[str, int]:
    kernel32 = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    )

    psapi = ctypes.WinDLL(
        "psapi",
        use_last_error=True,
    )

    get_current_process = (
        kernel32.GetCurrentProcess
    )

    get_current_process.restype = (
        ctypes.c_void_p
    )

    get_process_memory_info = (
        psapi.GetProcessMemoryInfo
    )

    get_process_memory_info.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(
            PROCESS_MEMORY_COUNTERS_EX
        ),
        ctypes.c_ulong,
    ]

    get_process_memory_info.restype = (
        ctypes.c_int
    )

    counters = (
        PROCESS_MEMORY_COUNTERS_EX()
    )

    counters.cb = ctypes.sizeof(
        counters
    )

    ok = get_process_memory_info(
        get_current_process(),
        ctypes.byref(
            counters
        ),
        counters.cb,
    )

    if not ok:
        raise OSError(
            ctypes.get_last_error()
        )

    return {
        "peak_working_set_bytes":
            int(
                counters.PeakWorkingSetSize
            ),

        "working_set_bytes":
            int(
                counters.WorkingSetSize
            ),

        "private_usage_bytes":
            int(
                counters.PrivateUsage
            ),
    }


def utc_now() -> str:
    return (
        datetime.now(
            timezone.utc
        )
        .isoformat(
            timespec="microseconds"
        )
        .replace(
            "+00:00",
            "Z",
        )
    )


def write_exclusive_json(
    path: Path,
    value: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    text = (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    )

    with path.open(
        "x",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        handle.write(
            text
        )


def require_repo_identity(
    repo: Path,
    protocol_path: Path,
    resolution_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if sha256_repo_file(
        protocol_path
    ) != EXPECTED_PROTOCOL_SHA256:
        raise RuntimeError(
            "frozen protocol SHA mismatch"
        )

    if sha256_repo_file(
        resolution_path
    ) != EXPECTED_RESOLUTION_SHA256:
        raise RuntimeError(
            "frozen source-resolution SHA mismatch"
        )

    protocol = json.loads(
        protocol_path.read_text(
            encoding="utf-8"
        )
    )

    resolution = json.loads(
        resolution_path.read_text(
            encoding="utf-8"
        )
    )

    if protocol.get(
        "workload",
        {}
    ).get(
        "records_per_run"
    ) != EXPECTED_RECORDS:
        raise RuntimeError(
            "frozen protocol workload denominator mismatch"
        )

    if resolution.get(
        "workload",
        {}
    ).get(
        "accepted_records"
    ) != EXPECTED_RECORDS:
        raise RuntimeError(
            "source-resolution workload denominator mismatch"
        )

    for item in resolution.get(
        "production_code",
        []
    ):
        relative = item.get(
            "source_path"
        )

        expected = item.get(
            "source_sha256"
        )

        if not isinstance(
            relative,
            str,
        ):
            raise RuntimeError(
                "production source path missing"
            )

        source_path = (
            repo
            / relative
        ).resolve()

        if not source_path.is_file():
            raise RuntimeError(
                "production source file missing: "
                + relative
            )

        observed = sha256_repo_file(
            source_path
        )

        if observed != expected:
            raise RuntimeError(
                "production source code SHA mismatch: "
                + relative
            )

    return protocol, resolution


def integrity_preflight(
    resolution: dict[str, Any],
) -> tuple[list[dict[str, Any]], float]:
    started = time.perf_counter_ns()

    verified = []

    sources = (
        resolution
        .get("workload", {})
        .get("sources", [])
    )

    if len(
        sources
    ) != 5:
        raise RuntimeError(
            "source-resolution denominator is not five"
        )

    for source in sources:
        source_id = source[
            "source_id"
        ]

        path = Path(
            source[
                "storage_path"
            ]
        )

        if not path.is_file():
            raise RuntimeError(
                "registered source file missing: "
                + source_id
            )

        observed_size = int(
            path.stat().st_size
        )

        expected_size = int(
            source[
                "registered_byte_size"
            ]
        )

        if observed_size != expected_size:
            raise RuntimeError(
                "registered source byte-size mismatch: "
                + source_id
            )

        observed_sha = sha256_file(
            path
        )

        expected_sha = str(
            source[
                "registered_sha256"
            ]
        ).lower()

        if observed_sha != expected_sha:
            raise RuntimeError(
                "registered source SHA-256 mismatch: "
                + source_id
            )

        verified.append(
            {
                "source_id":
                    source_id,

                "storage_path":
                    str(path),

                "expected_byte_size":
                    expected_size,

                "observed_byte_size":
                    observed_size,

                "expected_sha256":
                    expected_sha,

                "observed_sha256":
                    observed_sha,

                "integrity":
                    "PASS",
            }
        )

    elapsed = (
        time.perf_counter_ns()
        - started
    ) / 1_000_000_000

    return verified, elapsed


def run_processing(
    resolution: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    float,
    int,
    int,
    int,
]:
    processing_started = (
        time.perf_counter_ns()
    )

    source_results = []

    total_accepted = 0
    total_quarantined = 0
    total_semantic = 0

    sources = (
        resolution
        .get("workload", {})
        .get("sources", [])
    )

    for source in sources:
        source_id = source[
            "source_id"
        ]

        parser_name = source[
            "parser"
        ]

        parser = PARSER_MAP.get(
            parser_name
        )

        if parser is None:
            raise RuntimeError(
                "no frozen parser mapping for "
                + source_id
            )

        path = Path(
            source[
                "storage_path"
            ]
        )

        expected_accepted = int(
            source[
                "accepted_records"
            ]
        )

        source_started = (
            time.perf_counter_ns()
        )

        batch = parser(
            path,
            logical_source=source_id,
        )

        accepted = len(
            batch.accepted
        )

        quarantined = len(
            batch.quarantined
        )

        if accepted != expected_accepted:
            raise RuntimeError(
                "accepted-record count mismatch: "
                + source_id
            )

        if quarantined != 0:
            raise RuntimeError(
                "unexpected quarantined records: "
                + source_id
            )

        semantic_count = 0

        for canonical in batch.accepted:
            SemanticEvent.from_canonical(
                canonical
            )

            semantic_count += 1

        if semantic_count != accepted:
            raise RuntimeError(
                "semantic conversion accounting mismatch: "
                + source_id
            )

        total_accepted += accepted
        total_quarantined += quarantined
        total_semantic += semantic_count

        source_seconds = (
            time.perf_counter_ns()
            - source_started
        ) / 1_000_000_000

        memory_after_source = (
            process_memory()
        )

        source_results.append(
            {
                "source_id":
                    source_id,

                "telemetry_family":
                    source[
                        "telemetry_family"
                    ],

                "role":
                    source[
                        "role"
                    ],

                "accepted_records":
                    accepted,

                "quarantined_records":
                    quarantined,

                "semantic_events":
                    semantic_count,

                "processing_seconds":
                    source_seconds,

                "process_memory_after_source":
                    memory_after_source,
            }
        )

        del batch

        gc.collect()

    processing_seconds = (
        time.perf_counter_ns()
        - processing_started
    ) / 1_000_000_000

    return (
        source_results,
        processing_seconds,
        total_accepted,
        total_quarantined,
        total_semantic,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the frozen TraceSOC COV011 "
            "existing-real-corpus resource benchmark."
        )
    )

    parser.add_argument(
        "--repo",
        required=False,
        default=str(REPO),
    )

    args = parser.parse_args()

    repo = Path(
        args.repo
    ).resolve()

    if repo != REPO.resolve():
        raise SystemExit(
            "STOP: --repo does not identify runner repository"
        )

    protocol_path = (
        repo
        / PROTOCOL_RELATIVE
    ).resolve()

    resolution_path = (
        repo
        / RESOLUTION_RELATIVE
    ).resolve()

    result_path = (
        repo
        / RESULT_RELATIVE
    ).resolve()

    if result_path.exists():
        raise SystemExit(
            "STOP: benchmark result artifact already exists"
        )

    benchmark_process_started_utc = (
        utc_now()
    )

    end_to_end_started = (
        time.perf_counter_ns()
    )

    protocol, resolution = (
        require_repo_identity(
            repo,
            protocol_path,
            resolution_path,
        )
    )

    start_memory = (
        process_memory()
    )

    # Integrity-only byte access.
    # No parser is called until every source has passed
    # registered size and SHA-256 verification.
    verified_sources, preflight_seconds = (
        integrity_preflight(
            resolution
        )
    )

    payload_access_started = False

    try:
        payload_access_started = True

        (
            source_results,
            processing_seconds,
            total_accepted,
            total_quarantined,
            total_semantic,
        ) = run_processing(
            resolution
        )

        final_memory = (
            process_memory()
        )

        end_to_end_seconds = (
            time.perf_counter_ns()
            - end_to_end_started
        ) / 1_000_000_000

        accounting_pass = (
            total_accepted
            == EXPECTED_RECORDS
            and total_quarantined
            == 0
            and total_semantic
            == EXPECTED_RECORDS
        )

        memory_pass = (
            final_memory[
                "peak_working_set_bytes"
            ]
            <= MEMORY_THRESHOLD_BYTES
        )

        result_state = (
            "PASS"
            if (
                accounting_pass
                and memory_pass
            )
            else "FAIL"
        )

        result = {
            "record_type":
                "tracesoc-cov011-benchmark-result-v1",

            "schema_version":
                1,

            "phase":
                "PHASE-4J-E",

            "generated_utc":
                utc_now(),

            "benchmark_process_started_utc":
                benchmark_process_started_utc,

            "protocol": {
                "path":
                    PROTOCOL_RELATIVE,

                "sha256":
                    EXPECTED_PROTOCOL_SHA256,
            },

            "source_resolution": {
                "path":
                    RESOLUTION_RELATIVE,

                "sha256":
                    EXPECTED_RESOLUTION_SHA256,
            },

            "benchmark_scope":
                (
                    "REAL_FORMAT_PARSER_TO_CANONICAL_"
                    "ACCOUNTING_TO_SEMANTIC_CONVERSION"
                ),

            "workload": {
                "source_count":
                    5,

                "expected_records":
                    EXPECTED_RECORDS,

                "accepted_records":
                    total_accepted,

                "quarantined_records":
                    total_quarantined,

                "semantic_events":
                    total_semantic,
            },

            "integrity_preflight": {
                "result":
                    "PASS",

                "verified_source_count":
                    len(
                        verified_sources
                    ),

                "sources":
                    verified_sources,

                "runtime_seconds":
                    preflight_seconds,
            },

            "source_results":
                source_results,

            "runtime": {
                "processing_seconds":
                    processing_seconds,

                "end_to_end_seconds":
                    end_to_end_seconds,

                "threshold_seconds":
                    None,

                "threshold_applied":
                    False,
            },

            "memory": {
                "api":
                    "Windows GetProcessMemoryInfo",

                "metric":
                    "PeakWorkingSetSize",

                "threshold_bytes":
                    MEMORY_THRESHOLD_BYTES,

                "start":
                    start_memory,

                "final":
                    final_memory,

                "pass":
                    memory_pass,
            },

            "accounting": {
                "expected_records":
                    EXPECTED_RECORDS,

                "accepted_records":
                    total_accepted,

                "quarantined_records":
                    total_quarantined,

                "semantic_events":
                    total_semantic,

                "pass":
                    accounting_pass,

                "silently_discarded_records":
                    0
                    if accounting_pass
                    else None,
            },

            "holdout_boundary": {
                "primary_role":
                    "HOLDOUT",

                "secondary_use":
                    "RESOURCE_MEASUREMENT_ONLY",

                "reclassified":
                    False,

                "analytic_tuning_performed":
                    False,

                "accuracy_claim":
                    False,

                "publisher_labels_used":
                    False,
            },

            "correlation": {
                "real_cross_source_correlation_executed":
                    False,
            },

            "acceptance": {
                "accounting":
                    "PASS"
                    if accounting_pass
                    else "FAIL",

                "peak_working_set":
                    "PASS"
                    if memory_pass
                    else "FAIL",

                "runtime":
                    "MEASURED_NO_THRESHOLD",
            },

            "result":
                result_state,
        }

        write_exclusive_json(
            result_path,
            result,
        )

        print(
            "BENCHMARK_RESULT="
            + result_state
        )

        print(
            "WORKLOAD_EXPECTED_RECORDS="
            + str(
                EXPECTED_RECORDS
            )
        )

        print(
            "WORKLOAD_ACCEPTED_RECORDS="
            + str(
                total_accepted
            )
        )

        print(
            "WORKLOAD_QUARANTINED_RECORDS="
            + str(
                total_quarantined
            )
        )

        print(
            "SEMANTIC_EVENTS="
            + str(
                total_semantic
            )
        )

        print(
            "INTEGRITY_PREFLIGHT_SECONDS="
            + format(
                preflight_seconds,
                ".6f",
            )
        )

        print(
            "PROCESSING_RUNTIME_SECONDS="
            + format(
                processing_seconds,
                ".6f",
            )
        )

        print(
            "END_TO_END_RUNTIME_SECONDS="
            + format(
                end_to_end_seconds,
                ".6f",
            )
        )

        print(
            "PEAK_WORKING_SET_BYTES="
            + str(
                final_memory[
                    "peak_working_set_bytes"
                ]
            )
        )

        print(
            "MEMORY_THRESHOLD_BYTES="
            + str(
                MEMORY_THRESHOLD_BYTES
            )
        )

        print(
            "MEMORY_GATE="
            + (
                "PASS"
                if memory_pass
                else "FAIL"
            )
        )

        print(
            "ACCOUNTING_GATE="
            + (
                "PASS"
                if accounting_pass
                else "FAIL"
            )
        )

        print(
            "RESULT_PATH="
            + RESULT_RELATIVE
        )

        return (
            0
            if result_state == "PASS"
            else 1
        )

    except Exception as exc:
        final_memory = (
            process_memory()
        )

        end_to_end_seconds = (
            time.perf_counter_ns()
            - end_to_end_started
        ) / 1_000_000_000

        failure_result = {
            "record_type":
                "tracesoc-cov011-benchmark-result-v1",

            "schema_version":
                1,

            "phase":
                "PHASE-4J-E",

            "generated_utc":
                utc_now(),

            "benchmark_process_started_utc":
                benchmark_process_started_utc,

            "protocol_sha256":
                EXPECTED_PROTOCOL_SHA256,

            "source_resolution_sha256":
                EXPECTED_RESOLUTION_SHA256,

            "result":
                "FAIL",

            "failure": {
                "stage":
                    (
                        "PROCESSING_AFTER_PAYLOAD_ACCESS"
                        if payload_access_started
                        else "PRE_PAYLOAD"
                    ),

                "exception_type":
                    type(
                        exc
                    ).__name__,

                "exception_message_emitted_to_result":
                    False,
            },

            "runtime": {
                "integrity_preflight_seconds":
                    preflight_seconds,

                "end_to_end_seconds":
                    end_to_end_seconds,

                "threshold_seconds":
                    None,
            },

            "memory": {
                "metric":
                    "PeakWorkingSetSize",

                "threshold_bytes":
                    MEMORY_THRESHOLD_BYTES,

                "final":
                    final_memory,
            },

            "holdout_boundary": {
                "primary_role":
                    "HOLDOUT",

                "secondary_use":
                    "RESOURCE_MEASUREMENT_ONLY",

                "analytic_tuning_performed":
                    False,

                "publisher_labels_used":
                    False,
            },
        }

        write_exclusive_json(
            result_path,
            failure_result,
        )

        print(
            "BENCHMARK_RESULT=FAIL"
        )

        print(
            "FAILURE_STAGE="
            + failure_result[
                "failure"
            ][
                "stage"
            ]
        )

        print(
            "FAILURE_EXCEPTION_TYPE="
            + type(
                exc
            ).__name__
        )

        print(
            "FAILURE_EXCEPTION_MESSAGE_SUPPRESSED_FROM_RESULT=TRUE"
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
