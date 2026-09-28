from __future__ import annotations

import argparse
import csv
import ctypes
from ctypes import wintypes
import hashlib
import importlib.metadata
import json
import platform
import re
import subprocess
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any


EXPECTED_HEAD = (
    "8751a679f36b4983cdd3d2b0b35f44e9a11c4f39"
)

EXPECTED_TREE = (
    "fc420ee3fd1988cf578c0cf309ee3aefcccf33b2"
)

EXPECTED_CASE_ID = (
    "case_6bfc43f87590a1f654df3473d9d15c08"
    "e17304ed5030d191b4248ee3f4ee2348"
)

EXPECTED_FREEZE_SHA256 = (
    "8cc67c7b17f9a168938fba9119c518f4"
    "ac1dd748932419539f5215f0edeceae0"
)

EXPECTED_ASSIGNMENT_SHA256 = (
    "395130d0f93ed7e5d4913de0f6aba866"
    "f32b1896bb88242ae25d43d35ffc42db"
)

EXPECTED_ACCEPTANCE_SHA256 = (
    "ed379e5d1672569e772df8b3f59fff98"
    "991ea298dc41e5ef51e78bae4716230a"
)

EXPECTED_SCALE_SHA256 = (
    "33d05b38159fa4b67e9ec377028e4f64"
    "27c9466c58b47ab2e9a4c8facc35cc33"
)

TEMPLATE_HASHES = {
    "assessment-manifest-template.json":
        "41c93f5d164b2a69a8e99ed3a9ff74d"
        "fa1a4ac372c0375b1f16b2560ccb5175f",

    "evidence-index-template.csv":
        "835f9c3fb4183dfa1e4743a760ece024"
        "3d40edf3f777e47ae002a2c58d342073",

    "portfolio-continuity.md":
        "c41a8917d3e312550987d8f53b32d29"
        "d5e7a827e015de91c9a2adf29ff567426",

    "integrity-attestation-template.md":
        "94b46c5a21af7ef11ffb3a2793a39fb"
        "e9552b60c08cf9a80733b8817da893c6c",

    "ioc-set-template.csv":
        "47dac2cc4842a5cad7a43e88e898ffba"
        "0e65d7d474fce9a8c1dcbdd730558809",

    "timeline-template.csv":
        "f8fcc55e0543ee2f7a48f93ac46207e"
        "25eebec0eafa13d6db828401f066ef898",
}

PROOF_HASHES = {
    "final-grader-feedback-closure-audit.json":
        "db54bfea97dc8777296388479d66a164"
        "ff7de1e8df98659683f02a38dbd41065",

    "final-grader-feedback-closure-audit.md":
        "5ca1f0d0133dcc6ba4ad79dd2c340ef"
        "c331d818c58098f4f0f12a07aa345a2f5",

    "frozen-clean-reproduction-resource-validation.json":
        "36c2764bc8dbd87a3b567620d9d29585"
        "31abdbd7b5cbc7f5f3fd32a881621857",

    "holdout-final-adjudication.json":
        "cf4764f865a07d75bea647706434fa40"
        "5b9ac65fb047061cb570511f5785d80b",

    "r3-end-to-end-reverse-trace-proof.json":
        "cf32024dd0af104a27e8174343483ecc"
        "902bd8d4334c724001c80e43e99515db",

    "r3-pcap-processing-issue-census.json":
        "51b5df8c79fdad3c197cf0fb6a2f9e1c"
        "88e796eb1a9fbb069c46f14949e7b0c3",

    "r3-pcap-processing-issue-final-adjudication.json":
        "0a322b28e3b1dafe6fdddb774746267d"
        "440db866a96f835c0cf826692f51dadd",
}

R3_HASHES = {
    "case-manifest.json":
        "35e799edea98e91624f4dac8442e75479"
        "e50f8cbcc4b21d0a571ad6d6319fdba",

    "artifact-index.json":
        "a602658a3db11bc4ad3ee5d973ba1709"
        "ea4c8dd0274f49b205fb67467b75501a",

    "raw-evidence-index.json":
        "2e383646e116e8a7bc2fa42ae85a9bdb"
        "6e388024b0348505bb889cd5eedd1ff1",

    "powershell-scriptblocks.json":
        "7e966a12149c975af76b7a1d6c386a05"
        "771d78bf09848905a43625440ba980d5",

    "normalized-events.json":
        "729c42df46dc7e5fe900e8c292a19dce"
        "1acaff8b588891a971fac250611678f0",

    "detections.json":
        "674a988cbed0711e438165e0ff04c47a2"
        "def93461d33516a838bb3eb039d6fab",

    "correlations.json":
        "3078bc752749a016d66e0fa2f7eb02d9"
        "0fd0d677e278bf14932e5154ebd44fab",

    "relationships.json":
        "6aa9ff4230694c4a422b3dd445f9fcfc"
        "dc818a99bcdbd08e7709d8db7677a9f4",

    "hypotheses.json":
        "d575e077efb63d5b7b29903767e60bad"
        "c909c51f3329ea27a9c2bc0a95f783ac",

    "findings.json":
        "15779bc3b4f49793af98261b66e8ef59"
        "bd41f83b6a305bb8f98b4bb8c17eef26",

    "narrative-register.json":
        "d66605369393ef30ff6562daf55b9b825"
        "1bc298a8bf096473e5c3ffc92ba23fd",

    "response-register.json":
        "2c9e3de5564045ebe5ea076e8eb03c50"
        "13e45504916f55c5cf0302747b62fdda",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--repo",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def verify_hash(
    path: Path,
    expected: str,
    label: str,
) -> str:
    if not path.is_file():
        raise RuntimeError(
            f"{label} missing: {path}"
        )

    actual = sha256_file(path)

    if actual != expected:
        raise RuntimeError(
            f"{label} hash mismatch: "
            f"expected={expected} actual={actual}"
        )

    return actual


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(
            encoding="utf-8-sig"
        )
    )


def write_json(
    path: Path,
    value: Any,
    *,
    sort_keys: bool = True,
) -> None:
    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=sort_keys,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def csv_template_header(
    path: Path,
) -> list[str]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        reader = csv.reader(handle)

        try:
            header = next(reader)
        except StopIteration as exc:
            raise RuntimeError(
                "CSV template is empty: "
                + str(path)
            ) from exc

    return header


def repo_relative(
    repo: Path,
    path: Path,
) -> str:
    return (
        path.resolve()
        .relative_to(repo.resolve())
        .as_posix()
    )


def run_text(
    args: list[str],
    cwd: Path,
) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Command failed: "
            + " ".join(args)
            + "\n"
            + result.stdout
            + "\n"
            + result.stderr
        )

    return result.stdout.strip()


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def physical_ram_gb() -> float:
    if platform.system() != "Windows":
        raise RuntimeError(
            "Finalist package environment "
            "must be generated on Windows."
        )

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(
        MEMORYSTATUSEX
    )

    ok = ctypes.windll.kernel32.GlobalMemoryStatusEx(
        ctypes.byref(status)
    )

    if not ok:
        raise RuntimeError(
            "GlobalMemoryStatusEx failed."
        )

    return round(
        int(status.ullTotalPhys)
        / (1024 ** 3),
        2,
    )


def detect_environment(
    repo: Path,
) -> dict[str, Any]:
    python_version = platform.python_version()

    if python_version != "3.13.14":
        raise RuntimeError(
            "Expected Python 3.13.14; observed "
            + python_version
        )

    pip_version = importlib.metadata.version(
        "pip"
    )

    setuptools_version = (
        importlib.metadata.version(
            "setuptools"
        )
    )

    tracesoc_version = (
        importlib.metadata.version(
            "tracesoc"
        )
    )

    if pip_version != "26.1.2":
        raise RuntimeError(
            "pip version drift."
        )

    if setuptools_version != "84.0.0":
        raise RuntimeError(
            "setuptools version drift."
        )

    if tracesoc_version != "0.1.0":
        raise RuntimeError(
            "TraceSOC package version drift."
        )

    git_version = run_text(
        ["git", "--version"],
        repo,
    )

    powershell_version = run_text(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$PSVersionTable.PSVersion.ToString()",
        ],
        repo,
    )

    os_text = (
        platform.system()
        + " "
        + platform.release()
        + " "
        + platform.version()
    )

    cpu_text = (
        platform.processor()
        or "UNRESOLVED_BY_PLATFORM_API"
    )

    return {
        "os": os_text,
        "cpu": cpu_text,
        "memory_gb": physical_ram_gb(),
        "tool_versions": {
            "python": python_version,
            "pip": pip_version,
            "setuptools": setuptools_version,
            "tracesoc": tracesoc_version,
            "git": git_version,
            "powershell": powershell_version,
        },
    }


def build_raw_path_map(
    repo: Path,
    reference: Path,
    raw_index: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, str],
]:
    records = []
    by_basename: dict[str, str] = {}

    rows = raw_index.get(
        "raw_evidence_files",
        [],
    )

    if len(rows) != 6:
        raise RuntimeError(
            "Expected exactly six R3 raw files."
        )

    for row in rows:
        relative = row.get(
            "case_relative_path"
        )

        if not isinstance(
            relative,
            str,
        ):
            raise RuntimeError(
                "Raw evidence path missing."
            )

        local = (
            reference
            / Path(
                relative.replace(
                    "\\",
                    "/",
                )
            )
        )

        if not local.is_file():
            raise RuntimeError(
                "Imported raw evidence missing: "
                + str(local)
            )

        digest = sha256_file(local)

        if digest != row.get(
            "sha256"
        ):
            raise RuntimeError(
                "Raw evidence hash mismatch: "
                + relative
            )

        repo_path = repo_relative(
            repo,
            local,
        )

        basename = local.name

        if basename in by_basename:
            raise RuntimeError(
                "Ambiguous raw evidence basename: "
                + basename
            )

        by_basename[
            basename
        ] = repo_path

        records.append({
            "path":
                repo_path,

            "sha256":
                digest,

            "bytes":
                local.stat().st_size,

            "source_path_display":
                row.get(
                    "source_path_display"
                ),
        })

    return records, by_basename


def event_artifact_path(
    event: dict[str, Any],
    by_basename: dict[str, str],
) -> str:
    locator = event.get(
        "raw_locator",
        {},
    )

    logical_source = locator.get(
        "logical_source"
    )

    if not isinstance(
        logical_source,
        str,
    ) or not logical_source:
        raise RuntimeError(
            "Canonical event lacks logical_source."
        )

    basename = Path(
        logical_source.replace(
            "\\",
            "/",
        )
    ).name

    if basename not in by_basename:
        raise RuntimeError(
            "No imported raw artifact matches "
            "logical_source="
            + logical_source
        )

    return by_basename[
        basename
    ]


def source_timezone(
    raw_time: Any,
) -> str:
    if raw_time is None:
        return ""

    text = str(
        raw_time
    ).strip()

    if not text:
        return ""

    if (
        text.endswith("Z")
        or text.endswith("+00:00")
    ):
        return "UTC"

    if re.fullmatch(
        r"\d+(?:\.\d+)?",
        text,
    ):
        # Unix/pcap/Zeek epoch timestamps are
        # represented relative to UTC.
        return "UTC"

    return ""


def collect_primary_event_ids(
    reference: Path,
) -> set[str]:
    primary: set[str] = set()

    hypotheses = load_json(
        reference
        / "hypotheses.json"
    ).get(
        "hypotheses",
        [],
    )

    for row in hypotheses:
        for event_id in row.get(
            "observation_ids",
            [],
        ):
            if isinstance(
                event_id,
                str,
            ):
                primary.add(
                    event_id
                )

    narratives = load_json(
        reference
        / "narrative-register.json"
    ).get(
        "narratives",
        [],
    )

    for row in narratives:
        observations = (
            row.get(
                "observed",
                {},
            ).get(
                "observations",
                [],
            )
        )

        for observation in observations:
            event_id = observation.get(
                "event_id"
            )

            if isinstance(
                event_id,
                str,
            ):
                primary.add(
                    event_id
                )

    return primary


def claim(
    claim_id: str,
    report_section: str,
    text: str,
    artifact_path: str,
    locator: str,
    collected: str,
    sha256: str,
    proves: str,
    does_not_prove: str,
    alternative: str,
    disposition: str,
) -> dict[str, str]:
    return {
        "claim_id":
            claim_id,

        "report_section":
            report_section,

        "claim":
            text,

        "artifact_path":
            artifact_path,

        "exact_locator":
            locator,

        "collection_time_utc":
            collected,

        "sha256":
            sha256,

        "proves":
            proves,

        "does_not_prove":
            does_not_prove,

        "confidence":
            "high",

        "alternative_considered":
            alternative,

        "disposition":
            disposition,
    }


def main() -> None:
    args = parse_args()

    repo = args.repo.resolve()
    out = args.out.resolve()

    if not repo.is_dir():
        raise RuntimeError(
            "Repository path is missing."
        )

    if out.exists():
        if any(out.iterdir()):
            raise RuntimeError(
                "Output directory is not empty."
            )
    else:
        out.mkdir(
            parents=True,
            exist_ok=False,
        )

    templates = (
        repo
        / "evidence"
        / "submission-templates"
    )

    proof_root = (
        repo
        / "evidence"
        / "final-proof"
    )

    reference = (
        repo
        / "evidence"
        / "reference-case"
    )

    freeze_path = (
        repo
        / "project-control"
        / "finalist-candidate-freeze-v04.json"
    )

    assignment_path = (
        repo
        / "project-control"
        / "finalist-assignment-binding.json"
    )

    acceptance_path = (
        repo
        / "results"
        / "acceptance"
        / "public-test-results.json"
    )

    scale_path = (
        repo
        / "project-control"
        / "phase4j-cov011-benchmark-result-v1.json"
    )

    # -----------------------------------------------------
    # 1. Verify all authorities
    # -----------------------------------------------------

    verify_hash(
        freeze_path,
        EXPECTED_FREEZE_SHA256,
        "freeze record",
    )

    verify_hash(
        assignment_path,
        EXPECTED_ASSIGNMENT_SHA256,
        "assignment binding",
    )

    verify_hash(
        acceptance_path,
        EXPECTED_ACCEPTANCE_SHA256,
        "acceptance report",
    )

    verify_hash(
        scale_path,
        EXPECTED_SCALE_SHA256,
        "scale benchmark",
    )

    for name, digest in (
        TEMPLATE_HASHES.items()
    ):
        verify_hash(
            templates / name,
            digest,
            "template " + name,
        )

    for name, digest in (
        PROOF_HASHES.items()
    ):
        verify_hash(
            proof_root / name,
            digest,
            "proof " + name,
        )

    for name, digest in (
        R3_HASHES.items()
    ):
        verify_hash(
            reference / name,
            digest,
            "R3 " + name,
        )

    # -----------------------------------------------------
    # 2. Lock supplied template schemas
    # -----------------------------------------------------

    evidence_header = csv_template_header(
        templates
        / "evidence-index-template.csv"
    )

    timeline_header = csv_template_header(
        templates
        / "timeline-template.csv"
    )

    ioc_header = csv_template_header(
        templates
        / "ioc-set-template.csv"
    )

    expected_evidence_header = [
        "claim_id",
        "report_section",
        "claim",
        "artifact_path",
        "exact_locator",
        "collection_time_utc",
        "sha256",
        "proves",
        "does_not_prove",
        "confidence",
        "alternative_considered",
        "disposition",
    ]

    expected_timeline_header = [
        "event_id",
        "utc_time",
        "original_time",
        "source_timezone",
        "host",
        "user",
        "activity",
        "artifact_path",
        "exact_locator",
        "attack_technique",
        "confidence",
        "primary_or_supporting",
        "alternative_interpretation",
        "notes",
    ]

    expected_ioc_header = [
        "ioc_id",
        "type",
        "value",
        "first_seen_utc",
        "last_seen_utc",
        "host_or_context",
        "artifact_path",
        "exact_locator",
        "confidence",
        "handling",
        "expiry_or_review_date",
        "false_positive_risk",
    ]

    if (
        evidence_header
        != expected_evidence_header
    ):
        raise RuntimeError(
            "Evidence-index template schema changed."
        )

    if (
        timeline_header
        != expected_timeline_header
    ):
        raise RuntimeError(
            "Timeline template schema changed."
        )

    if (
        ioc_header
        != expected_ioc_header
    ):
        raise RuntimeError(
            "IOC template schema changed."
        )

    assessment_template = load_json(
        templates
        / "assessment-manifest-template.json"
    )

    required_assessment_keys = [
        "schema_version",
        "project_id",
        "variant",
        "candidate_binding",
        "assigned_pack",
        "commit",
        "supported_environment",
        "commands",
        "results",
        "inputs",
        "outputs",
        "manual_preconditions",
        "known_limitations",
    ]

    if (
        list(
            assessment_template.keys()
        )
        != required_assessment_keys
    ):
        raise RuntimeError(
            "Assessment template top-level "
            "schema/order changed."
        )

    # These are required authorities even though their
    # final artifacts are produced in later steps.
    continuity_template = (
        templates
        / "portfolio-continuity.md"
    ).read_text(
        encoding="utf-8-sig"
    )

    attestation_template = (
        templates
        / "integrity-attestation-template.md"
    ).read_text(
        encoding="utf-8-sig"
    )

    continuity_requirements = [
        "The previous-stage commit and exact component reused.",
        "The interface consumed and any backward-compatible extension.",
        "Evidence that the prior raw-to-result provenance remains intact.",
        "A migration record for every incompatible change.",
        "The component, schema, evidence, or decision record handed to the next stage.",
    ]

    for item in continuity_requirements:
        if item not in continuity_template:
            raise RuntimeError(
                "Continuity contract requirement missing: "
                + item
            )

    attestation_requirements = [
        "Intern code:",
        "Variant:",
        "Evidence marker:",
        "Assistance and tools used:",
        "Signed name:",
        "UTC date/time:",
    ]

    for item in attestation_requirements:
        if item not in attestation_template:
            raise RuntimeError(
                "Attestation template field missing: "
                + item
            )

    # -----------------------------------------------------
    # 3. Load measured authorities
    # -----------------------------------------------------

    freeze = load_json(
        freeze_path
    )

    assignment = load_json(
        assignment_path
    )

    acceptance = load_json(
        acceptance_path
    )

    scale = load_json(
        scale_path
    )

    holdout = load_json(
        proof_root
        / "holdout-final-adjudication.json"
    )

    reverse = load_json(
        proof_root
        / "r3-end-to-end-reverse-trace-proof.json"
    )

    pcap = load_json(
        proof_root
        / "r3-pcap-processing-issue-final-adjudication.json"
    )

    reproduction = load_json(
        proof_root
        / "frozen-clean-reproduction-resource-validation.json"
    )

    feedback = load_json(
        proof_root
        / "final-grader-feedback-closure-audit.json"
    )

    case_manifest = load_json(
        reference
        / "case-manifest.json"
    )

    raw_index = load_json(
        reference
        / "raw-evidence-index.json"
    )

    events = load_json(
        reference
        / "normalized-events.json"
    ).get(
        "events",
        [],
    )

    # -----------------------------------------------------
    # 4. Measured-state gates
    # -----------------------------------------------------

    if (
        case_manifest.get(
            "case_id"
        )
        != EXPECTED_CASE_ID
    ):
        raise RuntimeError(
            "Reference case ID mismatch."
        )

    counts = case_manifest.get(
        "analysis_counts",
        {},
    )

    expected_counts = {
        "canonical_events": 5442,
        "detection_evaluations": 32658,
        "matched_detections": 5,
        "findings": 6,
        "hypotheses": 6,
        "narrative_records": 6,
        "response_records": 6,
    }

    for key, expected in (
        expected_counts.items()
    ):
        if counts.get(key) != expected:
            raise RuntimeError(
                f"Reference count mismatch "
                f"{key}={counts.get(key)} "
                f"expected={expected}"
            )

    if len(events) != 5442:
        raise RuntimeError(
            "Expected 5,442 canonical events."
        )

    if acceptance.get(
        "commit"
    ) != EXPECTED_HEAD:
        raise RuntimeError(
            "Acceptance report commit mismatch."
        )

    if acceptance.get(
        "result"
    ) != "PASS":
        raise RuntimeError(
            "Acceptance report is not PASS."
        )

    regression = acceptance.get(
        "full_regression",
        {},
    )

    if (
        regression.get(
            "discovered"
        ) != 524
        or regression.get(
            "tests_run"
        ) != 524
        or regression.get(
            "passed"
        ) != 524
    ):
        raise RuntimeError(
            "Acceptance report is not 524/524."
        )

    if (
        feedback.get(
            "counts",
            {},
        ).get(
            "open"
        )
        != 0
    ):
        raise RuntimeError(
            "Feedback closure has open items."
        )

    if (
        holdout.get(
            "measured_status",
            {},
        ).get(
            "detection_accuracy"
        )
        != "UNADJUDICATED"
    ):
        raise RuntimeError(
            "Holdout accuracy boundary changed."
        )

    raw_inputs, by_basename = (
        build_raw_path_map(
            repo,
            reference,
            raw_index,
        )
    )

    primary_event_ids = (
        collect_primary_event_ids(
            reference
        )
    )

    # -----------------------------------------------------
    # 5. Generate TEMPLATE-COMPLIANT timeline.csv
    # -----------------------------------------------------

    timeline_rows = []

    for event in events:
        locator = event.get(
            "raw_locator"
        )

        if not isinstance(
            locator,
            dict,
        ) or not locator:
            raise RuntimeError(
                "Canonical event missing raw locator."
            )

        event_id = event.get(
            "event_id"
        )

        if not isinstance(
            event_id,
            str,
        ):
            raise RuntimeError(
                "Canonical event ID missing."
            )

        raw_time = event.get(
            "event_time_raw"
        )

        timeline_rows.append({
            "event_id":
                event_id,

            "utc_time":
                event.get(
                    "event_time_utc"
                )
                or "",

            "original_time":
                raw_time
                if raw_time is not None
                else "",

            "source_timezone":
                source_timezone(
                    raw_time
                ),

            "host":
                event.get(
                    "host"
                )
                or "",

            "user":
                event.get(
                    "principal"
                )
                or "",

            "activity":
                event.get(
                    "event_type"
                )
                or "",

            "artifact_path":
                event_artifact_path(
                    event,
                    by_basename,
                ),

            "exact_locator":
                json.dumps(
                    locator,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ),

            # No ATT&CK technique is invented at the
            # canonical observation layer.
            "attack_technique":
                "",

            # Confidence here concerns occurrence/source
            # provenance, not maliciousness.
            "confidence":
                "high",

            "primary_or_supporting":
                (
                    "primary"
                    if event_id in primary_event_ids
                    else "supporting"
                ),

            "alternative_interpretation":
                (
                    "Canonical observation alone does not "
                    "establish maliciousness or causality; "
                    "controlled/benign activity remains possible."
                ),

            "notes":
                (
                    "controlled reference case; "
                    "source_type="
                    + str(
                        event.get(
                            "source_type"
                        )
                    )
                    + "; clock_state="
                    + str(
                        event.get(
                            "clock_state"
                        )
                    )
                ),
        })

    timeline_rows.sort(
        key=lambda row: (
            row["utc_time"] == "",
            row["utc_time"],
            row["event_id"],
        )
    )

    timeline_path = (
        out
        / "timeline.csv"
    )

    with timeline_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=timeline_header,
            lineterminator="\n",
        )

        writer.writeheader()
        writer.writerows(
            timeline_rows
        )

    # -----------------------------------------------------
    # 6. Generate TEMPLATE-COMPLIANT ioc-set.csv
    # -----------------------------------------------------

    ioc_path = (
        out
        / "ioc-set.csv"
    )

    with ioc_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=ioc_header,
            lineterminator="\n",
        )

        writer.writeheader()

    # No placeholder IOC-001 is retained because no
    # confirmed-malicious IOC is established.

    # -----------------------------------------------------
    # 7. Material evidence claims
    # -----------------------------------------------------

    freeze_created = freeze.get(
        "created_utc",
        "",
    )

    holdout_created = holdout.get(
        "created_utc",
        "",
    )

    reverse_created = reverse.get(
        "created_utc",
        "",
    )

    pcap_created = pcap.get(
        "created_utc",
        "",
    )

    reproduction_created = (
        reproduction.get(
            "created_utc",
            "",
        )
    )

    feedback_created = feedback.get(
        "created_utc",
        "",
    )

    scale_created = scale.get(
        "generated_utc",
        "",
    )

    claims = [
        claim(
            "C-001",
            "Product integrity",
            (
                "TraceSOC finalist technical candidate "
                "is frozen at commit "
                + EXPECTED_HEAD
                + " and tree "
                + EXPECTED_TREE
                + "."
            ),
            "project-control/finalist-candidate-freeze-v04.json",
            "$.candidate;$.parent_commit;$.validation",
            freeze_created,
            EXPECTED_FREEZE_SHA256,
            (
                "Identifies the exact pre-holdout "
                "technical candidate."
            ),
            (
                "Does not by itself prove unseen-evidence "
                "generalization or detection accuracy."
            ),
            (
                "A later packaging commit may exist, but "
                "the technical candidate remains this freeze."
            ),
            "FROZEN_TECHNICAL_CANDIDATE",
        ),

        claim(
            "C-002",
            "Regression",
            (
                "The frozen candidate currently passes "
                "524/524 regression tests and all 4 public "
                "acceptance classes."
            ),
            "results/acceptance/public-test-results.json",
            "$.full_regression;$.public_acceptance",
            feedback_created,
            EXPECTED_ACCEPTANCE_SHA256,
            (
                "The frozen candidate passes the current "
                "machine-readable regression surface."
            ),
            (
                "Regression success does not establish "
                "universal correctness or detector accuracy."
            ),
            (
                "External and post-freeze evidence validation "
                "is independently required."
            ),
            "524_OF_524_PASS",
        ),

        claim(
            "C-003",
            "Reference reconstruction",
            (
                "The six-source R3 case contains 5,442 "
                "canonical observations, 32,658 detection "
                "evaluations, 5 matched detections and "
                "6 findings."
            ),
            "evidence/reference-case/case-manifest.json",
            "$.analysis_counts",
            freeze_created,
            R3_HASHES[
                "case-manifest.json"
            ],
            (
                "Demonstrates integrated processing of "
                "the controlled six-source reference case."
            ),
            (
                "Does not establish that the controlled "
                "reference activity is malicious ground truth."
            ),
            (
                "The same evidence is correctly interpreted "
                "as controlled interoperability/provenance "
                "validation."
            ),
            "CONTROLLED_REFERENCE_CASE",
        ),

        claim(
            "C-004",
            "Traceability",
            (
                "All 5,442 R3 canonical observations "
                "carry raw locators."
            ),
            "evidence/final-proof/final-grader-feedback-closure-audit.json",
            "$.mechanical_measurements.r3_traceability",
            feedback_created,
            PROOF_HASHES[
                "final-grader-feedback-closure-audit.json"
            ],
            (
                "Every R3 canonical observation is anchored "
                "to raw location metadata."
            ),
            (
                "Locator presence alone does not establish "
                "the correctness of every interpretation."
            ),
            (
                "End-to-end downstream linkage is tested "
                "separately."
            ),
            "5442_OF_5442_RAW_LOCATORS",
        ),

        claim(
            "C-005",
            "Reverse traceability",
            (
                "A complete R3 chain was mechanically "
                "proved from response to original raw "
                "artifact SHA-256."
            ),
            "evidence/final-proof/r3-end-to-end-reverse-trace-proof.json",
            "$.selected_chain;$.proof_checks;$.observation_proofs",
            reverse_created,
            PROOF_HASHES[
                "r3-end-to-end-reverse-trace-proof.json"
            ],
            (
                "Demonstrates mechanical reversibility "
                "of one complete downstream analytical chain."
            ),
            (
                "Does not establish maliciousness, causality, "
                "incident membership or executed response."
            ),
            (
                "The selected chain is evidence-backed "
                "corroboration rather than a compromise verdict."
            ),
            "END_TO_END_REVERSE_TRACE_PASS",
        ),

        claim(
            "C-006",
            "External real evidence",
            (
                "External IoT-23 Zeek evidence reconciled "
                "23,145 source rows to 23,145 canonical "
                "observations without using publisher labels "
                "as expected verdicts."
            ),
            "project-control/finalist-candidate-freeze-v04.json",
            "$.external_real_evidence",
            freeze_created,
            EXPECTED_FREEZE_SHA256,
            (
                "Supports real external Zeek representation "
                "ingestion/accounting beyond the controlled case."
            ),
            (
                "Matched detections are not claimed as "
                "ground-truth maliciousness or accuracy."
            ),
            (
                "Representation generalization and detector "
                "accuracy are separate questions."
            ),
            "EXTERNAL_REAL_EVIDENCE_PASS",
        ),

        claim(
            "C-007",
            "Post-freeze holdout",
            (
                "The sealed semantically unseen holdout "
                "reconciled 156,458 source rows to 156,458 "
                "canonical observations and executed "
                "938,748 detector evaluations after freeze."
            ),
            "evidence/final-proof/holdout-final-adjudication.json",
            "$.holdout;$.measured_status;$.detection_accuracy_boundary",
            holdout_created,
            PROOF_HASHES[
                "holdout-final-adjudication.json"
            ],
            (
                "Supports post-freeze ingestion, provenance, "
                "accounting and representation generalization."
            ),
            (
                "Zero matched detections do not establish "
                "true/false-negative rates or accuracy."
            ),
            (
                "Detection accuracy remains "
                "UNADJUDICATED because no exact valid "
                "scoring comparator was established."
            ),
            "INGESTION_PROVENANCE_GENERALIZATION_PASS",
        ),

        claim(
            "C-008",
            "Packet accounting",
            (
                "All 9,672 reference PCAPNG packet locators "
                "are accounted: 5,412 normalized IPv4 TCP/UDP "
                "events plus 4,260 processing issues, with "
                "zero recorded errors."
            ),
            "evidence/final-proof/r3-pcap-processing-issue-final-adjudication.json",
            "$.packet_accounting;$.mechanical_proof;$.adjudication",
            pcap_created,
            PROOF_HASHES[
                "r3-pcap-processing-issue-final-adjudication.json"
            ],
            (
                "The 4,260 issue records are mechanically "
                "reconciled under supported-partial PCAP handling."
            ),
            (
                "Does not establish protocol names for "
                "the two non-IPv4 EtherType values or "
                "universal PCAP support."
            ),
            (
                "Raw frames remain preserved even when "
                "not normalized into the supported IPv4 model."
            ),
            "CLOSED_ACCOUNTED_SUPPORTED_PARTIAL",
        ),

        claim(
            "C-009",
            "Reproducibility",
            (
                "Two fresh frozen six-source reproductions "
                "completed in 3.438 s and 3.393 s and produced "
                "the same 11 deterministic core artifact hashes "
                "as each other and as R3."
            ),
            "evidence/final-proof/frozen-clean-reproduction-resource-validation.json",
            "$.run1;$.run2;$.proof_checks",
            reproduction_created,
            PROOF_HASHES[
                "frozen-clean-reproduction-resource-validation.json"
            ],
            (
                "Demonstrates deterministic regeneration "
                "of the measured R3 analytical outputs."
            ),
            (
                "The ~4.5 MiB child-process metric is not "
                "total system consumption or a universal "
                "scalability bound."
            ),
            (
                "A separate scale benchmark provides the "
                "stronger resource measurement."
            ),
            "TWO_RUN_DETERMINISTIC_REPRODUCTION_PASS",
        ),

        claim(
            "C-010",
            "Resource validation",
            (
                "The real-format scale benchmark processed "
                "198,463 records with 198,463 accepted, "
                "zero quarantined and 198,463 semantic events "
                "in 15.9617856 seconds; peak working set was "
                "486,924,288 bytes."
            ),
            "project-control/phase4j-cov011-benchmark-result-v1.json",
            "$.accounting;$.runtime;$.memory;$.holdout_boundary",
            scale_created,
            EXPECTED_SCALE_SHA256,
            (
                "Demonstrates measured parser/accounting/"
                "semantic-conversion resource behavior on "
                "the target workstation."
            ),
            (
                "Real cross-source correlation was not "
                "executed in this benchmark and detector "
                "accuracy is not measured."
            ),
            (
                "Runtime is descriptive because no runtime "
                "threshold was frozen."
            ),
            "RESOURCE_ACCOUNTING_BENCHMARK_PASS",
        ),

        claim(
            "C-011",
            "Generalization controls",
            (
                "The closure audit found zero selected "
                "known reference-answer literal hits in "
                "frozen production source."
            ),
            "evidence/final-proof/final-grader-feedback-closure-audit.json",
            "$.mechanical_measurements.anti_hardcoding",
            feedback_created,
            PROOF_HASHES[
                "final-grader-feedback-closure-audit.json"
            ],
            (
                "Supports the measured anti-hardcoding "
                "control against selected known literals."
            ),
            (
                "A finite literal scan cannot prove absence "
                "of every possible hardcoding mechanism."
            ),
            (
                "External and post-freeze behavior provides "
                "additional generalization evidence."
            ),
            "ANTI_HARDCODING_SCAN_PASS",
        ),

        claim(
            "C-012",
            "Grader-feedback closure",
            (
                "The final carry-forward audit records "
                "13 transferable lessons SATISFIED, "
                "4 historical task-specific requirements "
                "NOT_APPLICABLE_TO_TRACESOC and 0 OPEN."
            ),
            "evidence/final-proof/final-grader-feedback-closure-audit.json",
            "$.closure_matrix;$.counts",
            feedback_created,
            PROOF_HASHES[
                "final-grader-feedback-closure-audit.json"
            ],
            (
                "Shows explicit reconciliation of applicable "
                "prior grader engineering lessons."
            ),
            (
                "Does not predict or guarantee an external "
                "competition result."
            ),
            (
                "Historical task-specific answers are not "
                "silently reintroduced as TraceSOC requirements."
            ),
            "CARRY_FORWARD_AUDIT_PASS",
        ),

        claim(
            "C-013",
            "Known limitation",
            (
                "detection_result_id is not globally unique "
                "across distinct no-match evaluations; "
                "hypothesis-cited matched IDs measured in R3 "
                "are unique."
            ),
            "evidence/final-proof/r3-end-to-end-reverse-trace-proof.json",
            "$.known_identifier_limitation",
            reverse_created,
            PROOF_HASHES[
                "r3-end-to-end-reverse-trace-proof.json"
            ],
            (
                "Defines the measured identifier limitation "
                "and its effect on R3 reverse traceability."
            ),
            (
                "Does not establish globally unique identity "
                "for all no-match detection evaluations."
            ),
            (
                "Future product work can strengthen no-match "
                "result identity semantics."
            ),
            "KNOWN_NONBLOCKING_LIMITATION",
        ),

        claim(
            "C-014",
            "Known limitation",
            (
                "Post-freeze holdout detection accuracy "
                "remains UNADJUDICATED."
            ),
            "evidence/final-proof/holdout-final-adjudication.json",
            "$.measured_status.detection_accuracy;$.posthoc_comparator",
            holdout_created,
            PROOF_HASHES[
                "holdout-final-adjudication.json"
            ],
            (
                "Prevents zero matched detections from being "
                "converted into an unsupported accuracy claim."
            ),
            (
                "Does not establish precision, recall, FPR, "
                "FNR, TPR or TNR."
            ),
            (
                "An exact observation-level labeled comparator "
                "would be required for scoring."
            ),
            "UNADJUDICATED",
        ),

        claim(
            "C-015",
            "Known limitation",
            (
                "Cross-publisher network holdout diversity "
                "is not established because development and "
                "holdout network evidence both originate "
                "from IoT-23."
            ),
            "evidence/final-proof/final-grader-feedback-closure-audit.json",
            "$.known_nonblocking_limitations",
            feedback_created,
            PROOF_HASHES[
                "final-grader-feedback-closure-audit.json"
            ],
            (
                "Defines the current population boundary "
                "of network generalization evidence."
            ),
            (
                "Does not support a cross-publisher network "
                "generalization claim."
            ),
            (
                "A future sealed corpus from another publisher "
                "would address this limitation."
            ),
            "KNOWN_NONBLOCKING_LIMITATION",
        ),

        claim(
            "C-016",
            "Indicator boundary",
            (
                "No controlled reference observable is "
                "promoted to a confirmed malicious IOC."
            ),
            "project-control/finalist-candidate-freeze-v04.json",
            "$.claim_boundary",
            freeze_created,
            EXPECTED_FREEZE_SHA256,
            (
                "Preserves the non-fabrication and "
                "non-maliciousness claim boundary."
            ),
            (
                "An empty confirmed-malicious IOC set does "
                "not mean observables cannot be preserved "
                "or used as validation pivots."
            ),
            (
                "Controlled observables remain evidence "
                "without being classified as malicious IOCs."
            ),
            "NO_CONFIRMED_MALICIOUS_IOCS",
        ),
    ]

    evidence_path = (
        out
        / "evidence-index.csv"
    )

    with evidence_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=evidence_header,
            lineterminator="\n",
        )

        writer.writeheader()
        writer.writerows(
            claims
        )

    # -----------------------------------------------------
    # 8. Additional finalist evidence ledger
    # -----------------------------------------------------

    source_counts = Counter(
        str(
            row.get(
                "source_type"
            )
        )
        for row in events
    )

    ledger = {
        "schema_version":
            "1.0",

        "record_type":
            "tracesoc-finalist-evidence-ledger",

        "authority_statement":
            (
                "This ledger is an additional machine-readable "
                "grader navigation record. Required UBI artifacts "
                "remain governed by the supplied templates."
            ),

        "technical_freeze": {
            "commit":
                EXPECTED_HEAD,

            "tree":
                EXPECTED_TREE,

            "candidate":
                freeze.get(
                    "candidate"
                ),

            "claim_boundary":
                freeze.get(
                    "claim_boundary"
                ),
        },

        "assignment": {
            "project_id":
                assignment.get(
                    "project_id"
                ),

            "variant":
                assignment.get(
                    "public_variant"
                ),

            "candidate_binding":
                assignment.get(
                    "candidate_binding"
                ),

            "evidence_marker":
                assignment.get(
                    "evidence_marker"
                ),

            "assigned_pack":
                assignment.get(
                    "assigned_pack"
                ),

            "analytical_use":
                assignment.get(
                    "analytical_use"
                ),
        },

        "product": {
            "name":
                "TraceSOC",

            "purpose":
                (
                    "Provenance-first SOC/DFIR evidence "
                    "reconstruction from heterogeneous raw "
                    "evidence to evidence-backed analytical "
                    "records with reversible raw provenance."
                ),

            "pipeline": [
                "raw evidence",
                "representation extraction",
                "canonical observation",
                "detection",
                "relationship/correlation",
                "hypothesis",
                "finding",
                "narrative",
                "response",
            ],
        },

        "reference_case": {
            "case_id":
                EXPECTED_CASE_ID,

            "role":
                "CONTROLLED_INTEROPERABILITY_AND_PROVENANCE_REFERENCE",

            "analysis_counts":
                counts,

            "source_type_counts":
                dict(
                    sorted(
                        source_counts.items()
                    )
                ),

            "raw_inputs":
                raw_inputs,

            "timeline_rows":
                len(
                    timeline_rows
                ),

            "primary_timeline_rows":
                sum(
                    1
                    for row in timeline_rows
                    if row[
                        "primary_or_supporting"
                    ]
                    == "primary"
                ),

            "controlled_case_malicious_ground_truth_claimed":
                False,
        },

        "validation": {
            "regression":
                regression,

            "public_acceptance":
                acceptance.get(
                    "public_acceptance"
                ),

            "external_real_evidence":
                freeze.get(
                    "external_real_evidence"
                ),

            "holdout": {
                "holdout":
                    holdout.get(
                        "holdout"
                    ),

                "measured_status":
                    holdout.get(
                        "measured_status"
                    ),

                "detection_accuracy_boundary":
                    holdout.get(
                        "detection_accuracy_boundary"
                    ),
            },

            "reverse_traceability": {
                "status":
                    reverse.get(
                        "final_status"
                    ),

                "selected_chain":
                    reverse.get(
                        "selected_chain"
                    ),

                "known_identifier_limitation":
                    reverse.get(
                        "known_identifier_limitation"
                    ),
            },

            "pcap_accounting": {
                "status":
                    pcap.get(
                        "final_status"
                    ),

                "packet_accounting":
                    pcap.get(
                        "packet_accounting"
                    ),

                "adjudication":
                    pcap.get(
                        "adjudication"
                    ),
            },

            "clean_reproduction": {
                "status":
                    reproduction.get(
                        "final_status"
                    ),

                "run1":
                    reproduction.get(
                        "run1"
                    ),

                "run2":
                    reproduction.get(
                        "run2"
                    ),

                "proof_checks":
                    reproduction.get(
                        "proof_checks"
                    ),
            },

            "scale_resource_benchmark": {
                "result":
                    scale.get(
                        "result"
                    ),

                "scope":
                    scale.get(
                        "benchmark_scope"
                    ),

                "accounting":
                    scale.get(
                        "accounting"
                    ),

                "runtime":
                    scale.get(
                        "runtime"
                    ),

                "memory":
                    scale.get(
                        "memory"
                    ),

                "correlation":
                    scale.get(
                        "correlation"
                    ),

                "holdout_boundary":
                    scale.get(
                        "holdout_boundary"
                    ),
            },

            "grader_feedback_closure": {
                "status":
                    feedback.get(
                        "final_status"
                    ),

                "counts":
                    feedback.get(
                        "counts"
                    ),
            },
        },

        "business_impact": {
            "problem":
                (
                    "SOC/DFIR evidence is fragmented across "
                    "email, endpoint and network representations; "
                    "manual stitching can detach analytical "
                    "conclusions from exact source evidence."
                ),

            "operational_value": [
                (
                    "Preserves raw evidence identity and "
                    "exact locators through analysis."
                ),
                (
                    "Accounts for unsupported or partial "
                    "evidence rather than silently discarding it."
                ),
                (
                    "Makes downstream findings mechanically "
                    "reversible to raw evidence."
                ),
                (
                    "Supports later reproduction and defense "
                    "of analytical decisions."
                ),
            ],

            "measured_support": {
                "reference_case_canonical_observations":
                    5442,

                "reference_case_raw_locator_coverage":
                    "5442/5442",

                "external_real_zeek_rows":
                    23145,

                "postfreeze_holdout_rows":
                    156458,

                "scale_benchmark_records":
                    198463,

                "current_regression_tests":
                    524,
            },

            "not_measured": [
                "monetary savings",
                "analyst-hours saved",
                "breach-cost reduction",
                "false-positive reduction percentage",
                "universal detection accuracy",
            ],
        },

        "ioc_summary": {
            "confirmed_malicious_ioc_count":
                0,

            "status":
                "NO_CONFIRMED_MALICIOUS_IOCS",
        },

        "known_limitations":
            feedback.get(
                "known_nonblocking_limitations",
                [],
            ),

        "claims":
            claims,

        "template_authorities": {
            name: {
                "path":
                    (
                        "evidence/submission-templates/"
                        + name
                    ),

                "sha256":
                    digest,
            }
            for name, digest
            in sorted(
                TEMPLATE_HASHES.items()
            )
        },

        "proof_authorities": {
            name: {
                "path":
                    (
                        "evidence/final-proof/"
                        + name
                    ),

                "sha256":
                    digest,
            }
            for name, digest
            in sorted(
                PROOF_HASHES.items()
            )
        },

        "submission_state": {
            "machine_readable_core":
                "DRY_RUN_READY",

            "continuity_record":
                "PENDING_TEMPLATE_GOVERNED_FINALIZATION",

            "integrity_attestation":
                "PENDING_USER_SIGNATURE_AND_UTC_DATE",

            "reports":
                "PENDING",

            "manifest_sha256":
                "PENDING_GENERATE_LAST",
        },
    }

    ledger_path = (
        out
        / "finalist-evidence-ledger.json"
    )

    write_json(
        ledger_path,
        ledger,
    )

    # -----------------------------------------------------
    # 9. Populate supplied assessment template EXACTLY
    # -----------------------------------------------------

    environment = detect_environment(
        repo
    )

    assessment = deepcopy(
        assessment_template
    )

    assessment[
        "schema_version"
    ] = "1.0"

    assessment[
        "project_id"
    ] = assignment[
        "project_id"
    ]

    assessment[
        "variant"
    ] = assignment[
        "public_variant"
    ]

    assessment[
        "candidate_binding"
    ] = assignment[
        "candidate_binding"
    ]

    assessment[
        "assigned_pack"
    ] = {
        "file_name":
            assignment[
                "assigned_pack"
            ][
                "file_name"
            ],

        "sha256":
            assignment[
                "assigned_pack"
            ][
                "sha256"
            ],

        "manifest_signature":
            assignment[
                "assigned_pack"
            ][
                "manifest_signature"
            ],

        "verified_before_use":
            True,
    }

    assessment[
        "commit"
    ] = EXPECTED_HEAD

    assessment[
        "supported_environment"
    ] = environment

    ps_prefix = (
        "powershell.exe -NoLogo -NoProfile "
        "-ExecutionPolicy Bypass -File "
    )

    assessment[
        "commands"
    ] = {
        "provision":
            ps_prefix
            + r".\provision.ps1",

        "build":
            ps_prefix
            + r".\build.ps1",

        "test":
            (
                ps_prefix
                + r".\test.ps1 -Commit "
                + EXPECTED_HEAD
                + r" -Output "
                + r"results\acceptance\public-test-results.json"
            ),

        "clean":
            ps_prefix
            + r".\clean.ps1",
    }

    # Use the larger real-format benchmark for the
    # template's singular runtime/memory fields.
    peak_memory_mb = round(
        scale[
            "memory"
        ][
            "final"
        ][
            "peak_working_set_bytes"
        ]
        / (1024 ** 2),
        3,
    )

    generated_before_assessment = {
        "finalist-evidence-ledger.json":
            sha256_file(
                ledger_path
            ),

        "evidence-index.csv":
            sha256_file(
                evidence_path
            ),

        "timeline.csv":
            sha256_file(
                timeline_path
            ),

        "ioc-set.csv":
            sha256_file(
                ioc_path
            ),

        "results/acceptance/public-test-results.json":
            EXPECTED_ACCEPTANCE_SHA256,
    }

    assessment[
        "results"
    ] = {
        "public_tests": {
            "passed": 524,
            "failed": 0,
            "report":
                "results/acceptance/public-test-results.json",
        },

        "runtime_seconds":
            scale[
                "runtime"
            ][
                "end_to_end_seconds"
            ],

        "peak_memory_mb":
            peak_memory_mb,

        "output_hashes":
            generated_before_assessment,
    }

    assessment[
        "inputs"
    ] = (
        [
            row["path"]
            for row in raw_inputs
        ]
        + [
            "project-control/finalist-candidate-freeze-v04.json",
            "project-control/finalist-assignment-binding.json",
            "project-control/phase4j-cov011-benchmark-result-v1.json",
            "evidence/final-proof/holdout-final-adjudication.json",
            "evidence/final-proof/r3-end-to-end-reverse-trace-proof.json",
            "evidence/final-proof/r3-pcap-processing-issue-final-adjudication.json",
            "evidence/final-proof/frozen-clean-reproduction-resource-validation.json",
            "evidence/final-proof/final-grader-feedback-closure-audit.json",
        ]
    )

    assessment[
        "outputs"
    ] = [
        "finalist-evidence-ledger.json",
        "evidence-index.csv",
        "timeline.csv",
        "ioc-set.csv",
        "assessment-manifest.json",
        "results/acceptance/public-test-results.json",
    ]

    assessment[
        "manual_preconditions"
    ] = [
        (
            "Run supported commands from the "
            "repository root on Windows."
        ),
        (
            "Supported Python is exactly 3.13.14 "
            "with the pinned repository environment."
        ),
        (
            "The six reference-case raw evidence files "
            "must remain byte-identical to their indexed hashes."
        ),
        (
            "Do not rerun or tune against the sealed "
            "post-freeze holdout during normal submission "
            "reproduction."
        ),
        (
            "The process-scoped PowerShell execution-policy "
            "bypass changes no machine-wide execution-policy setting."
        ),
    ]

    assessment[
        "known_limitations"
    ] = [
        (
            "Post-freeze holdout detection accuracy is "
            "UNADJUDICATED because an exact valid "
            "observation-level scoring comparator was not established."
        ),
        (
            "Cross-publisher network holdout diversity is "
            "not established; development and holdout network "
            "evidence both originate from IoT-23."
        ),
        (
            "detection_result_id is not globally unique "
            "across distinct no-match evaluations; matched "
            "hypothesis-cited IDs measured in R3 are unique."
        ),
        (
            "The assessment-manifest runtime and peak-memory "
            "values are from the 198,463-record real-format "
            "parser/accounting/semantic-conversion benchmark. "
            "That benchmark did not execute real cross-source "
            "correlation and does not measure detector accuracy."
        ),
        (
            "The smaller six-source clean-reproduction "
            "child-process peak-working-set metric is not "
            "interpreted as total system memory consumption."
        ),
        (
            "No confirmed malicious IOC is asserted from "
            "controlled reference observables."
        ),
    ]

    if (
        list(
            assessment.keys()
        )
        != required_assessment_keys
    ):
        raise RuntimeError(
            "Generated assessment manifest deviated "
            "from supplied top-level template."
        )

    assessment_path = (
        out
        / "assessment-manifest.json"
    )

    write_json(
        assessment_path,
        assessment,
        sort_keys=False,
    )

    # -----------------------------------------------------
    # 10. Validate generated template outputs
    # -----------------------------------------------------

    with evidence_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        evidence_reader = csv.DictReader(
            handle
        )

        if (
            evidence_reader.fieldnames
            != evidence_header
        ):
            raise RuntimeError(
                "Generated evidence-index header drift."
            )

        evidence_rows = list(
            evidence_reader
        )

    if len(
        evidence_rows
    ) != 16:
        raise RuntimeError(
            "Evidence-index must contain 16 claims."
        )

    with timeline_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        timeline_reader = csv.DictReader(
            handle
        )

        if (
            timeline_reader.fieldnames
            != timeline_header
        ):
            raise RuntimeError(
                "Generated timeline header drift."
            )

        checked_timeline = list(
            timeline_reader
        )

    if len(
        checked_timeline
    ) != 5442:
        raise RuntimeError(
            "Timeline must contain 5,442 rows."
        )

    if any(
        not row[
            "exact_locator"
        ]
        for row in checked_timeline
    ):
        raise RuntimeError(
            "Timeline contains a blank exact locator."
        )

    if any(
        not row[
            "artifact_path"
        ]
        for row in checked_timeline
    ):
        raise RuntimeError(
            "Timeline contains a blank artifact path."
        )

    with ioc_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        ioc_reader = csv.DictReader(
            handle
        )

        if (
            ioc_reader.fieldnames
            != ioc_header
        ):
            raise RuntimeError(
                "Generated IOC header drift."
            )

        ioc_rows = list(
            ioc_reader
        )

    if ioc_rows:
        raise RuntimeError(
            "Confirmed-malicious IOC file should "
            "contain zero data rows."
        )

    # -----------------------------------------------------
    # 11. Write generation record
    # -----------------------------------------------------

    output_hashes = {
        "assessment-manifest.json":
            sha256_file(
                assessment_path
            ),

        "evidence-index.csv":
            sha256_file(
                evidence_path
            ),

        "finalist-evidence-ledger.json":
            sha256_file(
                ledger_path
            ),

        "ioc-set.csv":
            sha256_file(
                ioc_path
            ),

        "timeline.csv":
            sha256_file(
                timeline_path
            ),
    }

    generation_record = {
        "schema_version":
            "1.0",

        "record_type":
            "tracesoc-finalist-template-compliant-core-generation",

        "technical_freeze": {
            "commit":
                EXPECTED_HEAD,

            "tree":
                EXPECTED_TREE,
        },

        "required_templates_verified":
            True,

        "template_sha256":
            TEMPLATE_HASHES,

        "reference_case_id":
            EXPECTED_CASE_ID,

        "evidence_index_rows":
            len(
                evidence_rows
            ),

        "timeline_rows":
            len(
                checked_timeline
            ),

        "timeline_primary_rows":
            sum(
                1
                for row in checked_timeline
                if row[
                    "primary_or_supporting"
                ]
                == "primary"
            ),

        "timeline_supporting_rows":
            sum(
                1
                for row in checked_timeline
                if row[
                    "primary_or_supporting"
                ]
                == "supporting"
            ),

        "timeline_blank_locator_rows":
            0,

        "confirmed_malicious_ioc_rows":
            0,

        "assessment_manifest_template_exact_top_level_schema":
            True,

        "continuity_contract_verified":
            True,

        "integrity_attestation_template_verified":
            True,

        "continuity_record_generated":
            False,

        "integrity_attestation_generated":
            False,

        "output_sha256":
            output_hashes,

        "root_artifacts_promoted":
            False,

        "final_status":
            "PASS",
    }

    generation_record_path = (
        out
        / "package-generation-record.json"
    )

    write_json(
        generation_record_path,
        generation_record,
    )

    print(
        "TEMPLATE_COMPLIANT_FINALIST_CORE=PASS"
    )

    print(
        "EVIDENCE_INDEX_ROWS="
        + str(
            len(
                evidence_rows
            )
        )
    )

    print(
        "TIMELINE_ROWS="
        + str(
            len(
                checked_timeline
            )
        )
    )

    print(
        "TIMELINE_PRIMARY_ROWS="
        + str(
            generation_record[
                "timeline_primary_rows"
            ]
        )
    )

    print(
        "TIMELINE_SUPPORTING_ROWS="
        + str(
            generation_record[
                "timeline_supporting_rows"
            ]
        )
    )

    print(
        "CONFIRMED_MALICIOUS_IOC_ROWS=0"
    )

    print(
        "ASSESSMENT_TEMPLATE_SCHEMA=PASS"
    )

    print(
        "CONTINUITY_TEMPLATE_AUTHORITY=PASS"
    )

    print(
        "ATTESTATION_TEMPLATE_AUTHORITY=PASS"
    )

    for name in sorted(
        output_hashes
    ):
        print(
            "GENERATED"
            + "|file="
            + name
            + "|sha256="
            + output_hashes[
                name
            ]
        )

    print(
        "GENERATED"
        + "|file=package-generation-record.json"
        + "|sha256="
        + sha256_file(
            generation_record_path
        )
    )


if __name__ == "__main__":
    main()
