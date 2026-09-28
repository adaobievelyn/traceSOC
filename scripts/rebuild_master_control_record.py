from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


MASTER_RECORD_TYPE = "tracesoc-master-control-record"
MASTER_SCHEMA_VERSION = 1

COMPLETE_COVERAGE_STATES = {
    "ACQUIRED",
    "PASS",
    "COMPLETE",
    "SATISFIED",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def relative_repo_path(
    repo: Path,
    path: Path,
) -> str:
    return path.resolve().relative_to(
        repo.resolve()
    ).as_posix()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for number, line in enumerate(
        path.read_text(
            encoding="utf-8-sig",
        ).splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Invalid JSONL record at {path}:{number}"
            ) from exc

        if not isinstance(value, dict):
            raise RuntimeError(
                f"JSONL record is not an object at {path}:{number}"
            )

        records.append(value)

    return records


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        return list(
            csv.DictReader(handle)
        )


def git_head(repo: Path) -> str:
    return subprocess.check_output(
        [
            "git",
            "rev-parse",
            "HEAD",
        ],
        cwd=repo,
        text=True,
    ).strip()


def control_file_record(
    repo: Path,
    relative: str,
) -> dict[str, Any]:
    path = repo / relative

    if not path.is_file():
        raise RuntimeError(
            f"Required control file missing: {relative}"
        )

    return {
        "path": relative,
        "byte_size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild a legacy engineering master-control snapshot. "
            "The canonical finalist master record is packaging-controlled "
            "and cannot be overwritten by this utility."
        )
    )

    parser.add_argument(
        "--repo",
        required=True,
    )

    parser.add_argument(
        "--evidence-root",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    parser.add_argument(
        "--next-phase",
        required=True,
    )

    args = parser.parse_args()

    repo = Path(
        args.repo
    ).resolve()

    evidence_root = Path(
        args.evidence_root
    ).resolve()

    output = Path(
        args.output
    ).resolve()

    finalist_master = (
        repo
        / "project-control"
        / "tracesoc-master-record.json"
    ).resolve()

    if output == finalist_master:
        raise SystemExit(
            "REFUSING_FINALIST_MASTER_OVERWRITE: "
            "canonical finalist master is packaging-controlled"
        )

    project_control = (
        repo
        / "project-control"
    )

    test_ledger_path = (
        project_control
        / "test-ledger.jsonl"
    )

    acquisition_register_path = (
        project_control
        / "evidence-acquisition-register.csv"
    )

    source_reference_path = (
        project_control
        / "evidence-source-reference.md"
    )

    coverage_path = (
        project_control
        / "evidence-coverage-matrix.csv"
    )

    challenge_plan_path = (
        project_control
        / "evidence-challenge-corpus-plan.md"
    )

    defense_path = (
        project_control
        / "defense-readiness-checklist.md"
    )

    requirements_path = (
        project_control
        / "requirements-matrix.csv"
    )

    decision_log_path = (
        project_control
        / "decision-log.md"
    )

    evidence_ledger_path = (
        project_control
        / "evidence-ledger.csv"
    )

    claim_register_path = (
        project_control
        / "claim-register.csv"
    )

    risk_register_path = (
        project_control
        / "risk-register.csv"
    )

    architecture_path = (
        project_control
        / "control-record-architecture.md"
    )

    for path in (
        test_ledger_path,
        acquisition_register_path,
        source_reference_path,
        coverage_path,
        challenge_plan_path,
        defense_path,
        requirements_path,
        decision_log_path,
        evidence_ledger_path,
        claim_register_path,
        risk_register_path,
        architecture_path,
    ):
        if not path.is_file():
            raise RuntimeError(
                f"Required control authority missing: {path}"
            )

    # --------------------------------------------------------
    # Consolidated test record
    # --------------------------------------------------------

    test_records = read_jsonl(
        test_ledger_path
    )

    run_ids = [
        str(
            record.get(
                "test_run_id",
                "",
            )
        )
        for record in test_records
    ]

    if any(
        not value
        for value in run_ids
    ):
        raise RuntimeError(
            "One or more test-ledger records lack test_run_id"
        )

    if len(
        set(run_ids)
    ) != len(run_ids):
        raise RuntimeError(
            "Duplicate test_run_id in consolidated test ledger"
        )

    # --------------------------------------------------------
    # External evidence register + live hash verification
    # --------------------------------------------------------

    acquisition_rows = read_csv(
        acquisition_register_path
    )

    evidence_records: list[
        dict[str, Any]
    ] = []

    failed_evidence: list[str] = []

    source_ids: list[str] = []

    for row in acquisition_rows:
        source_id = row.get(
            "source_id",
            "",
        )

        if not source_id:
            raise RuntimeError(
                "Acquisition register row lacks source_id"
            )

        source_ids.append(
            source_id
        )

        expected_hash = row.get(
            "sha256",
            "",
        ).lower()

        storage_path_text = row.get(
            "storage_path",
            "",
        )

        storage_path = Path(
            storage_path_text
        )

        exists = storage_path.is_file()

        observed_hash = (
            sha256_file(
                storage_path
            )
            if exists
            else None
        )

        hash_verified = (
            exists
            and observed_hash
            == expected_hash
        )

        if not hash_verified:
            failed_evidence.append(
                source_id
            )

        evidence_records.append(
            {
                "source_id": source_id,
                "role": row.get(
                    "role"
                ),
                "telemetry_family": row.get(
                    "telemetry_family"
                ),
                "publisher": row.get(
                    "publisher"
                ),
                "source_url": row.get(
                    "source_url"
                ),
                "original_filename": row.get(
                    "original_filename"
                ),
                "storage_path": storage_path_text,
                "byte_size": int(
                    row.get(
                        "byte_size",
                        "0",
                    )
                    or "0"
                ),
                "expected_sha256": expected_hash,
                "observed_sha256": observed_hash,
                "exists": exists,
                "hash_verified": hash_verified,
                "integrity_status": row.get(
                    "integrity_status"
                ),
            }
        )

    if len(
        set(source_ids)
    ) != len(source_ids):
        raise RuntimeError(
            "Duplicate source_id in acquisition register"
        )

    if failed_evidence:
        raise RuntimeError(
            "Raw evidence integrity failure: "
            + ", ".join(
                failed_evidence
            )
        )

    # --------------------------------------------------------
    # Coverage
    # --------------------------------------------------------

    coverage_rows = read_csv(
        coverage_path
    )

    coverage_by_id = {
        row["requirement_id"]: row
        for row in coverage_rows
    }

    core_ids = (
        "COV-001",
        "COV-002",
        "COV-003",
        "COV-004",
    )

    for requirement_id in core_ids:
        if requirement_id not in coverage_by_id:
            raise RuntimeError(
                f"Missing core coverage row: {requirement_id}"
            )

    core_families = []

    core_acquired = []

    core_missing = []

    for requirement_id in core_ids:
        row = coverage_by_id[
            requirement_id
        ]

        family = row.get(
            "family",
            "",
        )

        status = row.get(
            "status",
            "",
        )

        core_families.append(
            {
                "requirement_id": requirement_id,
                "family": family,
                "status": status,
                "source_or_candidate": row.get(
                    "source_or_candidate"
                ),
            }
        )

        if status == "ACQUIRED":
            core_acquired.append(
                family
            )
        else:
            core_missing.append(
                family
            )

    remaining_mandatory = []

    for row in coverage_rows:
        mandatory = (
            row.get(
                "mandatory_before_final",
                "",
            ).upper()
            == "TRUE"
        )

        status = row.get(
            "status",
            "",
        ).upper()

        if (
            mandatory
            and status
            not in COMPLETE_COVERAGE_STATES
        ):
            remaining_mandatory.append(
                {
                    "requirement_id": row.get(
                        "requirement_id"
                    ),
                    "category": row.get(
                        "category"
                    ),
                    "family": row.get(
                        "family"
                    ),
                    "status": row.get(
                        "status"
                    ),
                    "requirement": row.get(
                        "requirement"
                    ),
                }
            )

    corpus_complete = (
        len(
            remaining_mandatory
        )
        == 0
    )

    # --------------------------------------------------------
    # Historical phase proofs
    # --------------------------------------------------------

    phase_proofs = []

    for path in sorted(
        project_control.glob(
            "phase*.json"
        )
    ):
        phase_proofs.append(
            {
                "path": relative_repo_path(
                    repo,
                    path,
                ),
                "byte_size": path.stat().st_size,
                "sha256": sha256_file(
                    path
                ),
            }
        )

    # --------------------------------------------------------
    # External acquisition manifests
    # --------------------------------------------------------

    manifests_root = (
        evidence_root
        / "manifests"
    )

    external_manifests = []

    if manifests_root.is_dir():
        for path in sorted(
            manifests_root.glob(
                "*.json"
            )
        ):
            external_manifests.append(
                {
                    "path": str(
                        path
                    ),
                    "byte_size": path.stat().st_size,
                    "sha256": sha256_file(
                        path
                    ),
                }
            )

    # --------------------------------------------------------
    # Core specialized records
    # --------------------------------------------------------

    specialized_records = {
        "consolidated_test_record": (
            control_file_record(
                repo,
                "project-control/test-ledger.jsonl",
            )
        ),
        "evidence_acquisition_register": (
            control_file_record(
                repo,
                "project-control/evidence-acquisition-register.csv",
            )
        ),
        "evidence_source_candidates": (
            control_file_record(
                repo,
                "project-control/evidence-source-candidates.csv",
            )
        ),
        "human_source_reference": (
            control_file_record(
                repo,
                "project-control/evidence-source-reference.md",
            )
        ),
        "evidence_coverage_matrix": (
            control_file_record(
                repo,
                "project-control/evidence-coverage-matrix.csv",
            )
        ),
        "challenge_corpus_plan": (
            control_file_record(
                repo,
                "project-control/evidence-challenge-corpus-plan.md",
            )
        ),
        "holdout_isolation_policy": (
            control_file_record(
                repo,
                "project-control/holdout-isolation-policy.md",
            )
        ),
        "holdout_access_log": (
            control_file_record(
                repo,
                "project-control/holdout-access-log.jsonl",
            )
        ),
        "defense_readiness": (
            control_file_record(
                repo,
                "project-control/defense-readiness-checklist.md",
            )
        ),
        "requirements_matrix": (
            control_file_record(
                repo,
                "project-control/requirements-matrix.csv",
            )
        ),
        "decision_log": (
            control_file_record(
                repo,
                "project-control/decision-log.md",
            )
        ),
        "evidence_ledger": (
            control_file_record(
                repo,
                "project-control/evidence-ledger.csv",
            )
        ),
        "claim_register": (
            control_file_record(
                repo,
                "project-control/claim-register.csv",
            )
        ),
        "risk_register": (
            control_file_record(
                repo,
                "project-control/risk-register.csv",
            )
        ),
        "control_record_architecture": (
            control_file_record(
                repo,
                "project-control/control-record-architecture.md",
            )
        ),
        "v04_implementation_freeze": (
            control_file_record(
                repo,
                "project-control/v04-implementation-freeze.json",
            )
        ),
        "frozen_real_evidence_reproduction": (
            control_file_record(
                repo,
                "project-control/frozen-real-evidence-reproduction.json",
            )
        ),
        "one_command_reproduction_validation": (
            control_file_record(
                repo,
                "project-control/one-command-reproduction-validation.json",
            )
        ),
        "synthetic_positive_reconstruction_validation": (
            control_file_record(
                repo,
                "project-control/synthetic-positive-reconstruction-validation.json",
            )
        ),
        "stage9a_compatibility_validation": (
            control_file_record(
                repo,
                "project-control/stage9a-compatibility-validation.json",
            )
        ),
    }

    freeze_record = json.loads(
        (
            project_control
            / "v04-implementation-freeze.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    one_command_record = json.loads(
        (
            project_control
            / "one-command-reproduction-validation.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    synthetic_positive_record = json.loads(
        (
            project_control
            / "synthetic-positive-reconstruction-validation.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    stage9a_compatibility_record = json.loads(
        (
            project_control
            / "stage9a-compatibility-validation.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    freeze_acceptance = freeze_record.get(
        "accepted_validation",
        {},
    )

    if (
        freeze_record.get("source_commit")
        != "af8ea21eccad94061c3b99ad3c18faafda42fb5a"
    ):
        raise RuntimeError(
            "Current v0.4 implementation freeze source commit mismatch"
        )

    for key in (
        "sc23_representation_completeness",
        "sc24_representation_equivalence",
        "sc25_unknown_representation_safety",
    ):
        if freeze_acceptance.get(key) != "PASS":
            raise RuntimeError(
                f"Current implementation freeze acceptance is not PASS: {key}"
            )

    if one_command_record.get("status") != "PASS":
        raise RuntimeError(
            "Current one-command reproduction validation is not PASS"
        )

    if synthetic_positive_record.get("status") != "PASS":
        raise RuntimeError(
            "Current synthetic positive reconstruction validation is not PASS"
        )

    if (
        synthetic_positive_record.get(
            "analytic_path",
            {},
        ).get(
            "data_class"
        )
        != "CONTROLLED_SYNTHETIC_SCENARIO"
    ):
        raise RuntimeError(
            "Synthetic positive proof data-class boundary is invalid"
        )

    if (
        synthetic_positive_record.get(
            "safety",
            {},
        ).get(
            "real_incident_claim"
        )
        is not False
    ):
        raise RuntimeError(
            "Synthetic positive proof improperly asserts a real incident"
        )

    if stage9a_compatibility_record.get("status") != "PASS":
        raise RuntimeError(
            "Historical Stage9A compatibility validation is not PASS"
        )

    if (
        stage9a_compatibility_record.get(
            "role"
        )
        != "HISTORICAL_COMPATIBILITY_ONLY"
    ):
        raise RuntimeError(
            "Stage9A compatibility role boundary is invalid"
        )

    if (
        stage9a_compatibility_record.get(
            "compatibility_boundary",
            {},
        ).get(
            "post_replay_product_tuning_allowed"
        )
        is not False
    ):
        raise RuntimeError(
            "Stage9A post-replay tuning boundary is invalid"
        )

    record = {
        "record_type": MASTER_RECORD_TYPE,
        "schema_version": MASTER_SCHEMA_VERSION,
        "repository": {
            "path": str(
                repo
            ),
            "parent_head_at_build": git_head(
                repo
            ),
            "containing_commit_hash_embedded": False,
            "lineage_rule": (
                "After the pending commit is created, "
                "git HEAD^ must equal parent_head_at_build."
            ),
            "self_reference_note": (
                "The master record cannot embed the hash of the commit "
                "that contains itself because changing that field would "
                "change the containing commit hash."
            ),
        },
        "control_architecture": {
            "single_consolidated_machine_readable_test_record": True,
            "consolidated_test_record_path": (
                "project-control/test-ledger.jsonl"
            ),
            "master_record_path": (
                "project-control/tracesoc-master-record.json"
            ),
            "specialized_records_remain_authoritative": True,
        },
        "test_state": {
            "ledger_records": len(
                test_records
            ),
            "test_run_ids": run_ids,
            "ledger_sha256": sha256_file(
                test_ledger_path
            ),
        },
        "current_release_state": {
            "product": "TraceSOC",
            "implementation_source_commit": freeze_record.get(
                "source_commit"
            ),
            "freeze_status": freeze_record.get(
                "freeze_status"
            ),
            "frozen_file_count": freeze_record.get(
                "frozen_file_count"
            ),
            "analytical_candidate_sha256": freeze_record.get(
                "analytical_candidate_sha256"
            ),
            "canonical_commit_blob_fingerprint": freeze_record.get(
                "canonical_commit_blob_fingerprint"
            ),
            "representation_completeness": {
                "SC23": freeze_acceptance.get(
                    "sc23_representation_completeness"
                ),
                "SC24": freeze_acceptance.get(
                    "sc24_representation_equivalence"
                ),
                "SC25": freeze_acceptance.get(
                    "sc25_unknown_representation_safety"
                ),
            },
            "accepted_regression": {
                "unit": freeze_acceptance.get(
                    "unit_regression"
                ),
                "integration": freeze_acceptance.get(
                    "integration_regression"
                ),
                "public_acceptance": freeze_acceptance.get(
                    "public_acceptance"
                ),
            },
            "one_command_reproduction": {
                "status": one_command_record.get(
                    "status"
                ),
                "comparison_sha256": (
                    one_command_record.get(
                        "determinism",
                        {},
                    ).get(
                        "comparison_sha256"
                    )
                ),
                "raw_corpus_sha256": (
                    one_command_record.get(
                        "raw_evidence",
                        {},
                    ).get(
                        "corpus_sha256"
                    )
                ),
                "case_id": (
                    one_command_record.get(
                        "final_case",
                        {},
                    ).get(
                        "stable_case_result",
                        {},
                    ).get(
                        "case_id"
                    )
                ),
            },
            "synthetic_positive_reconstruction": {
                "status": synthetic_positive_record.get(
                    "status"
                ),
                "data_class": (
                    synthetic_positive_record.get(
                        "analytic_path",
                        {},
                    ).get(
                        "data_class"
                    )
                ),
                "detection_id": (
                    synthetic_positive_record.get(
                        "analytic_path",
                        {},
                    ).get(
                        "detection_id"
                    )
                ),
                "correlation_id": (
                    synthetic_positive_record.get(
                        "analytic_path",
                        {},
                    ).get(
                        "correlation_id"
                    )
                ),
                "finding_id": (
                    synthetic_positive_record.get(
                        "analytic_path",
                        {},
                    ).get(
                        "finding_id"
                    )
                ),
                "stage9a_accessed": (
                    synthetic_positive_record.get(
                        "safety",
                        {},
                    ).get(
                        "stage9a_accessed"
                    )
                ),
                "real_incident_claim": (
                    synthetic_positive_record.get(
                        "safety",
                        {},
                    ).get(
                        "real_incident_claim"
                    )
                ),
            },
            "stage9a_compatibility": {
                "status": stage9a_compatibility_record.get(
                    "status"
                ),
                "role": stage9a_compatibility_record.get(
                    "role"
                ),
                "artifact_count": (
                    stage9a_compatibility_record.get(
                        "artifact_accounting",
                        {},
                    ).get(
                        "accounted"
                    )
                ),
                "supported_processed": (
                    stage9a_compatibility_record.get(
                        "artifact_accounting",
                        {},
                    ).get(
                        "supported_processed"
                    )
                ),
                "unsupported_preserved": (
                    stage9a_compatibility_record.get(
                        "artifact_accounting",
                        {},
                    ).get(
                        "unsupported_preserved"
                    )
                ),
                "zero_silent_loss": (
                    stage9a_compatibility_record.get(
                        "artifact_accounting",
                        {},
                    ).get(
                        "zero_silent_loss"
                    )
                ),
                "raw_evidence_authority_sha256": (
                    stage9a_compatibility_record.get(
                        "provenance",
                        {},
                    ).get(
                        "raw_evidence_authority",
                        {},
                    ).get(
                        "archive_sha256"
                    )
                ),
                "cross_archive_raw_byte_identity": (
                    stage9a_compatibility_record.get(
                        "provenance",
                        {},
                    ).get(
                        "cross_archive_raw_byte_identity"
                    )
                ),
                "post_replay_product_tuning_allowed": (
                    stage9a_compatibility_record.get(
                        "compatibility_boundary",
                        {},
                    ).get(
                        "post_replay_product_tuning_allowed"
                    )
                ),
            },
        },
        "evidence_state": {
            "registered_real_artifacts": len(
                evidence_records
            ),
            "integrity_verified_artifacts": sum(
                1
                for item in evidence_records
                if item[
                    "hash_verified"
                ]
            ),
            "all_registered_evidence_hashes_verified": (
                all(
                    item[
                        "hash_verified"
                    ]
                    for item in evidence_records
                )
            ),
            "artifacts": evidence_records,
        },
        "coverage_state": {
            "core_required_count": 4,
            "core_acquired_count": len(
                core_acquired
            ),
            "core_missing_count": len(
                core_missing
            ),
            "core_families": core_families,
            "core_acquired": core_acquired,
            "core_missing": core_missing,
            "remaining_mandatory_requirements": (
                remaining_mandatory
            ),
            "final_corpus_complete": corpus_complete,
        },
        "historical_phase_proofs": phase_proofs,
        "external_acquisition_manifests": external_manifests,
        "specialized_records": specialized_records,
        "safety_and_integrity": {
            "raw_external_evidence_is_immutable": True,
            "derived_artifacts_must_preserve_lineage": True,
            "labels_may_not_be_hidden_production_selectors": True,
            "malware_execution_authorized": False,
        },
        "next_phase": args.next_phase,
    }

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(
            record,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    # Self-readback validates generated JSON.
    readback = json.loads(
        output.read_text(
            encoding="utf-8"
        )
    )

    if (
        readback.get(
            "record_type"
        )
        != MASTER_RECORD_TYPE
    ):
        raise RuntimeError(
            "Master-record readback identity mismatch"
        )

    if not (
        readback[
            "evidence_state"
        ][
            "all_registered_evidence_hashes_verified"
        ]
    ):
        raise RuntimeError(
            "Master record does not establish evidence integrity"
        )

    print(
        f"MASTER_RECORD={output}"
    )

    print(
        f"TEST_LEDGER_RECORDS={len(test_records)}"
    )

    print(
        "REGISTERED_REAL_ARTIFACTS="
        f"{len(evidence_records)}"
    )

    print(
        "RAW_EVIDENCE_HASHES_VERIFIED="
        f"{sum(1 for item in evidence_records if item['hash_verified'])}/"
        f"{len(evidence_records)}"
    )

    print(
        "CORE_TELEMETRY_ACQUIRED="
        f"{len(core_acquired)}/4"
    )

    print(
        "FINAL_CORPUS_COMPLETE="
        f"{str(corpus_complete).upper()}"
    )

    print(
        "PHASE_PROOFS_INDEXED="
        f"{len(phase_proofs)}"
    )

    print(
        "EXTERNAL_MANIFESTS_INDEXED="
        f"{len(external_manifests)}"
    )

    print(
        "MASTER_RECORD_SHA256="
        f"{sha256_file(output)}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())