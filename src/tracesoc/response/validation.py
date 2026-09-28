from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

from tracesoc.response.sandbox import (
    HostIsolationSession,
    HostState,
    JsonHostStateStore,
    ResponseContractError,
)


RESULT_RECORD_TYPE = (
    "tracesoc-response-validation-integration-v1"
)

SCENARIO_ID = "RESPONSE-VALIDATION-0001"


def _canonical_bytes(
    value: dict[str, Any],
) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def _require_status(
    record: Any,
    expected: str,
) -> None:
    if record.status != expected:
        raise ResponseContractError(
            "UNEXPECTED_STAGE_STATUS:"
            + record.stage
            + ":"
            + record.status
        )


def _create_initial_state(
    store: JsonHostStateStore,
    *,
    evidence_preserved: bool,
) -> tuple[HostState, str]:
    state = HostState(
        target_id="SIM-HOST-001",
        isolated=False,
        evidence_preserved=evidence_preserved,
        service_available=True,
    )

    store.save(state)

    return (
        state,
        store.sha256(),
    )


def _nominal_execution(
    root: Path,
) -> dict[str, Any]:
    store = JsonHostStateStore(
        root / "nominal-host.json"
    )

    initial_state, initial_sha256 = (
        _create_initial_state(
            store,
            evidence_preserved=True,
        )
    )

    session = HostIsolationSession(
        store,
        "RESP-NOMINAL-001",
    )

    _require_status(
        session.precondition(),
        "PASS",
    )

    _require_status(
        session.dry_run(),
        "PASS",
    )

    _require_status(
        session.apply(),
        "PASS",
    )

    _require_status(
        session.verify(),
        "PASS",
    )

    _require_status(
        session.rollback(),
        "PASS",
    )

    _require_status(
        session.verify_rollback(),
        "PASS",
    )

    final_state = store.load()
    final_sha256 = store.sha256()

    exact_restoration = (
        final_state == initial_state
        and
        final_sha256 == initial_sha256
    )

    if not exact_restoration:
        raise ResponseContractError(
            "NOMINAL_ROLLBACK_NOT_EXACT"
        )

    result = session.to_result()

    if (
        result["final_status"]
        != "COMPLETED_AND_ROLLED_BACK"
    ):
        raise ResponseContractError(
            "NOMINAL_FINAL_STATUS_UNEXPECTED"
        )

    return {
        "execution_id": "RESP-NOMINAL-001",
        "purpose": (
            "Nominal simulated host isolation, "
            "verification, and exact rollback."
        ),
        "initial_state_sha256": initial_sha256,
        "final_state_sha256": final_sha256,
        "exact_pre_action_state_restored": (
            exact_restoration
        ),
        "result": result,
    }


def _precondition_block_execution(
    root: Path,
) -> dict[str, Any]:
    store = JsonHostStateStore(
        root / "precondition-block-host.json"
    )

    initial_state, initial_sha256 = (
        _create_initial_state(
            store,
            evidence_preserved=False,
        )
    )

    session = HostIsolationSession(
        store,
        "RESP-PRECONDITION-FAIL-001",
    )

    record = session.precondition()

    _require_status(
        record,
        "FAIL",
    )

    if record.reason != "EVIDENCE_NOT_PRESERVED":
        raise ResponseContractError(
            "PRECONDITION_FAILURE_REASON_UNEXPECTED"
        )

    final_state = store.load()
    final_sha256 = store.sha256()

    state_unchanged = (
        final_state == initial_state
        and
        final_sha256 == initial_sha256
    )

    if not state_unchanged:
        raise ResponseContractError(
            "PRECONDITION_FAILURE_MUTATED_STATE"
        )

    result = session.to_result()

    if (
        result["final_status"]
        != "PRECONDITION_FAILED"
    ):
        raise ResponseContractError(
            "PRECONDITION_FINAL_STATUS_UNEXPECTED"
        )

    return {
        "execution_id": "RESP-PRECONDITION-FAIL-001",
        "purpose": (
            "Prove response action is blocked when "
            "evidence preservation is not established."
        ),
        "initial_state_sha256": initial_sha256,
        "final_state_sha256": final_sha256,
        "state_unchanged": state_unchanged,
        "result": result,
    }


def _verification_failure_recovery_execution(
    root: Path,
) -> dict[str, Any]:
    store = JsonHostStateStore(
        root / "verification-failure-host.json"
    )

    initial_state, initial_sha256 = (
        _create_initial_state(
            store,
            evidence_preserved=True,
        )
    )

    session = HostIsolationSession(
        store,
        "RESP-VERIFY-FAIL-001",
    )

    _require_status(
        session.precondition(),
        "PASS",
    )

    _require_status(
        session.dry_run(),
        "PASS",
    )

    _require_status(
        session.apply(),
        "PASS",
    )

    # Intentional sandbox-only fault injection:
    # the action's intended isolated state is altered
    # before verification. No real host state exists here.
    store.save(
        HostState(
            target_id="SIM-HOST-001",
            isolated=False,
            evidence_preserved=True,
            service_available=False,
        )
    )

    verification = session.verify()

    _require_status(
        verification,
        "FAIL",
    )

    if (
        verification.reason
        != "ACTUAL_STATE_DIFFERS_FROM_INTENDED_STATE"
    ):
        raise ResponseContractError(
            "VERIFICATION_FAILURE_REASON_UNEXPECTED"
        )

    _require_status(
        session.rollback(),
        "PASS",
    )

    _require_status(
        session.verify_rollback(),
        "PASS",
    )

    final_state = store.load()
    final_sha256 = store.sha256()

    exact_restoration = (
        final_state == initial_state
        and
        final_sha256 == initial_sha256
    )

    if not exact_restoration:
        raise ResponseContractError(
            "FAILURE_RECOVERY_ROLLBACK_NOT_EXACT"
        )

    result = session.to_result()

    if (
        result["final_status"]
        != "ROLLED_BACK_AFTER_VERIFICATION_FAILURE"
    ):
        raise ResponseContractError(
            "FAILURE_RECOVERY_FINAL_STATUS_UNEXPECTED"
        )

    return {
        "execution_id": "RESP-VERIFY-FAIL-001",
        "purpose": (
            "Prove measured verification detects "
            "unexpected state and exact rollback recovers."
        ),
        "intentional_fault_injection": True,
        "verification_failure_observed": True,
        "initial_state_sha256": initial_sha256,
        "final_state_sha256": final_sha256,
        "exact_pre_action_state_restored": (
            exact_restoration
        ),
        "result": result,
    }


def build_reference_validation() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="tracesoc-response-validation-"
    ) as temp:
        root = Path(temp)

        nominal = _nominal_execution(
            root
        )

        precondition_block = (
            _precondition_block_execution(
                root
            )
        )

        failure_recovery = (
            _verification_failure_recovery_execution(
                root
            )
        )

    return {
        "record_type": RESULT_RECORD_TYPE,
        "schema_version": 1,
        "scenario_id": SCENARIO_ID,
        "validation_status": "PASS",
        "execution_mode": "SIMULATED_LOCAL_STATE",
        "safe_by_default": True,
        "real_host_changes": False,
        "operating_system_firewall_changes": False,
        "account_changes": False,
        "external_network_changes": False,
        "malware_execution": False,
        "evidence_preservation_precondition": True,
        "dry_run_validated": True,
        "controlled_action_validated": True,
        "measured_verification_validated": True,
        "failure_handling_validated": True,
        "rollback_validated": True,
        "rollback_verification_validated": True,
        "business_tradeoff": (
            "Simulated host isolation intentionally "
            "models temporary service unavailability."
        ),
        "recovery_objective": (
            "Restore the exact pre-action simulated "
            "host state and verify byte-stable state identity."
        ),
        "executions": {
            "nominal": nominal,
            "precondition_block": (
                precondition_block
            ),
            "verification_failure_recovery": (
                failure_recovery
            ),
        },
    }


def write_reference_validation(
    output_path: Path | str,
) -> dict[str, Any]:
    path = Path(output_path)

    result = build_reference_validation()

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = _canonical_bytes(
        result
    )

    with path.open(
        "xb"
    ) as handle:
        handle.write(
            payload
        )

    return result


def sha256_file(
    path: Path | str,
) -> str:
    return hashlib.sha256(
        Path(path).read_bytes()
    ).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the TraceSOC simulated response "
            "validation reference scenario."
        )
    )

    parser.add_argument(
        "--output",
        required=True,
        help=(
            "Exclusive-create path for the "
            "machine-readable result."
        ),
    )

    args = parser.parse_args()

    result = write_reference_validation(
        args.output
    )

    output_sha256 = sha256_file(
        args.output
    )

    print(
        "VALIDATION_STATUS="
        + result["validation_status"]
    )

    print(
        "EXECUTION_MODE="
        + result["execution_mode"]
    )

    print(
        "NOMINAL_FINAL_STATUS="
        + result["executions"]["nominal"][
            "result"
        ]["final_status"]
    )

    print(
        "PRECONDITION_BLOCK_FINAL_STATUS="
        + result["executions"][
            "precondition_block"
        ]["result"]["final_status"]
    )

    print(
        "FAILURE_RECOVERY_FINAL_STATUS="
        + result["executions"][
            "verification_failure_recovery"
        ]["result"]["final_status"]
    )

    print(
        "REAL_HOST_CHANGES=FALSE"
    )

    print(
        "RESULT_SHA256="
        + output_sha256
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
