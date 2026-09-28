from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
import hashlib
import json
import os


class ResponseContractError(RuntimeError):
    """Raised when a response lifecycle contract is violated."""


@dataclass(frozen=True)
class HostState:
    target_id: str
    isolated: bool
    evidence_preserved: bool
    service_available: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StageRecord:
    stage: str
    status: str
    reason: str
    before_state: dict[str, Any] | None
    intended_state: dict[str, Any] | None
    observed_state: dict[str, Any] | None
    before_sha256: str | None
    after_sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_json_bytes(
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


class JsonHostStateStore:
    """
    File-backed simulated host state.

    This store never changes operating-system firewall, account,
    process, or network state. It is intentionally a local sandbox.
    """

    REQUIRED_KEYS = {
        "target_id",
        "isolated",
        "evidence_preserved",
        "service_available",
    }

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> HostState:
        if not self.exists():
            raise ResponseContractError(
                "TARGET_STATE_NOT_FOUND"
            )

        try:
            raw = json.loads(
                self.path.read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise ResponseContractError(
                "TARGET_STATE_INVALID_JSON"
            ) from exc

        if not isinstance(raw, dict):
            raise ResponseContractError(
                "TARGET_STATE_NOT_OBJECT"
            )

        if set(raw) != self.REQUIRED_KEYS:
            raise ResponseContractError(
                "TARGET_STATE_SCHEMA_MISMATCH"
            )

        if (
            not isinstance(raw["target_id"], str)
            or not raw["target_id"]
            or not isinstance(raw["isolated"], bool)
            or not isinstance(raw["evidence_preserved"], bool)
            or not isinstance(raw["service_available"], bool)
        ):
            raise ResponseContractError(
                "TARGET_STATE_TYPE_MISMATCH"
            )

        return HostState(
            target_id=raw["target_id"],
            isolated=raw["isolated"],
            evidence_preserved=raw["evidence_preserved"],
            service_available=raw["service_available"],
        )

    def save(self, state: HostState) -> None:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary = self.path.with_name(
            self.path.name + ".tmp"
        )

        temporary.write_bytes(
            _canonical_json_bytes(
                state.to_dict()
            )
        )

        os.replace(
            temporary,
            self.path,
        )

    def sha256(self) -> str:
        if not self.exists():
            raise ResponseContractError(
                "TARGET_STATE_NOT_FOUND"
            )

        return hashlib.sha256(
            self.path.read_bytes()
        ).hexdigest()


class HostIsolationSession:
    """
    Reversible simulated host-isolation response lifecycle.

    Lifecycle:
        precondition
        -> dry_run
        -> apply
        -> verify
        -> rollback
        -> verify_rollback

    Evidence preservation is a mandatory precondition.
    """

    ACTION_TYPE = "SIMULATED_HOST_ISOLATION"

    def __init__(
        self,
        store: JsonHostStateStore,
        action_id: str,
    ) -> None:
        if not action_id:
            raise ValueError(
                "action_id must be non-empty"
            )

        self.store = store
        self.action_id = action_id

        self.records: list[StageRecord] = []

        self._precondition_state: HostState | None = None
        self._precondition_sha256: str | None = None

        self._dry_run_state: HostState | None = None
        self._dry_run_sha256: str | None = None

        self._original_state: HostState | None = None
        self._original_sha256: str | None = None

        self._intended_state: HostState | None = None

        self._apply_succeeded = False
        self._verify_status: str | None = None
        self._rollback_succeeded = False
        self._rollback_verify_status: str | None = None

    def _append(
        self,
        *,
        stage: str,
        status: str,
        reason: str,
        before_state: HostState | None = None,
        intended_state: HostState | None = None,
        observed_state: HostState | None = None,
        before_sha256: str | None = None,
        after_sha256: str | None = None,
    ) -> StageRecord:
        record = StageRecord(
            stage=stage,
            status=status,
            reason=reason,
            before_state=(
                before_state.to_dict()
                if before_state is not None
                else None
            ),
            intended_state=(
                intended_state.to_dict()
                if intended_state is not None
                else None
            ),
            observed_state=(
                observed_state.to_dict()
                if observed_state is not None
                else None
            ),
            before_sha256=before_sha256,
            after_sha256=after_sha256,
        )

        self.records.append(record)
        return record

    def precondition(self) -> StageRecord:
        try:
            state = self.store.load()
            state_sha256 = self.store.sha256()
        except ResponseContractError as exc:
            return self._append(
                stage="PRECONDITION",
                status="FAIL",
                reason=str(exc),
            )

        if not state.evidence_preserved:
            return self._append(
                stage="PRECONDITION",
                status="FAIL",
                reason="EVIDENCE_NOT_PRESERVED",
                before_state=state,
                observed_state=state,
                before_sha256=state_sha256,
                after_sha256=state_sha256,
            )

        self._precondition_state = state
        self._precondition_sha256 = state_sha256

        return self._append(
            stage="PRECONDITION",
            status="PASS",
            reason="TARGET_EXISTS_AND_EVIDENCE_PRESERVED",
            before_state=state,
            observed_state=state,
            before_sha256=state_sha256,
            after_sha256=state_sha256,
        )

    def dry_run(self) -> StageRecord:
        if self._precondition_state is None:
            raise ResponseContractError(
                "PRECONDITION_NOT_PASSED"
            )

        state = self.store.load()
        state_sha256 = self.store.sha256()

        if state_sha256 != self._precondition_sha256:
            return self._append(
                stage="DRY_RUN",
                status="FAIL",
                reason="STATE_CHANGED_AFTER_PRECONDITION",
                before_state=self._precondition_state,
                observed_state=state,
                before_sha256=self._precondition_sha256,
                after_sha256=state_sha256,
            )

        intended = HostState(
            target_id=state.target_id,
            isolated=True,
            evidence_preserved=True,
            service_available=False,
        )

        self._dry_run_state = state
        self._dry_run_sha256 = state_sha256
        self._intended_state = intended

        return self._append(
            stage="DRY_RUN",
            status="PASS",
            reason="INTENDED_STATE_COMPUTED_NO_MUTATION",
            before_state=state,
            intended_state=intended,
            observed_state=state,
            before_sha256=state_sha256,
            after_sha256=state_sha256,
        )

    def apply(self) -> StageRecord:
        if (
            self._dry_run_state is None
            or self._dry_run_sha256 is None
            or self._intended_state is None
        ):
            raise ResponseContractError(
                "DRY_RUN_NOT_PASSED"
            )

        current = self.store.load()
        current_sha256 = self.store.sha256()

        if current_sha256 != self._dry_run_sha256:
            return self._append(
                stage="ACTION",
                status="FAIL",
                reason="STATE_CHANGED_SINCE_DRY_RUN",
                before_state=self._dry_run_state,
                intended_state=self._intended_state,
                observed_state=current,
                before_sha256=self._dry_run_sha256,
                after_sha256=current_sha256,
            )

        self._original_state = current
        self._original_sha256 = current_sha256

        self.store.save(
            self._intended_state
        )

        after = self.store.load()
        after_sha256 = self.store.sha256()

        self._apply_succeeded = True

        return self._append(
            stage="ACTION",
            status="PASS",
            reason="SIMULATED_HOST_ISOLATION_APPLIED",
            before_state=current,
            intended_state=self._intended_state,
            observed_state=after,
            before_sha256=current_sha256,
            after_sha256=after_sha256,
        )

    def verify(self) -> StageRecord:
        if (
            not self._apply_succeeded
            or self._intended_state is None
            or self._original_sha256 is None
        ):
            raise ResponseContractError(
                "ACTION_NOT_APPLIED"
            )

        observed = self.store.load()
        observed_sha256 = self.store.sha256()

        if observed == self._intended_state:
            self._verify_status = "PASS"

            return self._append(
                stage="VERIFY",
                status="PASS",
                reason="ACTUAL_STATE_MATCHES_INTENDED_STATE",
                before_state=self._original_state,
                intended_state=self._intended_state,
                observed_state=observed,
                before_sha256=self._original_sha256,
                after_sha256=observed_sha256,
            )

        self._verify_status = "FAIL"

        return self._append(
            stage="VERIFY",
            status="FAIL",
            reason="ACTUAL_STATE_DIFFERS_FROM_INTENDED_STATE",
            before_state=self._original_state,
            intended_state=self._intended_state,
            observed_state=observed,
            before_sha256=self._original_sha256,
            after_sha256=observed_sha256,
        )

    def rollback(self) -> StageRecord:
        if (
            self._original_state is None
            or self._original_sha256 is None
        ):
            raise ResponseContractError(
                "NO_ROLLBACK_SNAPSHOT"
            )

        before = self.store.load()
        before_sha256 = self.store.sha256()

        self.store.save(
            self._original_state
        )

        observed = self.store.load()
        observed_sha256 = self.store.sha256()

        self._rollback_succeeded = True

        return self._append(
            stage="ROLLBACK",
            status="PASS",
            reason="PRE_ACTION_STATE_RESTORED",
            before_state=before,
            intended_state=self._original_state,
            observed_state=observed,
            before_sha256=before_sha256,
            after_sha256=observed_sha256,
        )

    def verify_rollback(self) -> StageRecord:
        if (
            not self._rollback_succeeded
            or self._original_state is None
            or self._original_sha256 is None
        ):
            raise ResponseContractError(
                "ROLLBACK_NOT_APPLIED"
            )

        observed = self.store.load()
        observed_sha256 = self.store.sha256()

        if (
            observed == self._original_state
            and observed_sha256 == self._original_sha256
        ):
            self._rollback_verify_status = "PASS"

            return self._append(
                stage="VERIFY_ROLLBACK",
                status="PASS",
                reason="EXACT_PRE_ACTION_STATE_RESTORED",
                before_state=self._original_state,
                intended_state=self._original_state,
                observed_state=observed,
                before_sha256=self._original_sha256,
                after_sha256=observed_sha256,
            )

        self._rollback_verify_status = "FAIL"

        return self._append(
            stage="VERIFY_ROLLBACK",
            status="FAIL",
            reason="ROLLBACK_STATE_MISMATCH",
            before_state=self._original_state,
            intended_state=self._original_state,
            observed_state=observed,
            before_sha256=self._original_sha256,
            after_sha256=observed_sha256,
        )

    def final_status(self) -> str:
        if any(
            record.stage == "PRECONDITION"
            and record.status == "FAIL"
            for record in self.records
        ):
            return "PRECONDITION_FAILED"

        if any(
            record.stage in {"DRY_RUN", "ACTION"}
            and record.status == "FAIL"
            for record in self.records
        ):
            return "ACTION_FAILED_CLOSED"

        if (
            self._verify_status == "FAIL"
            and self._rollback_verify_status == "PASS"
        ):
            return "ROLLED_BACK_AFTER_VERIFICATION_FAILURE"

        if (
            self._verify_status == "PASS"
            and self._rollback_verify_status == "PASS"
        ):
            return "COMPLETED_AND_ROLLED_BACK"

        if self._verify_status == "PASS":
            return "ACTION_VERIFIED"

        return "IN_PROGRESS"

    def to_result(self) -> dict[str, Any]:
        return {
            "record_type": "tracesoc-response-validation-result-v1",
            "action_id": self.action_id,
            "action_type": self.ACTION_TYPE,
            "execution_mode": "SIMULATED_LOCAL_STATE",
            "safe_by_default": True,
            "evidence_preservation_required": True,
            "business_tradeoff": (
                "Simulated service availability is interrupted "
                "while the host is isolated."
            ),
            "recovery_objective": (
                "Restore the exact pre-action simulated host state."
            ),
            "final_status": self.final_status(),
            "stages": [
                record.to_dict()
                for record in self.records
            ],
        }
