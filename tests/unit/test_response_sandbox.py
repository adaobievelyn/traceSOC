from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tracesoc.response.sandbox import (
    HostIsolationSession,
    HostState,
    JsonHostStateStore,
    ResponseContractError,
)


class ResponseSandboxTests(unittest.TestCase):
    def _store(
        self,
        root: Path,
        *,
        evidence_preserved: bool = True,
    ) -> JsonHostStateStore:
        store = JsonHostStateStore(
            root / "host-state.json"
        )

        store.save(
            HostState(
                target_id="HOST-001",
                isolated=False,
                evidence_preserved=evidence_preserved,
                service_available=True,
            )
        )

        return store

    def test_dry_run_does_not_mutate_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = self._store(root)

            before = store.path.read_bytes()
            before_sha = store.sha256()

            session = HostIsolationSession(
                store,
                "RESP-001",
            )

            self.assertEqual(
                session.precondition().status,
                "PASS",
            )

            record = session.dry_run()

            self.assertEqual(
                record.status,
                "PASS",
            )

            self.assertEqual(
                store.path.read_bytes(),
                before,
            )

            self.assertEqual(
                store.sha256(),
                before_sha,
            )

            self.assertFalse(
                store.load().isolated
            )

    def test_full_isolation_verify_rollback_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = self._store(
                Path(temp)
            )

            original = store.load()
            original_sha = store.sha256()

            session = HostIsolationSession(
                store,
                "RESP-002",
            )

            self.assertEqual(
                session.precondition().status,
                "PASS",
            )

            self.assertEqual(
                session.dry_run().status,
                "PASS",
            )

            self.assertEqual(
                session.apply().status,
                "PASS",
            )

            applied = store.load()

            self.assertTrue(
                applied.isolated
            )

            self.assertFalse(
                applied.service_available
            )

            self.assertTrue(
                applied.evidence_preserved
            )

            self.assertEqual(
                session.verify().status,
                "PASS",
            )

            self.assertEqual(
                session.rollback().status,
                "PASS",
            )

            self.assertEqual(
                session.verify_rollback().status,
                "PASS",
            )

            self.assertEqual(
                store.load(),
                original,
            )

            self.assertEqual(
                store.sha256(),
                original_sha,
            )

            result = session.to_result()

            self.assertEqual(
                result["final_status"],
                "COMPLETED_AND_ROLLED_BACK",
            )

            self.assertEqual(
                [
                    stage["stage"]
                    for stage in result["stages"]
                ],
                [
                    "PRECONDITION",
                    "DRY_RUN",
                    "ACTION",
                    "VERIFY",
                    "ROLLBACK",
                    "VERIFY_ROLLBACK",
                ],
            )

    def test_precondition_blocks_when_evidence_not_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = self._store(
                Path(temp),
                evidence_preserved=False,
            )

            before = store.path.read_bytes()

            session = HostIsolationSession(
                store,
                "RESP-003",
            )

            record = session.precondition()

            self.assertEqual(
                record.status,
                "FAIL",
            )

            self.assertEqual(
                record.reason,
                "EVIDENCE_NOT_PRESERVED",
            )

            with self.assertRaises(
                ResponseContractError
            ):
                session.dry_run()

            self.assertEqual(
                store.path.read_bytes(),
                before,
            )

            self.assertEqual(
                session.to_result()["final_status"],
                "PRECONDITION_FAILED",
            )

    def test_missing_target_is_explicit_precondition_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JsonHostStateStore(
                Path(temp) / "missing.json"
            )

            session = HostIsolationSession(
                store,
                "RESP-004",
            )

            record = session.precondition()

            self.assertEqual(
                record.status,
                "FAIL",
            )

            self.assertEqual(
                record.reason,
                "TARGET_STATE_NOT_FOUND",
            )

            self.assertEqual(
                session.to_result()["final_status"],
                "PRECONDITION_FAILED",
            )

    def test_verification_failure_is_recorded_and_rollback_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = self._store(
                Path(temp)
            )

            original = store.load()
            original_sha = store.sha256()

            session = HostIsolationSession(
                store,
                "RESP-005",
            )

            self.assertEqual(
                session.precondition().status,
                "PASS",
            )

            self.assertEqual(
                session.dry_run().status,
                "PASS",
            )

            self.assertEqual(
                session.apply().status,
                "PASS",
            )

            store.save(
                HostState(
                    target_id="HOST-001",
                    isolated=False,
                    evidence_preserved=True,
                    service_available=False,
                )
            )

            verify = session.verify()

            self.assertEqual(
                verify.status,
                "FAIL",
            )

            self.assertEqual(
                verify.reason,
                "ACTUAL_STATE_DIFFERS_FROM_INTENDED_STATE",
            )

            self.assertEqual(
                session.rollback().status,
                "PASS",
            )

            self.assertEqual(
                session.verify_rollback().status,
                "PASS",
            )

            self.assertEqual(
                store.load(),
                original,
            )

            self.assertEqual(
                store.sha256(),
                original_sha,
            )

            self.assertEqual(
                session.to_result()["final_status"],
                "ROLLED_BACK_AFTER_VERIFICATION_FAILURE",
            )

    def test_state_drift_between_dry_run_and_apply_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = self._store(
                Path(temp)
            )

            session = HostIsolationSession(
                store,
                "RESP-006",
            )

            self.assertEqual(
                session.precondition().status,
                "PASS",
            )

            self.assertEqual(
                session.dry_run().status,
                "PASS",
            )

            drifted = HostState(
                target_id="HOST-001",
                isolated=False,
                evidence_preserved=True,
                service_available=False,
            )

            store.save(
                drifted
            )

            action = session.apply()

            self.assertEqual(
                action.status,
                "FAIL",
            )

            self.assertEqual(
                action.reason,
                "STATE_CHANGED_SINCE_DRY_RUN",
            )

            self.assertEqual(
                store.load(),
                drifted,
            )

            self.assertEqual(
                session.to_result()["final_status"],
                "ACTION_FAILED_CLOSED",
            )

            rendered = json.dumps(
                session.to_result(),
                sort_keys=True,
            )

            self.assertIn(
                '"safe_by_default": true',
                rendered,
            )


if __name__ == "__main__":
    unittest.main()
