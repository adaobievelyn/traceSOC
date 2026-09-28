from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from tracesoc.response.validation import (
    build_reference_validation,
    write_reference_validation,
)


class ResponseValidationIntegrationTests(
    unittest.TestCase
):
    def test_reference_validation_covers_required_lifecycle(
        self,
    ) -> None:
        result = build_reference_validation()

        self.assertEqual(
            result["validation_status"],
            "PASS",
        )

        self.assertEqual(
            result["execution_mode"],
            "SIMULATED_LOCAL_STATE",
        )

        self.assertFalse(
            result["real_host_changes"]
        )

        self.assertTrue(
            result[
                "evidence_preservation_precondition"
            ]
        )

        self.assertTrue(
            result["dry_run_validated"]
        )

        self.assertTrue(
            result[
                "measured_verification_validated"
            ]
        )

        self.assertTrue(
            result["failure_handling_validated"]
        )

        self.assertTrue(
            result["rollback_validated"]
        )

        self.assertTrue(
            result[
                "rollback_verification_validated"
            ]
        )

        nominal = result["executions"][
            "nominal"
        ]

        self.assertEqual(
            nominal["result"]["final_status"],
            "COMPLETED_AND_ROLLED_BACK",
        )

        self.assertTrue(
            nominal[
                "exact_pre_action_state_restored"
            ]
        )

        precondition = result["executions"][
            "precondition_block"
        ]

        self.assertEqual(
            precondition["result"][
                "final_status"
            ],
            "PRECONDITION_FAILED",
        )

        self.assertTrue(
            precondition["state_unchanged"]
        )

        failure_recovery = result[
            "executions"
        ]["verification_failure_recovery"]

        self.assertEqual(
            failure_recovery["result"][
                "final_status"
            ],
            (
                "ROLLED_BACK_AFTER_"
                "VERIFICATION_FAILURE"
            ),
        )

        self.assertTrue(
            failure_recovery[
                "verification_failure_observed"
            ]
        )

        self.assertTrue(
            failure_recovery[
                "exact_pre_action_state_restored"
            ]
        )

        failed_verify_records = [
            stage
            for stage in failure_recovery[
                "result"
            ]["stages"]
            if (
                stage["stage"] == "VERIFY"
                and
                stage["status"] == "FAIL"
            )
        ]

        self.assertEqual(
            len(failed_verify_records),
            1,
        )

    def test_machine_result_is_deterministic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            first = root / "first.json"
            second = root / "second.json"

            write_reference_validation(
                first
            )

            write_reference_validation(
                second
            )

            first_bytes = first.read_bytes()
            second_bytes = second.read_bytes()

            self.assertEqual(
                first_bytes,
                second_bytes,
            )

            self.assertEqual(
                hashlib.sha256(
                    first_bytes
                ).hexdigest(),
                hashlib.sha256(
                    second_bytes
                ).hexdigest(),
            )

    def test_machine_result_refuses_overwrite(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = (
                Path(temp)
                / "response-validation.json"
            )

            write_reference_validation(
                output
            )

            original = output.read_bytes()

            with self.assertRaises(
                FileExistsError
            ):
                write_reference_validation(
                    output
                )

            self.assertEqual(
                output.read_bytes(),
                original,
            )


if __name__ == "__main__":
    unittest.main()
