from __future__ import annotations

import unittest

from tracesoc.detection.sysmon_firewall import (
    DETECTION_ID,
    detect_sysmon_domain_firewall_zero_write,
)
from tracesoc.models import (
    ClockState,
    SemanticEvent,
    SourceType,
)


TARGET_PATH = (
    r"HKLM\System\CurrentControlSet\Services\SharedAccess"
    r"\Parameters\FirewallPolicy\DomainProfile\EnableFirewall"
)


def event(
    *,
    event_id: str = "evt_test_1",
    source_type: SourceType = SourceType.SYSMON,
    event_type: str = "registry_set_value",
    fields: dict[str, object] | None = None,
) -> SemanticEvent:
    return SemanticEvent(
        event_id=event_id,
        source_type=source_type,
        event_type=event_type,
        clock_state=ClockState.OBSERVED,
        event_time_utc=None,
        host=None,
        principal=None,
        fields=(
            {}
            if fields is None
            else fields
        ),
    )


class SysmonFirewallConfigurationDetectionTests(
    unittest.TestCase
):
    def test_target_path_and_dword_zero_matches(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    fields={
                        "registry_path":
                            TARGET_PATH,
                        "registry_details":
                            "DWORD (0x00000000)",
                    }
                )
            )
        )

        self.assertTrue(
            result.matched
        )

        self.assertEqual(
            result.detection_id,
            DETECTION_ID,
        )

        self.assertEqual(
            result.reason_code,
            (
                "sysmon_domain_firewall_"
                "enable_value_zero_write_observed"
            ),
        )

    def test_path_and_value_matching_is_case_insensitive(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    fields={
                        "registry_path":
                            TARGET_PATH.upper(),
                        "registry_details":
                            "dword (0X00000000)",
                    }
                )
            )
        )

        self.assertTrue(
            result.matched
        )

    def test_forward_slash_path_is_normalized(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    fields={
                        "registry_path":
                            TARGET_PATH.replace(
                                "\\",
                                "/",
                            ),
                        "registry_details":
                            "DWORD (0x00000000)",
                    }
                )
            )
        )

        self.assertTrue(
            result.matched
        )

    def test_wrong_source_does_not_match(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    source_type=
                        SourceType.POWERSHELL,
                    fields={
                        "registry_path":
                            TARGET_PATH,
                        "registry_details":
                            "DWORD (0x00000000)",
                    },
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "wrong_source",
        )

    def test_wrong_event_type_does_not_match(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    event_type=
                        "registry_delete",
                    fields={
                        "registry_path":
                            TARGET_PATH,
                        "registry_details":
                            "DWORD (0x00000000)",
                    },
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "wrong_event_type",
        )

    def test_missing_registry_path_does_not_match(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    fields={
                        "registry_details":
                            "DWORD (0x00000000)",
                    }
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "missing_registry_path",
        )

    def test_other_firewall_profile_does_not_match(
        self,
    ) -> None:
        private_path = TARGET_PATH.replace(
            "DomainProfile",
            "PrivateProfile",
        )

        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    fields={
                        "registry_path":
                            private_path,
                        "registry_details":
                            "DWORD (0x00000000)",
                    }
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "wrong_registry_path",
        )

    def test_missing_registry_details_does_not_match(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    fields={
                        "registry_path":
                            TARGET_PATH,
                    }
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "missing_registry_details",
        )

    def test_non_string_registry_details_does_not_match(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    fields={
                        "registry_path":
                            TARGET_PATH,
                        "registry_details":
                            0,
                    }
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "missing_registry_details",
        )

    def test_nonzero_target_value_does_not_match(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    fields={
                        "registry_path":
                            TARGET_PATH,
                        "registry_details":
                            "DWORD (0x00000001)",
                    }
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "value_not_dword_zero",
        )

    def test_other_registry_dword_zero_does_not_match(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    fields={
                        "registry_path":
                            (
                                r"HKLM\Software\Example"
                                r"\CompletelyDifferentValue"
                            ),
                        "registry_details":
                            "DWORD (0x00000000)",
                    }
                )
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "wrong_registry_path",
        )

    def test_match_has_exact_lineage_and_bounded_claim(
        self,
    ) -> None:
        result = (
            detect_sysmon_domain_firewall_zero_write(
                event(
                    event_id=
                        "evt_exact_parent",
                    fields={
                        "registry_path":
                            TARGET_PATH,
                        "registry_details":
                            "DWORD (0x00000000)",
                        "process_name":
                            r"C:\Any\Process.exe",
                    },
                )
            )
        )

        self.assertTrue(
            result.matched
        )

        self.assertEqual(
            result.contributing_event_ids,
            (
                "evt_exact_parent",
            ),
        )

        rationale = result.rationale.casefold()

        self.assertIn(
            "does not establish",
            rationale,
        )

        self.assertIn(
            "final firewall state",
            rationale,
        )

        self.assertIn(
            "malicious intent",
            rationale,
        )


if __name__ == "__main__":
    unittest.main()