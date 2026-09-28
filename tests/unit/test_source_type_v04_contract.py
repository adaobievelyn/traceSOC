from __future__ import annotations

import unittest

from tracesoc.models import SourceType


EXPECTED_VALUES = {'SYSMON': 'sysmon', 'WINDOWS_SECURITY': 'windows_security', 'POWERSHELL': 'powershell', 'ZEEK': 'zeek', 'EMAIL': 'email', 'PCAP': 'pcap'}


class SourceTypeV04ContractTests(
    unittest.TestCase
):
    def test_member_names_are_exact(
        self,
    ) -> None:
        self.assertEqual(
            set(SourceType.__members__),
            set(EXPECTED_VALUES),
        )

    def test_serialized_values_are_exact(
        self,
    ) -> None:
        self.assertEqual(
            {
                name: member.value
                for name, member
                in SourceType.__members__.items()
            },
            EXPECTED_VALUES,
        )

    def test_legacy_member_values_are_preserved(
        self,
    ) -> None:
        for name in (
            "SYSMON",
            "WINDOWS_SECURITY",
            "POWERSHELL",
            "ZEEK",
        ):
            with self.subTest(
                name=name
            ):
                self.assertEqual(
                    SourceType[
                        name
                    ].value,
                    EXPECTED_VALUES[
                        name
                    ],
                )

    def test_email_and_pcap_are_distinct_source_types(
        self,
    ) -> None:
        self.assertIs(
            SourceType(
                EXPECTED_VALUES[
                    "EMAIL"
                ]
            ),
            SourceType.EMAIL,
        )

        self.assertIs(
            SourceType(
                EXPECTED_VALUES[
                    "PCAP"
                ]
            ),
            SourceType.PCAP,
        )

        self.assertIsNot(
            SourceType.EMAIL,
            SourceType.PCAP,
        )


if __name__ == "__main__":
    unittest.main()
