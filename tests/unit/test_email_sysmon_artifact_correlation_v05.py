from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import (
    datetime,
    timezone,
)

from tracesoc.correlation.email_sysmon_artifact import (
    correlate_email_attachment_with_sysmon_process_image,
    extract_sysmon_sha256,
)
from tracesoc.models import (
    ClockState,
    SemanticEvent,
    SourceType,
)


SHA = "a" * 64
OTHER_SHA = "b" * 64

BASE_TIME = datetime(
    2026,
    9,
    24,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def email_event(
    *,
    sha256: str = SHA,
    filename: str = "payload.exe",
    derived: bool = True,
) -> SemanticEvent:
    return SemanticEvent(
        event_id=(
            "email-part-1"
        ),
        source_type=(
            SourceType.EMAIL
        ),
        event_type=(
            "email_mime_part"
        ),
        clock_state=(
            ClockState.UNTIMED
        ),
        event_time_utc=None,
        host=None,
        principal=None,
        fields={
            "filename":
                filename,

            "decoded_sha256":
                sha256,

            "derived_artifact_id":
                (
                    "art_"
                    + "1" * 64
                )
                if derived
                else None,
        },
    )


def sysmon_event(
    *,
    sha256: str = SHA,
    process_name: str = (
        r"C:\Temp\renamed.exe"
    ),
) -> SemanticEvent:
    return SemanticEvent(
        event_id=(
            "sysmon-process-1"
        ),
        source_type=(
            SourceType.SYSMON
        ),
        event_type=(
            "process_create"
        ),
        clock_state=(
            ClockState.OBSERVED
        ),
        event_time_utc=(
            BASE_TIME
        ),
        host=(
            "HOST-01"
        ),
        principal=None,
        fields={
            "process_name":
                process_name,

            "hashes":
                (
                    "MD5="
                    + "c" * 32
                    + ",SHA256="
                    + sha256.upper()
                ),
        },
    )


class EmailSysmonArtifactCorrelationTests(
    unittest.TestCase
):
    def test_exact_attachment_and_process_image_sha256_match(
        self,
    ) -> None:
        result = (
            correlate_email_attachment_with_sysmon_process_image(
                email_event=(
                    email_event()
                ),
                sysmon_event=(
                    sysmon_event()
                ),
            )
        )

        self.assertTrue(
            result.matched
        )

        self.assertEqual(
            result.edge.sha256,
            SHA,
        )

        self.assertEqual(
            result.edge.matched_dimensions,
            (
                "sha256",
            ),
        )

    def test_same_hash_different_filename_still_matches(
        self,
    ) -> None:
        result = (
            correlate_email_attachment_with_sysmon_process_image(
                email_event=(
                    email_event(
                        filename=(
                            "original-name.exe"
                        )
                    )
                ),
                sysmon_event=(
                    sysmon_event(
                        process_name=(
                            r"C:\Temp\completely-different.exe"
                        )
                    )
                ),
            )
        )

        self.assertTrue(
            result.matched
        )

    def test_same_filename_different_hash_fails(
        self,
    ) -> None:
        result = (
            correlate_email_attachment_with_sysmon_process_image(
                email_event=(
                    email_event(
                        filename=(
                            "same.exe"
                        )
                    )
                ),
                sysmon_event=(
                    sysmon_event(
                        sha256=(
                            OTHER_SHA
                        ),
                        process_name=(
                            r"C:\Temp\same.exe"
                        ),
                    )
                ),
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "sha256_mismatch",
        )

    def test_non_attachment_mime_part_fails_closed(
        self,
    ) -> None:
        result = (
            correlate_email_attachment_with_sysmon_process_image(
                email_event=(
                    email_event(
                        derived=False
                    )
                ),
                sysmon_event=(
                    sysmon_event()
                ),
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "email_part_not_attachment_artifact",
        )

    def test_missing_sysmon_sha256_fails_closed(
        self,
    ) -> None:
        target = replace(
            sysmon_event(),
            fields={
                "process_name":
                    r"C:\Temp\x.exe",

                "hashes":
                    (
                        "MD5="
                        + "c" * 32
                    ),
            },
        )

        result = (
            correlate_email_attachment_with_sysmon_process_image(
                email_event=(
                    email_event()
                ),
                sysmon_event=(
                    target
                ),
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "sysmon_sha256_unavailable",
        )

    def test_hash_parser_requires_explicit_sha256_label(
        self,
    ) -> None:
        self.assertEqual(
            extract_sysmon_sha256(
                "SHA1=abc,SHA256="
                + SHA.upper()
            ),
            SHA,
        )

        self.assertIsNone(
            extract_sysmon_sha256(
                SHA
            )
        )

    def test_wrong_source_family_fails_closed(
        self,
    ) -> None:
        source = replace(
            email_event(),
            source_type=(
                SourceType.POWERSHELL
            ),
        )

        result = (
            correlate_email_attachment_with_sysmon_process_image(
                email_event=(
                    source
                ),
                sysmon_event=(
                    sysmon_event()
                ),
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "source_type_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
