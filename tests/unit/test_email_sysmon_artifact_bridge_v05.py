from __future__ import annotations

import unittest
from datetime import (
    datetime,
    timezone,
)

from tracesoc.correlation.email_sysmon_artifact import (
    correlate_email_attachment_with_sysmon_process_image,
)
from tracesoc.evidence.correlation_bridge import (
    bridge_email_sysmon_artifact_correlation,
)
from tracesoc.evidence.graph import (
    RelationshipType,
)
from tracesoc.evidence.states import (
    EvidenceState,
)
from tracesoc.models import (
    ClockState,
    SemanticEvent,
    SourceType,
)


SHA = "a" * 64

BASE_TIME = datetime(
    2026,
    9,
    24,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def email() -> SemanticEvent:
    return SemanticEvent(
        event_id="email-1",
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
            "decoded_sha256":
                SHA,

            "derived_artifact_id":
                (
                    "art_"
                    + "1" * 64
                ),

            "filename":
                "mail-name.exe",
        },
    )


def sysmon() -> SemanticEvent:
    return SemanticEvent(
        event_id="sysmon-1",
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
        host="HOST-01",
        principal=None,
        fields={
            "process_name":
                r"C:\Temp\renamed.exe",

            "hashes":
                (
                    "SHA256="
                    + SHA.upper()
                ),
        },
    )


class EmailSysmonArtifactBridgeTests(
    unittest.TestCase
):
    def test_match_projects_exact_hash_corroboration(
        self,
    ) -> None:
        source = email()
        target = sysmon()

        result = (
            correlate_email_attachment_with_sysmon_process_image(
                email_event=source,
                sysmon_event=target,
            )
        )

        projection = (
            bridge_email_sysmon_artifact_correlation(
                result=result,
                email_event=source,
                sysmon_event=target,
            )
        )

        self.assertIsNotNone(
            projection
        )

        relationship = (
            projection.relationship
        )

        self.assertEqual(
            relationship.relationship_type,
            RelationshipType.CORROBORATES,
        )

        self.assertEqual(
            relationship.evidence_state,
            EvidenceState.CORROBORATED,
        )

        self.assertEqual(
            relationship.predicate_version,
            "TRC-CORR-005@1.0.0",
        )

        self.assertEqual(
            [
                (
                    anchor.anchor_type,
                    anchor.value,
                    anchor.temporal,
                )
                for anchor
                in relationship.anchors
            ],
            [
                (
                    "sha256",
                    SHA,
                    False,
                ),
            ],
        )

    def test_no_match_creates_no_graph_relationship(
        self,
    ) -> None:
        source = email()

        target = SemanticEvent(
            event_id="sysmon-2",
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
            host="HOST-01",
            principal=None,
            fields={
                "process_name":
                    r"C:\Temp\x.exe",

                "hashes":
                    (
                        "SHA256="
                        + "b" * 64
                    ),
            },
        )

        result = (
            correlate_email_attachment_with_sysmon_process_image(
                email_event=source,
                sysmon_event=target,
            )
        )

        self.assertIsNone(
            bridge_email_sysmon_artifact_correlation(
                result=result,
                email_event=source,
                sysmon_event=target,
            )
        )


if __name__ == "__main__":
    unittest.main()
