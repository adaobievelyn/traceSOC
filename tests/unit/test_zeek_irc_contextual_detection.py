from __future__ import annotations

import unittest

from tracesoc.detection.zeek_irc import (
    DETECTION_ID,
    detect_zeek_irc_service,
)
from tracesoc.models import (
    ClockState,
    SemanticEvent,
    SourceType,
)


def event(
    *,
    event_id: str = "evt_test_1",
    source_type: SourceType = SourceType.ZEEK,
    event_type: str = "connection",
    fields: dict | None = None,
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


class ZeekIrcContextualDetectionTests(
    unittest.TestCase
):
    def test_irc_service_matches(
        self,
    ) -> None:
        result = detect_zeek_irc_service(
            event(
                fields={
                    "service": "irc",
                }
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
            "zeek_irc_service_observed",
        )

    def test_service_matching_is_case_insensitive(
        self,
    ) -> None:
        result = detect_zeek_irc_service(
            event(
                fields={
                    "service": "IRC",
                }
            )
        )

        self.assertTrue(
            result.matched
        )

    def test_wrong_source_does_not_match(
        self,
    ) -> None:
        result = detect_zeek_irc_service(
            event(
                source_type=
                    SourceType.POWERSHELL,
                fields={
                    "service": "irc",
                },
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
        result = detect_zeek_irc_service(
            event(
                event_type=
                    "dns_query",
                fields={
                    "service": "irc",
                },
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "wrong_event_type",
        )

    def test_missing_service_does_not_match(
        self,
    ) -> None:
        result = detect_zeek_irc_service(
            event(
                fields={}
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "missing_service",
        )

    def test_non_string_service_does_not_match(
        self,
    ) -> None:
        result = detect_zeek_irc_service(
            event(
                fields={
                    "service": 6667,
                }
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "missing_service",
        )

    def test_non_irc_service_does_not_match(
        self,
    ) -> None:
        result = detect_zeek_irc_service(
            event(
                fields={
                    "service": "http",
                }
            )
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "service_not_irc",
        )

    def test_match_carries_exact_parent_event_id(
        self,
    ) -> None:
        result = detect_zeek_irc_service(
            event(
                event_id=
                    "evt_exact_parent",
                fields={
                    "service": "irc",
                },
            )
        )

        self.assertEqual(
            result.contributing_event_ids,
            (
                "evt_exact_parent",
            ),
        )

    def test_assessment_like_field_alone_does_not_trigger(
        self,
    ) -> None:
        result = detect_zeek_irc_service(
            event(
                fields={
                    "service": "http",
                    "det_label": "irc",
                }
            )
        )

        self.assertFalse(
            result.matched
        )

    def test_claim_is_explicitly_bounded(
        self,
    ) -> None:
        result = detect_zeek_irc_service(
            event(
                fields={
                    "service": "irc",
                }
            )
        )

        rationale = (
            result.rationale.casefold()
        )

        self.assertIn(
            "does not establish",
            rationale,
        )

        self.assertIn(
            "command-and-control",
            rationale,
        )

        self.assertIn(
            "malicious intent",
            rationale,
        )


if __name__ == "__main__":
    unittest.main()