from __future__ import annotations

import hashlib
import unittest
from datetime import (
    datetime,
    timezone,
)

from tracesoc.evidence.findings_v04 import (
    CaseFinding,
)
from tracesoc.evidence.states import (
    EvidenceState,
)
from tracesoc.models import (
    CanonicalEvent,
    ClockState,
    RawLocator,
    SourceType,
)
from tracesoc.evidence.identity import (
    compute_event_id,
)
from tracesoc.response.case_response import (
    TARGET_ESTABLISHED,
    TARGET_NOT_ESTABLISHED,
    create_case_response_records,
)
from tracesoc.response.sandbox import (
    HostIsolationSession,
)


UTC_TIME = datetime(
    2026,
    9,
    22,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def canonical_event(
    *,
    record_index: int,
    host: str | None,
) -> CanonicalEvent:
    raw = (
        "event-"
        + str(
            record_index
        )
    ).encode(
        "utf-8"
    )

    locator = RawLocator(
        logical_source=(
            "events.xml"
        ),
        record_index=(
            record_index
        ),
        line_number=(
            record_index
            + 1
        ),
        byte_offset=0,
        byte_length=len(
            raw
        ),
        raw_sha256=(
            hashlib.sha256(
                raw
            ).hexdigest()
        ),
        adapter_id=(
            "test-response"
        ),
        input_schema_version="1",
    )

    event_id = compute_event_id(
        locator=locator,
        source_type=(
            SourceType.SYSMON
        ),
        event_type=(
            "network_connection"
        ),
    )

    return CanonicalEvent(
        event_id=event_id,
        source_type=(
            SourceType.SYSMON
        ),
        event_type=(
            "network_connection"
        ),
        clock_state=(
            ClockState.OBSERVED
        ),
        provenance=locator,
        event_time_raw=(
            "2026-09-22T12:00:00Z"
        ),
        event_time_utc=(
            UTC_TIME
        ),
        host=host,
        principal=None,
        semantic_fields={},
        source_context={},
    )


def finding(
    *observation_ids: str,
) -> CaseFinding:
    return CaseFinding(
        finding_id=(
            "fnd_test_response"
        ),
        hypothesis_id=(
            "hyp_test_response"
        ),
        statement=(
            "Corroborated bounded activity."
        ),
        evidence_state=(
            EvidenceState.CORROBORATED
        ),
        detection_result_ids=(
            "detres_test",
        ),
        supporting_relationship_ids=(
            "rel_test",
        ),
        contradicting_relationship_ids=(),
        observation_ids=tuple(
            observation_ids
        ),
        rationale=(
            "Independent observations corroborate "
            "the bounded activity."
        ),
        alternative_or_falsifier=(
            "A material anchor mismatch falsifies "
            "the relationship."
        ),
        incident_status=(
            EvidenceState.NOT_ESTABLISHED
        ),
        malicious_intent_status=(
            EvidenceState.NOT_ESTABLISHED
        ),
    )


class CaseResponseV04Tests(
    unittest.TestCase
):
    def test_established_observation_host_becomes_plan_target(
        self,
    ) -> None:
        first = canonical_event(
            record_index=0,
            host="HOST-1",
        )

        second = canonical_event(
            record_index=1,
            host=None,
        )

        records = (
            create_case_response_records(
                findings=(
                    finding(
                        first.event_id,
                        second.event_id,
                    ),
                ),
                canonical_events=(
                    first,
                    second,
                ),
            )
        )

        self.assertEqual(
            len(
                records
            ),
            1,
        )

        record = records[0]

        self.assertEqual(
            record.target_status,
            TARGET_ESTABLISHED,
        )

        self.assertEqual(
            record.target_host,
            "HOST-1",
        )

        self.assertEqual(
            record.action_type,
            HostIsolationSession.ACTION_TYPE,
        )

        payload = record.to_dict()

        self.assertEqual(
            payload[
                "execution_status"
            ],
            "NOT_EXECUTED",
        )

        self.assertFalse(
            payload[
                "response_actions_executed"
            ]
        )

        self.assertEqual(
            payload[
                "dry_run"
            ][
                "status"
            ],
            "NOT_EXECUTED",
        )

        self.assertFalse(
            payload[
                "dry_run"
            ][
                "target_mutated"
            ]
        )

        self.assertTrue(
            payload[
                "rollback"
            ][
                "required"
            ]
        )

        self.assertTrue(
            payload[
                "rollback"
            ][
                "verification_required"
            ]
        )


    def test_conflicting_observation_hosts_are_not_guessed(
        self,
    ) -> None:
        first = canonical_event(
            record_index=2,
            host="HOST-A",
        )

        second = canonical_event(
            record_index=3,
            host="HOST-B",
        )

        record = (
            create_case_response_records(
                findings=(
                    finding(
                        first.event_id,
                        second.event_id,
                    ),
                ),
                canonical_events=(
                    first,
                    second,
                ),
            )[0]
        )

        self.assertEqual(
            record.target_status,
            TARGET_NOT_ESTABLISHED,
        )

        self.assertIsNone(
            record.target_host
        )

        self.assertEqual(
            record.target_reason,
            "CONFLICTING_OBSERVATION_HOSTS",
        )


    def test_missing_observation_host_is_not_fabricated(
        self,
    ) -> None:
        first = canonical_event(
            record_index=4,
            host=None,
        )

        record = (
            create_case_response_records(
                findings=(
                    finding(
                        first.event_id,
                    ),
                ),
                canonical_events=(
                    first,
                ),
            )[0]
        )

        self.assertEqual(
            record.target_status,
            TARGET_NOT_ESTABLISHED,
        )

        self.assertIsNone(
            record.target_host
        )

        payload = record.to_dict()

        self.assertEqual(
            payload[
                "target"
            ][
                "asset_owner_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            payload[
                "target"
            ][
                "service_availability_status"
            ],
            "NOT_ESTABLISHED",
        )


    def test_response_generation_is_deterministic(
        self,
    ) -> None:
        event = canonical_event(
            record_index=5,
            host="HOST-1",
        )

        finding_value = finding(
            event.event_id
        )

        first = (
            create_case_response_records(
                findings=(
                    finding_value,
                ),
                canonical_events=(
                    event,
                ),
            )
        )

        second = (
            create_case_response_records(
                findings=(
                    finding_value,
                ),
                canonical_events=(
                    event,
                ),
            )
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            first[0].to_dict(),
            second[0].to_dict(),
        )


if __name__ == "__main__":
    unittest.main()
