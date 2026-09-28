from __future__ import annotations

import hashlib
import unittest
from datetime import (
    datetime,
    timezone,
)

from tracesoc.evidence.case_narrative import (
    CaseNarrativeContractError,
    create_case_narratives,
)
from tracesoc.evidence.findings_v04 import (
    CaseFinding,
)
from tracesoc.evidence.identity import (
    compute_event_id,
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
from tracesoc.response.case_response import (
    create_case_response_records,
)


def event(
    *,
    record_index: int,
    host: str | None,
) -> CanonicalEvent:
    raw = (
        "narrative-event-"
        + str(
            record_index
        )
    ).encode(
        "utf-8"
    )

    locator = RawLocator(
        logical_source=(
            "narrative-events.xml"
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
            "test-narrative"
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
        event_time_utc=datetime(
            2026,
            9,
            22,
            12,
            0,
            0,
            tzinfo=timezone.utc,
        ),
        host=host,
        principal=(
            r"DOMAIN\User1"
        ),
        semantic_fields={},
        source_context={},
    )


def finding(
    *observation_ids: str,
    relationship_id: str = "rel_narrative",
) -> CaseFinding:
    return CaseFinding(
        finding_id=(
            "fnd_narrative"
        ),
        hypothesis_id=(
            "hyp_narrative"
        ),
        statement=(
            "Bounded activity is corroborated "
            "across independent evidence."
        ),
        evidence_state=(
            EvidenceState.CORROBORATED
        ),
        detection_result_ids=(
            "detres_narrative",
        ),
        supporting_relationship_ids=(
            relationship_id,
        ),
        contradicting_relationship_ids=(),
        observation_ids=tuple(
            observation_ids
        ),
        rationale=(
            "The detector and bounded relationship "
            "agree on the cited observations."
        ),
        alternative_or_falsifier=(
            "A material relationship-anchor mismatch "
            "would falsify this claim."
        ),
        incident_status=(
            EvidenceState.NOT_ESTABLISHED
        ),
        malicious_intent_status=(
            EvidenceState.NOT_ESTABLISHED
        ),
    )


class CaseNarrativeV04Tests(
    unittest.TestCase
):
    def test_narrative_cites_observations_and_raw_locators(
        self,
    ) -> None:
        first = event(
            record_index=0,
            host="HOST-1",
        )

        second = event(
            record_index=1,
            host="HOST-1",
        )

        source_finding = finding(
            first.event_id,
            second.event_id,
        )

        responses = (
            create_case_response_records(
                findings=(
                    source_finding,
                ),
                canonical_events=(
                    first,
                    second,
                ),
            )
        )

        records = create_case_narratives(
            findings=(
                source_finding,
            ),
            canonical_events=(
                first,
                second,
            ),
            relationship_payload={
                "relationships": [
                    {
                        "relationship_id":
                            "rel_narrative",
                    },
                ],
            },
            responses=responses,
        )

        self.assertEqual(
            len(records),
            1,
        )

        payload = records[
            0
        ].to_dict()

        self.assertEqual(
            payload[
                "corroborated"
            ][
                "evidence_state"
            ],
            "CORROBORATED",
        )

        self.assertEqual(
            len(
                payload[
                    "observed"
                ][
                    "observations"
                ]
            ),
            2,
        )

        for citation in payload[
            "observed"
        ][
            "observations"
        ]:
            self.assertEqual(
                citation[
                    "evidence_state"
                ],
                "OBSERVED",
            )

            self.assertTrue(
                citation[
                    "raw_locator"
                ][
                    "logical_source"
                ]
            )

            self.assertTrue(
                citation[
                    "raw_locator"
                ][
                    "raw_sha256"
                ]
            )


    def test_narrative_does_not_invent_incident_or_intent(
        self,
    ) -> None:
        source_event = event(
            record_index=2,
            host="HOST-1",
        )

        source_finding = finding(
            source_event.event_id
        )

        responses = (
            create_case_response_records(
                findings=(
                    source_finding,
                ),
                canonical_events=(
                    source_event,
                ),
            )
        )

        payload = (
            create_case_narratives(
                findings=(
                    source_finding,
                ),
                canonical_events=(
                    source_event,
                ),
                relationship_payload={
                    "relationships": [
                        {
                            "relationship_id":
                                "rel_narrative",
                        },
                    ],
                },
                responses=responses,
            )[0].to_dict()
        )

        self.assertEqual(
            payload[
                "not_established"
            ][
                "incident_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            payload[
                "not_established"
            ][
                "malicious_intent_status"
            ],
            "NOT_ESTABLISHED",
        )

        self.assertEqual(
            payload[
                "inferred"
            ][
                "claims"
            ],
            [],
        )

        self.assertFalse(
            payload[
                "uncertainty"
            ][
                "numeric_confidence_used"
            ]
        )


    def test_missing_relationship_fails_closed(
        self,
    ) -> None:
        source_event = event(
            record_index=3,
            host="HOST-1",
        )

        source_finding = finding(
            source_event.event_id
        )

        responses = (
            create_case_response_records(
                findings=(
                    source_finding,
                ),
                canonical_events=(
                    source_event,
                ),
            )
        )

        with self.assertRaises(
            CaseNarrativeContractError
        ):
            create_case_narratives(
                findings=(
                    source_finding,
                ),
                canonical_events=(
                    source_event,
                ),
                relationship_payload={
                    "relationships": [],
                },
                responses=responses,
            )


    def test_narrative_generation_is_deterministic(
        self,
    ) -> None:
        source_event = event(
            record_index=4,
            host="HOST-1",
        )

        source_finding = finding(
            source_event.event_id
        )

        responses = (
            create_case_response_records(
                findings=(
                    source_finding,
                ),
                canonical_events=(
                    source_event,
                ),
            )
        )

        kwargs = {
            "findings": (
                source_finding,
            ),
            "canonical_events": (
                source_event,
            ),
            "relationship_payload": {
                "relationships": [
                    {
                        "relationship_id":
                            "rel_narrative",
                    },
                ],
            },
            "responses":
                responses,
        }

        first = create_case_narratives(
            **kwargs
        )

        second = create_case_narratives(
            **kwargs
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            first[
                0
            ].to_dict(),
            second[
                0
            ].to_dict(),
        )


if __name__ == "__main__":
    unittest.main()
