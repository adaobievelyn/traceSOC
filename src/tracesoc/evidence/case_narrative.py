from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
import hashlib
import json

from tracesoc.evidence.findings_v04 import (
    CaseFinding,
)
from tracesoc.evidence.states import (
    EvidenceState,
)
from tracesoc.models import (
    CanonicalEvent,
)
from tracesoc.response.case_response import (
    CaseResponseRecord,
)


NARRATIVE_RECORD_SCHEMA_ID = (
    "tracesoc-case-narrative-record-v1"
)

NARRATIVE_IDENTITY_VERSION = "1"


class CaseNarrativeContractError(
    ValueError
):
    pass


def _require_text(
    value: object,
    field: str,
) -> str:
    if not isinstance(
        value,
        str,
    ):
        raise CaseNarrativeContractError(
            field
            + " must be text"
        )

    candidate = value.strip()

    if not candidate:
        raise CaseNarrativeContractError(
            field
            + " must not be empty"
        )

    return candidate


def _narrative_id(
    *,
    finding_id: str,
    statement: str,
) -> str:
    material = {
        "identity_version":
            NARRATIVE_IDENTITY_VERSION,

        "finding_id":
            finding_id,

        "statement":
            statement,
    }

    encoded = json.dumps(
        material,
        ensure_ascii=True,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    ).encode(
        "ascii"
    )

    return (
        "nar_"
        + hashlib.sha256(
            encoded
        ).hexdigest()
    )


def _utc_text(
    event: CanonicalEvent,
) -> str | None:
    value = event.event_time_utc

    if value is None:
        return None

    normalized = value.astimezone(
        timezone.utc
    )

    return normalized.isoformat(
        timespec=(
            "microseconds"
            if normalized.microsecond
            else "seconds"
        )
    ).replace(
        "+00:00",
        "Z",
    )


@dataclass(
    frozen=True,
    slots=True,
)
class NarrativeObservationCitation:
    event_id: str
    source_type: str
    event_type: str
    event_time_raw: str | None
    event_time_utc: str | None
    host: str | None
    principal: str | None

    logical_source: str
    record_index: int
    line_number: int | None
    byte_offset: int | None
    byte_length: int | None
    raw_sha256: str | None
    adapter_id: str
    input_schema_version: str

    @classmethod
    def from_event(
        cls,
        event: CanonicalEvent,
    ) -> "NarrativeObservationCitation":
        if not isinstance(
            event,
            CanonicalEvent,
        ):
            raise TypeError(
                "event must be CanonicalEvent"
            )

        locator = event.provenance

        return cls(
            event_id=_require_text(
                event.event_id,
                "event_id",
            ),
            source_type=(
                event.source_type.value
            ),
            event_type=_require_text(
                event.event_type,
                "event_type",
            ),
            event_time_raw=(
                event.event_time_raw
            ),
            event_time_utc=(
                _utc_text(
                    event
                )
            ),
            host=(
                event.host
            ),
            principal=(
                event.principal
            ),
            logical_source=(
                locator.logical_source
            ),
            record_index=(
                locator.record_index
            ),
            line_number=(
                locator.line_number
            ),
            byte_offset=(
                locator.byte_offset
            ),
            byte_length=(
                locator.byte_length
            ),
            raw_sha256=(
                locator.raw_sha256
            ),
            adapter_id=(
                locator.adapter_id
            ),
            input_schema_version=(
                locator.input_schema_version
            ),
        )

    def to_dict(
        self,
    ) -> dict[
        str,
        object,
    ]:
        return {
            "evidence_state":
                "OBSERVED",

            "event_id":
                self.event_id,

            "source_type":
                self.source_type,

            "event_type":
                self.event_type,

            "event_time_raw":
                self.event_time_raw,

            "event_time_utc":
                self.event_time_utc,

            "host":
                self.host,

            "principal":
                self.principal,

            "raw_locator": {
                "logical_source":
                    self.logical_source,

                "record_index":
                    self.record_index,

                "line_number":
                    self.line_number,

                "byte_offset":
                    self.byte_offset,

                "byte_length":
                    self.byte_length,

                "raw_sha256":
                    self.raw_sha256,

                "adapter_id":
                    self.adapter_id,

                "input_schema_version":
                    self.input_schema_version,
            },
        }


@dataclass(
    frozen=True,
    slots=True,
)
class CaseNarrativeRecord:
    narrative_id: str
    finding_id: str
    hypothesis_id: str

    statement: str
    rationale: str
    alternative_or_falsifier: str

    detection_result_ids: tuple[
        str,
        ...,
    ]

    supporting_relationship_ids: tuple[
        str,
        ...,
    ]

    contradicting_relationship_ids: tuple[
        str,
        ...,
    ]

    observations: tuple[
        NarrativeObservationCitation,
        ...,
    ]

    incident_status: str
    malicious_intent_status: str

    response_id: str
    response_execution_status: str
    response_actions_executed: bool

    asset_owner_status: str
    current_isolation_state_status: str
    service_availability_status: str

    def __post_init__(
        self,
    ) -> None:
        for field, value in (
            (
                "narrative_id",
                self.narrative_id,
            ),
            (
                "finding_id",
                self.finding_id,
            ),
            (
                "hypothesis_id",
                self.hypothesis_id,
            ),
            (
                "statement",
                self.statement,
            ),
            (
                "rationale",
                self.rationale,
            ),
            (
                "alternative_or_falsifier",
                self.alternative_or_falsifier,
            ),
            (
                "response_id",
                self.response_id,
            ),
            (
                "response_execution_status",
                self.response_execution_status,
            ),
        ):
            _require_text(
                value,
                field,
            )

        if (
            self.incident_status
            != EvidenceState.NOT_ESTABLISHED.value
        ):
            raise CaseNarrativeContractError(
                "narrative must not declare "
                "incident membership"
            )

        if (
            self.malicious_intent_status
            != EvidenceState.NOT_ESTABLISHED.value
        ):
            raise CaseNarrativeContractError(
                "narrative must not establish "
                "malicious intent"
            )

        if self.response_actions_executed:
            raise CaseNarrativeContractError(
                "narrative cannot claim a response "
                "action was executed"
            )

        if not self.detection_result_ids:
            raise CaseNarrativeContractError(
                "narrative requires a detection citation"
            )

        if not self.supporting_relationship_ids:
            raise CaseNarrativeContractError(
                "narrative requires a relationship citation"
            )

        if not self.observations:
            raise CaseNarrativeContractError(
                "narrative requires observation citations"
            )

    def to_dict(
        self,
    ) -> dict[
        str,
        object,
    ]:
        return {
            "record_schema_id":
                NARRATIVE_RECORD_SCHEMA_ID,

            "narrative_id":
                self.narrative_id,

            "finding_id":
                self.finding_id,

            "hypothesis_id":
                self.hypothesis_id,

            "observed": {
                "evidence_state":
                    "OBSERVED",

                "observations": [
                    item.to_dict()
                    for item
                    in self.observations
                ],
            },

            "corroborated": {
                "evidence_state":
                    EvidenceState.CORROBORATED.value,

                "statement":
                    self.statement,

                "rationale":
                    self.rationale,

                "detection_result_ids":
                    list(
                        self.detection_result_ids
                    ),

                "supporting_relationship_ids":
                    list(
                        self.supporting_relationship_ids
                    ),
            },

            "inferred": {
                "claims": [],

                "statement":
                    (
                        "No additional INFERRED claim is "
                        "introduced by narrative "
                        "materialization."
                    ),
            },

            "search_not_closed": {
                "claims": [],

                "statement":
                    (
                        "Narrative materialization does "
                        "not independently assert a "
                        "SEARCH_NOT_CLOSED claim."
                    ),
            },

            "not_established": {
                "incident_status":
                    self.incident_status,

                "malicious_intent_status":
                    self.malicious_intent_status,

                "asset_owner_status":
                    self.asset_owner_status,

                "current_isolation_state_status":
                    self.current_isolation_state_status,

                "service_availability_status":
                    self.service_availability_status,
            },

            "uncertainty": {
                "alternative_or_falsifier":
                    self.alternative_or_falsifier,

                "contradicting_relationship_ids":
                    list(
                        self.contradicting_relationship_ids
                    ),

                "numeric_confidence_used":
                    False,
            },

            "response": {
                "response_id":
                    self.response_id,

                "execution_status":
                    self.response_execution_status,

                "response_actions_executed":
                    self.response_actions_executed,
            },

            "citation_summary": {
                "finding_id":
                    self.finding_id,

                "hypothesis_id":
                    self.hypothesis_id,

                "detection_result_ids":
                    list(
                        self.detection_result_ids
                    ),

                "supporting_relationship_ids":
                    list(
                        self.supporting_relationship_ids
                    ),

                "contradicting_relationship_ids":
                    list(
                        self.contradicting_relationship_ids
                    ),

                "observation_ids": [
                    item.event_id
                    for item
                    in self.observations
                ],

                "raw_locators_present":
                    True,
            },
        }


def _relationship_ids(
    relationship_payload: dict[
        str,
        object,
    ],
) -> set[
    str
]:
    if not isinstance(
        relationship_payload,
        dict,
    ):
        raise TypeError(
            "relationship_payload must be dict"
        )

    raw = relationship_payload.get(
        "relationships"
    )

    if not isinstance(
        raw,
        list,
    ):
        raise CaseNarrativeContractError(
            "relationship payload has no "
            "relationship list"
        )

    result: set[
        str
    ] = set()

    for record in raw:
        if not isinstance(
            record,
            dict,
        ):
            raise CaseNarrativeContractError(
                "relationship list contains "
                "non-object record"
            )

        relationship_id = _require_text(
            record.get(
                "relationship_id"
            ),
            "relationship_id",
        )

        if relationship_id in result:
            raise CaseNarrativeContractError(
                "duplicate relationship ID"
            )

        result.add(
            relationship_id
        )

    return result


def create_case_narratives(
    *,
    findings: tuple[
        CaseFinding,
        ...,
    ],
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ],
    relationship_payload: dict[
        str,
        object,
    ],
    responses: tuple[
        CaseResponseRecord,
        ...,
    ],
) -> tuple[
    CaseNarrativeRecord,
    ...,
]:
    if not isinstance(
        findings,
        tuple,
    ):
        raise TypeError(
            "findings must be tuple"
        )

    if not isinstance(
        canonical_events,
        tuple,
    ):
        raise TypeError(
            "canonical_events must be tuple"
        )

    if not isinstance(
        responses,
        tuple,
    ):
        raise TypeError(
            "responses must be tuple"
        )

    event_by_id: dict[
        str,
        CanonicalEvent,
    ] = {}

    for event in canonical_events:
        if not isinstance(
            event,
            CanonicalEvent,
        ):
            raise TypeError(
                "canonical_events must contain "
                "CanonicalEvent"
            )

        if event.event_id in event_by_id:
            raise CaseNarrativeContractError(
                "duplicate canonical event ID"
            )

        event_by_id[
            event.event_id
        ] = event

    relationships = _relationship_ids(
        relationship_payload
    )

    response_by_finding: dict[
        str,
        CaseResponseRecord,
    ] = {}

    for response in responses:
        if not isinstance(
            response,
            CaseResponseRecord,
        ):
            raise TypeError(
                "responses must contain "
                "CaseResponseRecord"
            )

        if response.finding_id in response_by_finding:
            raise CaseNarrativeContractError(
                "multiple response records for "
                "one finding"
            )

        response_by_finding[
            response.finding_id
        ] = response

    records: list[
        CaseNarrativeRecord
    ] = []

    for finding in findings:
        if not isinstance(
            finding,
            CaseFinding,
        ):
            raise TypeError(
                "findings must contain CaseFinding"
            )

        if (
            finding.evidence_state
            is not EvidenceState.CORROBORATED
        ):
            raise CaseNarrativeContractError(
                "narrative requires a "
                "CORROBORATED finding"
            )

        missing_support = sorted(
            set(
                finding.supporting_relationship_ids
            )
            - relationships
        )

        missing_contradiction = sorted(
            set(
                finding.contradicting_relationship_ids
            )
            - relationships
        )

        if missing_support:
            raise CaseNarrativeContractError(
                "finding references missing "
                "supporting relationship: "
                + ",".join(
                    missing_support
                )
            )

        if missing_contradiction:
            raise CaseNarrativeContractError(
                "finding references missing "
                "contradicting relationship: "
                + ",".join(
                    missing_contradiction
                )
            )

        observation_records: list[
            NarrativeObservationCitation
        ] = []

        for event_id in finding.observation_ids:
            event = event_by_id.get(
                event_id
            )

            if event is None:
                raise CaseNarrativeContractError(
                    "finding references missing "
                    "observation: "
                    + event_id
                )

            observation_records.append(
                NarrativeObservationCitation.from_event(
                    event
                )
            )

        response = response_by_finding.get(
            finding.finding_id
        )

        if response is None:
            raise CaseNarrativeContractError(
                "finding has no response record: "
                + finding.finding_id
            )

        records.append(
            CaseNarrativeRecord(
                narrative_id=_narrative_id(
                    finding_id=(
                        finding.finding_id
                    ),
                    statement=(
                        finding.statement
                    ),
                ),
                finding_id=(
                    finding.finding_id
                ),
                hypothesis_id=(
                    finding.hypothesis_id
                ),
                statement=(
                    finding.statement
                ),
                rationale=(
                    finding.rationale
                ),
                alternative_or_falsifier=(
                    finding.alternative_or_falsifier
                ),
                detection_result_ids=(
                    finding.detection_result_ids
                ),
                supporting_relationship_ids=(
                    finding.supporting_relationship_ids
                ),
                contradicting_relationship_ids=(
                    finding.contradicting_relationship_ids
                ),
                observations=tuple(
                    sorted(
                        observation_records,
                        key=lambda item: (
                            item.event_id
                        ),
                    )
                ),
                incident_status=(
                    finding.incident_status.value
                ),
                malicious_intent_status=(
                    finding.malicious_intent_status.value
                ),
                response_id=(
                    response.response_id
                ),
                response_execution_status=(
                    response.execution_status
                ),
                response_actions_executed=(
                    response.response_actions_executed
                ),
                asset_owner_status=(
                    response.asset_owner_status
                ),
                current_isolation_state_status=(
                    response.current_isolation_state_status
                ),
                service_availability_status=(
                    response.service_availability_status
                ),
            )
        )

    by_id: dict[
        str,
        CaseNarrativeRecord,
    ] = {}

    for record in records:
        existing = by_id.get(
            record.narrative_id
        )

        if (
            existing is not None
            and existing != record
        ):
            raise CaseNarrativeContractError(
                "same narrative ID produced "
                "different content"
            )

        by_id[
            record.narrative_id
        ] = record

    return tuple(
        by_id[
            narrative_id
        ]
        for narrative_id
        in sorted(
            by_id
        )
    )
