from __future__ import annotations

from dataclasses import dataclass
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
from tracesoc.response.sandbox import (
    HostIsolationSession,
)


RESPONSE_RECORD_SCHEMA_ID = (
    "tracesoc-case-response-record-v1"
)

RESPONSE_IDENTITY_VERSION = "1"

EXECUTION_MODE = "CASE_PLAN_ONLY"
EXECUTION_STATUS = "NOT_EXECUTED"

TARGET_ESTABLISHED = "ESTABLISHED"
TARGET_NOT_ESTABLISHED = "NOT_ESTABLISHED"


class CaseResponseContractError(
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
        raise CaseResponseContractError(
            field
            + " must be text"
        )

    candidate = value.strip()

    if not candidate:
        raise CaseResponseContractError(
            field
            + " must not be empty"
        )

    return candidate


def _response_id(
    *,
    finding_id: str,
    target_host: str | None,
) -> str:
    material = {
        "identity_version":
            RESPONSE_IDENTITY_VERSION,

        "finding_id":
            finding_id,

        "action_type":
            HostIsolationSession.ACTION_TYPE,

        "target_host":
            target_host,
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
        "resp_"
        + hashlib.sha256(
            encoded
        ).hexdigest()
    )


def _finding_host(
    *,
    finding: CaseFinding,
    events_by_id: dict[
        str,
        CanonicalEvent,
    ],
) -> tuple[
    str | None,
    str,
]:
    observed_hosts: list[
        str
    ] = []

    for observation_id in (
        finding.observation_ids
    ):
        event = events_by_id.get(
            observation_id
        )

        if event is None:
            raise CaseResponseContractError(
                "finding observation is absent from "
                "the canonical case stream: "
                + observation_id
            )

        host = event.host

        if not isinstance(
            host,
            str,
        ):
            continue

        candidate = host.strip()

        if candidate:
            observed_hosts.append(
                candidate
            )

    by_casefold: dict[
        str,
        set[
            str
        ],
    ] = {}

    for host in observed_hosts:
        by_casefold.setdefault(
            host.casefold(),
            set(),
        ).add(
            host
        )

    if not by_casefold:
        return (
            None,
            (
                "OBSERVATION_HOST_NOT_ESTABLISHED"
            ),
        )

    if len(
        by_casefold
    ) != 1:
        return (
            None,
            (
                "CONFLICTING_OBSERVATION_HOSTS"
            ),
        )

    variants = next(
        iter(
            by_casefold.values()
        )
    )

    target_host = sorted(
        variants,
        key=lambda value: (
            value.casefold(),
            value,
        ),
    )[0]

    return (
        target_host,
        "OBSERVATION_HOST_ESTABLISHED",
    )


@dataclass(
    frozen=True,
    slots=True,
)
class CaseResponseRecord:
    response_id: str
    finding_id: str

    action_type: str
    execution_mode: str
    execution_status: str

    target_host: str | None
    target_status: str
    target_reason: str

    asset_owner_status: str
    current_isolation_state_status: str
    service_availability_status: str

    response_actions_executed: bool
    safe_by_default: bool
    evidence_preservation_required: bool

    rationale: str

    def __post_init__(
        self,
    ) -> None:
        _require_text(
            self.response_id,
            "response_id",
        )

        _require_text(
            self.finding_id,
            "finding_id",
        )

        if (
            self.action_type
            != HostIsolationSession.ACTION_TYPE
        ):
            raise CaseResponseContractError(
                "unsupported response action type"
            )

        if (
            self.execution_mode
            != EXECUTION_MODE
        ):
            raise CaseResponseContractError(
                "case response must be plan-only"
            )

        if (
            self.execution_status
            != EXECUTION_STATUS
        ):
            raise CaseResponseContractError(
                "case response must not claim execution"
            )

        if self.target_status not in {
            TARGET_ESTABLISHED,
            TARGET_NOT_ESTABLISHED,
        }:
            raise CaseResponseContractError(
                "invalid target status"
            )

        if (
            self.target_status
            == TARGET_ESTABLISHED
        ):
            _require_text(
                self.target_host,
                "target_host",
            )

        elif self.target_host is not None:
            raise CaseResponseContractError(
                "unestablished target must not "
                "contain a target host"
            )

        if self.response_actions_executed:
            raise CaseResponseContractError(
                "case analysis must not execute "
                "response actions"
            )

        if not self.safe_by_default:
            raise CaseResponseContractError(
                "case response must be safe by default"
            )

        if not self.evidence_preservation_required:
            raise CaseResponseContractError(
                "evidence preservation must be required"
            )

        _require_text(
            self.target_reason,
            "target_reason",
        )

        _require_text(
            self.rationale,
            "rationale",
        )

    def to_dict(
        self,
    ) -> dict[
        str,
        object,
    ]:
        return {
            "record_schema_id":
                RESPONSE_RECORD_SCHEMA_ID,

            "response_id":
                self.response_id,

            "finding_id":
                self.finding_id,

            "action_type":
                self.action_type,

            "execution_mode":
                self.execution_mode,

            "execution_status":
                self.execution_status,

            "target": {
                "host":
                    self.target_host,

                "status":
                    self.target_status,

                "reason":
                    self.target_reason,

                "asset_owner_status":
                    self.asset_owner_status,

                "current_isolation_state_status":
                    self.current_isolation_state_status,

                "service_availability_status":
                    self.service_availability_status,
            },

            "sandbox_contract": {
                "implementation":
                    (
                        "tracesoc.response.sandbox."
                        "HostIsolationSession"
                    ),

                "action_type":
                    HostIsolationSession.ACTION_TYPE,

                "execution_mode":
                    "SIMULATED_LOCAL_STATE",

                "lifecycle": [
                    "PRECONDITION",
                    "DRY_RUN",
                    "ACTION",
                    "VERIFY",
                    "ROLLBACK",
                    "VERIFY_ROLLBACK",
                ],

                "safe_by_default":
                    True,

                "evidence_preservation_required":
                    True,
            },

            "preconditions": [
                {
                    "name":
                        "CORROBORATED_FINDING",

                    "status":
                        "PASS",
                },
                {
                    "name":
                        "TARGET_HOST",

                    "status":
                        (
                            "PASS"
                            if self.target_status
                            == TARGET_ESTABLISHED
                            else "NOT_ESTABLISHED"
                        ),

                    "reason":
                        self.target_reason,
                },
                {
                    "name":
                        "TARGET_STATE_SNAPSHOT",

                    "status":
                        "NOT_EVALUATED",

                    "reason":
                        (
                            "Case analysis does not invent "
                            "current isolation or service state."
                        ),
                },
                {
                    "name":
                        "EVIDENCE_PRESERVATION",

                    "status":
                        "REQUIRED",
                },
                {
                    "name":
                        "OPERATOR_AUTHORIZATION",

                    "status":
                        "REQUIRED",
                },
            ],

            "dry_run": {
                "status":
                    "NOT_EXECUTED",

                "reason":
                    (
                        "Case analysis emits a plan only. "
                        "HostIsolationSession.dry_run() "
                        "requires an explicit sandbox "
                        "target-state snapshot."
                    ),

                "target_mutated":
                    False,
            },

            "verification": {
                "status":
                    "NOT_EXECUTED",

                "criteria": [
                    (
                        "Observed simulated state must "
                        "equal the intended isolated state."
                    ),
                    (
                        "Evidence preservation must remain "
                        "true."
                    ),
                    (
                        "Any verification mismatch requires "
                        "rollback."
                    ),
                ],
            },

            "rollback": {
                "status":
                    "NOT_EXECUTED",

                "required":
                    True,

                "objective":
                    (
                        "Restore the exact pre-action "
                        "target-state snapshot."
                    ),

                "verification_required":
                    True,

                "verification_criterion":
                    (
                        "State content and state SHA-256 "
                        "must equal the pre-action snapshot."
                    ),
            },

            "business_tradeoff": {
                "service_impact":
                    "NOT_ESTABLISHED",

                "statement":
                    (
                        "Host isolation may interrupt "
                        "service availability. Actual "
                        "business impact is not established "
                        "by the case evidence."
                    ),
            },

            "residual_risk": {
                "status":
                    "NOT_ESTABLISHED",

                "statement":
                    (
                        "Asset owner, current target state, "
                        "service dependency, and operational "
                        "impact require external validation "
                        "before execution."
                    ),
            },

            "response_actions_executed":
                self.response_actions_executed,

            "safe_by_default":
                self.safe_by_default,

            "evidence_preservation_required":
                self.evidence_preservation_required,

            "rationale":
                self.rationale,
        }


def create_case_response_records(
    *,
    findings: tuple[
        CaseFinding,
        ...,
    ],
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ],
) -> tuple[
    CaseResponseRecord,
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

    events_by_id: dict[
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

        if event.event_id in events_by_id:
            raise CaseResponseContractError(
                "duplicate canonical event ID"
            )

        events_by_id[
            event.event_id
        ] = event

    records: list[
        CaseResponseRecord
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
            raise CaseResponseContractError(
                "case response requires a "
                "CORROBORATED finding"
            )

        (
            target_host,
            target_reason,
        ) = _finding_host(
            finding=finding,
            events_by_id=events_by_id,
        )

        target_status = (
            TARGET_ESTABLISHED
            if target_host is not None
            else TARGET_NOT_ESTABLISHED
        )

        rationale = (
            "Response planning is derived from "
            "corroborated finding "
            + finding.finding_id
            + ". The supported host-isolation "
            "lifecycle is exposed for controlled "
            "sandbox validation, but case analysis "
            "does not execute response actions or "
            "fabricate target state."
        )

        records.append(
            CaseResponseRecord(
                response_id=_response_id(
                    finding_id=(
                        finding.finding_id
                    ),
                    target_host=(
                        target_host
                    ),
                ),
                finding_id=(
                    finding.finding_id
                ),
                action_type=(
                    HostIsolationSession.ACTION_TYPE
                ),
                execution_mode=(
                    EXECUTION_MODE
                ),
                execution_status=(
                    EXECUTION_STATUS
                ),
                target_host=(
                    target_host
                ),
                target_status=(
                    target_status
                ),
                target_reason=(
                    target_reason
                ),
                asset_owner_status=(
                    "NOT_ESTABLISHED"
                ),
                current_isolation_state_status=(
                    "NOT_ESTABLISHED"
                ),
                service_availability_status=(
                    "NOT_ESTABLISHED"
                ),
                response_actions_executed=(
                    False
                ),
                safe_by_default=(
                    True
                ),
                evidence_preservation_required=(
                    True
                ),
                rationale=rationale,
            )
        )

    by_id: dict[
        str,
        CaseResponseRecord,
    ] = {}

    for record in records:
        existing = by_id.get(
            record.response_id
        )

        if (
            existing is not None
            and existing != record
        ):
            raise CaseResponseContractError(
                "same response ID produced "
                "different content"
            )

        by_id[
            record.response_id
        ] = record

    return tuple(
        by_id[
            response_id
        ]
        for response_id
        in sorted(
            by_id
        )
    )
