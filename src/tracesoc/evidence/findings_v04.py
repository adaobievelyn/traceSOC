from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from tracesoc.evidence.hypotheses import (
    Hypothesis,
)
from tracesoc.evidence.states import (
    EvidenceState,
)


FINDING_IDENTITY_VERSION = 1


class CaseFindingContractError(
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
        raise CaseFindingContractError(
            field
            + " must be text"
        )

    candidate = value.strip()

    if not candidate:
        raise CaseFindingContractError(
            field
            + " must not be empty"
        )

    return candidate


def _normalized_ids(
    values: tuple[
        str,
        ...,
    ],
    *,
    field: str,
) -> tuple[
    str,
    ...,
]:
    if not isinstance(
        values,
        tuple,
    ):
        raise CaseFindingContractError(
            field
            + " must be tuple"
        )

    normalized = tuple(
        sorted(
            {
                _require_text(
                    value,
                    field,
                )
                for value
                in values
            }
        )
    )

    return normalized


def _finding_id(
    *,
    hypothesis_id: str,
    statement: str,
) -> str:
    material = {
        "identity_version":
            FINDING_IDENTITY_VERSION,

        "hypothesis_id":
            hypothesis_id,

        "statement":
            statement,
    }

    encoded = json.dumps(
        material,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode(
        "ascii"
    )

    return (
        "fnd_"
        + hashlib.sha256(
            encoded
        ).hexdigest()
    )


@dataclass(
    frozen=True,
    slots=True,
)
class CaseFinding:
    finding_id: str
    hypothesis_id: str
    statement: str
    evidence_state: EvidenceState

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

    observation_ids: tuple[
        str,
        ...,
    ]

    rationale: str
    alternative_or_falsifier: str

    incident_status: EvidenceState
    malicious_intent_status: EvidenceState

    @classmethod
    def from_hypothesis(
        cls,
        hypothesis: Hypothesis,
    ) -> "CaseFinding":
        if not isinstance(
            hypothesis,
            Hypothesis,
        ):
            raise TypeError(
                "hypothesis must be Hypothesis"
            )

        if (
            hypothesis.evidence_state
            is not EvidenceState.CORROBORATED
        ):
            raise CaseFindingContractError(
                "v0.4 case finding requires a "
                "CORROBORATED hypothesis"
            )

        hypothesis_id = _require_text(
            hypothesis.hypothesis_id,
            "hypothesis_id",
        )

        statement = _require_text(
            hypothesis.statement,
            "statement",
        )

        detection_ids = (
            _normalized_ids(
                hypothesis.detection_result_ids,
                field=(
                    "detection_result_ids"
                ),
            )
        )

        relationship_ids = (
            _normalized_ids(
                hypothesis.supporting_relationship_ids,
                field=(
                    "supporting_relationship_ids"
                ),
            )
        )

        contradiction_ids = (
            _normalized_ids(
                hypothesis.contradicting_relationship_ids,
                field=(
                    "contradicting_relationship_ids"
                ),
            )
        )

        observation_ids = (
            _normalized_ids(
                hypothesis.observation_ids,
                field=(
                    "observation_ids"
                ),
            )
        )

        if not detection_ids:
            raise CaseFindingContractError(
                "case finding requires a concrete "
                "matched detection result reference"
            )

        if not relationship_ids:
            raise CaseFindingContractError(
                "case finding requires a supporting "
                "relationship"
            )

        if not observation_ids:
            raise CaseFindingContractError(
                "case finding requires source "
                "observation lineage"
            )

        if (
            set(
                relationship_ids
            )
            & set(
                contradiction_ids
            )
        ):
            raise CaseFindingContractError(
                "same relationship cannot both "
                "support and contradict a finding"
            )

        rationale = _require_text(
            hypothesis.rationale,
            "rationale",
        )

        alternative = _require_text(
            hypothesis.alternative_or_falsifier,
            "alternative_or_falsifier",
        )

        finding_id = _finding_id(
            hypothesis_id=(
                hypothesis_id
            ),
            statement=(
                statement
            ),
        )

        return cls(
            finding_id=finding_id,
            hypothesis_id=(
                hypothesis_id
            ),
            statement=statement,
            evidence_state=(
                EvidenceState.CORROBORATED
            ),
            detection_result_ids=(
                detection_ids
            ),
            supporting_relationship_ids=(
                relationship_ids
            ),
            contradicting_relationship_ids=(
                contradiction_ids
            ),
            observation_ids=(
                observation_ids
            ),
            rationale=rationale,
            alternative_or_falsifier=(
                alternative
            ),
            incident_status=(
                EvidenceState.NOT_ESTABLISHED
            ),
            malicious_intent_status=(
                EvidenceState.NOT_ESTABLISHED
            ),
        )

    def to_dict(
        self,
    ) -> dict[
        str,
        object,
    ]:
        return {
            "finding_id":
                self.finding_id,

            "hypothesis_id":
                self.hypothesis_id,

            "statement":
                self.statement,

            "evidence_state":
                self.evidence_state.value,

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

            "observation_ids":
                list(
                    self.observation_ids
                ),

            "rationale":
                self.rationale,

            "alternative_or_falsifier":
                self.alternative_or_falsifier,

            "incident_status":
                self.incident_status.value,

            "malicious_intent_status":
                self.malicious_intent_status.value,
        }


def create_case_findings(
    hypotheses: tuple[
        Hypothesis,
        ...,
    ],
) -> tuple[
    CaseFinding,
    ...,
]:
    if not isinstance(
        hypotheses,
        tuple,
    ):
        raise TypeError(
            "hypotheses must be tuple"
        )

    findings: list[
        CaseFinding
    ] = []

    for hypothesis in hypotheses:
        if not isinstance(
            hypothesis,
            Hypothesis,
        ):
            raise TypeError(
                "hypotheses must contain Hypothesis"
            )

        if (
            hypothesis.evidence_state
            is not EvidenceState.CORROBORATED
        ):
            continue

        findings.append(
            CaseFinding.from_hypothesis(
                hypothesis
            )
        )

    by_id: dict[
        str,
        CaseFinding,
    ] = {}

    for finding in findings:
        existing = by_id.get(
            finding.finding_id
        )

        if (
            existing is not None
            and existing != finding
        ):
            raise CaseFindingContractError(
                "same finding ID produced "
                "different content"
            )

        by_id[
            finding.finding_id
        ] = finding

    return tuple(
        by_id[
            finding_id
        ]
        for finding_id
        in sorted(
            by_id
        )
    )
