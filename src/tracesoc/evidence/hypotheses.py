from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from tracesoc.detection.models import (
    DetectionResult,
)
from tracesoc.evidence.graph import (
    Relationship,
    RelationshipType,
)
from tracesoc.evidence.states import (
    EvidenceState,
)


HYPOTHESIS_IDENTITY_VERSION = 1
DETECTION_RESULT_REFERENCE_VERSION = 1


class HypothesisContractError(
    ValueError
):
    pass


_ALLOWED_HYPOTHESIS_STATES = (
    EvidenceState.CORROBORATED,
    EvidenceState.INFERRED,
    EvidenceState.SEARCH_NOT_CLOSED,
    EvidenceState.NOT_ESTABLISHED,
)


_CONTRADICTION_TYPES = (
    RelationshipType.CONTRADICTS,
    RelationshipType.FALSIFIES_HYPOTHESIS,
)


def _require_text(
    value: str,
    field_name: str,
) -> str:
    if not isinstance(
        value,
        str,
    ):
        raise TypeError(
            field_name
            + " must be str"
        )

    normalized = value.strip()

    if not normalized:
        raise HypothesisContractError(
            field_name
            + " must not be blank"
        )

    return normalized


def _canonical_json(
    value: object,
) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    ).encode(
        "utf-8"
    )


def _hash_id(
    prefix: str,
    material: object,
) -> str:
    return (
        prefix
        + hashlib.sha256(
            _canonical_json(
                material
            )
        ).hexdigest()
    )


def _normalized_ids(
    values: tuple[
        str,
        ...,
    ],
    *,
    field_name: str,
) -> tuple[
    str,
    ...,
]:
    if not isinstance(
        values,
        tuple,
    ):
        raise TypeError(
            field_name
            + " must be tuple"
        )

    normalized = tuple(
        sorted(
            _require_text(
                value,
                field_name
                + " item",
            )
            for value
            in values
        )
    )

    if (
        len(
            normalized
        )
        != len(
            set(
                normalized
            )
        )
    ):
        raise HypothesisContractError(
            field_name
            + " must not contain duplicates"
        )

    return normalized


def detection_result_reference(
    result: DetectionResult,
) -> str:
    """
    Produce a deterministic reference to one concrete DetectionResult.

    Detector identity alone is insufficient because the same detector may
    evaluate many observations. Contributing event IDs therefore form part
    of the result reference while fixture names, paths, labels and expected
    answers do not.
    """

    if not isinstance(
        result,
        DetectionResult,
    ):
        raise TypeError(
            "result must be DetectionResult"
        )

    contributing = tuple(
        sorted(
            result.contributing_event_ids
        )
    )

    return _hash_id(
        "detres_",
        {
            "reference_version":
                DETECTION_RESULT_REFERENCE_VERSION,
            "detection_id":
                result.detection_id,
            "detection_version":
                result.detection_version,
            "state":
                result.state.value,
            "reason_code":
                result.reason_code,
            "contributing_event_ids":
                contributing,
        },
    )


@dataclass(
    frozen=True,
    slots=True,
)
class Hypothesis:
    hypothesis_id: str
    hypothesis_key: str
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

    rationale: str | None = None

    alternative_or_falsifier: (
        str
        | None
    ) = None

    @classmethod
    def create(
        cls,
        *,
        hypothesis_key: str,
        statement: str,
        evidence_state: EvidenceState,
        detections: tuple[
            DetectionResult,
            ...,
        ] = (),
        supporting_relationships: tuple[
            Relationship,
            ...,
        ] = (),
        contradicting_relationships: tuple[
            Relationship,
            ...,
        ] = (),
        observation_ids: tuple[
            str,
            ...,
        ] = (),
        rationale: str | None = None,
        alternative_or_falsifier: (
            str
            | None
        ) = None,
    ) -> "Hypothesis":
        key = _require_text(
            hypothesis_key,
            "hypothesis_key",
        )

        normalized_statement = (
            _require_text(
                statement,
                "statement",
            )
        )

        if not isinstance(
            evidence_state,
            EvidenceState,
        ):
            raise TypeError(
                "evidence_state must be EvidenceState"
            )

        if (
            evidence_state
            not in _ALLOWED_HYPOTHESIS_STATES
        ):
            raise HypothesisContractError(
                "hypothesis state must be one of "
                "CORROBORATED, INFERRED, "
                "SEARCH_NOT_CLOSED, or NOT_ESTABLISHED"
            )

        if not isinstance(
            detections,
            tuple,
        ):
            raise TypeError(
                "detections must be tuple"
            )

        detection_refs: list[
            str
        ] = []

        for result in detections:
            if not isinstance(
                result,
                DetectionResult,
            ):
                raise TypeError(
                    "detections must contain DetectionResult"
                )

            if not result.matched:
                raise HypothesisContractError(
                    "NO_MATCH detection cannot support a hypothesis"
                )

            detection_refs.append(
                detection_result_reference(
                    result
                )
            )

        normalized_detection_refs = (
            _normalized_ids(
                tuple(
                    detection_refs
                ),
                field_name=(
                    "detection_result_ids"
                ),
            )
        )

        if not isinstance(
            supporting_relationships,
            tuple,
        ):
            raise TypeError(
                "supporting_relationships must be tuple"
            )

        supporting_ids: list[
            str
        ] = []

        for relationship in (
            supporting_relationships
        ):
            if not isinstance(
                relationship,
                Relationship,
            ):
                raise TypeError(
                    "supporting_relationships must "
                    "contain Relationship"
                )

            if (
                relationship.relationship_type
                in _CONTRADICTION_TYPES
            ):
                raise HypothesisContractError(
                    "contradiction relationship cannot "
                    "be supplied as supporting evidence"
                )

            supporting_ids.append(
                relationship.relationship_id
            )

        normalized_supporting_ids = (
            _normalized_ids(
                tuple(
                    supporting_ids
                ),
                field_name=(
                    "supporting_relationship_ids"
                ),
            )
        )

        if not isinstance(
            contradicting_relationships,
            tuple,
        ):
            raise TypeError(
                "contradicting_relationships must be tuple"
            )

        contradiction_ids: list[
            str
        ] = []

        for relationship in (
            contradicting_relationships
        ):
            if not isinstance(
                relationship,
                Relationship,
            ):
                raise TypeError(
                    "contradicting_relationships must "
                    "contain Relationship"
                )

            if (
                relationship.relationship_type
                not in _CONTRADICTION_TYPES
            ):
                raise HypothesisContractError(
                    "contradicting evidence requires "
                    "CONTRADICTS or FALSIFIES_HYPOTHESIS"
                )

            contradiction_ids.append(
                relationship.relationship_id
            )

        normalized_contradiction_ids = (
            _normalized_ids(
                tuple(
                    contradiction_ids
                ),
                field_name=(
                    "contradicting_relationship_ids"
                ),
            )
        )

        if (
            set(
                normalized_supporting_ids
            )
            & set(
                normalized_contradiction_ids
            )
        ):
            raise HypothesisContractError(
                "same relationship cannot be both "
                "supporting and contradicting"
            )

        normalized_observation_ids = (
            _normalized_ids(
                observation_ids,
                field_name=(
                    "observation_ids"
                ),
            )
        )

        normalized_rationale = (
            None
            if rationale is None
            else _require_text(
                rationale,
                "rationale",
            )
        )

        normalized_alternative = (
            None
            if alternative_or_falsifier
            is None
            else _require_text(
                alternative_or_falsifier,
                "alternative_or_falsifier",
            )
        )

        positive_support_count = (
            len(
                normalized_detection_refs
            )
            + len(
                normalized_supporting_ids
            )
            + len(
                normalized_observation_ids
            )
        )

        if (
            evidence_state
            is EvidenceState.CORROBORATED
        ):
            if not normalized_detection_refs:
                raise HypothesisContractError(
                    "CORROBORATED hypothesis requires "
                    "at least one matched detection"
                )

            if not normalized_supporting_ids:
                raise HypothesisContractError(
                    "CORROBORATED hypothesis requires "
                    "at least one supporting relationship"
                )

        if (
            evidence_state
            is EvidenceState.INFERRED
        ):
            if positive_support_count == 0:
                raise HypothesisContractError(
                    "INFERRED hypothesis requires "
                    "supporting evidence"
                )

            if normalized_rationale is None:
                raise HypothesisContractError(
                    "INFERRED hypothesis requires rationale"
                )

            if normalized_alternative is None:
                raise HypothesisContractError(
                    "INFERRED hypothesis requires an "
                    "alternative or falsifier"
                )

        if (
            evidence_state
            in (
                EvidenceState.SEARCH_NOT_CLOSED,
                EvidenceState.NOT_ESTABLISHED,
            )
            and normalized_rationale is None
        ):
            raise HypothesisContractError(
                evidence_state.value
                + " hypothesis requires rationale"
            )

        if (
            normalized_contradiction_ids
            and normalized_rationale is None
        ):
            raise HypothesisContractError(
                "hypothesis with contradictory evidence "
                "requires rationale"
            )

        hypothesis_id = _hash_id(
            "hyp_",
            {
                "identity_version":
                    HYPOTHESIS_IDENTITY_VERSION,
                "hypothesis_key":
                    key,
                "statement":
                    normalized_statement,
            },
        )

        return cls(
            hypothesis_id=(
                hypothesis_id
            ),
            hypothesis_key=(
                key
            ),
            statement=(
                normalized_statement
            ),
            evidence_state=(
                evidence_state
            ),
            detection_result_ids=(
                normalized_detection_refs
            ),
            supporting_relationship_ids=(
                normalized_supporting_ids
            ),
            contradicting_relationship_ids=(
                normalized_contradiction_ids
            ),
            observation_ids=(
                normalized_observation_ids
            ),
            rationale=(
                normalized_rationale
            ),
            alternative_or_falsifier=(
                normalized_alternative
            ),
        )

    @property
    def positive_support_ids(
        self,
    ) -> tuple[
        str,
        ...,
    ]:
        return tuple(
            sorted(
                self.detection_result_ids
                + self.supporting_relationship_ids
                + self.observation_ids
            )
        )

    @property
    def has_contradiction(
        self,
    ) -> bool:
        return bool(
            self.contradicting_relationship_ids
        )

    def to_dict(
        self,
    ) -> dict[
        str,
        object,
    ]:
        return {
            "hypothesis_id":
                self.hypothesis_id,
            "hypothesis_key":
                self.hypothesis_key,
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
        }
