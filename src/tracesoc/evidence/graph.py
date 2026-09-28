from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from enum import StrEnum

from tracesoc.evidence.states import (
    EvidenceState,
)
from tracesoc.models import (
    ClockState,
)


ENTITY_IDENTITY_VERSION = 1
RELATIONSHIP_IDENTITY_VERSION = 1


class EntityKind(StrEnum):
    ARTIFACT = "ARTIFACT"
    OBSERVATION = "OBSERVATION"
    HOST = "HOST"
    PRINCIPAL = "PRINCIPAL"
    PROCESS = "PROCESS"
    SCRIPT = "SCRIPT"
    FILE = "FILE"
    MESSAGE = "MESSAGE"
    HASH = "HASH"
    IP = "IP"
    DOMAIN = "DOMAIN"
    ENDPOINT = "ENDPOINT"
    FLOW = "FLOW"
    REGISTRY = "REGISTRY"
    CONFIG = "CONFIG"
    DETECTION = "DETECTION"
    HYPOTHESIS = "HYPOTHESIS"
    FINDING = "FINDING"
    RESPONSE_ACTION = "RESPONSE_ACTION"


class RelationshipType(StrEnum):
    DERIVED_FROM = "DERIVED_FROM"
    OBSERVED_ON = "OBSERVED_ON"
    SENT_TO = "SENT_TO"
    CONTAINS_ATTACHMENT = "CONTAINS_ATTACHMENT"
    IDENTIFIED_BY_HASH = "IDENTIFIED_BY_HASH"
    EXECUTED = "EXECUTED"
    PARENT_OF = "PARENT_OF"
    INITIATED_CONNECTION = "INITIATED_CONNECTION"
    CONNECTED_TO = "CONNECTED_TO"
    RESOLVED_TO = "RESOLVED_TO"
    MODIFIED = "MODIFIED"
    CORROBORATES = "CORROBORATES"
    CONTRADICTS = "CONTRADICTS"
    SUPPORTS_HYPOTHESIS = "SUPPORTS_HYPOTHESIS"
    FALSIFIES_HYPOTHESIS = "FALSIFIES_HYPOTHESIS"


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
        raise ValueError(
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


def _identity_hash(
    prefix: str,
    payload: object,
) -> str:
    return (
        prefix
        + hashlib.sha256(
            _canonical_json(
                payload
            )
        ).hexdigest()
    )


def _normalize_pairs(
    value: tuple[
        tuple[
            str,
            str,
        ],
        ...,
    ],
    *,
    field_name: str,
    require_nonempty: bool,
) -> tuple[
    tuple[
        str,
        str,
    ],
    ...,
]:
    if not isinstance(
        value,
        tuple,
    ):
        raise TypeError(
            field_name
            + " must be tuple"
        )

    if (
        require_nonempty
        and not value
    ):
        raise ValueError(
            field_name
            + " must not be empty"
        )

    normalized: list[
        tuple[
            str,
            str,
        ]
    ] = []

    keys: set[str] = set()

    for item in value:
        if not (
            isinstance(
                item,
                tuple,
            )
            and len(
                item
            ) == 2
        ):
            raise TypeError(
                field_name
                + " entries must be two-item tuples"
            )

        key = _require_text(
            item[0],
            field_name
            + " key",
        )

        item_value = _require_text(
            item[1],
            field_name
            + " value",
        )

        if key in keys:
            raise ValueError(
                field_name
                + " contains duplicate key: "
                + key
            )

        keys.add(
            key
        )

        normalized.append(
            (
                key,
                item_value,
            )
        )

    return tuple(
        sorted(
            normalized
        )
    )


def _normalize_ids(
    value: tuple[
        str,
        ...,
    ],
    *,
    field_name: str,
    require_nonempty: bool,
) -> tuple[
    str,
    ...,
]:
    if not isinstance(
        value,
        tuple,
    ):
        raise TypeError(
            field_name
            + " must be tuple"
        )

    if (
        require_nonempty
        and not value
    ):
        raise ValueError(
            field_name
            + " must not be empty"
        )

    normalized = tuple(
        sorted(
            _require_text(
                item,
                field_name
                + " item",
            )
            for item
            in value
        )
    )

    if (
        len(
            set(
                normalized
            )
        )
        != len(
            normalized
        )
    ):
        raise ValueError(
            field_name
            + " must not contain duplicates"
        )

    return normalized


@dataclass(
    frozen=True,
    slots=True,
)
class Entity:
    entity_id: str
    kind: EntityKind

    identity_attributes: tuple[
        tuple[
            str,
            str,
        ],
        ...,
    ]

    display_name: str | None = None

    @classmethod
    def create(
        cls,
        *,
        kind: EntityKind,
        identity_attributes: tuple[
            tuple[
                str,
                str,
            ],
            ...,
        ],
        display_name: str | None = None,
    ) -> "Entity":
        if not isinstance(
            kind,
            EntityKind,
        ):
            raise TypeError(
                "kind must be EntityKind"
            )

        normalized_attributes = (
            _normalize_pairs(
                identity_attributes,
                field_name=(
                    "identity_attributes"
                ),
                require_nonempty=True,
            )
        )

        normalized_display = (
            None
            if display_name
            is None
            else _require_text(
                display_name,
                "display_name",
            )
        )

        entity_id = _identity_hash(
            "ent_",
            {
                "identity_version":
                    ENTITY_IDENTITY_VERSION,
                "kind":
                    kind.value,
                "identity_attributes":
                    normalized_attributes,
            },
        )

        return cls(
            entity_id=entity_id,
            kind=kind,
            identity_attributes=(
                normalized_attributes
            ),
            display_name=(
                normalized_display
            ),
        )

    def __post_init__(
        self,
    ) -> None:
        if not isinstance(
            self.kind,
            EntityKind,
        ):
            raise TypeError(
                "kind must be EntityKind"
            )

        normalized = (
            _normalize_pairs(
                self.identity_attributes,
                field_name=(
                    "identity_attributes"
                ),
                require_nonempty=True,
            )
        )

        if (
            normalized
            != self.identity_attributes
        ):
            raise ValueError(
                "identity_attributes must already "
                "be normalized and sorted"
            )

        expected = _identity_hash(
            "ent_",
            {
                "identity_version":
                    ENTITY_IDENTITY_VERSION,
                "kind":
                    self.kind.value,
                "identity_attributes":
                    self.identity_attributes,
            },
        )

        if (
            self.entity_id
            != expected
        ):
            raise ValueError(
                "entity_id does not match "
                "deterministic entity identity"
            )

        if (
            self.display_name
            is not None
            and self.display_name
            != self.display_name.strip()
        ):
            raise ValueError(
                "display_name must already be normalized"
            )

        if (
            self.display_name
            == ""
        ):
            raise ValueError(
                "display_name must not be blank"
            )

    def to_dict(
        self,
    ) -> dict[
        str,
        object,
    ]:
        return {
            "entity_id":
                self.entity_id,
            "kind":
                self.kind.value,
            "identity_attributes":
                {
                    key:
                        value
                    for key, value
                    in self.identity_attributes
                },
            "display_name":
                self.display_name,
        }


@dataclass(
    frozen=True,
    slots=True,
)
class RelationshipAnchor:
    anchor_type: str
    value: str
    temporal: bool = False

    def __post_init__(
        self,
    ) -> None:
        normalized_type = (
            _require_text(
                self.anchor_type,
                "anchor_type",
            )
        )

        normalized_value = (
            _require_text(
                self.value,
                "value",
            )
        )

        if (
            normalized_type
            != self.anchor_type
        ):
            raise ValueError(
                "anchor_type must already be normalized"
            )

        if (
            normalized_value
            != self.value
        ):
            raise ValueError(
                "anchor value must already be normalized"
            )

        if not isinstance(
            self.temporal,
            bool,
        ):
            raise TypeError(
                "temporal must be bool"
            )


@dataclass(
    frozen=True,
    slots=True,
)
class RelationshipTimeSupport:
    source_clock_state: ClockState
    target_clock_state: ClockState
    delta_seconds: float
    tolerance_seconds: float
    method: str

    def __post_init__(
        self,
    ) -> None:
        if not isinstance(
            self.source_clock_state,
            ClockState,
        ):
            raise TypeError(
                "source_clock_state must be ClockState"
            )

        if not isinstance(
            self.target_clock_state,
            ClockState,
        ):
            raise TypeError(
                "target_clock_state must be ClockState"
            )

        if isinstance(
            self.delta_seconds,
            bool,
        ) or not isinstance(
            self.delta_seconds,
            (
                int,
                float,
            ),
        ):
            raise TypeError(
                "delta_seconds must be numeric"
            )

        if isinstance(
            self.tolerance_seconds,
            bool,
        ) or not isinstance(
            self.tolerance_seconds,
            (
                int,
                float,
            ),
        ):
            raise TypeError(
                "tolerance_seconds must be numeric"
            )

        if not math.isfinite(
            float(
                self.delta_seconds
            )
        ):
            raise ValueError(
                "delta_seconds must be finite"
            )

        if not math.isfinite(
            float(
                self.tolerance_seconds
            )
        ):
            raise ValueError(
                "tolerance_seconds must be finite"
            )

        if (
            self.tolerance_seconds
            < 0
        ):
            raise ValueError(
                "tolerance_seconds must be nonnegative"
            )

        normalized_method = (
            _require_text(
                self.method,
                "method",
            )
        )

        if (
            normalized_method
            != self.method
        ):
            raise ValueError(
                "method must already be normalized"
            )


_ALLOWED_RELATIONSHIP_STATES = (
    EvidenceState.OBSERVED,
    EvidenceState.CONFIRMED,
    EvidenceState.CORROBORATED,
    EvidenceState.INFERRED,
)


@dataclass(
    frozen=True,
    slots=True,
)
class Relationship:
    relationship_id: str
    relationship_type: RelationshipType
    source_entity_id: str
    target_entity_id: str
    predicate_version: str

    supporting_ids: tuple[
        str,
        ...,
    ]

    anchors: tuple[
        RelationshipAnchor,
        ...,
    ]

    evidence_state: EvidenceState

    time_support: (
        RelationshipTimeSupport
        | None
    ) = None

    rationale: str | None = None

    alternative_or_falsifier: (
        str
        | None
    ) = None

    @classmethod
    def create(
        cls,
        *,
        relationship_type: RelationshipType,
        source_entity_id: str,
        target_entity_id: str,
        predicate_version: str,
        supporting_ids: tuple[
            str,
            ...,
        ],
        anchors: tuple[
            RelationshipAnchor,
            ...,
        ],
        evidence_state: EvidenceState,
        time_support: (
            RelationshipTimeSupport
            | None
        ) = None,
        rationale: str | None = None,
        alternative_or_falsifier: (
            str
            | None
        ) = None,
    ) -> "Relationship":
        if not isinstance(
            relationship_type,
            RelationshipType,
        ):
            raise TypeError(
                "relationship_type must be RelationshipType"
            )

        source = _require_text(
            source_entity_id,
            "source_entity_id",
        )

        target = _require_text(
            target_entity_id,
            "target_entity_id",
        )

        if not source.startswith(
            "ent_"
        ):
            raise ValueError(
                "source_entity_id must start with ent_"
            )

        if not target.startswith(
            "ent_"
        ):
            raise ValueError(
                "target_entity_id must start with ent_"
            )

        if source == target:
            raise ValueError(
                "self-referential relationships are not allowed"
            )

        predicate = (
            _require_text(
                predicate_version,
                "predicate_version",
            )
        )

        normalized_supporting_ids = (
            _normalize_ids(
                supporting_ids,
                field_name=(
                    "supporting_ids"
                ),
                require_nonempty=True,
            )
        )

        if not isinstance(
            anchors,
            tuple,
        ):
            raise TypeError(
                "anchors must be tuple"
            )

        if not anchors:
            raise ValueError(
                "anchors must not be empty"
            )

        for anchor in anchors:
            if not isinstance(
                anchor,
                RelationshipAnchor,
            ):
                raise TypeError(
                    "anchors must contain RelationshipAnchor"
                )

        normalized_anchors = tuple(
            sorted(
                anchors,
                key=lambda item: (
                    item.temporal,
                    item.anchor_type,
                    item.value,
                ),
            )
        )

        if len(
            set(
                normalized_anchors
            )
        ) != len(
            normalized_anchors
        ):
            raise ValueError(
                "anchors must not contain duplicates"
            )

        if not any(
            not anchor.temporal
            for anchor
            in normalized_anchors
        ):
            raise ValueError(
                "relationship requires at least "
                "one non-temporal anchor"
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
            not in _ALLOWED_RELATIONSHIP_STATES
        ):
            raise ValueError(
                "SEARCH_NOT_CLOSED and NOT_ESTABLISHED "
                "do not assert graph edges"
            )

        if (
            time_support
            is not None
            and not isinstance(
                time_support,
                RelationshipTimeSupport,
            )
        ):
            raise TypeError(
                "time_support must be "
                "RelationshipTimeSupport or None"
            )

        normalized_rationale = (
            None
            if rationale is None
            else _require_text(
                rationale,
                "rationale",
            )
        )

        if (
            evidence_state
            is EvidenceState.INFERRED
            and normalized_rationale
            is None
        ):
            raise ValueError(
                "INFERRED relationship requires rationale"
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

        relationship_id = (
            _identity_hash(
                "rel_",
                {
                    "identity_version":
                        RELATIONSHIP_IDENTITY_VERSION,
                    "relationship_type":
                        relationship_type.value,
                    "source_entity_id":
                        source,
                    "target_entity_id":
                        target,
                    "predicate_version":
                        predicate,
                },
            )
        )

        return cls(
            relationship_id=(
                relationship_id
            ),
            relationship_type=(
                relationship_type
            ),
            source_entity_id=(
                source
            ),
            target_entity_id=(
                target
            ),
            predicate_version=(
                predicate
            ),
            supporting_ids=(
                normalized_supporting_ids
            ),
            anchors=(
                normalized_anchors
            ),
            evidence_state=(
                evidence_state
            ),
            time_support=(
                time_support
            ),
            rationale=(
                normalized_rationale
            ),
            alternative_or_falsifier=(
                normalized_alternative
            ),
        )

    def __post_init__(
        self,
    ) -> None:
        if not isinstance(
            self.relationship_type,
            RelationshipType,
        ):
            raise TypeError(
                "relationship_type must be RelationshipType"
            )

        if not isinstance(
            self.evidence_state,
            EvidenceState,
        ):
            raise TypeError(
                "evidence_state must be EvidenceState"
            )

        expected = _identity_hash(
            "rel_",
            {
                "identity_version":
                    RELATIONSHIP_IDENTITY_VERSION,
                "relationship_type":
                    self.relationship_type.value,
                "source_entity_id":
                    self.source_entity_id,
                "target_entity_id":
                    self.target_entity_id,
                "predicate_version":
                    self.predicate_version,
            },
        )

        if (
            self.relationship_id
            != expected
        ):
            raise ValueError(
                "relationship_id does not match "
                "deterministic relationship identity"
            )

        if (
            tuple(
                sorted(
                    self.supporting_ids
                )
            )
            != self.supporting_ids
        ):
            raise ValueError(
                "supporting_ids must be sorted"
            )

        if (
            len(
                set(
                    self.supporting_ids
                )
            )
            != len(
                self.supporting_ids
            )
        ):
            raise ValueError(
                "supporting_ids must be unique"
            )

        if not self.supporting_ids:
            raise ValueError(
                "supporting_ids must not be empty"
            )

        if not self.anchors:
            raise ValueError(
                "anchors must not be empty"
            )

        if not any(
            not anchor.temporal
            for anchor
            in self.anchors
        ):
            raise ValueError(
                "relationship requires at least "
                "one non-temporal anchor"
            )

        if (
            self.evidence_state
            not in _ALLOWED_RELATIONSHIP_STATES
        ):
            raise ValueError(
                "relationship evidence_state "
                "does not assert an edge"
            )

        if (
            self.evidence_state
            is EvidenceState.INFERRED
            and self.rationale
            is None
        ):
            raise ValueError(
                "INFERRED relationship requires rationale"
            )

    def to_dict(
        self,
    ) -> dict[
        str,
        object,
    ]:
        return {
            "relationship_id":
                self.relationship_id,
            "relationship_type":
                self.relationship_type.value,
            "source_entity_id":
                self.source_entity_id,
            "target_entity_id":
                self.target_entity_id,
            "predicate_version":
                self.predicate_version,
            "supporting_ids":
                list(
                    self.supporting_ids
                ),
            "anchors":
                [
                    {
                        "anchor_type":
                            anchor.anchor_type,
                        "value":
                            anchor.value,
                        "temporal":
                            anchor.temporal,
                    }
                    for anchor
                    in self.anchors
                ],
            "evidence_state":
                self.evidence_state.value,
            "time_support":
                (
                    None
                    if self.time_support
                    is None
                    else {
                        "source_clock_state":
                            self.time_support.source_clock_state.value,
                        "target_clock_state":
                            self.time_support.target_clock_state.value,
                        "delta_seconds":
                            self.time_support.delta_seconds,
                        "tolerance_seconds":
                            self.time_support.tolerance_seconds,
                        "method":
                            self.time_support.method,
                    }
                ),
            "rationale":
                self.rationale,
            "alternative_or_falsifier":
                self.alternative_or_falsifier,
        }
