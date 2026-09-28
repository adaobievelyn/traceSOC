from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class EvidenceState(StrEnum):
    OBSERVED = "OBSERVED"
    CONFIRMED = "CONFIRMED"
    CORROBORATED = "CORROBORATED"
    INFERRED = "INFERRED"
    SEARCH_NOT_CLOSED = "SEARCH_NOT_CLOSED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"


_SUPPORT_REQUIRED_STATES = frozenset(
    {
        EvidenceState.OBSERVED,
        EvidenceState.CONFIRMED,
        EvidenceState.CORROBORATED,
        EvidenceState.INFERRED,
    }
)

_RATIONALE_REQUIRED_STATES = frozenset(
    {
        EvidenceState.INFERRED,
        EvidenceState.SEARCH_NOT_CLOSED,
        EvidenceState.NOT_ESTABLISHED,
    }
)


def _required_text(
    value: object,
    *,
    field: str,
) -> str:
    if value is None:
        raise ValueError(
            f"{field} must not be missing"
        )

    if not isinstance(value, str):
        raise TypeError(
            f"{field} must be a string"
        )

    cleaned = value.strip()

    if not cleaned:
        raise ValueError(
            f"{field} must not be empty"
        )

    return cleaned


def _optional_text(
    value: object,
    *,
    field: str,
) -> str | None:
    if value is None:
        return None

    return _required_text(
        value,
        field=field,
    )


def _validated_supporting_ids(
    value: object,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise TypeError(
            "supporting_ids must be a tuple"
        )

    normalized = tuple(
        _required_text(
            item,
            field="supporting_id",
        )
        for item in value
    )

    if len(set(normalized)) != len(
        normalized
    ):
        raise ValueError(
            "supporting_ids must be unique"
        )

    return tuple(
        sorted(normalized)
    )


@dataclass(
    frozen=True,
    slots=True,
)
class EvidenceAssertion:
    statement: str
    state: EvidenceState
    supporting_ids: tuple[str, ...] = ()
    rationale: str | None = None

    def __post_init__(
        self,
    ) -> None:
        statement = _required_text(
            self.statement,
            field="statement",
        )

        if not isinstance(
            self.state,
            EvidenceState,
        ):
            raise TypeError(
                "state must be EvidenceState"
            )

        supporting_ids = (
            _validated_supporting_ids(
                self.supporting_ids
            )
        )

        rationale = _optional_text(
            self.rationale,
            field="rationale",
        )

        if (
            self.state
            in _SUPPORT_REQUIRED_STATES
            and not supporting_ids
        ):
            raise ValueError(
                f"{self.state.value} requires at least one supporting ID"
            )

        if (
            self.state
            in _RATIONALE_REQUIRED_STATES
            and rationale is None
        ):
            raise ValueError(
                f"{self.state.value} requires rationale"
            )

        object.__setattr__(
            self,
            "statement",
            statement,
        )

        object.__setattr__(
            self,
            "supporting_ids",
            supporting_ids,
        )

        object.__setattr__(
            self,
            "rationale",
            rationale,
        )

    def to_dict(
        self,
    ) -> dict[str, object]:
        return {
            "statement":
                self.statement,
            "state":
                self.state.value,
            "supporting_ids":
                list(
                    self.supporting_ids
                ),
            "rationale":
                self.rationale,
        }
