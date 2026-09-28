from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CorrelationState(StrEnum):
    MATCH = "match"
    NO_MATCH = "no_match"


@dataclass(frozen=True, slots=True)
class CorrelationEdge:
    correlation_id: str
    correlation_version: str
    edge_id: str
    relationship: str
    source_event_id: str
    target_event_id: str
    delta_seconds: float
    destination_ip: str
    destination_port: int
    matched_dimensions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.correlation_id.strip():
            raise ValueError("correlation_id must not be empty")

        if not self.edge_id.strip():
            raise ValueError("edge_id must not be empty")

        if not self.relationship.strip():
            raise ValueError("relationship must not be empty")

        if not self.source_event_id.strip():
            raise ValueError("source_event_id must not be empty")

        if not self.target_event_id.strip():
            raise ValueError("target_event_id must not be empty")

        if self.delta_seconds < 0:
            raise ValueError("delta_seconds must not be negative")

        if not self.destination_ip.strip():
            raise ValueError("destination_ip must not be empty")

        if self.destination_port < 1 or self.destination_port > 65535:
            raise ValueError("destination_port must be between 1 and 65535")

        if not self.matched_dimensions:
            raise ValueError("matched_dimensions must not be empty")


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    correlation_id: str
    correlation_version: str
    state: CorrelationState
    reason_code: str
    rationale: str
    edge: CorrelationEdge | None

    @property
    def matched(self) -> bool:
        return self.state == CorrelationState.MATCH

    def __post_init__(self) -> None:
        if self.state == CorrelationState.MATCH and self.edge is None:
            raise ValueError("matched correlation requires an edge")

        if self.state == CorrelationState.NO_MATCH and self.edge is not None:
            raise ValueError("non-match must not contain an edge")