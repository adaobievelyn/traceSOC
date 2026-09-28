from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DetectionState(StrEnum):
    MATCH = "match"
    NO_MATCH = "no_match"


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """
    Result of evaluating one detector.

    A DetectionResult is not an incident verdict.

    MATCH means only that the detector's explicitly documented behavioral
    conditions were satisfied.
    """

    detection_id: str
    detection_version: str
    title: str
    state: DetectionState
    reason_code: str
    rationale: str
    contributing_event_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.detection_id.strip():
            raise ValueError("detection_id must not be empty")

        if not self.detection_version.strip():
            raise ValueError("detection_version must not be empty")

        if not self.title.strip():
            raise ValueError("title must not be empty")

        if not self.reason_code.strip():
            raise ValueError("reason_code must not be empty")

        if not self.rationale.strip():
            raise ValueError("rationale must not be empty")

        if self.state == DetectionState.MATCH:
            if not self.contributing_event_ids:
                raise ValueError(
                    "matched detections require contributing event IDs"
                )

        if self.state == DetectionState.NO_MATCH:
            if self.contributing_event_ids:
                raise ValueError(
                    "non-matches must not claim contributing event IDs"
                )

    @property
    def matched(self) -> bool:
        return self.state == DetectionState.MATCH