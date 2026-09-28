from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from tracesoc.models import CanonicalEvent


class FindingState(StrEnum):
    CORROBORATED = "corroborated"


class Confidence(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    event_id: str
    source_type: str
    logical_source: str
    record_index: int
    line_number: int | None
    byte_offset: int | None
    byte_length: int | None
    raw_sha256: str

    @classmethod
    def from_canonical(
        cls,
        event: CanonicalEvent,
    ) -> "EvidenceReference":
        locator = event.provenance

        return cls(
            event_id=event.event_id,
            source_type=event.source_type.value,
            logical_source=locator.logical_source,
            record_index=locator.record_index,
            line_number=locator.line_number,
            byte_offset=locator.byte_offset,
            byte_length=locator.byte_length,
            raw_sha256=locator.raw_sha256,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source_type": self.source_type,
            "logical_source": self.logical_source,
            "record_index": self.record_index,
            "line_number": self.line_number,
            "byte_offset": self.byte_offset,
            "byte_length": self.byte_length,
            "raw_sha256": self.raw_sha256,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    title: str
    state: FindingState
    confidence: Confidence
    confidence_scope: str
    observed_facts: tuple[str, ...]
    inference: str
    alternative_explanation: str
    falsifier: str
    residual_risk: str
    business_impact: str
    decision_required: str
    recommended_action: str
    response_validation_status: str
    evidence: tuple[EvidenceReference, ...]
    detection_ids: tuple[str, ...]
    correlation_ids: tuple[str, ...]
    correlation_edge_ids: tuple[str, ...]
    malicious_intent_established: bool
    synthetic_fixture: bool

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("finding_id must not be empty")

        if not self.observed_facts:
            raise ValueError("finding requires observed facts")

        if not self.evidence:
            raise ValueError("finding requires evidence references")

        if not self.detection_ids:
            raise ValueError("finding requires detection IDs")

        if not self.correlation_ids:
            raise ValueError("finding requires correlation IDs")

        if not self.correlation_edge_ids:
            raise ValueError("finding requires correlation edge IDs")

        for value in (
            self.confidence_scope,
            self.inference,
            self.alternative_explanation,
            self.falsifier,
            self.residual_risk,
            self.business_impact,
            self.decision_required,
            self.recommended_action,
            self.response_validation_status,
        ):
            if not value.strip():
                raise ValueError(
                    "finding explanatory fields must not be empty"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "state": self.state.value,
            "confidence": self.confidence.value,
            "confidence_scope": self.confidence_scope,
            "observed_facts": list(self.observed_facts),
            "inference": self.inference,
            "alternative_explanation": self.alternative_explanation,
            "falsifier": self.falsifier,
            "residual_risk": self.residual_risk,
            "business_impact": self.business_impact,
            "decision_required": self.decision_required,
            "recommended_action": self.recommended_action,
            "response_validation_status": self.response_validation_status,
            "evidence": [
                item.to_dict()
                for item in self.evidence
            ],
            "detection_ids": list(self.detection_ids),
            "correlation_ids": list(self.correlation_ids),
            "correlation_edge_ids": list(
                self.correlation_edge_ids
            ),
            "malicious_intent_established": (
                self.malicious_intent_established
            ),
            "synthetic_fixture": self.synthetic_fixture,
        }