from __future__ import annotations

from collections.abc import Mapping

from tracesoc.correlation.models import CorrelationResult
from tracesoc.detection.models import DetectionResult
from tracesoc.findings.models import (
    Confidence,
    EvidenceReference,
    Finding,
    FindingState,
)
from tracesoc.models import CanonicalEvent


FINDING_ID = "FINDING-001"


def build_finding_001(
    *,
    detection: DetectionResult,
    correlation: CorrelationResult,
    canonical_events: Mapping[str, CanonicalEvent],
) -> Finding:
    if not detection.matched:
        raise ValueError(
            "FINDING-001 requires a matched detection"
        )

    if not correlation.matched or correlation.edge is None:
        raise ValueError(
            "FINDING-001 requires a matched correlation"
        )

    edge = correlation.edge

    required_event_ids = (
        edge.source_event_id,
        edge.target_event_id,
    )

    missing = [
        event_id
        for event_id in required_event_ids
        if event_id not in canonical_events
    ]

    if missing:
        raise ValueError(
            "canonical evidence missing for correlated event IDs"
        )

    source_event = canonical_events[
        edge.source_event_id
    ]

    target_event = canonical_events[
        edge.target_event_id
    ]

    evidence = (
        EvidenceReference.from_canonical(
            source_event
        ),
        EvidenceReference.from_canonical(
            target_event
        ),
    )

    observed_facts = (
        (
            "A PowerShell semantic event satisfied TRC-DET-001: "
            "recognized web-retrieval behavior was observed."
        ),
        (
            "Zeek recorded a connection from the same host and source IP "
            f"to {edge.destination_ip}:{edge.destination_port} "
            f"{edge.delta_seconds:.3f} seconds after the PowerShell event."
        ),
    )

    return Finding(
        finding_id=FINDING_ID,
        title=(
            "PowerShell web retrieval corroborated by network telemetry"
        ),
        state=FindingState.CORROBORATED,
        confidence=Confidence.HIGH,
        confidence_scope=(
            "High confidence in the bounded cross-source behavioral "
            "correlation only; this is not a confidence rating for "
            "malicious intent."
        ),
        observed_facts=observed_facts,
        inference=(
            "Independent endpoint and network telemetry corroborate that "
            "the observed PowerShell web-retrieval behavior corresponded "
            "to a network connection to the same destination within the "
            "bounded correlation window."
        ),
        alternative_explanation=(
            "Authorized administrative, software retrieval, testing, or "
            "other legitimate scripted activity remains plausible."
        ),
        falsifier=(
            "This finding must not form if agreement on host, source IP, "
            "destination IP, destination port, directionality, or the "
            "60-second time bound is removed."
        ),
        residual_risk=(
            "The retrieved content, application-level retrieval success, "
            "execution of retrieved content, user intent, and malicious "
            "purpose are not established by this correlation."
        ),
        business_impact=(
            "UNKNOWN — this finding is generated from a synthetic "
            "architecture-validation fixture and no real business impact "
            "is claimed."
        ),
        decision_required=(
            "No operational decision is required for the synthetic "
            "fixture. With real evidence, authorization and retrieved "
            "content must be assessed before containment."
        ),
        recommended_action=(
            "For real telemetry, validate whether the retrieval was "
            "authorized, preserve the referenced raw evidence, and inspect "
            "the retrieved content before escalating response."
        ),
        response_validation_status=(
            "NOT_APPLICABLE_SYNTHETIC_FIXTURE"
        ),
        evidence=evidence,
        detection_ids=(
            detection.detection_id,
        ),
        correlation_ids=(
            correlation.correlation_id,
        ),
        correlation_edge_ids=(
            edge.edge_id,
        ),
        malicious_intent_established=False,
        synthetic_fixture=True,
    )