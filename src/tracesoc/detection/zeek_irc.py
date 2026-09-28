from __future__ import annotations

from tracesoc.detection.models import (
    DetectionResult,
    DetectionState,
)
from tracesoc.models import (
    SemanticEvent,
    SourceType,
)


DETECTION_ID = "TRC-DET-004"
DETECTION_VERSION = "1.0.0"
TITLE = "Zeek IRC service observation"


def detect_zeek_irc_service(
    event: SemanticEvent,
) -> DetectionResult:
    """
    Detect a Zeek connection whose promoted semantic service is IRC.

    MATCH establishes only that the supplied Zeek connection was
    semantically classified as IRC service. It does not establish
    command-and-control, malicious intent, malware identity, or incident
    membership.
    """

    if event.source_type is not SourceType.ZEEK:
        return _no_match(
            "wrong_source",
            "Detector requires a Zeek semantic event.",
        )

    if event.event_type != "connection":
        return _no_match(
            "wrong_event_type",
            "Detector requires a Zeek connection event.",
        )

    service = event.fields.get(
        "service"
    )

    if (
        not isinstance(
            service,
            str,
        )
        or
        not service.strip()
    ):
        return _no_match(
            "missing_service",
            "Detector requires a non-empty promoted service field.",
        )

    if service.strip().casefold() != "irc":
        return _no_match(
            "service_not_irc",
            "The observed Zeek connection service was not IRC.",
        )

    return DetectionResult(
        detection_id=DETECTION_ID,
        detection_version=DETECTION_VERSION,
        title=TITLE,
        state=DetectionState.MATCH,
        reason_code="zeek_irc_service_observed",
        rationale=(
            "A Zeek connection semantic event has service=IRC. "
            "This establishes the observed service classification only; "
            "it does not establish command-and-control, malicious intent, "
            "malware identity, or incident membership."
        ),
        contributing_event_ids=(
            event.event_id,
        ),
    )


def _no_match(
    reason_code: str,
    rationale: str,
) -> DetectionResult:
    return DetectionResult(
        detection_id=DETECTION_ID,
        detection_version=DETECTION_VERSION,
        title=TITLE,
        state=DetectionState.NO_MATCH,
        reason_code=reason_code,
        rationale=rationale,
        contributing_event_ids=(),
    )