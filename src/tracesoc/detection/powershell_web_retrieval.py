from __future__ import annotations

import re
from pathlib import PureWindowsPath

from tracesoc.detection.models import (
    DetectionResult,
    DetectionState,
)
from tracesoc.models import SemanticEvent, SourceType


DETECTION_ID = "TRC-DET-001"
DETECTION_VERSION = "1.0.0"
TITLE = "PowerShell web-retrieval behavior"


_RETRIEVAL_PRIMITIVE = re.compile(
    r"\b(?:invoke-webrequest|start-bitstransfer)\b",
    re.IGNORECASE,
)

_HTTP_URI = re.compile(
    r"https?://\S+",
    re.IGNORECASE,
)


def detect_powershell_web_retrieval(
    event: SemanticEvent,
) -> DetectionResult:
    """
    Detect an explicit PowerShell web-retrieval behavior.

    This establishes that a recognized PowerShell retrieval primitive and
    explicit HTTP(S) URI occur in the same semantic script-execution event.

    It does not establish malicious intent.
    """

    if event.source_type != SourceType.POWERSHELL:
        return _no_match(
            "wrong_source",
            "Event is not PowerShell telemetry.",
        )

    if event.event_type != "script_execution":
        return _no_match(
            "wrong_event_type",
            "PowerShell event is not a script-execution event.",
        )

    engine = event.fields.get("engine")

    if not isinstance(engine, str) or not engine.strip():
        return _no_match(
            "missing_engine",
            "Detector requires a PowerShell engine field.",
        )

    engine_name = PureWindowsPath(
        engine.strip()
    ).name.lower()

    if engine_name not in {
        "powershell.exe",
        "pwsh.exe",
    }:
        return _no_match(
            "unsupported_engine",
            "Script engine is not powershell.exe or pwsh.exe.",
        )

    script_text = event.fields.get("script_text")

    if not isinstance(script_text, str) or not script_text.strip():
        return _no_match(
            "missing_script_text",
            "Detector requires semantic script text.",
        )

    if not _RETRIEVAL_PRIMITIVE.search(script_text):
        return _no_match(
            "no_retrieval_primitive",
            "No supported PowerShell web-retrieval primitive was observed.",
        )

    if not _HTTP_URI.search(script_text):
        return _no_match(
            "no_http_uri",
            "Retrieval primitive was present but no explicit HTTP(S) URI was observed.",
        )

    return DetectionResult(
        detection_id=DETECTION_ID,
        detection_version=DETECTION_VERSION,
        title=TITLE,
        state=DetectionState.MATCH,
        reason_code="powershell_web_retrieval_observed",
        rationale=(
            "A PowerShell semantic event contains a recognized web-retrieval "
            "primitive and an explicit HTTP(S) URI. This establishes web-"
            "retrieval behavior but does not establish malicious intent."
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