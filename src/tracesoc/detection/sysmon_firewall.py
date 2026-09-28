from __future__ import annotations

from tracesoc.detection.models import (
    DetectionResult,
    DetectionState,
)
from tracesoc.models import (
    SemanticEvent,
    SourceType,
)


DETECTION_ID = "TRC-DET-005"
DETECTION_VERSION = "1.0.0"
TITLE = (
    "Sysmon Windows Firewall DomainProfile "
    "EnableFirewall zero write"
)


_DOMAIN_ENABLE_FIREWALL_SUFFIX = (
    "\\services\\sharedaccess\\parameters\\"
    "firewallpolicy\\domainprofile\\enablefirewall"
)

_DWORD_ZERO = "dword (0x00000000)"


def detect_sysmon_domain_firewall_zero_write(
    event: SemanticEvent,
) -> DetectionResult:
    """
    Detect a Sysmon registry-set-value observation recording DWORD zero
    for the Windows Firewall DomainProfile EnableFirewall value.

    MATCH establishes only the recorded configuration-write observation.
    It does not establish final firewall state, successful disablement
    effect, write persistence, motive, malicious intent, or incident
    membership.
    """

    if event.source_type is not SourceType.SYSMON:
        return _no_match(
            reason_code="wrong_source",
            rationale=(
                "Detector requires a Sysmon semantic event."
            ),
        )

    if event.event_type != "registry_set_value":
        return _no_match(
            reason_code="wrong_event_type",
            rationale=(
                "Detector requires a Sysmon registry_set_value event."
            ),
        )

    registry_path = _normalize_registry_path(
        event.fields.get(
            "registry_path"
        )
    )

    if not registry_path:
        return _no_match(
            reason_code="missing_registry_path",
            rationale=(
                "Detector requires a non-empty promoted registry path."
            ),
        )

    if not registry_path.endswith(
        _DOMAIN_ENABLE_FIREWALL_SUFFIX
    ):
        return _no_match(
            reason_code="wrong_registry_path",
            rationale=(
                "The registry write did not target the Windows Firewall "
                "DomainProfile EnableFirewall value."
            ),
        )

    registry_details = event.fields.get(
        "registry_details"
    )

    if (
        not isinstance(
            registry_details,
            str,
        )
        or
        not registry_details.strip()
    ):
        return _no_match(
            reason_code="missing_registry_details",
            rationale=(
                "Detector requires a non-empty promoted registry value."
            ),
        )

    if (
        registry_details.strip().casefold()
        !=
        _DWORD_ZERO
    ):
        return _no_match(
            reason_code="value_not_dword_zero",
            rationale=(
                "The DomainProfile EnableFirewall registry write did "
                "not record DWORD zero."
            ),
        )

    return DetectionResult(
        detection_id=DETECTION_ID,
        detection_version=DETECTION_VERSION,
        title=TITLE,
        state=DetectionState.MATCH,
        reason_code=(
            "sysmon_domain_firewall_enable_value_zero_write_observed"
        ),
        rationale=(
            "A Sysmon registry-set-value semantic event recorded DWORD "
            "zero for the Windows Firewall DomainProfile EnableFirewall "
            "value. This establishes the recorded configuration-write "
            "observation only; it does not establish final firewall "
            "state, successful disablement effect, write persistence, "
            "motive, malicious intent, or incident membership."
        ),
        contributing_event_ids=(
            event.event_id,
        ),
    )


def _normalize_registry_path(
    value: object,
) -> str:
    if not isinstance(
        value,
        str,
    ):
        return ""

    return (
        value.strip()
        .replace(
            "/",
            "\\",
        )
        .casefold()
    )


def _no_match(
    *,
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