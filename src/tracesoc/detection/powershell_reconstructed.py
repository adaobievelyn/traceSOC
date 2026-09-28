from __future__ import annotations

import re

from tracesoc.detection.models import (
    DetectionResult,
    DetectionState,
)
from tracesoc.normalization.powershell_scriptblock import (
    PowerShellScriptBlock,
    ScriptBlockState,
)


WEB_EXECUTION_DETECTION_ID = "TRC-DET-002"
WEB_EXECUTION_DETECTION_VERSION = "1.0.0"
WEB_EXECUTION_TITLE = (
    "PowerShell web retrieval with dynamic execution"
)

PREAUTH_DISCOVERY_DETECTION_ID = "TRC-DET-003"
PREAUTH_DISCOVERY_DETECTION_VERSION = "1.0.0"
PREAUTH_DISCOVERY_TITLE = (
    "PowerShell domain-user preauthentication discovery"
)


_RETRIEVAL_PRIMITIVE = re.compile(
    r"\b(?:invoke-webrequest|iwr)\b",
    re.IGNORECASE,
)

_DYNAMIC_EXECUTION_PRIMITIVE = re.compile(
    r"\b(?:invoke-expression|iex)\b",
    re.IGNORECASE,
)

_DOMAIN_USER_QUERY = re.compile(
    r"\bget-domainuser\b",
    re.IGNORECASE,
)

_PREAUTH_NOT_REQUIRED = re.compile(
    r"\bpreauthnotrequired\b",
    re.IGNORECASE,
)


def detect_powershell_web_retrieval_execution(
    script_block: PowerShellScriptBlock,
) -> DetectionResult:
    """
    Detect web retrieval combined with dynamic execution in one complete
    reconstructed PowerShell ScriptBlock.

    MATCH establishes only that both behavioral primitives were present in
    the same complete reconstructed script. It does not establish retrieval
    success, downloaded-content identity, execution consequence, or
    malicious intent.
    """

    if (
        script_block.state
        is not ScriptBlockState.COMPLETE
    ):
        return _no_match(
            detection_id=
                WEB_EXECUTION_DETECTION_ID,
            detection_version=
                WEB_EXECUTION_DETECTION_VERSION,
            title=
                WEB_EXECUTION_TITLE,
            reason_code=
                "incomplete_script_block",
            rationale=(
                "Detector requires a complete reconstructed "
                "PowerShell ScriptBlock."
            ),
        )

    script_text = script_block.script_text

    if (
        not isinstance(
            script_text,
            str,
        )
        or
        not script_text.strip()
    ):
        return _no_match(
            detection_id=
                WEB_EXECUTION_DETECTION_ID,
            detection_version=
                WEB_EXECUTION_DETECTION_VERSION,
            title=
                WEB_EXECUTION_TITLE,
            reason_code=
                "missing_script_text",
            rationale=(
                "Complete reconstruction does not expose "
                "non-empty script text."
            ),
        )

    if (
        _RETRIEVAL_PRIMITIVE.search(
            script_text
        )
        is None
    ):
        return _no_match(
            detection_id=
                WEB_EXECUTION_DETECTION_ID,
            detection_version=
                WEB_EXECUTION_DETECTION_VERSION,
            title=
                WEB_EXECUTION_TITLE,
            reason_code=
                "no_web_retrieval_primitive",
            rationale=(
                "No supported PowerShell web-retrieval "
                "primitive was observed."
            ),
        )

    if (
        _DYNAMIC_EXECUTION_PRIMITIVE.search(
            script_text
        )
        is None
    ):
        return _no_match(
            detection_id=
                WEB_EXECUTION_DETECTION_ID,
            detection_version=
                WEB_EXECUTION_DETECTION_VERSION,
            title=
                WEB_EXECUTION_TITLE,
            reason_code=
                "no_dynamic_execution_primitive",
            rationale=(
                "Web retrieval was present without a supported "
                "dynamic-execution primitive in the same "
                "reconstructed script."
            ),
        )

    return DetectionResult(
        detection_id=
            WEB_EXECUTION_DETECTION_ID,
        detection_version=
            WEB_EXECUTION_DETECTION_VERSION,
        title=
            WEB_EXECUTION_TITLE,
        state=
            DetectionState.MATCH,
        reason_code=
            "powershell_web_retrieval_dynamic_execution_observed",
        rationale=(
            "A complete reconstructed PowerShell ScriptBlock contains "
            "both a supported web-retrieval primitive and a supported "
            "dynamic-execution primitive. This establishes the observed "
            "script behavior but does not establish retrieval success, "
            "downloaded-content identity, execution consequence, or "
            "malicious intent."
        ),
        contributing_event_ids=
            script_block.parent_event_ids,
    )


def detect_domain_user_preauth_discovery(
    script_block: PowerShellScriptBlock,
) -> DetectionResult:
    """
    Detect a domain-user query combined with a PreauthNotRequired
    selection in one complete reconstructed PowerShell ScriptBlock.

    MATCH establishes the query behavior only. It does not establish that
    any account satisfied the query, that credentials were obtained, or
    that malicious intent existed.
    """

    if (
        script_block.state
        is not ScriptBlockState.COMPLETE
    ):
        return _no_match(
            detection_id=
                PREAUTH_DISCOVERY_DETECTION_ID,
            detection_version=
                PREAUTH_DISCOVERY_DETECTION_VERSION,
            title=
                PREAUTH_DISCOVERY_TITLE,
            reason_code=
                "incomplete_script_block",
            rationale=(
                "Detector requires a complete reconstructed "
                "PowerShell ScriptBlock."
            ),
        )

    script_text = script_block.script_text

    if (
        not isinstance(
            script_text,
            str,
        )
        or
        not script_text.strip()
    ):
        return _no_match(
            detection_id=
                PREAUTH_DISCOVERY_DETECTION_ID,
            detection_version=
                PREAUTH_DISCOVERY_DETECTION_VERSION,
            title=
                PREAUTH_DISCOVERY_TITLE,
            reason_code=
                "missing_script_text",
            rationale=(
                "Complete reconstruction does not expose "
                "non-empty script text."
            ),
        )

    if (
        _DOMAIN_USER_QUERY.search(
            script_text
        )
        is None
    ):
        return _no_match(
            detection_id=
                PREAUTH_DISCOVERY_DETECTION_ID,
            detection_version=
                PREAUTH_DISCOVERY_DETECTION_VERSION,
            title=
                PREAUTH_DISCOVERY_TITLE,
            reason_code=
                "no_domain_user_query",
            rationale=(
                "No supported domain-user query primitive "
                "was observed."
            ),
        )

    if (
        _PREAUTH_NOT_REQUIRED.search(
            script_text
        )
        is None
    ):
        return _no_match(
            detection_id=
                PREAUTH_DISCOVERY_DETECTION_ID,
            detection_version=
                PREAUTH_DISCOVERY_DETECTION_VERSION,
            title=
                PREAUTH_DISCOVERY_TITLE,
            reason_code=
                "no_preauth_not_required_selection",
            rationale=(
                "A domain-user query was present without a "
                "PreauthNotRequired selection in the same "
                "reconstructed script."
            ),
        )

    return DetectionResult(
        detection_id=
            PREAUTH_DISCOVERY_DETECTION_ID,
        detection_version=
            PREAUTH_DISCOVERY_DETECTION_VERSION,
        title=
            PREAUTH_DISCOVERY_TITLE,
        state=
            DetectionState.MATCH,
        reason_code=
            "domain_user_preauth_discovery_observed",
        rationale=(
            "A complete reconstructed PowerShell ScriptBlock contains "
            "a domain-user query together with a PreauthNotRequired "
            "selection. This establishes the observed discovery query "
            "behavior but does not establish that any account matched, "
            "that credentials were obtained, or malicious intent."
        ),
        contributing_event_ids=
            script_block.parent_event_ids,
    )


def _no_match(
    *,
    detection_id: str,
    detection_version: str,
    title: str,
    reason_code: str,
    rationale: str,
) -> DetectionResult:
    return DetectionResult(
        detection_id=detection_id,
        detection_version=detection_version,
        title=title,
        state=DetectionState.NO_MATCH,
        reason_code=reason_code,
        rationale=rationale,
        contributing_event_ids=(),
    )