from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from tracesoc.correlation.models import (
    CorrelationState,
)
from tracesoc.models import (
    SemanticEvent,
    SourceType,
)


CORRELATION_ID = "TRC-CORR-005"
CORRELATION_VERSION = "1.0.0"

RELATIONSHIP = (
    "email_attachment_sysmon_process_image_identity"
)

_SHA256_RE = re.compile(
    r"^[0-9a-f]{64}$"
)

_SYSMON_SHA256_RE = re.compile(
    r"(?:^|[,;])\s*SHA256\s*=\s*"
    r"([0-9A-Fa-f]{64})(?=$|[,;])",
    re.IGNORECASE,
)


@dataclass(
    frozen=True,
    slots=True,
)
class EmailSysmonArtifactEdge:
    correlation_id: str
    correlation_version: str
    edge_id: str
    relationship: str
    source_event_id: str
    target_event_id: str
    sha256: str
    matched_dimensions: tuple[
        str,
        ...,
    ]

    def __post_init__(
        self,
    ) -> None:
        if not self.edge_id:
            raise ValueError(
                "edge_id must not be empty"
            )

        if (
            _SHA256_RE.fullmatch(
                self.sha256
            )
            is None
        ):
            raise ValueError(
                "sha256 must be lowercase hexadecimal"
            )

        if not self.matched_dimensions:
            raise ValueError(
                "matched_dimensions must not be empty"
            )


@dataclass(
    frozen=True,
    slots=True,
)
class EmailSysmonArtifactResult:
    correlation_id: str
    correlation_version: str
    state: CorrelationState
    reason_code: str
    rationale: str
    edge: EmailSysmonArtifactEdge | None

    @property
    def matched(
        self,
    ) -> bool:
        return (
            self.state
            == CorrelationState.MATCH
        )

    def __post_init__(
        self,
    ) -> None:
        if (
            self.matched
            and self.edge is None
        ):
            raise ValueError(
                "matched email/Sysmon correlation "
                "requires edge"
            )

        if (
            not self.matched
            and self.edge is not None
        ):
            raise ValueError(
                "non-match email/Sysmon correlation "
                "must not contain edge"
            )


def normalize_sha256(
    value: object,
) -> str | None:
    if not isinstance(
        value,
        str,
    ):
        return None

    text = (
        value
        .strip()
        .casefold()
    )

    if (
        _SHA256_RE.fullmatch(
            text
        )
        is None
    ):
        return None

    return text


def extract_sysmon_sha256(
    value: object,
) -> str | None:
    if not isinstance(
        value,
        str,
    ):
        return None

    match = (
        _SYSMON_SHA256_RE.search(
            value.strip()
        )
    )

    if match is None:
        return None

    return (
        match.group(1)
        .casefold()
    )


def _no_match(
    reason_code: str,
    rationale: str,
) -> EmailSysmonArtifactResult:
    return EmailSysmonArtifactResult(
        correlation_id=(
            CORRELATION_ID
        ),
        correlation_version=(
            CORRELATION_VERSION
        ),
        state=(
            CorrelationState.NO_MATCH
        ),
        reason_code=reason_code,
        rationale=rationale,
        edge=None,
    )


def _edge_id(
    *,
    source_event_id: str,
    target_event_id: str,
    sha256: str,
) -> str:
    material = {
        "correlation_id":
            CORRELATION_ID,

        "correlation_version":
            CORRELATION_VERSION,

        "relationship":
            RELATIONSHIP,

        "source_event_id":
            source_event_id,

        "target_event_id":
            target_event_id,

        "sha256":
            sha256,
    }

    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    ).encode(
        "utf-8"
    )

    return (
        "edge_"
        + hashlib.sha256(
            encoded
        ).hexdigest()
    )


def correlate_email_attachment_with_sysmon_process_image(
    *,
    email_event: SemanticEvent,
    sysmon_event: SemanticEvent,
) -> EmailSysmonArtifactResult:
    """
    Corroborate exact byte identity between a decoded
    MIME attachment and a Sysmon-hashed process image.

    Filename and timestamp are deliberately not selectors.

    A match proves byte identity only. It does not prove
    message delivery, user interaction, causal execution
    from the email, malicious intent, or incident membership.
    """

    if (
        email_event.source_type
        is not SourceType.EMAIL
    ):
        return _no_match(
            "source_type_mismatch",
            (
                "Source event is not email "
                "evidence."
            ),
        )

    if (
        email_event.event_type
        != "email_mime_part"
    ):
        return _no_match(
            "source_event_type_mismatch",
            (
                "Email event is not a MIME "
                "part observation."
            ),
        )

    if (
        sysmon_event.source_type
        is not SourceType.SYSMON
    ):
        return _no_match(
            "target_type_mismatch",
            (
                "Target event is not Sysmon "
                "evidence."
            ),
        )

    if (
        sysmon_event.event_type
        != "process_create"
    ):
        return _no_match(
            "target_event_type_mismatch",
            (
                "Sysmon event is not process "
                "creation telemetry."
            ),
        )

    email_fields = (
        email_event.fields
    )

    sysmon_fields = (
        sysmon_event.fields
    )

    derived_artifact_id = (
        email_fields.get(
            "derived_artifact_id"
        )
    )

    if (
        not isinstance(
            derived_artifact_id,
            str,
        )
        or not derived_artifact_id.strip()
    ):
        return _no_match(
            "email_part_not_attachment_artifact",
            (
                "The MIME part does not have "
                "a derived attachment artifact "
                "identity."
            ),
        )

    email_sha256 = (
        normalize_sha256(
            email_fields.get(
                "decoded_sha256"
            )
        )
    )

    if email_sha256 is None:
        return _no_match(
            "email_sha256_unavailable",
            (
                "The MIME attachment has no "
                "valid decoded SHA-256."
            ),
        )

    sysmon_sha256 = (
        extract_sysmon_sha256(
            sysmon_fields.get(
                "hashes"
            )
        )
    )

    if sysmon_sha256 is None:
        return _no_match(
            "sysmon_sha256_unavailable",
            (
                "The Sysmon process observation "
                "does not provide an explicit "
                "SHA256 value."
            ),
        )

    if (
        email_sha256
        != sysmon_sha256
    ):
        return _no_match(
            "sha256_mismatch",
            (
                "The decoded MIME attachment "
                "and Sysmon process image have "
                "different SHA-256 values."
            ),
        )

    edge = EmailSysmonArtifactEdge(
        correlation_id=(
            CORRELATION_ID
        ),
        correlation_version=(
            CORRELATION_VERSION
        ),
        edge_id=_edge_id(
            source_event_id=(
                email_event.event_id
            ),
            target_event_id=(
                sysmon_event.event_id
            ),
            sha256=(
                email_sha256
            ),
        ),
        relationship=(
            RELATIONSHIP
        ),
        source_event_id=(
            email_event.event_id
        ),
        target_event_id=(
            sysmon_event.event_id
        ),
        sha256=(
            email_sha256
        ),
        matched_dimensions=(
            "sha256",
        ),
    )

    return EmailSysmonArtifactResult(
        correlation_id=(
            CORRELATION_ID
        ),
        correlation_version=(
            CORRELATION_VERSION
        ),
        state=(
            CorrelationState.MATCH
        ),
        reason_code=(
            "email_attachment_process_image_byte_identity"
        ),
        rationale=(
            "The decoded MIME attachment SHA-256 "
            "exactly matches the explicit SHA256 "
            "value recorded for the Sysmon process "
            "image. This corroborates byte identity "
            "only; it does not establish email "
            "delivery, user action, causal execution "
            "from the message, malicious intent, or "
            "incident membership."
        ),
        edge=edge,
    )
