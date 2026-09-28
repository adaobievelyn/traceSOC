from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from email import policy
from email.message import Message
from email.parser import BytesParser

from tracesoc.evidence.artifacts import (
    Artifact,
    ArtifactImmutabilityState,
    ArtifactProcessingState,
)
from tracesoc.evidence.locators import (
    EvidenceLocator,
    LocatorKind,
)
from tracesoc.models import SourceType


EMAIL_ADAPTER_ID = "tracesoc-email-eml-v1"
EMAIL_INPUT_SCHEMA_VERSION = "1"
EMAIL_ARTIFACT_TYPE = "message/rfc822"

EMAIL_MESSAGE_EVENT_TYPE = "email_message"
EMAIL_PART_EVENT_TYPE = "email_mime_part"


def _sha256(
    value: bytes,
) -> str:
    return hashlib.sha256(
        value
    ).hexdigest()


def _header(
    message: Message,
    name: str,
) -> str | None:
    value = message.get(
        name
    )

    if value is None:
        return None

    return str(
        value
    )


def _defect_names(
    message: Message,
) -> tuple[str, ...]:
    names: set[str] = set()

    for part in message.walk():
        for defect in part.defects:
            names.add(
                type(
                    defect
                ).__name__
            )

    return tuple(
        sorted(
            names
        )
    )


def _decoded_payload(
    part: Message,
) -> bytes:
    decoded = part.get_payload(
        decode=True
    )

    if decoded is not None:
        return decoded

    payload = part.get_payload()

    if payload is None:
        return b""

    if isinstance(
        payload,
        str,
    ):
        charset = (
            part.get_content_charset()
            or "utf-8"
        )

        try:
            return payload.encode(
                charset
            )
        except (
            LookupError,
            UnicodeEncodeError,
        ):
            return payload.encode(
                "utf-8",
                errors="surrogatepass",
            )

    raise ValueError(
        "non-multipart MIME leaf has unsupported payload type"
    )


def _leaf_parts(
    message: Message,
) -> tuple[
    tuple[
        tuple[int, ...],
        Message,
    ],
    ...,
]:
    output: list[
        tuple[
            tuple[int, ...],
            Message,
        ]
    ] = []

    if not message.is_multipart():
        return (
            (
                (0,),
                message,
            ),
        )

    def visit(
        parent: Message,
        prefix: tuple[int, ...],
    ) -> None:
        payload = parent.get_payload()

        if not isinstance(
            payload,
            list,
        ):
            raise ValueError(
                "multipart MIME entity does not contain a part list"
            )

        for index, child in enumerate(
            payload
        ):
            path = (
                prefix
                + (index,)
            )

            if child.is_multipart():
                visit(
                    child,
                    path,
                )
            else:
                output.append(
                    (
                        path,
                        child,
                    )
                )

    visit(
        message,
        (),
    )

    return tuple(
        output
    )


def _part_token(
    path: tuple[int, ...],
) -> str:
    return "-".join(
        str(
            component
        )
        for component in path
    )


@dataclass(
    frozen=True,
    slots=True,
)
class EmailMessageObservation:
    artifact_id: str
    source_type: SourceType
    event_type: str
    locator: EvidenceLocator
    message_id: str | None
    date: str | None
    from_value: str | None
    to_value: str | None
    subject: str | None
    defects: tuple[str, ...]


@dataclass(
    frozen=True,
    slots=True,
)
class EmailPartObservation:
    artifact_id: str
    source_type: SourceType
    event_type: str
    locator: EvidenceLocator
    content_type: str
    content_disposition: str | None
    filename: str | None
    content_id: str | None
    transfer_encoding: str | None
    decoded_sha256: str
    decoded_bytes: int
    derived_artifact_id: str | None


@dataclass(
    frozen=True,
    slots=True,
)
class EmailAdapterResult:
    artifact: Artifact
    message: EmailMessageObservation | None
    parts: tuple[
        EmailPartObservation,
        ...,
    ]
    derived_artifacts: tuple[
        Artifact,
        ...,
    ]
    errors: tuple[
        str,
        ...,
    ] = ()


def load_eml_bytes(
    *,
    raw_bytes: bytes,
    source_path_display: str,
    acquired_or_observed_utc: datetime,
) -> EmailAdapterResult:
    if not isinstance(
        raw_bytes,
        bytes,
    ):
        raise TypeError(
            "raw_bytes must be bytes"
        )

    raw_sha256 = _sha256(
        raw_bytes
    )

    if not raw_bytes:
        artifact = Artifact.create(
            artifact_type=EMAIL_ARTIFACT_TYPE,
            source_path_display=source_path_display,
            sha256=raw_sha256,
            bytes=0,
            acquired_or_observed_utc=(
                acquired_or_observed_utc
            ),
            immutability_state=(
                ArtifactImmutabilityState.PRESERVED_SOURCE
            ),
            processing_state=(
                ArtifactProcessingState.MALFORMED_QUARANTINED
            ),
        )

        return EmailAdapterResult(
            artifact=artifact,
            message=None,
            parts=(),
            derived_artifacts=(),
            errors=(
                "empty_eml",
            ),
        )

    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(
            raw_bytes
        )
    except Exception as exc:
        artifact = Artifact.create(
            artifact_type=EMAIL_ARTIFACT_TYPE,
            source_path_display=source_path_display,
            sha256=raw_sha256,
            bytes=len(
                raw_bytes
            ),
            acquired_or_observed_utc=(
                acquired_or_observed_utc
            ),
            immutability_state=(
                ArtifactImmutabilityState.PRESERVED_SOURCE
            ),
            processing_state=(
                ArtifactProcessingState.MALFORMED_QUARANTINED
            ),
        )

        return EmailAdapterResult(
            artifact=artifact,
            message=None,
            parts=(),
            derived_artifacts=(),
            errors=(
                "email_parse_error:"
                + type(
                    exc
                ).__name__,
            ),
        )

    leaf_parts = _leaf_parts(
        message
    )

    decoded_parts: list[
        tuple[
            tuple[int, ...],
            Message,
            bytes,
        ]
    ] = []

    for path, part in leaf_parts:
        decoded_parts.append(
            (
                path,
                part,
                _decoded_payload(
                    part
                ),
            )
        )

    defects = _defect_names(
        message
    )

    processing_state = (
        ArtifactProcessingState.SUPPORTED_PARTIAL
        if defects
        else ArtifactProcessingState.SUPPORTED_PROCESSED
    )

    artifact = Artifact.create(
        artifact_type=EMAIL_ARTIFACT_TYPE,
        source_path_display=source_path_display,
        sha256=raw_sha256,
        bytes=len(
            raw_bytes
        ),
        acquired_or_observed_utc=(
            acquired_or_observed_utc
        ),
        immutability_state=(
            ArtifactImmutabilityState.PRESERVED_SOURCE
        ),
        processing_state=processing_state,
    )

    message_locator = EvidenceLocator(
        artifact_id=artifact.artifact_id,
        artifact_type=artifact.artifact_type,
        locator_kind=LocatorKind.BYTE_RANGE,
        raw_sha256=raw_sha256,
        adapter_id=EMAIL_ADAPTER_ID,
        input_schema_version=(
            EMAIL_INPUT_SCHEMA_VERSION
        ),
        byte_offset=0,
        byte_length=len(
            raw_bytes
        ),
    )

    message_observation = (
        EmailMessageObservation(
            artifact_id=artifact.artifact_id,
            source_type=SourceType.EMAIL,
            event_type=EMAIL_MESSAGE_EVENT_TYPE,
            locator=message_locator,
            message_id=_header(
                message,
                "Message-ID",
            ),
            date=_header(
                message,
                "Date",
            ),
            from_value=_header(
                message,
                "From",
            ),
            to_value=_header(
                message,
                "To",
            ),
            subject=_header(
                message,
                "Subject",
            ),
            defects=defects,
        )
    )

    part_observations: list[
        EmailPartObservation
    ] = []

    derived_artifacts: list[
        Artifact
    ] = []

    for path, part, decoded in decoded_parts:
        decoded_sha256 = _sha256(
            decoded
        )

        locator = EvidenceLocator(
            artifact_id=artifact.artifact_id,
            artifact_type=artifact.artifact_type,
            locator_kind=(
                LocatorKind.MIME_PART
            ),
            raw_sha256=decoded_sha256,
            adapter_id=EMAIL_ADAPTER_ID,
            input_schema_version=(
                EMAIL_INPUT_SCHEMA_VERSION
            ),
            mime_part_path=path,
        )

        disposition = (
            part.get_content_disposition()
        )

        filename_value = (
            part.get_filename()
        )

        filename = (
            None
            if filename_value is None
            else str(
                filename_value
            )
        )

        content_id_value = (
            part.get(
                "Content-ID"
            )
        )

        content_id = (
            None
            if content_id_value is None
            else str(
                content_id_value
            )
        )

        transfer_encoding_value = (
            part.get(
                "Content-Transfer-Encoding"
            )
        )

        transfer_encoding = (
            None
            if transfer_encoding_value is None
            else str(
                transfer_encoding_value
            )
        )

        derived_artifact: (
            Artifact
            | None
        ) = None

        if (
            disposition == "attachment"
            or filename is not None
        ):
            token = _part_token(
                path
            )

            derived_path = (
                "derived/"
                + artifact.artifact_id
                + "/mime/part-"
                + token
                + ".bin"
            )

            derived_artifact = (
                Artifact.create(
                    artifact_type=(
                        part.get_content_type()
                    ),
                    source_path_display=(
                        derived_path
                    ),
                    sha256=decoded_sha256,
                    bytes=len(
                        decoded
                    ),
                    acquired_or_observed_utc=(
                        acquired_or_observed_utc
                    ),
                    immutability_state=(
                        ArtifactImmutabilityState.PRESERVED_DERIVED
                    ),
                    processing_state=(
                        ArtifactProcessingState.SUPPORTED_PROCESSED
                    ),
                    parent_artifact_id=(
                        artifact.artifact_id
                    ),
                    derivation_method=(
                        "mime_payload_decode"
                    ),
                    derivation_tool=(
                        EMAIL_ADAPTER_ID
                    ),
                    derivation_tool_version=(
                        EMAIL_INPUT_SCHEMA_VERSION
                    ),
                )
            )

            derived_artifacts.append(
                derived_artifact
            )

        part_observations.append(
            EmailPartObservation(
                artifact_id=(
                    artifact.artifact_id
                ),
                source_type=(
                    SourceType.EMAIL
                ),
                event_type=(
                    EMAIL_PART_EVENT_TYPE
                ),
                locator=locator,
                content_type=(
                    part.get_content_type()
                ),
                content_disposition=(
                    disposition
                ),
                filename=filename,
                content_id=content_id,
                transfer_encoding=(
                    transfer_encoding
                ),
                decoded_sha256=(
                    decoded_sha256
                ),
                decoded_bytes=len(
                    decoded
                ),
                derived_artifact_id=(
                    None
                    if derived_artifact
                    is None
                    else derived_artifact.artifact_id
                ),
            )
        )

    return EmailAdapterResult(
        artifact=artifact,
        message=message_observation,
        parts=tuple(
            part_observations
        ),
        derived_artifacts=tuple(
            derived_artifacts
        ),
        errors=tuple(
            "parser_defect:"
            + name
            for name in defects
        ),
    )
