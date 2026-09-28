from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum


ARTIFACT_IDENTITY_VERSION = 1

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_ID_RE = re.compile(r"^art_[0-9a-f]{64}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


class ArtifactProcessingState(StrEnum):
    SUPPORTED_PROCESSED = "SUPPORTED_PROCESSED"
    SUPPORTED_PARTIAL = "SUPPORTED_PARTIAL"
    UNSUPPORTED_PRESERVED = "UNSUPPORTED_PRESERVED"
    MALFORMED_QUARANTINED = "MALFORMED_QUARANTINED"
    FAILED_EXPLICIT = "FAILED_EXPLICIT"


class ArtifactImmutabilityState(StrEnum):
    PRESERVED_SOURCE = "PRESERVED_SOURCE"
    PRESERVED_DERIVED = "PRESERVED_DERIVED"


def _required_text(
    value: object,
    *,
    field: str,
) -> str:
    if value is None:
        raise ValueError(f"{field} must not be missing")

    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")

    cleaned = value.strip()

    if not cleaned:
        raise ValueError(f"{field} must not be empty")

    return cleaned


def _normalize_source_path(
    value: object,
) -> str:
    if not isinstance(value, str):
        raise TypeError("source_path_display must be a string")

    if not value or not value.strip():
        raise ValueError("source_path_display must not be empty")

    if value != value.strip():
        raise ValueError(
            "source_path_display must not have leading or trailing whitespace"
        )

    normalized = value.replace("\\", "/")

    if "\x00" in normalized:
        raise ValueError(
            "source_path_display contains a NUL character"
        )

    if (
        normalized.startswith("/")
        or _WINDOWS_DRIVE_RE.match(normalized) is not None
    ):
        raise ValueError(
            "source_path_display must be relative"
        )

    parts = normalized.split("/")

    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(
            "source_path_display contains an unsafe path segment"
        )

    return normalized


def _validate_sha256(
    value: object,
) -> str:
    if not isinstance(value, str):
        raise TypeError("sha256 must be a string")

    if _SHA256_RE.fullmatch(value) is None:
        raise ValueError(
            "sha256 must be exactly 64 lowercase hexadecimal characters"
        )

    return value


def _validate_bytes(
    value: object,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
    ):
        raise ValueError(
            "bytes must be a non-negative integer"
        )

    return value


def _validate_utc(
    value: object,
) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(
            "acquired_or_observed_utc must be a datetime"
        )

    if (
        value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(
            "acquired_or_observed_utc must be timezone-aware UTC"
        )

    return value


def compute_artifact_id(
    *,
    source_path_display: str,
    sha256: str,
    bytes: int,
) -> str:
    normalized_path = _normalize_source_path(
        source_path_display
    )

    validated_sha256 = _validate_sha256(
        sha256
    )

    byte_count = _validate_bytes(
        bytes
    )

    identity = {
        "identity_version": ARTIFACT_IDENTITY_VERSION,
        "source_path_display": normalized_path,
        "sha256": validated_sha256,
        "bytes": byte_count,
    }

    payload = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return "art_" + hashlib.sha256(payload).hexdigest()


@dataclass(
    frozen=True,
    slots=True,
)
class Artifact:
    artifact_id: str
    artifact_type: str
    source_path_display: str
    sha256: str
    bytes: int
    acquired_or_observed_utc: datetime
    immutability_state: ArtifactImmutabilityState
    processing_state: ArtifactProcessingState
    parent_artifact_id: str | None = None
    derivation_method: str | None = None
    derivation_tool: str | None = None
    derivation_tool_version: str | None = None

    def __post_init__(
        self,
    ) -> None:
        normalized_path = _normalize_source_path(
            self.source_path_display
        )

        artifact_type = _required_text(
            self.artifact_type,
            field="artifact_type",
        )

        validated_sha256 = _validate_sha256(
            self.sha256
        )

        byte_count = _validate_bytes(
            self.bytes
        )

        _validate_utc(
            self.acquired_or_observed_utc
        )

        if not isinstance(
            self.immutability_state,
            ArtifactImmutabilityState,
        ):
            raise TypeError(
                "immutability_state must be ArtifactImmutabilityState"
            )

        if not isinstance(
            self.processing_state,
            ArtifactProcessingState,
        ):
            raise TypeError(
                "processing_state must be ArtifactProcessingState"
            )

        expected_artifact_id = compute_artifact_id(
            source_path_display=normalized_path,
            sha256=validated_sha256,
            bytes=byte_count,
        )

        if self.artifact_id != expected_artifact_id:
            raise ValueError(
                "artifact_id does not match deterministic artifact identity"
            )

        if _ARTIFACT_ID_RE.fullmatch(self.artifact_id) is None:
            raise ValueError(
                "artifact_id has invalid format"
            )

        if (
            self.immutability_state
            is ArtifactImmutabilityState.PRESERVED_SOURCE
        ):
            lineage_values = (
                self.parent_artifact_id,
                self.derivation_method,
                self.derivation_tool,
                self.derivation_tool_version,
            )

            if any(value is not None for value in lineage_values):
                raise ValueError(
                    "source artifact must not contain derivation lineage"
                )

        if (
            self.immutability_state
            is ArtifactImmutabilityState.PRESERVED_DERIVED
        ):
            parent_artifact_id = _required_text(
                self.parent_artifact_id,
                field="parent_artifact_id",
            )

            if _ARTIFACT_ID_RE.fullmatch(parent_artifact_id) is None:
                raise ValueError(
                    "parent_artifact_id has invalid format"
                )

            if parent_artifact_id == self.artifact_id:
                raise ValueError(
                    "derived artifact cannot be its own parent"
                )

            derivation_method = _required_text(
                self.derivation_method,
                field="derivation_method",
            )

            derivation_tool = _required_text(
                self.derivation_tool,
                field="derivation_tool",
            )

            derivation_tool_version = _required_text(
                self.derivation_tool_version,
                field="derivation_tool_version",
            )

            object.__setattr__(
                self,
                "parent_artifact_id",
                parent_artifact_id,
            )

            object.__setattr__(
                self,
                "derivation_method",
                derivation_method,
            )

            object.__setattr__(
                self,
                "derivation_tool",
                derivation_tool,
            )

            object.__setattr__(
                self,
                "derivation_tool_version",
                derivation_tool_version,
            )

        object.__setattr__(
            self,
            "source_path_display",
            normalized_path,
        )

        object.__setattr__(
            self,
            "artifact_type",
            artifact_type,
        )

    @classmethod
    def create(
        cls,
        *,
        artifact_type: str,
        source_path_display: str,
        sha256: str,
        bytes: int,
        acquired_or_observed_utc: datetime,
        immutability_state: ArtifactImmutabilityState,
        processing_state: ArtifactProcessingState,
        parent_artifact_id: str | None = None,
        derivation_method: str | None = None,
        derivation_tool: str | None = None,
        derivation_tool_version: str | None = None,
    ) -> "Artifact":
        artifact_id = compute_artifact_id(
            source_path_display=source_path_display,
            sha256=sha256,
            bytes=bytes,
        )

        return cls(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            source_path_display=source_path_display,
            sha256=sha256,
            bytes=bytes,
            acquired_or_observed_utc=acquired_or_observed_utc,
            immutability_state=immutability_state,
            processing_state=processing_state,
            parent_artifact_id=parent_artifact_id,
            derivation_method=derivation_method,
            derivation_tool=derivation_tool,
            derivation_tool_version=derivation_tool_version,
        )
