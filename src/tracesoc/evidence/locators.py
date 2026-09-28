from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from tracesoc.evidence.artifacts import Artifact
from tracesoc.models import RawLocator


_ARTIFACT_ID_RE = re.compile(r"^art_[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class LocatorKind(StrEnum):
    RECORD = "RECORD"
    BYTE_RANGE = "BYTE_RANGE"
    MIME_PART = "MIME_PART"
    PCAP_PACKET = "PCAP_PACKET"


def _required_text(
    value: object,
    *,
    field: str,
) -> str:
    if value is None:
        raise ValueError(
            f"{field} must not be missing"
        )

    if not isinstance(value, str):
        raise TypeError(
            f"{field} must be a string"
        )

    cleaned = value.strip()

    if not cleaned:
        raise ValueError(
            f"{field} must not be empty"
        )

    return cleaned


def _validate_artifact_id(
    value: object,
) -> str:
    artifact_id = _required_text(
        value,
        field="artifact_id",
    )

    if _ARTIFACT_ID_RE.fullmatch(
        artifact_id
    ) is None:
        raise ValueError(
            "artifact_id has invalid format"
        )

    return artifact_id


def _validate_sha256(
    value: object,
) -> str:
    raw_sha256 = _required_text(
        value,
        field="raw_sha256",
    )

    if _SHA256_RE.fullmatch(
        raw_sha256
    ) is None:
        raise ValueError(
            "raw_sha256 must be exactly 64 lowercase hexadecimal characters"
        )

    return raw_sha256


def _optional_nonnegative_int(
    value: object,
    *,
    field: str,
) -> int | None:
    if value is None:
        return None

    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
    ):
        raise ValueError(
            f"{field} must be a non-negative integer"
        )

    return value


def _optional_positive_int(
    value: object,
    *,
    field: str,
) -> int | None:
    if value is None:
        return None

    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
    ):
        raise ValueError(
            f"{field} must be a positive integer"
        )

    return value


def _validate_mime_part_path(
    value: object,
) -> tuple[int, ...] | None:
    if value is None:
        return None

    if not isinstance(value, tuple):
        raise TypeError(
            "mime_part_path must be a tuple"
        )

    if not value:
        raise ValueError(
            "mime_part_path must not be empty"
        )

    for component in value:
        if (
            not isinstance(component, int)
            or isinstance(component, bool)
            or component < 0
        ):
            raise ValueError(
                "mime_part_path components must be non-negative integers"
            )

    return value


@dataclass(
    frozen=True,
    slots=True,
)
class EvidenceLocator:
    artifact_id: str
    artifact_type: str
    locator_kind: LocatorKind
    raw_sha256: str
    adapter_id: str
    input_schema_version: str

    record_index: int | None = None
    line_number: int | None = None
    byte_offset: int | None = None
    byte_length: int | None = None
    mime_part_path: tuple[int, ...] | None = None
    packet_number: int | None = None

    def __post_init__(
        self,
    ) -> None:
        artifact_id = _validate_artifact_id(
            self.artifact_id
        )

        artifact_type = _required_text(
            self.artifact_type,
            field="artifact_type",
        )

        raw_sha256 = _validate_sha256(
            self.raw_sha256
        )

        adapter_id = _required_text(
            self.adapter_id,
            field="adapter_id",
        )

        input_schema_version = (
            _required_text(
                self.input_schema_version,
                field="input_schema_version",
            )
        )

        if not isinstance(
            self.locator_kind,
            LocatorKind,
        ):
            raise TypeError(
                "locator_kind must be LocatorKind"
            )

        record_index = (
            _optional_nonnegative_int(
                self.record_index,
                field="record_index",
            )
        )

        line_number = (
            _optional_positive_int(
                self.line_number,
                field="line_number",
            )
        )

        byte_offset = (
            _optional_nonnegative_int(
                self.byte_offset,
                field="byte_offset",
            )
        )

        byte_length = (
            _optional_nonnegative_int(
                self.byte_length,
                field="byte_length",
            )
        )

        mime_part_path = (
            _validate_mime_part_path(
                self.mime_part_path
            )
        )

        packet_number = (
            _optional_positive_int(
                self.packet_number,
                field="packet_number",
            )
        )

        if (
            (byte_offset is None)
            != (byte_length is None)
        ):
            raise ValueError(
                "byte_offset and byte_length must be supplied together"
            )

        if (
            self.locator_kind
            is LocatorKind.RECORD
        ):
            if record_index is None:
                raise ValueError(
                    "RECORD locator requires record_index"
                )

            if (
                mime_part_path is not None
                or packet_number is not None
            ):
                raise ValueError(
                    "RECORD locator cannot contain MIME or PCAP coordinates"
                )

        elif (
            self.locator_kind
            is LocatorKind.BYTE_RANGE
        ):
            if (
                byte_offset is None
                or byte_length is None
            ):
                raise ValueError(
                    "BYTE_RANGE locator requires byte_offset and byte_length"
                )

            if (
                record_index is not None
                or line_number is not None
                or mime_part_path is not None
                or packet_number is not None
            ):
                raise ValueError(
                    "BYTE_RANGE locator cannot contain record, line, MIME, or packet coordinates"
                )

        elif (
            self.locator_kind
            is LocatorKind.MIME_PART
        ):
            if mime_part_path is None:
                raise ValueError(
                    "MIME_PART locator requires mime_part_path"
                )

            if (
                record_index is not None
                or line_number is not None
                or byte_offset is not None
                or byte_length is not None
                or packet_number is not None
            ):
                raise ValueError(
                    "MIME_PART locator cannot contain record, line, byte-range, or packet coordinates"
                )

        elif (
            self.locator_kind
            is LocatorKind.PCAP_PACKET
        ):
            if packet_number is None:
                raise ValueError(
                    "PCAP_PACKET locator requires packet_number"
                )

            if (
                byte_offset is None
                or byte_length is None
            ):
                raise ValueError(
                    "PCAP_PACKET locator requires byte_offset and byte_length"
                )

            if (
                record_index is not None
                or line_number is not None
                or mime_part_path is not None
            ):
                raise ValueError(
                    "PCAP_PACKET locator cannot contain record, line, or MIME coordinates"
                )

        object.__setattr__(
            self,
            "artifact_id",
            artifact_id,
        )

        object.__setattr__(
            self,
            "artifact_type",
            artifact_type,
        )

        object.__setattr__(
            self,
            "raw_sha256",
            raw_sha256,
        )

        object.__setattr__(
            self,
            "adapter_id",
            adapter_id,
        )

        object.__setattr__(
            self,
            "input_schema_version",
            input_schema_version,
        )

    @classmethod
    def from_raw_locator(
        cls,
        *,
        artifact: Artifact,
        locator: RawLocator,
    ) -> "EvidenceLocator":
        if not isinstance(
            artifact,
            Artifact,
        ):
            raise TypeError(
                "artifact must be Artifact"
            )

        if not isinstance(
            locator,
            RawLocator,
        ):
            raise TypeError(
                "locator must be RawLocator"
            )

        if (
            artifact.source_path_display
            != locator.logical_source
        ):
            raise ValueError(
                "artifact path does not match RawLocator logical_source"
            )

        return cls(
            artifact_id=artifact.artifact_id,
            artifact_type=artifact.artifact_type,
            locator_kind=LocatorKind.RECORD,
            raw_sha256=locator.raw_sha256,
            adapter_id=locator.adapter_id,
            input_schema_version=(
                locator.input_schema_version
            ),
            record_index=locator.record_index,
            line_number=locator.line_number,
            byte_offset=locator.byte_offset,
            byte_length=locator.byte_length,
        )
