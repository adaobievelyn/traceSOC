from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:/")


class SourceType(StrEnum):
    """Telemetry families supported by the first TraceSOC vertical slice."""

    SYSMON = "sysmon"
    WINDOWS_SECURITY = "windows_security"
    POWERSHELL = "powershell"
    ZEEK = "zeek"
    EMAIL = "email"
    PCAP = "pcap"


class ClockState(StrEnum):
    """Explicit state of an event's normalized timestamp."""

    OBSERVED = "observed"
    CORRECTED = "corrected"
    UNTIMED = "untimed"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class RawLocator:
    """Stable logical locator from a derived event back to raw evidence."""

    logical_source: str
    record_index: int
    raw_sha256: str
    adapter_id: str
    input_schema_version: str
    line_number: int | None = None
    byte_offset: int | None = None
    byte_length: int | None = None

    def __post_init__(self) -> None:
        source = self.logical_source.strip().replace("\\", "/")

        if not source:
            raise ValueError("logical_source must not be empty")

        if (
            source.startswith("/")
            or _WINDOWS_ABSOLUTE_RE.match(source)
            or source == ".."
            or source.startswith("../")
            or "/../" in source
        ):
            raise ValueError(
                "logical_source must be a repository/evidence-relative logical path"
            )

        digest = self.raw_sha256.strip().lower()

        if not _SHA256_RE.fullmatch(digest):
            raise ValueError("raw_sha256 must contain exactly 64 hexadecimal characters")

        if self.record_index < 0:
            raise ValueError("record_index must be zero or greater")

        if self.line_number is not None and self.line_number < 1:
            raise ValueError("line_number must be one or greater")

        if self.byte_offset is not None and self.byte_offset < 0:
            raise ValueError("byte_offset must be zero or greater")

        if self.byte_length is not None and self.byte_length < 0:
            raise ValueError("byte_length must be zero or greater")

        if not self.adapter_id.strip():
            raise ValueError("adapter_id must not be empty")

        if not self.input_schema_version.strip():
            raise ValueError("input_schema_version must not be empty")

        object.__setattr__(self, "logical_source", source)
        object.__setattr__(self, "raw_sha256", digest)


@dataclass(frozen=True, slots=True)
class CanonicalEvent:
    """
    Provenance-rich event used by the evidence and correlation layers.

    source_context may retain normalized source-specific information that
    detectors must not automatically receive.

    semantic_fields contains only information deliberately promoted for
    detector-facing semantic analysis.
    """

    event_id: str
    source_type: SourceType
    event_type: str
    clock_state: ClockState
    provenance: RawLocator
    event_time_raw: str | None = None
    event_time_utc: datetime | None = None
    host: str | None = None
    principal: str | None = None
    semantic_fields: Mapping[str, Any] = field(default_factory=dict)
    source_context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id.strip():
            raise ValueError("event_id must not be empty")

        if not self.event_type.strip():
            raise ValueError("event_type must not be empty")

        if self.clock_state in {ClockState.OBSERVED, ClockState.CORRECTED}:
            if self.event_time_utc is None:
                raise ValueError(
                    "observed/corrected events require event_time_utc"
                )

        if self.clock_state in {ClockState.UNTIMED, ClockState.UNRESOLVED}:
            if self.event_time_utc is not None:
                raise ValueError(
                    "untimed/unresolved events must not claim event_time_utc"
                )

        if self.event_time_utc is not None:
            if self.event_time_utc.tzinfo is None:
                raise ValueError("event_time_utc must be timezone-aware")

            if self.event_time_utc.utcoffset() != timedelta(0):
                raise ValueError("event_time_utc must be normalized to UTC")

        object.__setattr__(
            self,
            "semantic_fields",
            MappingProxyType(dict(self.semantic_fields)),
        )

        object.__setattr__(
            self,
            "source_context",
            MappingProxyType(dict(self.source_context)),
        )


@dataclass(frozen=True, slots=True)
class SemanticEvent:
    """
    Detector-facing event.

    Raw provenance and source_context are deliberately absent. This is the
    structural boundary that prevents fixture metadata, expected outcomes,
    raw assessment fields, and other source-only material from reaching a
    behavioral detector by default.
    """

    event_id: str
    source_type: SourceType
    event_type: str
    clock_state: ClockState
    event_time_utc: datetime | None
    host: str | None
    principal: str | None
    fields: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "fields",
            MappingProxyType(dict(self.fields)),
        )

    @classmethod
    def from_canonical(cls, event: CanonicalEvent) -> "SemanticEvent":
        return cls(
            event_id=event.event_id,
            source_type=event.source_type,
            event_type=event.event_type,
            clock_state=event.clock_state,
            event_time_utc=event.event_time_utc,
            host=event.host,
            principal=event.principal,
            fields=event.semantic_fields,
        )