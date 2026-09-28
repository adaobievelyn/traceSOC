from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Callable

from tracesoc.evidence.artifacts import (
    Artifact,
    ArtifactImmutabilityState,
    ArtifactProcessingState,
)
from tracesoc.evidence.locators import (
    EvidenceLocator,
)
from tracesoc.models import (
    CanonicalEvent,
    RawLocator,
    SourceType,
)
from tracesoc.parsers.powershell import (
    load_powershell_windows_event_xml,
)
from tracesoc.parsers.sysmon import (
    load_sysmon_windows_event_xml,
)


WINDOWS_EVENT_XML_ARTIFACT_TYPE = (
    "windows_event_xml"
)


class EvidenceMutationError(
    RuntimeError
):
    pass


class EvidenceBoundaryError(
    RuntimeError
):
    pass


@dataclass(
    frozen=True,
    slots=True,
)
class SourceNativeArtifactBatch:
    artifact: Artifact
    source_type: SourceType
    adapter_id: str
    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ]
    event_locators: tuple[
        EvidenceLocator,
        ...,
    ]
    quarantined_locators: tuple[
        EvidenceLocator,
        ...,
    ]
    errors: tuple[
        str,
        ...,
    ] = ()

    @property
    def accepted_count(
        self,
    ) -> int:
        return len(
            self.canonical_events
        )

    @property
    def quarantined_count(
        self,
    ) -> int:
        return len(
            self.quarantined_locators
        )

    @property
    def accounted_record_count(
        self,
    ) -> int:
        return (
            self.accepted_count
            + self.quarantined_count
        )


def _sha256(
    value: bytes,
) -> str:
    return hashlib.sha256(
        value
    ).hexdigest()


def _require_exact_raw_locator(
    *,
    locator: RawLocator,
    artifact_bytes: bytes,
) -> None:
    if not isinstance(
        locator,
        RawLocator,
    ):
        raise EvidenceBoundaryError(
            "record provenance is not RawLocator"
        )

    if (
        locator.byte_offset is None
        or locator.byte_length is None
    ):
        raise EvidenceBoundaryError(
            "source-native Windows Event record "
            "must have exact byte_offset and byte_length"
        )

    start = locator.byte_offset
    length = locator.byte_length
    end = start + length

    if (
        start < 0
        or length < 0
        or end > len(
            artifact_bytes
        )
    ):
        raise EvidenceBoundaryError(
            "record byte range is outside artifact bounds"
        )

    selected = artifact_bytes[
        start:end
    ]

    actual_sha256 = _sha256(
        selected
    )

    if (
        actual_sha256
        != locator.raw_sha256
    ):
        raise EvidenceBoundaryError(
            "record raw_sha256 does not match "
            "the exact artifact byte range"
        )


def _processing_state(
    *,
    accepted_count: int,
    quarantined_count: int,
) -> tuple[
    ArtifactProcessingState,
    tuple[
        str,
        ...,
    ],
]:
    if (
        accepted_count > 0
        and quarantined_count == 0
    ):
        return (
            ArtifactProcessingState.SUPPORTED_PROCESSED,
            (),
        )

    if (
        accepted_count > 0
        and quarantined_count > 0
    ):
        return (
            ArtifactProcessingState.SUPPORTED_PARTIAL,
            (),
        )

    if (
        accepted_count == 0
        and quarantined_count > 0
    ):
        return (
            ArtifactProcessingState.MALFORMED_QUARANTINED,
            (),
        )

    return (
        ArtifactProcessingState.FAILED_EXPLICIT,
        (
            "no_records",
        ),
    )


def _load_windows_event_artifact(
    *,
    path: Path,
    logical_source: str,
    acquired_or_observed_utc: datetime,
    expected_source_type: SourceType,
    loader: Callable[..., object],
) -> SourceNativeArtifactBatch:
    if not isinstance(
        path,
        Path,
    ):
        raise TypeError(
            "path must be pathlib.Path"
        )

    if not path.is_file():
        raise FileNotFoundError(
            str(
                path
            )
        )

    raw_before = (
        path.read_bytes()
    )

    provisional_artifact = (
        Artifact.create(
            artifact_type=(
                WINDOWS_EVENT_XML_ARTIFACT_TYPE
            ),
            source_path_display=(
                logical_source
            ),
            sha256=_sha256(
                raw_before
            ),
            bytes=len(
                raw_before
            ),
            acquired_or_observed_utc=(
                acquired_or_observed_utc
            ),
            immutability_state=(
                ArtifactImmutabilityState.PRESERVED_SOURCE
            ),
            processing_state=(
                ArtifactProcessingState.FAILED_EXPLICIT
            ),
        )
    )

    batch = loader(
        path,
        logical_source=logical_source,
    )

    raw_after = (
        path.read_bytes()
    )

    if raw_after != raw_before:
        raise EvidenceMutationError(
            "evidence file changed while source-native "
            "Windows Event loader was reading it"
        )

    batch_source_type = getattr(
        batch,
        "source_type",
        None,
    )

    if (
        batch_source_type
        is not expected_source_type
    ):
        raise EvidenceBoundaryError(
            "source-native loader returned unexpected source_type"
        )

    adapter_id = getattr(
        batch,
        "adapter_id",
        None,
    )

    if (
        not isinstance(
            adapter_id,
            str,
        )
        or not adapter_id.strip()
    ):
        raise EvidenceBoundaryError(
            "source-native loader returned invalid adapter_id"
        )

    accepted = tuple(
        getattr(
            batch,
            "accepted",
            (),
        )
    )

    quarantined = tuple(
        getattr(
            batch,
            "quarantined",
            (),
        )
    )

    state, errors = (
        _processing_state(
            accepted_count=len(
                accepted
            ),
            quarantined_count=len(
                quarantined
            ),
        )
    )

    artifact = replace(
        provisional_artifact,
        processing_state=state,
    )

    canonical_events: list[
        CanonicalEvent
    ] = []

    event_locators: list[
        EvidenceLocator
    ] = []

    for event in accepted:
        if not isinstance(
            event,
            CanonicalEvent,
        ):
            raise EvidenceBoundaryError(
                "accepted source-native record "
                "is not CanonicalEvent"
            )

        if (
            event.source_type
            is not expected_source_type
        ):
            raise EvidenceBoundaryError(
                "CanonicalEvent source_type does not "
                "match loader source_type"
            )

        _require_exact_raw_locator(
            locator=event.provenance,
            artifact_bytes=raw_before,
        )

        event_locator = (
            EvidenceLocator.from_raw_locator(
                artifact=artifact,
                locator=event.provenance,
            )
        )

        canonical_events.append(
            event
        )

        event_locators.append(
            event_locator
        )

    quarantined_locators: list[
        EvidenceLocator
    ] = []

    for item in quarantined:
        locator = getattr(
            item,
            "locator",
            None,
        )

        if not isinstance(
            locator,
            RawLocator,
        ):
            raise EvidenceBoundaryError(
                "quarantined record does not expose RawLocator"
            )

        _require_exact_raw_locator(
            locator=locator,
            artifact_bytes=raw_before,
        )

        quarantined_locators.append(
            EvidenceLocator.from_raw_locator(
                artifact=artifact,
                locator=locator,
            )
        )

    return SourceNativeArtifactBatch(
        artifact=artifact,
        source_type=expected_source_type,
        adapter_id=(
            adapter_id.strip()
        ),
        canonical_events=tuple(
            canonical_events
        ),
        event_locators=tuple(
            event_locators
        ),
        quarantined_locators=tuple(
            quarantined_locators
        ),
        errors=errors,
    )


def load_powershell_xml_artifact(
    path: Path,
    *,
    logical_source: str,
    acquired_or_observed_utc: datetime,
) -> SourceNativeArtifactBatch:
    return _load_windows_event_artifact(
        path=path,
        logical_source=logical_source,
        acquired_or_observed_utc=(
            acquired_or_observed_utc
        ),
        expected_source_type=(
            SourceType.POWERSHELL
        ),
        loader=(
            load_powershell_windows_event_xml
        ),
    )


def load_sysmon_xml_artifact(
    path: Path,
    *,
    logical_source: str,
    acquired_or_observed_utc: datetime,
) -> SourceNativeArtifactBatch:
    return _load_windows_event_artifact(
        path=path,
        logical_source=logical_source,
        acquired_or_observed_utc=(
            acquired_or_observed_utc
        ),
        expected_source_type=(
            SourceType.SYSMON
        ),
        loader=(
            load_sysmon_windows_event_xml
        ),
    )
