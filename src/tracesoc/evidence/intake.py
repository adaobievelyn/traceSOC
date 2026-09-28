from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
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
from tracesoc.evidence.windows_event_bridge import (
    EvidenceMutationError,
    load_powershell_xml_artifact,
    load_sysmon_xml_artifact,
)
from tracesoc.models import (
    CanonicalEvent,
    RawLocator,
    SourceType,
)
from tracesoc.parsers.eml import (
    load_eml_bytes,
)
from tracesoc.parsers.pcap import (
    load_pcap_bytes,
)
from tracesoc.parsers.pcapng import load_pcapng_bytes
from tracesoc.parsers.powershell import (
    load_powershell_windows_event_json,
)
from tracesoc.parsers.sysmon import (
    load_sysmon_windows_event_json,
)
from tracesoc.parsers.windows_event_json import (
    probe_windows_event_json_providers,
)
from tracesoc.parsers.windows_security import (
    WINDOWS_SECURITY_PROVIDER,
    load_windows_security_splunk,
    load_windows_security_windows_event_json,
    load_windows_security_windows_event_xml,
)
from tracesoc.parsers.zeek import (
    load_zeek_conn_ascii,
    load_zeek_conn_native_json,
    probe_zeek_conn_json,
)


GENERIC_ARTIFACT_TYPE = (
    "application/octet-stream"
)

WINDOWS_SECURITY_ARTIFACT_TYPE = (
    "windows_security_splunk"
)

ZEEK_ARTIFACT_TYPE = (
    "zeek_ascii"
)

ZEEK_JSON_ARTIFACT_TYPE = (
    "zeek_json"
)

WINDOWS_EVENT_JSON_ARTIFACT_TYPE = (
    "windows_event_json"
)

_CLASSIC_PCAP_MAGIC = frozenset(
    {
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    }
)
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class AdapterFamily(StrEnum):
    EMAIL = "EMAIL"
    PCAP = "PCAP"
    PCAPNG = "PCAPNG"
    POWERSHELL_XML = "POWERSHELL_XML"
    POWERSHELL_JSON = "POWERSHELL_JSON"
    SYSMON_XML = "SYSMON_XML"
    SYSMON_JSON = "SYSMON_JSON"
    WINDOWS_SECURITY_XML = (
        "WINDOWS_SECURITY_XML"
    )
    WINDOWS_SECURITY_JSON = (
        "WINDOWS_SECURITY_JSON"
    )
    WINDOWS_SECURITY_SPLUNK = (
        "WINDOWS_SECURITY_SPLUNK"
    )
    ZEEK_ASCII = "ZEEK_ASCII"
    ZEEK_JSON = "ZEEK_JSON"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(
    frozen=True,
    slots=True,
)
class EvidenceClassification:
    family: AdapterFamily
    reason: str


@dataclass(
    frozen=True,
    slots=True,
)
class EvidenceFileIntake:
    artifact: Artifact
    adapter_family: AdapterFamily

    canonical_events: tuple[
        CanonicalEvent,
        ...,
    ] = ()

    evidence_locators: tuple[
        EvidenceLocator,
        ...,
    ] = ()

    derived_artifacts: tuple[
        Artifact,
        ...,
    ] = ()

    native_observations: tuple[
        object,
        ...,
    ] = ()

    issue_count: int = 0

    errors: tuple[
        str,
        ...,
    ] = ()

    @property
    def logical_source(
        self,
    ) -> str:
        return (
            self.artifact.source_path_display
        )


@dataclass(
    frozen=True,
    slots=True,
)
class EvidenceDirectoryIntake:
    root_display_name: str

    items: tuple[
        EvidenceFileIntake,
        ...,
    ]

    def __post_init__(
        self,
    ) -> None:
        logical_sources = tuple(
            item.logical_source
            for item in self.items
        )

        if len(
            set(
                logical_sources
            )
        ) != len(
            logical_sources
        ):
            raise ValueError(
                "directory intake contains duplicate logical sources"
            )

        if logical_sources != tuple(
            sorted(
                logical_sources
            )
        ):
            raise ValueError(
                "directory intake items must be deterministically sorted"
            )

        if (
            self.accounted_artifact_count
            != self.discovered_artifact_count
        ):
            raise ValueError(
                "directory intake artifact accounting is incomplete"
            )

    @property
    def discovered_artifact_count(
        self,
    ) -> int:
        return len(
            self.items
        )

    @property
    def supported_processed_count(
        self,
    ) -> int:
        return sum(
            item.artifact.processing_state
            is ArtifactProcessingState.SUPPORTED_PROCESSED
            for item in self.items
        )

    @property
    def supported_partial_count(
        self,
    ) -> int:
        return sum(
            item.artifact.processing_state
            is ArtifactProcessingState.SUPPORTED_PARTIAL
            for item in self.items
        )

    @property
    def unsupported_preserved_count(
        self,
    ) -> int:
        return sum(
            item.artifact.processing_state
            is ArtifactProcessingState.UNSUPPORTED_PRESERVED
            for item in self.items
        )

    @property
    def malformed_quarantined_count(
        self,
    ) -> int:
        return sum(
            item.artifact.processing_state
            is ArtifactProcessingState.MALFORMED_QUARANTINED
            for item in self.items
        )

    @property
    def failed_explicit_count(
        self,
    ) -> int:
        return sum(
            item.artifact.processing_state
            is ArtifactProcessingState.FAILED_EXPLICIT
            for item in self.items
        )

    @property
    def accounted_artifact_count(
        self,
    ) -> int:
        return (
            self.supported_processed_count
            + self.supported_partial_count
            + self.unsupported_preserved_count
            + self.malformed_quarantined_count
            + self.failed_explicit_count
        )


def _sha256(
    value: bytes,
) -> str:
    return hashlib.sha256(
        value
    ).hexdigest()


def _new_discovered_artifact(
    *,
    raw_bytes: bytes,
    logical_source: str,
    acquired_or_observed_utc: datetime,
) -> Artifact:
    return Artifact.create(
        artifact_type=(
            GENERIC_ARTIFACT_TYPE
        ),
        source_path_display=(
            logical_source
        ),
        sha256=_sha256(
            raw_bytes
        ),
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
            ArtifactProcessingState.FAILED_EXPLICIT
        ),
    )


def classify_evidence_bytes(
    *,
    raw_bytes: bytes,
    logical_source: str,
) -> EvidenceClassification:
    if not isinstance(
        raw_bytes,
        bytes,
    ):
        raise TypeError(
            "raw_bytes must be bytes"
        )

    suffix = (
        Path(
            logical_source
        ).suffix.lower()
    )

    if suffix == ".eml":
        return EvidenceClassification(
            family=(
                AdapterFamily.EMAIL
            ),
            reason=(
                "eml_extension"
            ),
        )

    if raw_bytes[:4] == _PCAPNG_MAGIC:
        return EvidenceClassification(
            family=(
                AdapterFamily.PCAPNG
            ),
            reason=(
                "pcapng_section_header_magic"
            ),
        )

    if suffix == ".pcapng":
        return EvidenceClassification(
            family=(
                AdapterFamily.PCAPNG
            ),
            reason=(
                "pcapng_extension"
            ),
        )
    if (
        raw_bytes[:4]
        in _CLASSIC_PCAP_MAGIC
    ):
        return EvidenceClassification(
            family=(
                AdapterFamily.PCAP
            ),
            reason=(
                "classic_pcap_magic"
            ),
        )

    if suffix == ".pcap":
        return EvidenceClassification(
            family=(
                AdapterFamily.PCAP
            ),
            reason=(
                "pcap_extension"
            ),
        )


    if suffix in {
        ".json",
        ".jsonl",
    }:
        providers = (
            probe_windows_event_json_providers(
                raw_bytes=raw_bytes,
                logical_source=(
                    logical_source
                ),
            )
        )

        zeek_conn_json = (
            probe_zeek_conn_json(
                raw_bytes=raw_bytes,
                logical_source=(
                    logical_source
                ),
            )
        )

        if providers and zeek_conn_json:
            return EvidenceClassification(
                family=(
                    AdapterFamily.UNSUPPORTED
                ),
                reason=(
                    "ambiguous_json_source_profile"
                ),
            )

        if len(
            providers
        ) > 1:
            return EvidenceClassification(
                family=(
                    AdapterFamily.UNSUPPORTED
                ),
                reason=(
                    "ambiguous_windows_event_json_provider"
                ),
            )

        if providers == (
            "Microsoft-Windows-PowerShell",
        ):
            return EvidenceClassification(
                family=(
                    AdapterFamily.POWERSHELL_JSON
                ),
                reason=(
                    "powershell_windows_event_json_profile"
                ),
            )

        if providers == (
            "Microsoft-Windows-Sysmon",
        ):
            return EvidenceClassification(
                family=(
                    AdapterFamily.SYSMON_JSON
                ),
                reason=(
                    "sysmon_windows_event_json_profile"
                ),
            )

        if providers == (
            WINDOWS_SECURITY_PROVIDER,
        ):
            return EvidenceClassification(
                family=(
                    AdapterFamily.WINDOWS_SECURITY_JSON
                ),
                reason=(
                    "windows_security_windows_event_json_profile"
                ),
            )

        if zeek_conn_json:
            return EvidenceClassification(
                family=(
                    AdapterFamily.ZEEK_JSON
                ),
                reason=(
                    "zeek_native_conn_json_profile"
                ),
            )

        if providers:
            return EvidenceClassification(
                family=(
                    AdapterFamily.UNSUPPORTED
                ),
                reason=(
                    "windows_event_json_provider_not_supported"
                ),
            )

        return EvidenceClassification(
            family=(
                AdapterFamily.UNSUPPORTED
            ),
            reason=(
                "no_supported_json_profile"
            ),
        )

    sample = raw_bytes[
        :65536
    ]

    # Provider strings alone are not sufficient proof of a Windows
    # Event XML representation. Splunk Security exports legitimately
    # contain SourceName=Microsoft-Windows-Security-Auditing.
    #
    # Require a structural XML lead before any XML provider route is
    # eligible. This keeps representation classification independent
    # from semantic provider metadata embedded in another format.
    xml_lead = raw_bytes.lstrip(
        b"\xef\xbb\xbf \t\r\n"
    )

    windows_event_xml_candidate = (
        xml_lead.startswith(
            b"<Event"
        )
        or xml_lead.startswith(
            b"<?xml"
        )
    )

    # Provider-signature ambiguity is evaluated independently of the
    # representation. Multiple incompatible Windows provider signatures
    # must always fail closed rather than being guessed.
    raw_powershell_provider = (
        b"Microsoft-Windows-PowerShell"
        in sample
    )

    raw_sysmon_provider = (
        b"Microsoft-Windows-Sysmon"
        in sample
    )

    raw_security_provider = (
        WINDOWS_SECURITY_PROVIDER.encode(
            "ascii"
        )
        in sample
    )

    provider_count = sum(
        (
            raw_powershell_provider,
            raw_sysmon_provider,
            raw_security_provider,
        )
    )

    # A single provider signature becomes eligible for an XML adapter
    # only after the bytes have independently satisfied the structural
    # Windows Event XML gate.
    powershell_provider = (
        windows_event_xml_candidate
        and raw_powershell_provider
    )

    sysmon_provider = (
        windows_event_xml_candidate
        and raw_sysmon_provider
    )

    security_provider = (
        windows_event_xml_candidate
        and raw_security_provider
    )

    if provider_count > 1:
        return EvidenceClassification(
            family=(
                AdapterFamily.UNSUPPORTED
            ),
            reason=(
                "ambiguous_windows_event_provider"
            ),
        )

    if powershell_provider:
        return EvidenceClassification(
            family=(
                AdapterFamily.POWERSHELL_XML
            ),
            reason=(
                "powershell_provider"
            ),
        )

    if sysmon_provider:
        return EvidenceClassification(
            family=(
                AdapterFamily.SYSMON_XML
            ),
            reason=(
                "sysmon_provider"
            ),
        )

    if security_provider:
        return EvidenceClassification(
            family=(
                AdapterFamily.WINDOWS_SECURITY_XML
            ),
            reason=(
                "windows_security_provider"
            ),
        )

    stripped = raw_bytes.lstrip(
        b"\xef\xbb\xbf \t\r\n"
    )

    zeek_signature = (
        stripped.startswith(
            b"#separator"
        )
        and b"#fields" in sample
    )

    windows_security_signature = (
        b"LogName=Security"
        in sample
        and b"EventCode="
        in sample
    )

    if (
        zeek_signature
        and windows_security_signature
    ):
        return EvidenceClassification(
            family=(
                AdapterFamily.UNSUPPORTED
            ),
            reason=(
                "ambiguous_text_source_signature"
            ),
        )

    if zeek_signature:
        return EvidenceClassification(
            family=(
                AdapterFamily.ZEEK_ASCII
            ),
            reason=(
                "zeek_declared_header"
            ),
        )

    if windows_security_signature:
        return EvidenceClassification(
            family=(
                AdapterFamily.WINDOWS_SECURITY_SPLUNK
            ),
            reason=(
                "windows_security_splunk_fields"
            ),
        )

    return EvidenceClassification(
        family=(
            AdapterFamily.UNSUPPORTED
        ),
        reason=(
            "no_supported_source_signature"
        ),
    )


def _verify_raw_locator(
    *,
    locator: RawLocator,
    artifact_bytes: bytes,
) -> None:
    if not isinstance(
        locator,
        RawLocator,
    ):
        raise ValueError(
            "provenance is not RawLocator"
        )

    if (
        locator.byte_offset is None
        or locator.byte_length is None
    ):
        raise ValueError(
            "record locator lacks exact byte range"
        )

    start = (
        locator.byte_offset
    )

    length = (
        locator.byte_length
    )

    end = (
        start
        + length
    )

    if (
        start < 0
        or length < 0
        or end > len(
            artifact_bytes
        )
    ):
        raise ValueError(
            "record locator range exceeds artifact bounds"
        )

    selected = artifact_bytes[
        start:end
    ]

    if (
        _sha256(
            selected
        )
        != locator.raw_sha256
    ):
        raise ValueError(
            "record locator hash does not match artifact bytes"
        )


def _batch_state(
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


def _legacy_batch_intake(
    *,
    path: Path,
    logical_source: str,
    raw_before: bytes,
    discovered_artifact: Artifact,
    source_type: SourceType,
    artifact_type: str,
    adapter_family: AdapterFamily,
    loader: Callable[..., object],
) -> EvidenceFileIntake:
    batch = loader(
        path,
        logical_source=logical_source,
    )

    raw_after = (
        path.read_bytes()
    )

    if raw_after != raw_before:
        raise EvidenceMutationError(
            "evidence file changed during adapter execution"
        )

    if (
        getattr(
            batch,
            "source_type",
            None,
        )
        is not source_type
    ):
        raise ValueError(
            "adapter returned unexpected source_type"
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
        _batch_state(
            accepted_count=(
                len(
                    accepted
                )
            ),
            quarantined_count=(
                len(
                    quarantined
                )
            ),
        )
    )

    artifact = replace(
        discovered_artifact,
        artifact_type=(
            artifact_type
        ),
        processing_state=(
            state
        ),
    )

    canonical_events: list[
        CanonicalEvent
    ] = []

    locators: list[
        EvidenceLocator
    ] = []

    for event in accepted:
        if not isinstance(
            event,
            CanonicalEvent,
        ):
            raise ValueError(
                "accepted record is not CanonicalEvent"
            )

        if (
            event.source_type
            is not source_type
        ):
            raise ValueError(
                "CanonicalEvent source_type mismatch"
            )

        _verify_raw_locator(
            locator=(
                event.provenance
            ),
            artifact_bytes=(
                raw_before
            ),
        )

        canonical_events.append(
            event
        )

        locators.append(
            EvidenceLocator.from_raw_locator(
                artifact=artifact,
                locator=(
                    event.provenance
                ),
            )
        )

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
            raise ValueError(
                "quarantined record lacks RawLocator"
            )

        _verify_raw_locator(
            locator=locator,
            artifact_bytes=(
                raw_before
            ),
        )

        locators.append(
            EvidenceLocator.from_raw_locator(
                artifact=artifact,
                locator=locator,
            )
        )

    return EvidenceFileIntake(
        artifact=artifact,
        adapter_family=(
            adapter_family
        ),
        canonical_events=tuple(
            canonical_events
        ),
        evidence_locators=tuple(
            locators
        ),
        issue_count=len(
            quarantined
        ),
        errors=errors,
    )


def _assert_same_artifact_identity(
    *,
    discovered: Artifact,
    returned: Artifact,
) -> None:
    if (
        discovered.artifact_id
        != returned.artifact_id
        or discovered.sha256
        != returned.sha256
        or discovered.bytes
        != returned.bytes
        or discovered.source_path_display
        != returned.source_path_display
    ):
        raise ValueError(
            "adapter artifact identity differs "
            "from discovery artifact identity"
        )


def ingest_evidence_file(
    path: Path,
    *,
    root: Path,
    acquired_or_observed_utc: datetime,
) -> EvidenceFileIntake:
    if not isinstance(
        path,
        Path,
    ):
        raise TypeError(
            "path must be pathlib.Path"
        )

    if not isinstance(
        root,
        Path,
    ):
        raise TypeError(
            "root must be pathlib.Path"
        )

    if path.is_symlink():
        raise ValueError(
            "symbolic-link evidence inputs are not supported"
        )

    if not path.is_file():
        raise FileNotFoundError(
            str(
                path
            )
        )

    try:
        relative = path.relative_to(
            root
        )
    except ValueError as exc:
        raise ValueError(
            "evidence path is outside intake root"
        ) from exc

    logical_source = (
        relative.as_posix()
    )

    raw_before = (
        path.read_bytes()
    )

    discovered = (
        _new_discovered_artifact(
            raw_bytes=(
                raw_before
            ),
            logical_source=(
                logical_source
            ),
            acquired_or_observed_utc=(
                acquired_or_observed_utc
            ),
        )
    )

    classification = (
        classify_evidence_bytes(
            raw_bytes=(
                raw_before
            ),
            logical_source=(
                logical_source
            ),
        )
    )

    family = (
        classification.family
    )

    try:
        if (
            family
            is AdapterFamily.EMAIL
        ):
            native = load_eml_bytes(
                raw_bytes=(
                    raw_before
                ),
                source_path_display=(
                    logical_source
                ),
                acquired_or_observed_utc=(
                    acquired_or_observed_utc
                ),
            )

            _assert_same_artifact_identity(
                discovered=(
                    discovered
                ),
                returned=(
                    native.artifact
                ),
            )

            observations: list[
                object
            ] = []

            locators: list[
                EvidenceLocator
            ] = []

            if (
                native.message
                is not None
            ):
                observations.append(
                    native.message
                )

                locators.append(
                    native.message.locator
                )

            for part in native.parts:
                observations.append(
                    part
                )

                locators.append(
                    part.locator
                )

            result = (
                EvidenceFileIntake(
                    artifact=(
                        native.artifact
                    ),
                    adapter_family=(
                        family
                    ),
                    evidence_locators=tuple(
                        locators
                    ),
                    derived_artifacts=(
                        native.derived_artifacts
                    ),
                    native_observations=tuple(
                        observations
                    ),
                    issue_count=len(
                        native.errors
                    ),
                    errors=(
                        native.errors
                    ),
                )
            )

        elif (
            family
            in {
                AdapterFamily.PCAP,
                AdapterFamily.PCAPNG,
            }
        ):
            packet_loader = (
                load_pcap_bytes
                if family is AdapterFamily.PCAP
                else load_pcapng_bytes
            )

            native = packet_loader(
                raw_bytes=(
                    raw_before
                ),
                source_path_display=(
                    logical_source
                ),
                acquired_or_observed_utc=(
                    acquired_or_observed_utc
                ),
            )

            _assert_same_artifact_identity(
                discovered=(
                    discovered
                ),
                returned=(
                    native.artifact
                ),
            )

            locators = tuple(
                packet.locator
                for packet
                in native.packets
            ) + tuple(
                issue.locator
                for issue
                in native.issues
            )

            result = (
                EvidenceFileIntake(
                    artifact=(
                        native.artifact
                    ),
                    adapter_family=(
                        family
                    ),
                    evidence_locators=(
                        locators
                    ),
                    native_observations=(
                        native.packets
                    ),
                    issue_count=len(
                        native.issues
                    ),
                    errors=(
                        native.errors
                    ),
                )
            )

        elif (
            family
            is AdapterFamily.POWERSHELL_XML
        ):
            native = (
                load_powershell_xml_artifact(
                    path,
                    logical_source=(
                        logical_source
                    ),
                    acquired_or_observed_utc=(
                        acquired_or_observed_utc
                    ),
                )
            )

            _assert_same_artifact_identity(
                discovered=(
                    discovered
                ),
                returned=(
                    native.artifact
                ),
            )

            result = (
                EvidenceFileIntake(
                    artifact=(
                        native.artifact
                    ),
                    adapter_family=(
                        family
                    ),
                    canonical_events=(
                        native.canonical_events
                    ),
                    evidence_locators=(
                        native.event_locators
                        + native.quarantined_locators
                    ),
                    issue_count=(
                        native.quarantined_count
                    ),
                    errors=(
                        native.errors
                    ),
                )
            )


        elif (
            family
            is AdapterFamily.POWERSHELL_JSON
        ):
            result = (
                _legacy_batch_intake(
                    path=path,
                    logical_source=(
                        logical_source
                    ),
                    raw_before=(
                        raw_before
                    ),
                    discovered_artifact=(
                        discovered
                    ),
                    source_type=(
                        SourceType.POWERSHELL
                    ),
                    artifact_type=(
                        WINDOWS_EVENT_JSON_ARTIFACT_TYPE
                    ),
                    adapter_family=(
                        family
                    ),
                    loader=(
                        load_powershell_windows_event_json
                    ),
                )
            )

        elif (
            family
            is AdapterFamily.SYSMON_XML
        ):
            native = (
                load_sysmon_xml_artifact(
                    path,
                    logical_source=(
                        logical_source
                    ),
                    acquired_or_observed_utc=(
                        acquired_or_observed_utc
                    ),
                )
            )

            _assert_same_artifact_identity(
                discovered=(
                    discovered
                ),
                returned=(
                    native.artifact
                ),
            )

            result = (
                EvidenceFileIntake(
                    artifact=(
                        native.artifact
                    ),
                    adapter_family=(
                        family
                    ),
                    canonical_events=(
                        native.canonical_events
                    ),
                    evidence_locators=(
                        native.event_locators
                        + native.quarantined_locators
                    ),
                    issue_count=(
                        native.quarantined_count
                    ),
                    errors=(
                        native.errors
                    ),
                )
            )


        elif (
            family
            is AdapterFamily.SYSMON_JSON
        ):
            result = (
                _legacy_batch_intake(
                    path=path,
                    logical_source=(
                        logical_source
                    ),
                    raw_before=(
                        raw_before
                    ),
                    discovered_artifact=(
                        discovered
                    ),
                    source_type=(
                        SourceType.SYSMON
                    ),
                    artifact_type=(
                        WINDOWS_EVENT_JSON_ARTIFACT_TYPE
                    ),
                    adapter_family=(
                        family
                    ),
                    loader=(
                        load_sysmon_windows_event_json
                    ),
                )
            )


        elif (
            family
            is AdapterFamily.WINDOWS_SECURITY_XML
        ):
            result = (
                _legacy_batch_intake(
                    path=path,
                    logical_source=(
                        logical_source
                    ),
                    raw_before=(
                        raw_before
                    ),
                    discovered_artifact=(
                        discovered
                    ),
                    source_type=(
                        SourceType.WINDOWS_SECURITY
                    ),
                    artifact_type=(
                        WINDOWS_SECURITY_ARTIFACT_TYPE
                    ),
                    adapter_family=(
                        family
                    ),
                    loader=(
                        load_windows_security_windows_event_xml
                    ),
                )
            )

        elif (
            family
            is AdapterFamily.WINDOWS_SECURITY_JSON
        ):
            result = (
                _legacy_batch_intake(
                    path=path,
                    logical_source=(
                        logical_source
                    ),
                    raw_before=(
                        raw_before
                    ),
                    discovered_artifact=(
                        discovered
                    ),
                    source_type=(
                        SourceType.WINDOWS_SECURITY
                    ),
                    artifact_type=(
                        WINDOWS_SECURITY_ARTIFACT_TYPE
                    ),
                    adapter_family=(
                        family
                    ),
                    loader=(
                        load_windows_security_windows_event_json
                    ),
                )
            )

        elif (
            family
            is AdapterFamily.WINDOWS_SECURITY_SPLUNK
        ):
            result = (
                _legacy_batch_intake(
                    path=path,
                    logical_source=(
                        logical_source
                    ),
                    raw_before=(
                        raw_before
                    ),
                    discovered_artifact=(
                        discovered
                    ),
                    source_type=(
                        SourceType.WINDOWS_SECURITY
                    ),
                    artifact_type=(
                        WINDOWS_SECURITY_ARTIFACT_TYPE
                    ),
                    adapter_family=(
                        family
                    ),
                    loader=(
                        load_windows_security_splunk
                    ),
                )
            )


        elif (
            family
            is AdapterFamily.ZEEK_JSON
        ):
            result = (
                _legacy_batch_intake(
                    path=path,
                    logical_source=(
                        logical_source
                    ),
                    raw_before=(
                        raw_before
                    ),
                    discovered_artifact=(
                        discovered
                    ),
                    source_type=(
                        SourceType.ZEEK
                    ),
                    artifact_type=(
                        ZEEK_JSON_ARTIFACT_TYPE
                    ),
                    adapter_family=(
                        family
                    ),
                    loader=(
                        load_zeek_conn_native_json
                    ),
                )
            )

        elif (
            family
            is AdapterFamily.ZEEK_ASCII
        ):
            result = (
                _legacy_batch_intake(
                    path=path,
                    logical_source=(
                        logical_source
                    ),
                    raw_before=(
                        raw_before
                    ),
                    discovered_artifact=(
                        discovered
                    ),
                    source_type=(
                        SourceType.ZEEK
                    ),
                    artifact_type=(
                        ZEEK_ARTIFACT_TYPE
                    ),
                    adapter_family=(
                        family
                    ),
                    loader=(
                        load_zeek_conn_ascii
                    ),
                )
            )

        else:
            result = (
                EvidenceFileIntake(
                    artifact=replace(
                        discovered,
                        processing_state=(
                            ArtifactProcessingState.UNSUPPORTED_PRESERVED
                        ),
                    ),
                    adapter_family=(
                        AdapterFamily.UNSUPPORTED
                    ),
                    errors=(
                        classification.reason,
                    ),
                )
            )

    except EvidenceMutationError:
        raise

    except Exception as exc:
        result = (
            EvidenceFileIntake(
                artifact=replace(
                    discovered,
                    processing_state=(
                        ArtifactProcessingState.FAILED_EXPLICIT
                    ),
                ),
                adapter_family=(
                    family
                ),
                errors=(
                    "adapter_error:"
                    + family.value
                    + ":"
                    + type(
                        exc
                    ).__name__,
                ),
            )
        )

    raw_after = (
        path.read_bytes()
    )

    if raw_after != raw_before:
        raise EvidenceMutationError(
            "evidence file changed during intake"
        )

    return result


def ingest_evidence_directory(
    root: Path,
    *,
    acquired_or_observed_utc: datetime,
) -> EvidenceDirectoryIntake:
    if not isinstance(
        root,
        Path,
    ):
        raise TypeError(
            "root must be pathlib.Path"
        )

    if not root.is_dir():
        raise NotADirectoryError(
            str(
                root
            )
        )

    root = (
        root.resolve()
    )

    discovered_paths: list[
        Path
    ] = []

    for path in root.rglob(
        "*"
    ):
        if path.is_symlink():
            raise ValueError(
                "symbolic-link evidence input encountered: "
                + path.relative_to(
                    root
                ).as_posix()
            )

        if path.is_file():
            discovered_paths.append(
                path
            )

    discovered_paths.sort(
        key=lambda path: (
            path.relative_to(
                root
            ).as_posix()
        )
    )

    items = tuple(
        ingest_evidence_file(
            path,
            root=root,
            acquired_or_observed_utc=(
                acquired_or_observed_utc
            ),
        )
        for path
        in discovered_paths
    )

    return EvidenceDirectoryIntake(
        root_display_name=(
            root.name
        ),
        items=items,
    )
