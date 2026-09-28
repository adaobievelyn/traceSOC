from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Callable

from tracesoc.detection.models import (
    DetectionResult,
)
from tracesoc.detection.powershell_reconstructed import (
    PREAUTH_DISCOVERY_DETECTION_ID,
    PREAUTH_DISCOVERY_DETECTION_VERSION,
    WEB_EXECUTION_DETECTION_ID,
    WEB_EXECUTION_DETECTION_VERSION,
    detect_domain_user_preauth_discovery,
    detect_powershell_web_retrieval_execution,
)
from tracesoc.detection.powershell_web_retrieval import (
    DETECTION_ID as WEB_RETRIEVAL_DETECTION_ID,
    DETECTION_VERSION as WEB_RETRIEVAL_DETECTION_VERSION,
    detect_powershell_web_retrieval,
)
from tracesoc.detection.sysmon_firewall import (
    DETECTION_ID as FIREWALL_DETECTION_ID,
    DETECTION_VERSION as FIREWALL_DETECTION_VERSION,
    detect_sysmon_domain_firewall_zero_write,
)
from tracesoc.detection.sysmon_powershell_behavior import (
    DETECTION_ID_006,
    DETECTION_ID_007,
    DETECTION_ID_008,
    DETECTION_VERSION as SYSMON_POWERSHELL_DETECTION_VERSION,
    detect_powershell_cross_process_access,
    detect_powershell_initiated_network_connection,
    detect_powershell_process_creation,
)
from tracesoc.detection.zeek_irc import (
    DETECTION_ID as ZEEK_IRC_DETECTION_ID,
    DETECTION_VERSION as ZEEK_IRC_DETECTION_VERSION,
    detect_zeek_irc_service,
)


class DetectorRegistryError(
    RuntimeError
):
    pass


class DetectorInputKind(StrEnum):
    SEMANTIC_EVENT = "semantic_event"
    POWERSHELL_SCRIPT_BLOCK = (
        "powershell_script_block"
    )


DetectorEvaluator = Callable[
    [object],
    DetectionResult,
]


@dataclass(
    frozen=True,
    slots=True,
)
class DetectorSpec:
    detection_id: str
    detection_version: str
    input_kind: DetectorInputKind
    evaluator: DetectorEvaluator

    def __post_init__(
        self,
    ) -> None:
        if (
            not isinstance(
                self.detection_id,
                str,
            )
            or not self.detection_id.strip()
        ):
            raise ValueError(
                "detection_id must not be blank"
            )

        if (
            not isinstance(
                self.detection_version,
                str,
            )
            or not self.detection_version.strip()
        ):
            raise ValueError(
                "detection_version must not be blank"
            )

        if not isinstance(
            self.input_kind,
            DetectorInputKind,
        ):
            raise TypeError(
                "input_kind must be DetectorInputKind"
            )

        if not callable(
            self.evaluator
        ):
            raise TypeError(
                "evaluator must be callable"
            )

    def evaluate(
        self,
        value: object,
    ) -> DetectionResult:
        result = self.evaluator(
            value
        )

        if not isinstance(
            result,
            DetectionResult,
        ):
            raise DetectorRegistryError(
                self.detection_id
                + " returned a non-DetectionResult value"
            )

        if (
            result.detection_id
            != self.detection_id
        ):
            raise DetectorRegistryError(
                self.detection_id
                + " returned unexpected detection_id "
                + result.detection_id
            )

        if (
            result.detection_version
            != self.detection_version
        ):
            raise DetectorRegistryError(
                self.detection_id
                + " returned unexpected detection_version "
                + result.detection_version
            )

        return result


DET001 = DetectorSpec(
    detection_id=(
        WEB_RETRIEVAL_DETECTION_ID
    ),
    detection_version=(
        WEB_RETRIEVAL_DETECTION_VERSION
    ),
    input_kind=(
        DetectorInputKind.SEMANTIC_EVENT
    ),
    evaluator=(
        detect_powershell_web_retrieval
    ),
)

DET002 = DetectorSpec(
    detection_id=(
        WEB_EXECUTION_DETECTION_ID
    ),
    detection_version=(
        WEB_EXECUTION_DETECTION_VERSION
    ),
    input_kind=(
        DetectorInputKind.POWERSHELL_SCRIPT_BLOCK
    ),
    evaluator=(
        detect_powershell_web_retrieval_execution
    ),
)

DET003 = DetectorSpec(
    detection_id=(
        PREAUTH_DISCOVERY_DETECTION_ID
    ),
    detection_version=(
        PREAUTH_DISCOVERY_DETECTION_VERSION
    ),
    input_kind=(
        DetectorInputKind.POWERSHELL_SCRIPT_BLOCK
    ),
    evaluator=(
        detect_domain_user_preauth_discovery
    ),
)

DET004 = DetectorSpec(
    detection_id=(
        ZEEK_IRC_DETECTION_ID
    ),
    detection_version=(
        ZEEK_IRC_DETECTION_VERSION
    ),
    input_kind=(
        DetectorInputKind.SEMANTIC_EVENT
    ),
    evaluator=(
        detect_zeek_irc_service
    ),
)

DET005 = DetectorSpec(
    detection_id=(
        FIREWALL_DETECTION_ID
    ),
    detection_version=(
        FIREWALL_DETECTION_VERSION
    ),
    input_kind=(
        DetectorInputKind.SEMANTIC_EVENT
    ),
    evaluator=(
        detect_sysmon_domain_firewall_zero_write
    ),
)

DET006 = DetectorSpec(
    detection_id=(
        DETECTION_ID_006
    ),
    detection_version=(
        SYSMON_POWERSHELL_DETECTION_VERSION
    ),
    input_kind=(
        DetectorInputKind.SEMANTIC_EVENT
    ),
    evaluator=(
        detect_powershell_process_creation
    ),
)

DET007 = DetectorSpec(
    detection_id=(
        DETECTION_ID_007
    ),
    detection_version=(
        SYSMON_POWERSHELL_DETECTION_VERSION
    ),
    input_kind=(
        DetectorInputKind.SEMANTIC_EVENT
    ),
    evaluator=(
        detect_powershell_initiated_network_connection
    ),
)

DET008 = DetectorSpec(
    detection_id=(
        DETECTION_ID_008
    ),
    detection_version=(
        SYSMON_POWERSHELL_DETECTION_VERSION
    ),
    input_kind=(
        DetectorInputKind.SEMANTIC_EVENT
    ),
    evaluator=(
        detect_powershell_cross_process_access
    ),
)


ALL_DETECTORS: tuple[
    DetectorSpec,
    ...,
] = (
    DET001,
    DET002,
    DET003,
    DET004,
    DET005,
    DET006,
    DET007,
    DET008,
)


def _validate_registry() -> None:
    identifiers = tuple(
        spec.detection_id
        for spec
        in ALL_DETECTORS
    )

    if identifiers != (
        "TRC-DET-001",
        "TRC-DET-002",
        "TRC-DET-003",
        "TRC-DET-004",
        "TRC-DET-005",
        "TRC-DET-006",
        "TRC-DET-007",
        "TRC-DET-008",
    ):
        raise DetectorRegistryError(
            "detector identity contract changed"
        )

    if len(
        set(
            identifiers
        )
    ) != len(
        identifiers
    ):
        raise DetectorRegistryError(
            "duplicate detector IDs"
        )


_validate_registry()


SEMANTIC_EVENT_DETECTORS: tuple[
    DetectorSpec,
    ...,
] = tuple(
    spec
    for spec
    in ALL_DETECTORS
    if (
        spec.input_kind
        is DetectorInputKind.SEMANTIC_EVENT
    )
)


POWERSHELL_SCRIPT_BLOCK_DETECTORS: tuple[
    DetectorSpec,
    ...,
] = tuple(
    spec
    for spec
    in ALL_DETECTORS
    if (
        spec.input_kind
        is DetectorInputKind.POWERSHELL_SCRIPT_BLOCK
    )
)


def get_detector_spec(
    detection_id: str,
) -> DetectorSpec:
    if not isinstance(
        detection_id,
        str,
    ):
        raise TypeError(
            "detection_id must be str"
        )

    for spec in ALL_DETECTORS:
        if (
            spec.detection_id
            == detection_id
        ):
            return spec

    raise KeyError(
        detection_id
    )


def evaluate_semantic_event(
    event: object,
) -> tuple[
    DetectionResult,
    ...,
]:
    """
    Evaluate the normalized-event detector family.

    The registry performs no source-path, fixture, scenario, answer,
    expected-outcome, or case-name selection. Each detector receives
    the same normalized event and retains its own existing semantic
    guards.
    """

    return tuple(
        spec.evaluate(
            event
        )
        for spec
        in SEMANTIC_EVENT_DETECTORS
    )


def evaluate_powershell_script_block(
    script_block: object,
) -> tuple[
    DetectionResult,
    ...,
]:
    """
    Evaluate detectors whose established contract consumes one
    reconstructed PowerShell ScriptBlock.

    Reconstruction remains outside the detector registry. The registry
    does not synthesize, complete, or reinterpret ScriptBlock evidence.
    """

    return tuple(
        spec.evaluate(
            script_block
        )
        for spec
        in POWERSHELL_SCRIPT_BLOCK_DETECTORS
    )
