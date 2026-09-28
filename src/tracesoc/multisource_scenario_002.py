from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tracesoc.correlation.powershell_process import (
    CORRELATION_ID,
    correlate_powershell_detection_with_sysmon_process,
)
from tracesoc.detection.powershell_web_retrieval import (
    DETECTION_ID,
    detect_powershell_web_retrieval,
)
from tracesoc.models import (
    CanonicalEvent,
    SemanticEvent,
)
from tracesoc.parsers.powershell import (
    load_powershell_jsonl,
)
from tracesoc.parsers.sysmon import (
    load_sysmon_jsonl,
)


SCENARIO_ID = (
    "MULTISOURCE-SCENARIO-0002"
)

SCENARIO_DIRECTORY = (
    Path("tests")
    / "fixtures"
    / "scenarios"
    / "multisource-powershell-process-002"
)

MANIFEST_NAME = (
    "scenario-manifest.json"
)


@dataclass(
    frozen=True,
)
class ScenarioComponents:
    powershell_canonical: CanonicalEvent
    powershell_semantic: SemanticEvent
    detection: Any
    sysmon_canonical: CanonicalEvent
    sysmon_semantic: SemanticEvent
    correlation: Any


def _sha256_file(
    path: Path,
) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def _load_manifest(
    repo: Path,
) -> dict[str, Any]:
    path = (
        repo
        / SCENARIO_DIRECTORY
        / MANIFEST_NAME
    )

    value = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        value,
        dict,
    ):
        raise ValueError(
            "scenario manifest must be an object"
        )

    if (
        value.get("scenario_id")
        != SCENARIO_ID
    ):
        raise ValueError(
            "scenario manifest ID mismatch"
        )

    if (
        value.get("classification")
        != "SYNTHETIC_ARCHITECTURE_REGRESSION"
    ):
        raise ValueError(
            "scenario classification mismatch"
        )

    if (
        value.get("real_incident_claim")
        is not False
    ):
        raise ValueError(
            "synthetic scenario must not claim a real incident"
        )

    return value


def load_scenario_components(
    repo: Path | str,
) -> ScenarioComponents:
    repo_path = Path(repo)

    manifest = _load_manifest(
        repo_path
    )

    generated = manifest[
        "generated_inputs"
    ]

    powershell_path = (
        repo_path
        / SCENARIO_DIRECTORY
        / "powershell.jsonl"
    )

    sysmon_path = (
        repo_path
        / SCENARIO_DIRECTORY
        / "sysmon.jsonl"
    )

    if (
        _sha256_file(
            powershell_path
        )
        != generated["powershell"]["sha256"]
    ):
        raise ValueError(
            "scenario PowerShell SHA mismatch"
        )

    if (
        _sha256_file(
            sysmon_path
        )
        != generated["sysmon"]["sha256"]
    ):
        raise ValueError(
            "scenario Sysmon SHA mismatch"
        )

    powershell_batch = load_powershell_jsonl(
        powershell_path,
        logical_source=generated[
            "powershell"
        ]["logical_source"],
    )

    sysmon_batch = load_sysmon_jsonl(
        sysmon_path,
        logical_source=generated[
            "sysmon"
        ]["logical_source"],
    )

    if len(
        powershell_batch.accepted
    ) != 1:
        raise ValueError(
            "scenario requires one accepted PowerShell event"
        )

    if len(
        sysmon_batch.accepted
    ) != 1:
        raise ValueError(
            "scenario requires one accepted Sysmon event"
        )

    powershell_canonical = (
        powershell_batch.accepted[0]
    )

    sysmon_canonical = (
        sysmon_batch.accepted[0]
    )

    powershell_semantic = (
        SemanticEvent.from_canonical(
            powershell_canonical
        )
    )

    sysmon_semantic = (
        SemanticEvent.from_canonical(
            sysmon_canonical
        )
    )

    for forbidden_key in (
        "fixture_id",
        "expected_answer",
    ):
        if (
            forbidden_key
            in powershell_semantic.fields
        ):
            raise ValueError(
                "PowerShell test metadata crossed semantic boundary"
            )

        if (
            forbidden_key
            in sysmon_semantic.fields
        ):
            raise ValueError(
                "Sysmon test metadata crossed semantic boundary"
            )

    detection = (
        detect_powershell_web_retrieval(
            powershell_semantic
        )
    )

    correlation = (
        correlate_powershell_detection_with_sysmon_process(
            detection=detection,
            powershell_event=(
                powershell_semantic
            ),
            sysmon_event=sysmon_semantic,
        )
    )

    return ScenarioComponents(
        powershell_canonical=(
            powershell_canonical
        ),
        powershell_semantic=(
            powershell_semantic
        ),
        detection=detection,
        sysmon_canonical=(
            sysmon_canonical
        ),
        sysmon_semantic=(
            sysmon_semantic
        ),
        correlation=correlation,
    )


def evaluate_scenario(
    repo: Path | str,
) -> dict[str, Any]:
    repo_path = Path(repo)

    manifest = _load_manifest(
        repo_path
    )

    components = load_scenario_components(
        repo_path
    )

    detection = components.detection
    correlation = components.correlation

    if not detection.matched:
        raise ValueError(
            "scenario detection did not match"
        )

    if not correlation.matched:
        raise ValueError(
            "scenario correlation did not match"
        )

    if correlation.edge is None:
        raise ValueError(
            "matched correlation requires an edge"
        )

    edge = correlation.edge

    return {
        "record_type": (
            "tracesoc-multisource-"
            "scenario-result-v1"
        ),
        "schema_version": 1,
        "scenario_id": SCENARIO_ID,
        "classification": (
            manifest["classification"]
        ),
        "validation_status": "PASS",
        "real_incident_claim": False,
        "malicious_intent_established": False,
        "exact_pid_ancestry_established": False,
        "causality_established": False,
        "publisher_label_used": False,
        "expected_answer_used_as_selector": False,
        "fixture_id_used_as_selector": False,
        "production_selector_hardcoding": False,
        "telemetry_families": [
            "sysmon",
            "powershell",
        ],
        "powershell": {
            "event_id": (
                components
                .powershell_canonical
                .event_id
            ),
            "logical_source": (
                components
                .powershell_canonical
                .provenance
                .logical_source
            ),
            "raw_sha256": (
                components
                .powershell_canonical
                .provenance
                .raw_sha256
            ),
        },
        "sysmon": {
            "event_id": (
                components
                .sysmon_canonical
                .event_id
            ),
            "logical_source": (
                components
                .sysmon_canonical
                .provenance
                .logical_source
            ),
            "raw_sha256": (
                components
                .sysmon_canonical
                .provenance
                .raw_sha256
            ),
        },
        "detection": {
            "detection_id": DETECTION_ID,
            "matched": True,
        },
        "correlation": {
            "correlation_id": (
                CORRELATION_ID
            ),
            "matched": True,
            "reason_code": (
                correlation.reason_code
            ),
            "edge_id": edge.edge_id,
            "source_event_id": (
                edge.source_event_id
            ),
            "target_event_id": (
                edge.target_event_id
            ),
            "delta_seconds": (
                edge.delta_seconds
            ),
            "process_name": (
                edge.process_name
            ),
            "local_ip": edge.local_ip,
            "principal": edge.principal,
            "matched_dimensions": list(
                edge.matched_dimensions
            ),
        },
        "claim": (
            "Synthetic Sysmon process creation "
            "corroborates detected synthetic PowerShell "
            "behavior on the same host, principal, "
            "local IP, process family, and bounded "
            "directional interval."
        ),
        "alternative_explanation": (
            "The PowerShell execution could represent "
            "legitimate administration, automation, "
            "software installation, or testing."
        ),
        "residual_risk": (
            "Exact PID ancestry, causality, malicious "
            "intent, and applicability to independent "
            "real corpora remain not established."
        ),
        "falsifier": (
            "The correlation must not form when host, "
            "principal, local IP, PowerShell process "
            "family, or directional time relationship "
            "does not satisfy the contract."
        ),
        "business_impact": (
            "Unknown for this synthetic scenario; "
            "no real business asset is represented."
        ),
        "claim_boundary": (
            manifest["claim_boundary"]
        ),
    }


def _canonical_bytes(
    value: dict[str, Any],
) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def write_scenario_result(
    repo: Path | str,
    output: Path | str,
) -> dict[str, Any]:
    result = evaluate_scenario(
        repo
    )

    output_path = Path(
        output
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "xb"
    ) as handle:
        handle.write(
            _canonical_bytes(
                result
            )
        )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate TraceSOC controlled "
            "multi-source scenario 002."
        )
    )

    parser.add_argument(
        "--repo",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    args = parser.parse_args()

    result = write_scenario_result(
        args.repo,
        args.output,
    )

    output_sha256 = _sha256_file(
        Path(args.output)
    )

    print(
        "SCENARIO_ID="
        + result["scenario_id"]
    )

    print(
        "CLASSIFICATION="
        + result["classification"]
    )

    print(
        "VALIDATION_STATUS="
        + result["validation_status"]
    )

    print(
        "DETECTION_MATCHED=TRUE"
    )

    print(
        "CORRELATION_MATCHED=TRUE"
    )

    print(
        "CORRELATION_ID="
        + result["correlation"][
            "correlation_id"
        ]
    )

    print(
        "EXACT_PID_ANCESTRY_ESTABLISHED=FALSE"
    )

    print(
        "CAUSALITY_ESTABLISHED=FALSE"
    )

    print(
        "REAL_INCIDENT_CLAIM=FALSE"
    )

    print(
        "RESULT_SHA256="
        + output_sha256
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
