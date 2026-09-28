from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tracesoc.correlation.web_retrieval_network import (
    CORRELATION_ID,
    correlate_web_retrieval_with_zeek,
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
from tracesoc.parsers.zeek import (
    load_zeek_jsonl,
)


SCENARIO_ID = (
    "MULTISOURCE-SCENARIO-0001"
)

SCENARIO_DIRECTORY = (
    Path("tests")
    / "fixtures"
    / "scenarios"
    / "multisource-web-retrieval-001"
)

MANIFEST_NAME = (
    "scenario-manifest.json"
)


@dataclass(frozen=True)
class ScenarioComponents:
    powershell_canonical: CanonicalEvent
    powershell_semantic: SemanticEvent
    detection: Any
    zeek_canonical: CanonicalEvent
    zeek_semantic: SemanticEvent
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

    zeek_path = (
        repo_path
        / SCENARIO_DIRECTORY
        / "zeek.jsonl"
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
            zeek_path
        )
        != generated["zeek"]["sha256"]
    ):
        raise ValueError(
            "scenario Zeek SHA mismatch"
        )

    powershell_batch = load_powershell_jsonl(
        powershell_path,
        logical_source=generated[
            "powershell"
        ]["logical_source"],
    )

    zeek_batch = load_zeek_jsonl(
        zeek_path,
        logical_source=generated[
            "zeek"
        ]["logical_source"],
    )

    if len(
        powershell_batch.accepted
    ) != 1:
        raise ValueError(
            "scenario requires exactly one accepted PowerShell event"
        )

    if len(
        zeek_batch.accepted
    ) != 1:
        raise ValueError(
            "scenario requires exactly one accepted Zeek event"
        )

    powershell_canonical = (
        powershell_batch.accepted[0]
    )

    zeek_canonical = (
        zeek_batch.accepted[0]
    )

    powershell_semantic = (
        SemanticEvent.from_canonical(
            powershell_canonical
        )
    )

    zeek_semantic = (
        SemanticEvent.from_canonical(
            zeek_canonical
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
            in zeek_semantic.fields
        ):
            raise ValueError(
                "Zeek test metadata crossed semantic boundary"
            )

    detection = (
        detect_powershell_web_retrieval(
            powershell_semantic
        )
    )

    correlation = (
        correlate_web_retrieval_with_zeek(
            detection=detection,
            powershell_event=(
                powershell_semantic
            ),
            zeek_event=zeek_semantic,
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
        zeek_canonical=zeek_canonical,
        zeek_semantic=zeek_semantic,
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
        "publisher_label_used": False,
        "expected_answer_used_as_selector": False,
        "fixture_id_used_as_selector": False,
        "production_selector_hardcoding": False,
        "telemetry_families": [
            "powershell",
            "zeek",
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
        "zeek": {
            "event_id": (
                components
                .zeek_canonical
                .event_id
            ),
            "logical_source": (
                components
                .zeek_canonical
                .provenance
                .logical_source
            ),
            "raw_sha256": (
                components
                .zeek_canonical
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
            "destination_ip": (
                edge.destination_ip
            ),
            "destination_port": (
                edge.destination_port
            ),
            "matched_dimensions": list(
                edge.matched_dimensions
            ),
        },
        "claim": (
            "Synthetic PowerShell retrieval behavior "
            "is corroborated by synthetic Zeek network "
            "telemetry under the production bounded "
            "correlation contract."
        ),
        "alternative_explanation": (
            "The same behavior could represent "
            "legitimate scripted administration or "
            "software retrieval."
        ),
        "residual_risk": (
            "Malicious intent and applicability to "
            "independent real corpora remain not established."
        ),
        "falsifier": (
            "The correlation must not form if host, "
            "source IP, URI destination IP/port, or "
            "directional bounded time relationship fails."
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
            "multi-source scenario 001."
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
        "DETECTION_MATCHED="
        + str(
            result["detection"][
                "matched"
            ]
        ).upper()
    )

    print(
        "CORRELATION_MATCHED="
        + str(
            result["correlation"][
                "matched"
            ]
        ).upper()
    )

    print(
        "CORRELATION_ID="
        + result["correlation"][
            "correlation_id"
        ]
    )

    print(
        "REAL_INCIDENT_CLAIM=FALSE"
    )

    print(
        "MALICIOUS_INTENT_ESTABLISHED=FALSE"
    )

    print(
        "EXPECTED_ANSWER_USED_AS_SELECTOR=FALSE"
    )

    print(
        "FIXTURE_ID_USED_AS_SELECTOR=FALSE"
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
