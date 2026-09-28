from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from tracesoc.correlation.powershell_process import (
    correlate_powershell_detection_with_sysmon_process,
)
from tracesoc.correlation.web_retrieval_network import (
    correlate_web_retrieval_with_zeek,
)
from tracesoc.detection.powershell_web_retrieval import (
    DETECTION_ID,
    detect_powershell_web_retrieval,
)
from tracesoc.models import SemanticEvent
from tracesoc.parsers.powershell import (
    load_powershell_jsonl,
)
from tracesoc.parsers.sysmon import (
    load_sysmon_jsonl,
)
from tracesoc.parsers.zeek import (
    load_zeek_jsonl,
)


SCENARIO_ID = (
    "MULTISOURCE-SCENARIO-0003"
)

SCENARIO_DIRECTORY = (
    Path("tests")
    / "fixtures"
    / "scenarios"
    / "multisource-three-source-chain-003"
)


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
        / "scenario-manifest.json"
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
            "scenario ID mismatch"
        )

    if (
        value.get("scenario_shape")
        != "THREE_SOURCE_TWO_EDGE_CHAIN"
    ):
        raise ValueError(
            "scenario graph shape mismatch"
        )

    if (
        value.get("real_incident_claim")
        is not False
    ):
        raise ValueError(
            "synthetic scenario cannot claim a real incident"
        )

    return value


def load_components(
    repo: Path | str,
) -> dict[str, Any]:
    repo_path = Path(
        repo
    )

    manifest = _load_manifest(
        repo_path
    )

    generated = manifest[
        "generated_inputs"
    ]

    ps_path = (
        repo_path
        / SCENARIO_DIRECTORY
        / "powershell.jsonl"
    )

    sysmon_path = (
        repo_path
        / SCENARIO_DIRECTORY
        / "sysmon.jsonl"
    )

    zeek_path = (
        repo_path
        / SCENARIO_DIRECTORY
        / "zeek.jsonl"
    )

    for name, path in (
        ("powershell", ps_path),
        ("sysmon", sysmon_path),
        ("zeek", zeek_path),
    ):
        if (
            _sha256_file(
                path
            )
            != generated[name]["sha256"]
        ):
            raise ValueError(
                name
                + " scenario SHA mismatch"
            )

    ps_batch = load_powershell_jsonl(
        ps_path,
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

    zeek_batch = load_zeek_jsonl(
        zeek_path,
        logical_source=generated[
            "zeek"
        ]["logical_source"],
    )

    if len(
        ps_batch.accepted
    ) != 1:
        raise ValueError(
            "expected one accepted PowerShell event"
        )

    if len(
        sysmon_batch.accepted
    ) != 1:
        raise ValueError(
            "expected one accepted Sysmon event"
        )

    if len(
        zeek_batch.accepted
    ) != 1:
        raise ValueError(
            "expected one accepted Zeek event"
        )

    ps_canonical = (
        ps_batch.accepted[0]
    )

    sysmon_canonical = (
        sysmon_batch.accepted[0]
    )

    zeek_canonical = (
        zeek_batch.accepted[0]
    )

    ps_semantic = SemanticEvent.from_canonical(
        ps_canonical
    )

    sysmon_semantic = SemanticEvent.from_canonical(
        sysmon_canonical
    )

    zeek_semantic = SemanticEvent.from_canonical(
        zeek_canonical
    )

    for forbidden_key in (
        "fixture_id",
        "expected_answer",
    ):
        for semantic in (
            ps_semantic,
            sysmon_semantic,
            zeek_semantic,
        ):
            if forbidden_key in semantic.fields:
                raise ValueError(
                    "test metadata crossed semantic boundary"
                )

    detection = detect_powershell_web_retrieval(
        ps_semantic
    )

    process_correlation = (
        correlate_powershell_detection_with_sysmon_process(
            detection=detection,
            powershell_event=ps_semantic,
            sysmon_event=sysmon_semantic,
        )
    )

    network_correlation = (
        correlate_web_retrieval_with_zeek(
            detection=detection,
            powershell_event=ps_semantic,
            zeek_event=zeek_semantic,
        )
    )

    return {
        "manifest": manifest,
        "powershell_canonical": (
            ps_canonical
        ),
        "sysmon_canonical": (
            sysmon_canonical
        ),
        "zeek_canonical": (
            zeek_canonical
        ),
        "powershell_semantic": (
            ps_semantic
        ),
        "sysmon_semantic": (
            sysmon_semantic
        ),
        "zeek_semantic": (
            zeek_semantic
        ),
        "detection": detection,
        "process_correlation": (
            process_correlation
        ),
        "network_correlation": (
            network_correlation
        ),
    }


def evaluate_scenario(
    repo: Path | str,
) -> dict[str, Any]:
    components = load_components(
        repo
    )

    detection = components[
        "detection"
    ]

    process_correlation = components[
        "process_correlation"
    ]

    network_correlation = components[
        "network_correlation"
    ]

    if not detection.matched:
        raise ValueError(
            "DET002 did not match"
        )

    if not process_correlation.matched:
        raise ValueError(
            "TRC-CORR-002 did not match"
        )

    if not network_correlation.matched:
        raise ValueError(
            "TRC-CORR-001 did not match"
        )

    if process_correlation.edge is None:
        raise ValueError(
            "TRC-CORR-002 matched without edge"
        )

    if network_correlation.edge is None:
        raise ValueError(
            "TRC-CORR-001 matched without edge"
        )

    ps_canonical = components[
        "powershell_canonical"
    ]

    sysmon_canonical = components[
        "sysmon_canonical"
    ]

    zeek_canonical = components[
        "zeek_canonical"
    ]

    node_ids = [
        sysmon_canonical.event_id,
        ps_canonical.event_id,
        zeek_canonical.event_id,
    ]

    if len(
        set(node_ids)
    ) != 3:
        raise ValueError(
            "graph requires three distinct event nodes"
        )

    edge_ids = [
        process_correlation.edge.edge_id,
        network_correlation.edge.edge_id,
    ]

    if len(
        set(edge_ids)
    ) != 2:
        raise ValueError(
            "graph requires two distinct edges"
        )

    return {
        "record_type": (
            "tracesoc-multisource-"
            "scenario-result-v1"
        ),
        "schema_version": 1,
        "scenario_id": SCENARIO_ID,
        "classification": (
            "SYNTHETIC_ARCHITECTURE_REGRESSION"
        ),
        "scenario_shape": (
            "THREE_SOURCE_TWO_EDGE_CHAIN"
        ),
        "validation_status": "PASS",
        "real_incident_claim": False,
        "malicious_intent_established": False,
        "causality_established": False,
        "exact_pid_ancestry_established": False,
        "expected_answer_used_as_selector": False,
        "fixture_id_used_as_selector": False,
        "publisher_label_used_as_selector": False,
        "telemetry_families": [
            "sysmon",
            "powershell",
            "zeek",
        ],
        "graph": {
            "node_count": 3,
            "edge_count": 2,
            "nodes": [
                {
                    "role": (
                        "process_creation"
                    ),
                    "event_id": (
                        sysmon_canonical
                        .event_id
                    ),
                    "logical_source": (
                        sysmon_canonical
                        .provenance
                        .logical_source
                    ),
                    "raw_sha256": (
                        sysmon_canonical
                        .provenance
                        .raw_sha256
                    ),
                },
                {
                    "role": (
                        "detected_behavior"
                    ),
                    "event_id": (
                        ps_canonical
                        .event_id
                    ),
                    "logical_source": (
                        ps_canonical
                        .provenance
                        .logical_source
                    ),
                    "raw_sha256": (
                        ps_canonical
                        .provenance
                        .raw_sha256
                    ),
                },
                {
                    "role": (
                        "network_observation"
                    ),
                    "event_id": (
                        zeek_canonical
                        .event_id
                    ),
                    "logical_source": (
                        zeek_canonical
                        .provenance
                        .logical_source
                    ),
                    "raw_sha256": (
                        zeek_canonical
                        .provenance
                        .raw_sha256
                    ),
                },
            ],
            "edges": [
                {
                    "correlation_id": (
                        "TRC-CORR-002"
                    ),
                    "edge_id": (
                        process_correlation
                        .edge
                        .edge_id
                    ),
                    "source_event_id": (
                        process_correlation
                        .edge
                        .source_event_id
                    ),
                    "target_event_id": (
                        process_correlation
                        .edge
                        .target_event_id
                    ),
                    "reason_code": (
                        process_correlation
                        .reason_code
                    ),
                },
                {
                    "correlation_id": (
                        "TRC-CORR-001"
                    ),
                    "edge_id": (
                        network_correlation
                        .edge
                        .edge_id
                    ),
                    "source_event_id": (
                        network_correlation
                        .edge
                        .source_event_id
                    ),
                    "target_event_id": (
                        network_correlation
                        .edge
                        .target_event_id
                    ),
                    "reason_code": (
                        network_correlation
                        .reason_code
                    ),
                },
            ],
            "shared_middle_event_id": (
                ps_canonical.event_id
            ),
        },
        "detection": {
            "detection_id": (
                DETECTION_ID
            ),
            "matched": True,
        },
        "claim": (
            "A synthetic Sysmon PowerShell process "
            "creation, detected PowerShell retrieval "
            "behavior, and synthetic Zeek network "
            "observation form one reproducible "
            "three-node/two-edge evidence graph under "
            "two independently bounded production "
            "correlation contracts."
        ),
        "alternative_explanation": (
            "The same observable sequence may arise "
            "from legitimate administration, testing, "
            "automation, or software retrieval."
        ),
        "residual_risk": (
            "Causality, exact PID ancestry, malicious "
            "intent, and applicability to independent "
            "real corpora remain not established."
        ),
        "falsifier": (
            "Breaking either the Sysmon-to-PowerShell "
            "correlation contract or the PowerShell-to-"
            "Zeek correlation contract must make the "
            "complete three-source graph invalid."
        ),
        "business_impact": (
            "Unknown for this synthetic scenario; "
            "no real business asset is represented."
        ),
        "claim_boundary": (
            components[
                "manifest"
            ][
                "claim_boundary"
            ]
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
            "multi-source scenario 003."
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
        "VALIDATION_STATUS="
        + result["validation_status"]
    )

    print(
        "GRAPH_NODES="
        + str(
            result["graph"][
                "node_count"
            ]
        )
    )

    print(
        "GRAPH_EDGES="
        + str(
            result["graph"][
                "edge_count"
            ]
        )
    )

    print(
        "TRC_CORR_002_MATCHED=TRUE"
    )

    print(
        "TRC_CORR_001_MATCHED=TRUE"
    )

    print(
        "REAL_INCIDENT_CLAIM=FALSE"
    )

    print(
        "CAUSALITY_ESTABLISHED=FALSE"
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
