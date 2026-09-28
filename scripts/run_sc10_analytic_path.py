from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

import tracesoc
from tracesoc.cli.explain import explain_finding
from tracesoc.correlation.web_retrieval_network import (
    correlate_web_retrieval_with_zeek,
)
from tracesoc.models import SemanticEvent, SourceType
from tracesoc.multisource_scenarios import (
    load_scenario_components,
    write_scenario_result,
)


SCHEMA_VERSION = "tracesoc-sc10-analytic-path-v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        + "\n"
    ).encode(
        "utf-8"
    )


def _enum_token(value: object) -> str:
    if value is None:
        return ""

    candidate = getattr(
        value,
        "value",
        None,
    )

    if candidate is not None:
        return str(
            candidate
        ).strip().upper()

    candidate = getattr(
        value,
        "name",
        None,
    )

    if candidate is not None:
        return str(
            candidate
        ).strip().upper()

    return str(
        value
    ).strip().upper()


def _is_match(value: object) -> bool:
    matched = getattr(
        value,
        "matched",
        None,
    )

    if matched is not None:
        return bool(
            matched
        )

    token = _enum_token(
        getattr(
            value,
            "state",
            None,
        )
    )

    return token in {
        "MATCH",
        "MATCHED",
        "CORRELATED",
    }


def _component_values(
    value: object,
) -> list[object]:
    if dataclasses.is_dataclass(
        value
    ):
        return [
            getattr(
                value,
                field.name,
            )
            for field in dataclasses.fields(
                value
            )
        ]

    mapping = getattr(
        value,
        "__dict__",
        None,
    )

    if isinstance(
        mapping,
        dict,
    ):
        return list(
            mapping.values()
        )

    return []


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--repo",
        required=True,
    )

    parser.add_argument(
        "--output-dir",
        required=True,
    )

    args = parser.parse_args()

    repo = Path(
        args.repo
    ).resolve()

    output_dir = Path(
        args.output_dir
    ).resolve()

    if output_dir.exists():
        if any(
            output_dir.iterdir()
        ):
            raise SystemExit(
                "STOP: SC10 analytic output directory is not empty."
            )
    else:
        output_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

    installed_package = Path(
        tracesoc.__file__
    ).resolve()

    source_tree = (
        repo
        / "src"
        / "tracesoc"
    ).resolve()

    try:
        installed_package.relative_to(
            source_tree
        )
    except ValueError:
        pass
    else:
        raise SystemExit(
            "STOP: TraceSOC imported from repository src instead of installed package."
        )

    print(
        "SC10_INSTALLED_PACKAGE_PATH="
        + str(
            installed_package
        )
    )

    print(
        "SC10_INSTALL=PASS"
    )

    # ------------------------------------------------------
    # INGEST
    # ------------------------------------------------------

    components = load_scenario_components(
        repo
    )

    component_values = _component_values(
        components
    )

    semantic_events = [
        value
        for value in component_values
        if isinstance(
            value,
            SemanticEvent,
        )
    ]

    if not semantic_events:
        raise SystemExit(
            "STOP: controlled scenario produced no SemanticEvent objects."
        )

    print(
        "SC10_INGEST_EVENT_COUNT="
        + str(
            len(
                semantic_events
            )
        )
    )

    print(
        "SC10_INGEST=PASS"
    )

    # ------------------------------------------------------
    # DETECT
    # ------------------------------------------------------

    detection = getattr(
        components,
        "detection",
        None,
    )

    if detection is None:
        raise SystemExit(
            "STOP: ScenarioComponents lacks production detection."
        )

    if not _is_match(
        detection
    ):
        raise SystemExit(
            "STOP: production controlled-scenario detection is not MATCH."
        )

    contributing_ids = tuple(
        getattr(
            detection,
            "contributing_event_ids",
            (),
        )
    )

    if not contributing_ids:
        raise SystemExit(
            "STOP: matched detection lacks contributing event IDs."
        )

    print(
        "SC10_DETECTION_ID="
        + str(
            getattr(
                detection,
                "detection_id",
                "",
            )
        )
    )

    print(
        "SC10_DETECT=PASS"
    )

    # ------------------------------------------------------
    # Select semantic evidence by source type and lineage.
    # No fixture/scenario ID is used as a production selector.
    # ------------------------------------------------------

    powershell_events = [
        event
        for event in semantic_events
        if (
            event.source_type
            == SourceType.POWERSHELL
            and
            event.event_id
            in contributing_ids
        )
    ]

    zeek_events = [
        event
        for event in semantic_events
        if event.source_type
        == SourceType.ZEEK
    ]

    if not powershell_events:
        explicit_powershell = getattr(
            components,
            "powershell_semantic",
            None,
        )

        if isinstance(
            explicit_powershell,
            SemanticEvent,
        ):
            powershell_events = [
                explicit_powershell
            ]

    if not powershell_events:
        raise SystemExit(
            "STOP: no grounded PowerShell semantic event available for correlation."
        )

    if not zeek_events:
        raise SystemExit(
            "STOP: no grounded Zeek semantic event available for correlation."
        )

    # ------------------------------------------------------
    # CORRELATE
    # ------------------------------------------------------

    matched_correlations = []

    for powershell_event in powershell_events:
        for zeek_event in zeek_events:
            correlation = correlate_web_retrieval_with_zeek(
                detection=detection,
                powershell_event=powershell_event,
                zeek_event=zeek_event,
            )

            if _is_match(
                correlation
            ):
                matched_correlations.append(
                    correlation
                )

    if len(
        matched_correlations
    ) != 1:
        raise SystemExit(
            "STOP: expected exactly one bounded production correlation match; observed "
            + str(
                len(
                    matched_correlations
                )
            )
        )

    correlation = matched_correlations[
        0
    ]

    print(
        "SC10_CORRELATION_ID="
        + str(
            getattr(
                correlation,
                "correlation_id",
                "",
            )
        )
    )

    print(
        "SC10_CORRELATE=PASS"
    )

    # ------------------------------------------------------
    # Persist existing controlled scenario result
    # ------------------------------------------------------

    scenario_path = (
        output_dir
        / "scenario-result.json"
    )

    scenario_result = write_scenario_result(
        repo,
        scenario_path,
    )

    if not scenario_path.is_file():
        raise SystemExit(
            "STOP: scenario-result.json was not written."
        )

    # ------------------------------------------------------
    # EXPLAIN
    # FINDING-001 is the grounded controlled vertical slice,
    # not a selector in production detection/correlation.
    # ------------------------------------------------------

    explanation = explain_finding(
        repo=repo,
        finding_id="FINDING-001",
    )

    if not isinstance(
        explanation,
        dict,
    ):
        raise SystemExit(
            "STOP: explain_finding did not return a dictionary."
        )

    explanation_path = (
        output_dir
        / "finding-explanation.json"
    )

    explanation_path.write_bytes(
        _canonical_json(
            explanation
        )
    )

    print(
        "SC10_EXPLAIN=PASS"
    )

    record = {
        "schema_version":
            SCHEMA_VERSION,

        "data_class":
            "CONTROLLED_SYNTHETIC_SCENARIO",

        "installed_package_relpath":
            (
                installed_package.relative_to(
                    repo
                ).as_posix()
                if repo in installed_package.parents
                else (
                    "external-install/"
                    + installed_package.parent.name
                    + "/"
                    + installed_package.name
                )
            ),

        "ingest":
            {
                "status":
                    "PASS",

                "semantic_event_count":
                    len(
                        semantic_events
                    ),
            },

        "detect":
            {
                "status":
                    "PASS",

                "detection_id":
                    str(
                        getattr(
                            detection,
                            "detection_id",
                            "",
                        )
                    ),

                "state":
                    _enum_token(
                        getattr(
                            detection,
                            "state",
                            None,
                        )
                    ),

                "contributing_event_count":
                    len(
                        contributing_ids
                    ),
            },

        "correlate":
            {
                "status":
                    "PASS",

                "correlation_id":
                    str(
                        getattr(
                            correlation,
                            "correlation_id",
                            "",
                        )
                    ),

                "state":
                    _enum_token(
                        getattr(
                            correlation,
                            "state",
                            None,
                        )
                    ),

                "matched_pair_count":
                    len(
                        matched_correlations
                    ),
            },

        "explain":
            {
                "status":
                    "PASS",

                "finding_id":
                    "FINDING-001",

                "output":
                    explanation_path.name,

                "sha256":
                    _sha256(
                        explanation_path
                    ),
            },

        "scenario_result":
            {
                "output":
                    scenario_path.name,

                "sha256":
                    _sha256(
                        scenario_path
                    ),

                "result_type":
                    type(
                        scenario_result
                    ).__name__,
            },

        "stage9a_access":
            False,

        "holdout_access":
            False,

        "real_incident_claim":
            False,
    }

    record_path = (
        output_dir
        / "analytic-path.json"
    )

    record_path.write_bytes(
        _canonical_json(
            record
        )
    )

    print(
        "SC10_ANALYTIC_PATH_SHA256="
        + _sha256(
            record_path
        )
    )

    print(
        "SC10_ANALYTIC_PATH=PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )