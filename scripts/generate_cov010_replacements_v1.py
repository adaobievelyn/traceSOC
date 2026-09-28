#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


VERSION = "1.0.0"

CONTRACT_FREEZE_COMMIT = (
    "f42e9b122bad5bbef841be47c56d9eb3b275cb94"
)

EXPECTED_CONTRACT_SHA256 = (
    "0fbc57c552b8fddea20a9aa2cdb271ecc8c352338964410389f02a6b8df0b900"
)

EXPECTED_SCENARIO_MANIFEST_SHA256 = (
    "a94f7690432e3d66dc1e5c2abfe12ed8ff8c3f0bdce6a176c511029f316d3dce"
)

CONTRACT_RELATIVE = Path(
    "project-control"
) / "phase4i-cov010-replacement-contracts-v1.json"

PARENT_SELECTION_RELATIVE = Path(
    "project-control"
) / "phase4i-challenge-exact-parent-selection.json"

SCENARIO_DIRECTORY_RELATIVE = (
    Path("tests")
    / "fixtures"
    / "scenarios"
    / "multisource-powershell-process-002"
)

SCENARIO_MANIFEST_RELATIVE = (
    SCENARIO_DIRECTORY_RELATIVE
    / "scenario-manifest.json"
)

SCENARIO_POWERSHELL_RELATIVE = (
    SCENARIO_DIRECTORY_RELATIVE
    / "powershell.jsonl"
)

SCENARIO_SYSMON_RELATIVE = (
    SCENARIO_DIRECTORY_RELATIVE
    / "sysmon.jsonl"
)

DEFAULT_OUTPUT_RELATIVE = (
    Path("tests")
    / "fixtures"
    / "challenges"
    / "cov010-replacements-v1"
)

ORIGINAL_CORPUS_RELATIVE = (
    Path("tests")
    / "fixtures"
    / "challenges"
    / "cov010"
)

REPLACEMENT_IDS = (
    "CHAL-MAL-001-V2",
    "CHAL-TIME-002-V2",
    "CHAL-TIME-003-V2",
)

RECORD_NUMBER_PATTERN = re.compile(
    rb"(?m)^(RecordNumber=)([0-9]+)(\r?)$"
)


def sha256_bytes(
    value: bytes,
) -> str:
    return hashlib.sha256(
        value
    ).hexdigest()


def sha256_file(
    path: Path,
) -> str:
    return sha256_bytes(
        path.read_bytes()
    )


def json_bytes(
    value: Any,
) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode(
        "utf-8"
    )


def jsonl_bytes(
    value: dict[str, Any],
) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode(
        "utf-8"
    )


def load_json(
    path: Path,
) -> Any:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def read_one_jsonl_object(
    path: Path,
) -> dict[str, Any]:
    lines = [
        line
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    if len(
        lines
    ) != 1:
        raise RuntimeError(
            "expected exactly one nonblank JSONL record: "
            + str(
                path
            )
        )

    value = json.loads(
        lines[
            0
        ]
    )

    if not isinstance(
        value,
        dict,
    ):
        raise RuntimeError(
            "JSONL record is not an object: "
            + str(
                path
            )
        )

    return value


def parse_utc_timestamp(
    value: str,
) -> datetime:
    if not isinstance(
        value,
        str,
    ):
        raise RuntimeError(
            "timestamp must be text"
        )

    normalized = value

    if normalized.endswith(
        "Z"
    ):
        normalized = (
            normalized[
                :-1
            ]
            + "+00:00"
        )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )
    except ValueError as exc:
        raise RuntimeError(
            "timestamp is not ISO-8601: "
            + repr(
                value
            )
        ) from exc

    if parsed.tzinfo is None:
        raise RuntimeError(
            "timestamp is timezone-naive: "
            + repr(
                value
            )
        )

    return parsed.astimezone(
        timezone.utc
    )


def format_utc_timestamp(
    value: datetime,
) -> str:
    normalized = value.astimezone(
        timezone.utc
    )

    if normalized.microsecond:
        text = normalized.isoformat(
            timespec="microseconds"
        )
    else:
        text = normalized.isoformat(
            timespec="seconds"
        )

    if not text.endswith(
        "+00:00"
    ):
        raise RuntimeError(
            "UTC formatter produced unexpected offset"
        )

    return (
        text[
            :-6
        ]
        + "Z"
    )


def require(
    condition: bool,
    message: str,
) -> None:
    if not condition:
        raise RuntimeError(
            message
        )


def get_replacement(
    contract: dict[str, Any],
    replacement_id: str,
) -> dict[str, Any]:
    matches = [
        item
        for item in contract.get(
            "replacements",
            [],
        )
        if (
            isinstance(
                item,
                dict,
            )
            and item.get(
                "replacement_id"
            )
            == replacement_id
        )
    ]

    if len(
        matches
    ) != 1:
        raise RuntimeError(
            "replacement contract not uniquely resolved: "
            + replacement_id
        )

    return matches[
        0
    ]


def validate_contract(
    contract: dict[str, Any],
) -> None:
    require(
        contract.get(
            "state"
        )
        == "FROZEN_BEFORE_REPLACEMENT_GENERATION",
        "replacement contract is not frozen before generation",
    )

    replacement_set = contract.get(
        "replacement_set",
        {},
    )

    require(
        replacement_set.get(
            "replacement_set_id"
        )
        == "COV010-RPL-V1",
        "replacement-set identity mismatch",
    )

    require(
        replacement_set.get(
            "root"
        )
        == DEFAULT_OUTPUT_RELATIVE.as_posix(),
        "replacement output root changed",
    )

    require(
        replacement_set.get(
            "challenge_count"
        )
        == 3,
        "replacement challenge denominator changed",
    )

    require(
        replacement_set.get(
            "generated_input_count"
        )
        == 5,
        "replacement input denominator changed",
    )

    require(
        replacement_set.get(
            "expected_generated_file_count"
        )
        == 9,
        "replacement file denominator changed",
    )

    require(
        tuple(
            replacement_set.get(
                "execution_order",
                [],
            )
        )
        == REPLACEMENT_IDS,
        "replacement execution order changed",
    )

    original = contract.get(
        "original_frozen_run",
        {},
    )

    require(
        original.get(
            "frozen_row_denominator"
        )
        == 15,
        "original frozen denominator changed",
    )

    require(
        original.get(
            "observed_rows"
        )
        == 15,
        "original frozen run is not 15/15 observed",
    )

    require(
        original.get(
            "observed_pass_rows"
        )
        == 12,
        "original frozen pass count changed",
    )

    require(
        original.get(
            "preserved_adjudicated_red_rows"
        )
        == [
            7,
            13,
            14,
        ],
        "original frozen RED history changed",
    )

    malformed = get_replacement(
        contract,
        "CHAL-MAL-001-V2",
    )

    malformed_generation = malformed.get(
        "generation_contract",
        {},
    )

    require(
        malformed_generation.get(
            "field"
        )
        == "RecordNumber",
        "Row-7 V2 malformed field changed",
    )

    require(
        malformed_generation.get(
            "replacement_value"
        )
        == "not-a-number",
        "Row-7 V2 replacement value changed",
    )

    require(
        malformed_generation.get(
            "replacement_count"
        )
        == 1,
        "Row-7 V2 mutation cardinality changed",
    )

    parent_ids = malformed.get(
        "original_parent_ids",
        [],
    )

    require(
        isinstance(
            parent_ids,
            list,
        )
        and len(
            parent_ids
        )
        == 1,
        "Row-7 V2 parent denominator changed",
    )

    for replacement_id, expected_delta in (
        (
            "CHAL-TIME-002-V2",
            30.0,
        ),
        (
            "CHAL-TIME-003-V2",
            31.0,
        ),
    ):
        item = get_replacement(
            contract,
            replacement_id,
        )

        generation = item.get(
            "generation_contract",
            {},
        )

        require(
            generation.get(
                "source"
            )
            == "GROUNDED_MULTISOURCE_SCENARIO_002_POSITIVE_PAIR",
            replacement_id
            + " source contract changed",
        )

        require(
            generation.get(
                "powershell_detector"
            )
            == "TRC-DET-001",
            replacement_id
            + " detector contract changed",
        )

        require(
            generation.get(
                "correlation"
            )
            == "TRC-CORR-002",
            replacement_id
            + " correlation contract changed",
        )

        require(
            float(
                generation.get(
                    "directional_delta_seconds"
                )
            )
            == expected_delta,
            replacement_id
            + " directional delta changed",
        )

        require(
            float(
                generation.get(
                    "max_seconds"
                )
            )
            == 30.0,
            replacement_id
            + " maximum correlation window changed",
        )

        require(
            generation.get(
                "preserve_identity_dimensions"
            )
            is True,
            replacement_id
            + " identity-preservation contract changed",
        )

        require(
            generation.get(
                "preserve_detector_positive_behavior"
            )
            is True,
            replacement_id
            + " detector-positive preservation contract changed",
        )

    closure = contract.get(
        "closure_policy",
        {},
    )

    require(
        closure.get(
            "original_reds_may_be_deleted_or_rewritten"
        )
        is False,
        "original RED preservation policy weakened",
    )

    require(
        closure.get(
            "replacement_green_erases_original_red"
        )
        is False,
        "replacement GREEN erasure policy changed",
    )


def load_frozen_contract(
    repo: Path,
) -> tuple[
    dict[str, Any],
    Path,
]:
    path = (
        repo
        / CONTRACT_RELATIVE
    )

    require(
        path.is_file(),
        "frozen replacement contract missing",
    )

    require(
        sha256_file(
            path
        )
        == EXPECTED_CONTRACT_SHA256,
        "frozen replacement contract SHA mismatch",
    )

    contract = load_json(
        path
    )

    require(
        isinstance(
            contract,
            dict,
        ),
        "replacement contract is not a JSON object",
    )

    validate_contract(
        contract
    )

    return (
        contract,
        path,
    )


def load_parent_selection(
    repo: Path,
    contract: dict[str, Any],
) -> tuple[
    dict[str, Any],
    Path,
]:
    path = (
        repo
        / PARENT_SELECTION_RELATIVE
    )

    require(
        path.is_file(),
        "exact-parent selection artifact missing",
    )

    expected_sha = (
        contract[
            "grounding"
        ][
            "original_parent_selection"
        ][
            "sha256"
        ]
    )

    require(
        sha256_file(
            path
        )
        == expected_sha,
        "exact-parent selection SHA mismatch",
    )

    value = load_json(
        path
    )

    require(
        isinstance(
            value,
            dict,
        ),
        "exact-parent selection is not a JSON object",
    )

    return (
        value,
        path,
    )


def resolve_security_parent(
    contract: dict[str, Any],
    parent_selection: dict[str, Any],
) -> tuple[
    str,
    dict[str, Any],
]:
    malformed = get_replacement(
        contract,
        "CHAL-MAL-001-V2",
    )

    parent_ids = malformed[
        "original_parent_ids"
    ]

    parent_id = parent_ids[
        0
    ]

    parents = parent_selection.get(
        "parents"
    )

    require(
        isinstance(
            parents,
            dict,
        ),
        "parent-selection parents mapping missing",
    )

    info = parents.get(
        parent_id
    )

    require(
        isinstance(
            info,
            dict,
        ),
        "selected Security parent object missing",
    )

    require(
        info.get(
            "telemetry_family"
        )
        == "WINDOWS_SECURITY",
        "selected Row-7 parent is not Windows Security",
    )

    require(
        info.get(
            "source_role"
        )
        == "DEVELOPMENT",
        "selected Row-7 parent is not development evidence",
    )

    source_id = info.get(
        "source_id"
    )

    require(
        isinstance(
            source_id,
            str,
        )
        and not source_id.startswith(
            "TS-HOLD"
        ),
        "holdout source prohibited for replacement generation",
    )

    require(
        info.get(
            "exact_slice_integrity_reverified"
        )
        is True,
        "selected Row-7 parent exact-slice integrity is not verified",
    )

    require(
        info.get(
            "artifact_integrity_reverified"
        )
        is True,
        "selected Row-7 source artifact integrity is not verified",
    )

    return (
        parent_id,
        info,
    )


def read_exact_security_parent(
    parent_id: str,
    info: dict[str, Any],
) -> tuple[
    bytes,
    dict[str, Any],
]:
    storage_path = info.get(
        "storage_path"
    )

    require(
        isinstance(
            storage_path,
            str,
        )
        and storage_path,
        "selected Security parent storage path missing",
    )

    source_path = Path(
        storage_path
    )

    require(
        source_path.is_file(),
        "selected Security source artifact missing: "
        + str(
            source_path
        ),
    )

    source_bytes = source_path.read_bytes()

    require(
        sha256_bytes(
            source_bytes
        )
        == info.get(
            "source_sha256"
        ),
        "selected Security source artifact SHA mismatch",
    )

    offset = int(
        info[
            "byte_offset"
        ]
    )

    length = int(
        info[
            "byte_length"
        ]
    )

    require(
        offset >= 0
        and length > 0
        and (
            offset
            + length
        )
        <= len(
            source_bytes
        ),
        "selected Security parent locator is outside source artifact",
    )

    record = source_bytes[
        offset:
        offset
        + length
    ]

    require(
        sha256_bytes(
            record
        )
        == info.get(
            "record_sha256"
        ),
        "selected Security parent record SHA mismatch",
    )

    lineage = {
        "parent_id":
            parent_id,

        "source_id":
            info[
                "source_id"
            ],

        "source_sha256":
            info[
                "source_sha256"
            ],

        "source_role":
            info[
                "source_role"
            ],

        "telemetry_family":
            info[
                "telemetry_family"
            ],

        "source_record_sha256":
            info[
                "record_sha256"
            ],

        "exact_locator": {
            "byte_offset":
                offset,

            "byte_length":
                length,

            "record_index":
                int(
                    info[
                        "record_index"
                    ]
                ),

            "line_number":
                int(
                    info[
                        "line_number"
                    ]
                ),
        },
    }

    return (
        record,
        lineage,
    )


def mutate_security_record_number(
    record: bytes,
) -> tuple[
    bytes,
    dict[str, Any],
]:
    matches = list(
        RECORD_NUMBER_PATTERN.finditer(
            record
        )
    )

    require(
        len(
            matches
        )
        == 1,
        "selected Security record must contain exactly one "
        "top-level numeric RecordNumber field",
    )

    match = matches[
        0
    ]

    old_value = match.group(
        2
    )

    require(
        old_value.isdigit(),
        "selected Security RecordNumber is not ASCII decimal",
    )

    replacement = b"not-a-number"

    start, end = match.span(
        2
    )

    mutated = (
        record[
            :start
        ]
        + replacement
        + record[
            end:
        ]
    )

    require(
        mutated[
            :start
        ]
        == record[
            :start
        ],
        "bytes before RecordNumber value changed",
    )

    require(
        mutated[
            start
            + len(
                replacement
            ):
        ]
        == record[
            end:
        ],
        "bytes after RecordNumber value changed",
    )

    require(
        mutated.count(
            b"RecordNumber=not-a-number"
        )
        == 1,
        "derived Security record does not contain exactly one "
        "invalid RecordNumber replacement",
    )

    mutation = {
        "operator":
            "REPLACE_REQUIRED_NUMERIC_RECORDNUMBER_WITH_NON_NUMERIC_LITERAL",

        "field":
            "RecordNumber",

        "old_value":
            old_value.decode(
                "ascii"
            ),

        "new_value":
            "not-a-number",

        "replacement_count":
            1,

        "all_other_bytes_preserved":
            True,

        "source_record_sha256":
            sha256_bytes(
                record
            ),

        "derived_record_sha256":
            sha256_bytes(
                mutated
            ),

        "source_record_bytes":
            len(
                record
            ),

        "derived_record_bytes":
            len(
                mutated
            ),
    }

    return (
        mutated,
        mutation,
    )


def load_scenario_002_inputs(
    repo: Path,
    contract: dict[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    manifest_path = (
        repo
        / SCENARIO_MANIFEST_RELATIVE
    )

    powershell_path = (
        repo
        / SCENARIO_POWERSHELL_RELATIVE
    )

    sysmon_path = (
        repo
        / SCENARIO_SYSMON_RELATIVE
    )

    for path in (
        manifest_path,
        powershell_path,
        sysmon_path,
    ):
        require(
            path.is_file(),
            "Scenario 002 fixture component missing: "
            + str(
                path
            ),
        )

    require(
        sha256_file(
            manifest_path
        )
        == EXPECTED_SCENARIO_MANIFEST_SHA256,
        "Scenario 002 manifest SHA mismatch",
    )

    grounding = (
        contract[
            "grounding"
        ][
            "scenario002_positive_source"
        ]
    )

    scenario_source_path = (
        repo
        / grounding[
            "source_path"
        ]
    )

    scenario_test_path = (
        repo
        / grounding[
            "integration_test_path"
        ]
    )

    require(
        scenario_source_path.is_file(),
        "grounded Scenario 002 source missing",
    )

    require(
        scenario_test_path.is_file(),
        "grounded Scenario 002 integration test missing",
    )

    require(
        sha256_file(
            scenario_source_path
        )
        == grounding[
            "source_sha256"
        ],
        "grounded Scenario 002 source SHA mismatch",
    )

    require(
        sha256_file(
            scenario_test_path
        )
        == grounding[
            "integration_test_sha256"
        ],
        "grounded Scenario 002 integration-test SHA mismatch",
    )

    manifest = load_json(
        manifest_path
    )

    require(
        isinstance(
            manifest,
            dict,
        ),
        "Scenario 002 manifest is not a JSON object",
    )

    generated = manifest.get(
        "generated_inputs"
    )

    require(
        isinstance(
            generated,
            dict,
        ),
        "Scenario 002 generated_inputs mapping missing",
    )

    for family, path, relative in (
        (
            "powershell",
            powershell_path,
            SCENARIO_POWERSHELL_RELATIVE,
        ),
        (
            "sysmon",
            sysmon_path,
            SCENARIO_SYSMON_RELATIVE,
        ),
    ):
        info = generated.get(
            family
        )

        require(
            isinstance(
                info,
                dict,
            ),
            "Scenario 002 manifest entry missing: "
            + family,
        )

        require(
            info.get(
                "logical_source"
            )
            == relative.as_posix(),
            "Scenario 002 logical source changed: "
            + family,
        )

        require(
            sha256_file(
                path
            )
            == info.get(
                "sha256"
            ),
            "Scenario 002 generated input SHA mismatch: "
            + family,
        )

    powershell = read_one_jsonl_object(
        powershell_path
    )

    sysmon = read_one_jsonl_object(
        sysmon_path
    )

    require(
        powershell.get(
            "event_type"
        )
        == "script_execution",
        "Scenario 002 PowerShell event_type changed",
    )

    require(
        sysmon.get(
            "event_type"
        )
        == "process_create",
        "Scenario 002 Sysmon event_type changed",
    )

    for field in (
        "host",
        "principal",
        "local_ip",
    ):
        require(
            powershell.get(
                field
            )
            == sysmon.get(
                field
            ),
            "Scenario 002 identity dimension differs: "
            + field,
        )

    require(
        isinstance(
            powershell.get(
                "timestamp"
            ),
            str,
        ),
        "Scenario 002 PowerShell timestamp missing",
    )

    require(
        isinstance(
            sysmon.get(
                "timestamp"
            ),
            str,
        ),
        "Scenario 002 Sysmon timestamp missing",
    )

    lineage = {
        "scenario_id":
            manifest.get(
                "scenario_id"
            ),

        "manifest_path":
            SCENARIO_MANIFEST_RELATIVE.as_posix(),

        "manifest_sha256":
            sha256_file(
                manifest_path
            ),

        "powershell_path":
            SCENARIO_POWERSHELL_RELATIVE.as_posix(),

        "powershell_sha256":
            sha256_file(
                powershell_path
            ),

        "sysmon_path":
            SCENARIO_SYSMON_RELATIVE.as_posix(),

        "sysmon_sha256":
            sha256_file(
                sysmon_path
            ),

        "production_baseline_grounding":
            (
                "Scenario 002 is frozen by contract as the "
                "existing TRC-DET-001 to TRC-CORR-002 positive source."
            ),
    }

    return (
        powershell,
        sysmon,
        lineage,
    )


def build_time_pair(
    baseline_powershell: dict[str, Any],
    baseline_sysmon: dict[str, Any],
    delta_seconds: float,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    require(
        float(
            delta_seconds
        ).is_integer(),
        "replacement timing delta must be whole seconds",
    )

    powershell = copy.deepcopy(
        baseline_powershell
    )

    sysmon = copy.deepcopy(
        baseline_sysmon
    )

    anchor = parse_utc_timestamp(
        sysmon[
            "timestamp"
        ]
    )

    new_powershell_time = (
        anchor
        + timedelta(
            seconds=float(
                delta_seconds
            )
        )
    )

    old_powershell_time = powershell[
        "timestamp"
    ]

    powershell[
        "timestamp"
    ] = format_utc_timestamp(
        new_powershell_time
    )

    require(
        sysmon
        == baseline_sysmon,
        "Sysmon source object changed during timing derivation",
    )

    baseline_without_time = {
        key:
            value
        for key, value in baseline_powershell.items()
        if key != "timestamp"
    }

    derived_without_time = {
        key:
            value
        for key, value in powershell.items()
        if key != "timestamp"
    }

    require(
        derived_without_time
        == baseline_without_time,
        "non-timestamp PowerShell fields changed during timing derivation",
    )

    observed_delta = (
        parse_utc_timestamp(
            powershell[
                "timestamp"
            ]
        )
        - parse_utc_timestamp(
            sysmon[
                "timestamp"
            ]
        )
    ).total_seconds()

    require(
        observed_delta
        == float(
            delta_seconds
        ),
        "derived directional timing delta is incorrect",
    )

    mutation = {
        "operator":
            "SET_POWERSHELL_TIMESTAMP_RELATIVE_TO_UNCHANGED_SYSMON_ANCHOR",

        "sysmon_anchor_timestamp":
            sysmon[
                "timestamp"
            ],

        "original_powershell_timestamp":
            old_powershell_time,

        "derived_powershell_timestamp":
            powershell[
                "timestamp"
            ],

        "directional_delta_seconds":
            observed_delta,

        "sysmon_object_changed":
            False,

        "non_timestamp_powershell_fields_changed":
            False,
    }

    return (
        powershell,
        sysmon,
        mutation,
    )


def artifact_entry(
    challenge_id: str,
    filename: str,
    payload: bytes,
    role: str,
) -> dict[str, Any]:
    return {
        "path":
            (
                Path(
                    challenge_id
                )
                / filename
            ).as_posix(),

        "role":
            role,

        "sha256":
            sha256_bytes(
                payload
            ),

        "bytes":
            len(
                payload
            ),
    }


def challenge_manifest_bytes(
    *,
    replacement: dict[str, Any],
    artifacts: list[dict[str, Any]],
    source_lineage: dict[str, Any],
    mutation: dict[str, Any],
    generator_sha256: str,
) -> bytes:
    value = {
        "record_type":
            "tracesoc-cov010-replacement-challenge-manifest-v1",

        "schema_version":
            1,

        "replacement_set_id":
            "COV010-RPL-V1",

        "challenge_id":
            replacement[
                "replacement_id"
            ],

        "replaces_original_matrix_row":
            replacement[
                "replaces_original_matrix_row"
            ],

        "replaces_original_challenge_id":
            replacement[
                "replaces_original_challenge_id"
            ],

        "original_red_must_remain_preserved":
            replacement[
                "original_red_must_remain_preserved"
            ],

        "contract_path":
            CONTRACT_RELATIVE.as_posix(),

        "contract_sha256":
            EXPECTED_CONTRACT_SHA256,

        "contract_freeze_commit":
            CONTRACT_FREEZE_COMMIT,

        "generator_version":
            VERSION,

        "generator_path":
            "scripts/generate_cov010_replacements_v1.py",

        "generator_sha256":
            generator_sha256,

        "execution_status":
            "NOT_EXECUTED",

        "production_defect_previously_established":
            replacement[
                "production_defect_previously_established"
            ],

        "generation_contract":
            replacement[
                "generation_contract"
            ],

        "production_call_chain":
            replacement[
                "production_call_chain"
            ],

        "frozen_pass_invariants":
            replacement[
                "frozen_pass_invariants"
            ],

        "frozen_genuine_red_if":
            replacement[
                "frozen_genuine_red_if"
            ],

        "source_lineage":
            source_lineage,

        "mutation":
            mutation,

        "generated_artifacts":
            artifacts,
    }

    return json_bytes(
        value
    )


def build_payloads(
    repo: Path,
) -> dict[
    Path,
    bytes,
]:
    contract, contract_path = (
        load_frozen_contract(
            repo
        )
    )

    parent_selection, parent_selection_path = (
        load_parent_selection(
            repo,
            contract,
        )
    )

    generator_path = Path(
        __file__
    ).resolve()

    generator_sha256 = sha256_file(
        generator_path
    )

    payloads: dict[
        Path,
        bytes,
    ] = {}

    # -----------------------------------------------------
    # CHAL-MAL-001-V2
    # -----------------------------------------------------

    malformed = get_replacement(
        contract,
        "CHAL-MAL-001-V2",
    )

    parent_id, parent_info = (
        resolve_security_parent(
            contract,
            parent_selection,
        )
    )

    source_record, security_lineage = (
        read_exact_security_parent(
            parent_id,
            parent_info,
        )
    )

    malformed_bytes, malformed_mutation = (
        mutate_security_record_number(
            source_record
        )
    )

    malformed_input_relative = (
        Path(
            "CHAL-MAL-001-V2"
        )
        / "windows-security.txt"
    )

    malformed_artifacts = [
        artifact_entry(
            "CHAL-MAL-001-V2",
            "windows-security.txt",
            malformed_bytes,
            "MALFORMED_WINDOWS_SECURITY_INPUT",
        )
    ]

    malformed_manifest = (
        challenge_manifest_bytes(
            replacement=malformed,
            artifacts=malformed_artifacts,
            source_lineage={
                "kind":
                    "EXACT_SELECTED_DEVELOPMENT_PARENT",

                "parent_selection_path":
                    PARENT_SELECTION_RELATIVE.as_posix(),

                "parent_selection_sha256":
                    sha256_file(
                        parent_selection_path
                    ),

                **security_lineage,
            },
            mutation=malformed_mutation,
            generator_sha256=generator_sha256,
        )
    )

    payloads[
        malformed_input_relative
    ] = malformed_bytes

    payloads[
        Path(
            "CHAL-MAL-001-V2"
        )
        / "challenge-manifest.json"
    ] = malformed_manifest

    # -----------------------------------------------------
    # Scenario 002 source pair for TIME V2 challenges.
    # No production detector/correlation execution occurs.
    # -----------------------------------------------------

    (
        baseline_powershell,
        baseline_sysmon,
        scenario_lineage,
    ) = load_scenario_002_inputs(
        repo,
        contract,
    )

    for replacement_id, delta in (
        (
            "CHAL-TIME-002-V2",
            30.0,
        ),
        (
            "CHAL-TIME-003-V2",
            31.0,
        ),
    ):
        replacement = get_replacement(
            contract,
            replacement_id,
        )

        (
            derived_powershell,
            derived_sysmon,
            timing_mutation,
        ) = build_time_pair(
            baseline_powershell,
            baseline_sysmon,
            delta,
        )

        powershell_bytes = jsonl_bytes(
            derived_powershell
        )

        sysmon_bytes = jsonl_bytes(
            derived_sysmon
        )

        artifacts = [
            artifact_entry(
                replacement_id,
                "powershell.jsonl",
                powershell_bytes,
                "POWERSHELL_SCRIPT_EXECUTION_INPUT",
            ),
            artifact_entry(
                replacement_id,
                "sysmon.jsonl",
                sysmon_bytes,
                "SYSMON_PROCESS_CREATE_INPUT",
            ),
        ]

        manifest_bytes = (
            challenge_manifest_bytes(
                replacement=replacement,
                artifacts=artifacts,
                source_lineage={
                    "kind":
                        "GROUNDED_MULTISOURCE_SCENARIO_002_POSITIVE_PAIR",

                    **scenario_lineage,
                },
                mutation=timing_mutation,
                generator_sha256=generator_sha256,
            )
        )

        payloads[
            Path(
                replacement_id
            )
            / "powershell.jsonl"
        ] = powershell_bytes

        payloads[
            Path(
                replacement_id
            )
            / "sysmon.jsonl"
        ] = sysmon_bytes

        payloads[
            Path(
                replacement_id
            )
            / "challenge-manifest.json"
        ] = manifest_bytes

    # -----------------------------------------------------
    # Root replacement-corpus manifest.
    # -----------------------------------------------------

    challenge_summaries = []

    for replacement_id in REPLACEMENT_IDS:
        manifest_relative = (
            Path(
                replacement_id
            )
            / "challenge-manifest.json"
        )

        manifest_payload = payloads[
            manifest_relative
        ]

        manifest_value = json.loads(
            manifest_payload.decode(
                "utf-8"
            )
        )

        challenge_summaries.append(
            {
                "challenge_id":
                    replacement_id,

                "manifest_path":
                    manifest_relative.as_posix(),

                "manifest_sha256":
                    sha256_bytes(
                        manifest_payload
                    ),

                "execution_status":
                    "NOT_EXECUTED",

                "generated_artifacts":
                    manifest_value[
                        "generated_artifacts"
                    ],
            }
        )

    root_manifest = {
        "record_type":
            "tracesoc-cov010-replacement-corpus-manifest-v1",

        "schema_version":
            1,

        "replacement_set_id":
            "COV010-RPL-V1",

        "logical_root":
            DEFAULT_OUTPUT_RELATIVE.as_posix(),

        "contract_path":
            CONTRACT_RELATIVE.as_posix(),

        "contract_sha256":
            EXPECTED_CONTRACT_SHA256,

        "contract_freeze_commit":
            CONTRACT_FREEZE_COMMIT,

        "generator_version":
            VERSION,

        "generator_path":
            "scripts/generate_cov010_replacements_v1.py",

        "generator_sha256":
            generator_sha256,

        "original_frozen_run":
            {
                "row_denominator":
                    15,

                "observed_rows":
                    15,

                "pass_rows":
                    12,

                "preserved_adjudicated_red_rows":
                    [
                        7,
                        13,
                        14,
                    ],

                "replacement_results_rewrite_original_history":
                    False,
            },

        "challenge_count":
            3,

        "challenge_manifest_count":
            3,

        "generated_input_count":
            5,

        "file_count":
            9,

        "execution_order":
            list(
                REPLACEMENT_IDS
            ),

        "replacement_execution":
            "NOT_STARTED",

        "COV_010":
            "DERIVED_CORPUS_PENDING",

        "holdout_sources_used":
            0,

        "raw_originals_modified":
            False,

        "production_logic_executed_during_generation":
            False,

        "source_controls":
            {
                "parent_selection_path":
                    PARENT_SELECTION_RELATIVE.as_posix(),

                "parent_selection_sha256":
                    sha256_file(
                        parent_selection_path
                    ),

                "scenario_manifest_path":
                    SCENARIO_MANIFEST_RELATIVE.as_posix(),

                "scenario_manifest_sha256":
                    EXPECTED_SCENARIO_MANIFEST_SHA256,

                "contract_path":
                    contract_path.relative_to(
                        repo
                    ).as_posix(),
            },

        "challenges":
            challenge_summaries,
    }

    payloads[
        Path(
            "corpus-manifest.json"
        )
    ] = json_bytes(
        root_manifest
    )

    require(
        len(
            payloads
        )
        == 9,
        "replacement payload file denominator is not 9",
    )

    input_count = sum(
        1
        for relative in payloads
        if relative.name
        not in (
            "challenge-manifest.json",
            "corpus-manifest.json",
        )
    )

    require(
        input_count
        == 5,
        "replacement generated-input denominator is not 5",
    )

    challenge_manifest_count = sum(
        1
        for relative in payloads
        if relative.name
        == "challenge-manifest.json"
    )

    require(
        challenge_manifest_count
        == 3,
        "replacement challenge-manifest denominator is not 3",
    )

    return payloads


def write_payloads(
    output: Path,
    payloads: dict[
        Path,
        bytes,
    ],
) -> None:
    require(
        not output.exists(),
        "replacement output path already exists: "
        + str(
            output
        ),
    )

    for relative in payloads:
        require(
            not relative.is_absolute(),
            "generated path unexpectedly absolute",
        )

        require(
            ".."
            not in relative.parts,
            "generated path contains traversal",
        )

    output.mkdir(
        parents=True,
        exist_ok=False,
    )

    for relative in sorted(
        payloads,
        key=lambda value:
            value.as_posix(),
    ):
        destination = (
            output
            / relative
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        destination.write_bytes(
            payloads[
                relative
            ]
        )

    files = sorted(
        path
        for path in output.rglob(
            "*"
        )
        if path.is_file()
    )

    require(
        len(
            files
        )
        == 9,
        "written replacement file denominator is not 9",
    )

    for relative, expected_bytes in payloads.items():
        path = (
            output
            / relative
        )

        require(
            path.is_file(),
            "generated replacement file missing: "
            + relative.as_posix(),
        )

        require(
            path.read_bytes()
            == expected_bytes,
            "written replacement bytes differ from in-memory bytes: "
            + relative.as_posix(),
        )


def generate(
    repo: Path,
    output_override: Path | None = None,
) -> Path:
    repo = repo.resolve()

    require(
        repo.is_dir(),
        "repository path does not exist",
    )

    payloads = build_payloads(
        repo
    )

    if output_override is None:
        output = (
            repo
            / DEFAULT_OUTPUT_RELATIVE
        )
    else:
        output = output_override

        if not output.is_absolute():
            output = (
                repo
                / output
            )

    output = output.resolve()

    original_corpus = (
        repo
        / ORIGINAL_CORPUS_RELATIVE
    ).resolve()

    require(
        output
        != original_corpus,
        "replacement generator may not overwrite original COV010 corpus",
    )

    require(
        output
        != repo.resolve(),
        "replacement generator output may not be repository root",
    )

    write_payloads(
        output,
        payloads,
    )

    return output


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the frozen COV010-RPL-V1 replacement "
            "challenge corpus without executing production analytics."
        )
    )

    parser.add_argument(
        "--repo",
        required=True,
        help="TraceSOC repository root.",
    )

    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Optional alternate output directory for deterministic "
            "reproduction checks. The manifest logical root remains "
            "the frozen COV010-RPL-V1 root."
        ),
    )

    args = parser.parse_args()

    repo = Path(
        args.repo
    )

    output_override = (
        None
        if args.output is None
        else Path(
            args.output
        )
    )

    output = generate(
        repo,
        output_override,
    )

    files = sorted(
        path
        for path in output.rglob(
            "*"
        )
        if path.is_file()
    )

    print(
        "REPLACEMENT_SET=COV010-RPL-V1"
    )

    print(
        "REPLACEMENT_OUTPUT="
        + str(
            output
        )
    )

    print(
        "REPLACEMENT_CHALLENGES_GENERATED=3"
    )

    print(
        "REPLACEMENT_INPUTS_GENERATED=5"
    )

    print(
        "REPLACEMENT_FILES_GENERATED="
        + str(
            len(
                files
            )
        )
    )

    print(
        "REPLACEMENT_CHALLENGES_EXECUTED=FALSE"
    )

    print(
        "PRODUCTION_LOGIC_EXECUTED_DURING_GENERATION=FALSE"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
