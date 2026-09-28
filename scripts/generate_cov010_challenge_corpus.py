from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


VERSION = "1.0.0"

CHALLENGE_IDS = [
    "CHAL-DUP-001",
    "CHAL-DUP-002",
    "CHAL-MAL-001",
    "CHAL-MAL-002",
    "CHAL-MISS-001",
    "CHAL-MISS-002",
    "CHAL-TIME-001",
    "CHAL-TIME-002",
    "CHAL-TIME-003",
    "CHAL-CLOCK-001",
    "CHAL-UNKNOWN-001",
    "CHAL-LABEL-001",
    "CHAL-MIX-001",
    "CHAL-CORR-001",
    "CHAL-CORR-002",
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def jsonl_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def local_name(tag: str) -> str:
    return tag.split("}")[-1]


def parse_xml(data: bytes) -> ET.Element:
    return ET.fromstring(
        data.decode(
            "utf-8",
            errors="strict",
        ).strip()
    )


def serialize_xml(root: ET.Element) -> bytes:
    if root.tag.startswith("{"):
        namespace = root.tag[1:].split("}", 1)[0]
        ET.register_namespace("", namespace)

    return (
        ET.tostring(
            root,
            encoding="utf-8",
        )
        + b"\n"
    )


def newline(data: bytes) -> bytes:
    return data.rstrip(b"\r\n") + b"\n"


def first_jsonl(path: Path) -> dict[str, Any]:
    lines = [
        line
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    if not lines:
        raise RuntimeError(
            "empty JSONL template: "
            + str(path)
        )

    obj = json.loads(lines[0])

    if not isinstance(obj, dict):
        raise RuntimeError(
            "JSONL template is not an object: "
            + str(path)
        )

    return obj


def existing_key(
    obj: dict[str, Any],
    candidates: list[str],
    label: str,
) -> str:
    matches = [
        candidate
        for candidate in candidates
        if candidate in obj
    ]

    if len(matches) != 1:
        raise RuntimeError(
            label
            + " requires exactly one existing key from "
            + repr(candidates)
            + "; observed "
            + repr(matches)
        )

    return matches[0]


def set_field(
    obj: dict[str, Any],
    candidates: list[str],
    value: Any,
    label: str,
) -> str:
    key = existing_key(
        obj,
        candidates,
        label,
    )

    obj[key] = value

    return key


def set_optional(
    obj: dict[str, Any],
    candidates: list[str],
    value: Any,
) -> None:
    for key in candidates:
        if key in obj:
            obj[key] = value
            return


class Builder:
    def __init__(
        self,
        *,
        repo: Path,
        evidence_root: Path,
        selection: Path,
        output: Path,
        created_utc: str,
        parent_commit: str,
    ) -> None:
        self.repo = repo
        self.evidence_root = evidence_root
        self.selection_path = selection
        self.output = output
        self.created_utc = created_utc
        self.parent_commit = parent_commit

        self.selection = json.loads(
            selection.read_text(
                encoding="utf-8"
            )
        )

        self.parents = self.selection[
            "parents"
        ]

        self.challenges = self.selection[
            "challenges"
        ]

        if sorted(self.challenges) != sorted(
            CHALLENGE_IDS
        ):
            raise RuntimeError(
                "frozen 15-class challenge set changed"
            )

        if len(self.parents) != 7:
            raise RuntimeError(
                "expected seven frozen parents"
            )

        self.source_cache: dict[
            str,
            tuple[Path, bytes]
        ] = {}

        self.generated_inputs = 0
        self.generated_challenges = []

        self.template_paths = {
            "corr1_ps":
                repo
                / "tests/fixtures/scenarios/"
                "multisource-web-retrieval-001/"
                "powershell.jsonl",

            "corr1_zeek":
                repo
                / "tests/fixtures/scenarios/"
                "multisource-web-retrieval-001/"
                "zeek.jsonl",

            "corr2_ps":
                repo
                / "tests/fixtures/scenarios/"
                "multisource-powershell-process-002/"
                "powershell.jsonl",

            "corr2_sysmon":
                repo
                / "tests/fixtures/scenarios/"
                "multisource-powershell-process-002/"
                "sysmon.jsonl",
        }

        for name, path in self.template_paths.items():
            if not path.is_file():
                raise RuntimeError(
                    "grounded fixture template missing: "
                    + name
                    + "="
                    + str(path)
                )

    def frozen_ids(
        self,
        challenge_id: str,
    ) -> list[str]:
        return list(
            self.challenges[
                challenge_id
            ][
                "parents"
            ]
        )

    def source_path(
        self,
        parent: dict[str, Any],
    ) -> Path:
        path = Path(
            parent[
                "storage_path"
            ]
        )

        if not path.is_absolute():
            path = (
                self.evidence_root
                / path
            )

        return path.resolve()

    def parent(
        self,
        parent_id: str,
    ) -> tuple[
        dict[str, Any],
        bytes,
    ]:
        if parent_id not in self.parents:
            raise RuntimeError(
                "unknown frozen parent: "
                + parent_id
            )

        info = self.parents[
            parent_id
        ]

        source_id = info[
            "source_id"
        ]

        if source_id.startswith(
            "TS-HOLD"
        ):
            raise RuntimeError(
                "holdout parent forbidden"
            )

        path = self.source_path(
            info
        )

        if source_id not in self.source_cache:
            if not path.is_file():
                raise RuntimeError(
                    "source missing: "
                    + str(path)
                )

            raw = path.read_bytes()

            if sha256_bytes(
                raw
            ) != info[
                "source_sha256"
            ]:
                raise RuntimeError(
                    "source SHA mismatch: "
                    + parent_id
                )

            self.source_cache[
                source_id
            ] = (
                path,
                raw,
            )

        cached_path, source = (
            self.source_cache[
                source_id
            ]
        )

        if cached_path != path:
            raise RuntimeError(
                "source path instability"
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

        record = source[
            offset:
            offset + length
        ]

        if len(record) != length:
            raise RuntimeError(
                "parent slice outside source"
            )

        if sha256_bytes(
            record
        ) != info[
                "record_sha256"
            ]:
            raise RuntimeError(
                "parent record SHA mismatch: "
                + parent_id
            )

        return (
            info,
            record,
        )

    def parent_meta(
        self,
        parent_id: str,
    ) -> dict[str, Any]:
        info = self.parents[
            parent_id
        ]

        return {
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
            "record_sha256":
                info[
                    "record_sha256"
                ],
            "telemetry_family":
                info[
                    "telemetry_family"
                ],
            "semantic_role":
                info[
                    "semantic_role"
                ],
            "exact_locator": {
                "byte_offset":
                    int(
                        info[
                            "byte_offset"
                        ]
                    ),
                "byte_length":
                    int(
                        info[
                            "byte_length"
                        ]
                    ),
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

    def zeek(
        self,
        parent_id: str,
    ) -> tuple[
        bytes,
        list[str],
        list[bytes],
    ]:
        info, record = self.parent(
            parent_id
        )

        path = self.source_path(
            info
        )

        source = path.read_bytes()

        header_lines = []

        for line in source.splitlines(
            keepends=True
        ):
            if not line.startswith(
                b"#"
            ):
                break

            header_lines.append(
                line
            )

        if not header_lines:
            raise RuntimeError(
                "Zeek source has no header"
            )

        fields_line = next(
            (
                line.decode(
                    "utf-8",
                    errors="strict",
                ).rstrip(
                    "\r\n"
                )
                for line
                in header_lines
                if line.startswith(
                    b"#fields"
                )
            ),
            None,
        )

        if fields_line is None:
            raise RuntimeError(
                "Zeek #fields header missing"
            )

        field_names = fields_line.split(
            "\t"
        )[1:]

        values = record.rstrip(
            b"\r\n"
        ).split(
            b"\t"
        )

        if len(values) != len(
            field_names
        ):
            raise RuntimeError(
                "Zeek parent/header cardinality mismatch"
            )

        return (
            b"".join(
                header_lines
            ),
            field_names,
            values,
        )

    def zeek_document(
        self,
        parent_id: str,
        values: list[bytes] | None = None,
    ) -> bytes:
        header, _, original = self.zeek(
            parent_id
        )

        selected = (
            original
            if values is None
            else values
        )

        return (
            header
            + b"\t".join(
                selected
            )
            + b"\n"
        )

    def xml_data(
        self,
        parent_id: str,
        field_name: str,
    ) -> str:
        _, record = self.parent(
            parent_id
        )

        root = parse_xml(
            record
        )

        matches = [
            element
            for element in root.iter()
            if (
                local_name(
                    element.tag
                )
                == "Data"
                and element.attrib.get(
                    "Name"
                )
                == field_name
            )
        ]

        if len(matches) != 1:
            raise RuntimeError(
                "expected exactly one XML Data field "
                + field_name
                + " in "
                + parent_id
            )

        return (
            matches[
                0
            ].text
            or ""
        )

    def emit(
        self,
        challenge_id: str,
        files: list[
            tuple[
                str,
                bytes,
                list[str],
            ]
        ],
        operator: str,
        parameters: dict[
            str,
            Any,
        ],
        structural_effect: str,
        analytical_boundary: str,
        template_paths: list[str] | None = None,
    ) -> None:
        expected_parents = self.frozen_ids(
            challenge_id
        )

        used = []

        directory = (
            self.output
            / challenge_id
        )

        directory.mkdir(
            parents=True,
            exist_ok=False,
        )

        artifacts = []

        for filename, data, parent_ids in files:
            for parent_id in parent_ids:
                if parent_id not in expected_parents:
                    raise RuntimeError(
                        "artifact uses non-frozen parent: "
                        + challenge_id
                        + ":"
                        + parent_id
                    )

                if parent_id not in used:
                    used.append(
                        parent_id
                    )

            if b"CHAL-" in data:
                raise RuntimeError(
                    "challenge identifier entered semantic input"
                )

            path = (
                directory
                / filename
            )

            path.write_bytes(
                data
            )

            artifacts.append(
                {
                    "path":
                        (
                            challenge_id
                            + "/"
                            + filename
                        ),
                    "sha256":
                        sha256_file(
                            path
                        ),
                    "parent_ids":
                        list(
                            parent_ids
                        ),
                }
            )

            self.generated_inputs += 1

        if set(used) != set(
            expected_parents
        ):
            raise RuntimeError(
                "generated parent membership differs "
                "from frozen selection: "
                + challenge_id
            )

        manifest = {
            "record_type":
                "tracesoc-derived-challenge-v1",
            "challenge_id":
                challenge_id,
            "creation_timestamp_utc":
                self.created_utc,
            "tool_script_version":
                VERSION,
            "purpose":
                self.challenges[
                    challenge_id
                ][
                    "purpose"
                ],
            "base_parents": [
                self.parent_meta(
                    parent_id
                )
                for parent_id
                in expected_parents
            ],
            "mutation": {
                "operator":
                    operator,
                "parameters":
                    parameters,
            },
            "serialization_templates":
                template_paths
                or [],
            "generated_artifacts":
                artifacts,
            "expected_structural_effect":
                structural_effect,
            "expected_analytical_boundary":
                analytical_boundary,
            "execution_status":
                "NOT_EXECUTED",
            "challenge_id_is_test_metadata":
                True,
            "challenge_id_embedded_in_input":
                False,
            "publisher_label_is_production_selector":
                False,
            "expected_answer_is_production_selector":
                False,
            "real_incident_claim":
                False,
            "raw_original_modified":
                False,
        }

        manifest_path = (
            directory
            / "challenge-manifest.json"
        )

        manifest_path.write_bytes(
            json_bytes(
                manifest
            )
        )

        self.generated_challenges.append(
            {
                "challenge_id":
                    challenge_id,
                "manifest_sha256":
                    sha256_file(
                        manifest_path
                    ),
                "input_count":
                    len(
                        files
                    ),
            }
        )

    def synthetic_templates(
        self,
    ) -> dict[str, dict[str, Any]]:
        return {
            name:
                first_jsonl(
                    path
                )
            for name, path
            in self.template_paths.items()
        }

    def mutate_common(
        self,
        obj: dict[str, Any],
        *,
        timestamp: str,
        host: str,
    ) -> None:
        set_field(
            obj,
            [
                "timestamp",
                "event_time_utc",
            ],
            timestamp,
            "timestamp",
        )

        set_field(
            obj,
            [
                "host",
                "hostname",
                "computer",
            ],
            host,
            "host",
        )

        set_optional(
            obj,
            [
                "fixture_id",
            ],
            "COV010_DERIVED_FIXTURE",
        )

        set_optional(
            obj,
            [
                "expected_answer",
            ],
            "SYNTHETIC_TEST_METADATA_ONLY",
        )

    def generate(self) -> None:
        if self.output.exists():
            raise RuntimeError(
                "output already exists"
            )

        self.output.mkdir(
            parents=True,
        )

        # DUP-001: exact record duplication.
        ps_id = "PARENT-PS-DET002-001"
        _, ps_record = self.parent(
            ps_id
        )

        self.emit(
            "CHAL-DUP-001",
            [
                (
                    "powershell.xml",
                    newline(
                        ps_record
                    )
                    + newline(
                        ps_record
                    ),
                    [
                        ps_id,
                    ],
                ),
            ],
            "EXACT_RECORD_DUPLICATION",
            {
                "copies":
                    2,
            },
            "Two byte-identical PowerShell Event records.",
            "Both raw inputs must remain explicitly accounted for.",
        )

        # DUP-002: same Sysmon behavior, distinct EventRecordID.
        dup2_id = "PARENT-SYSMON-DET005-LATE"
        _, dup2_record = self.parent(
            dup2_id
        )

        root_a = parse_xml(
            dup2_record
        )

        root_b = parse_xml(
            dup2_record
        )

        ids = [
            element
            for element in root_b.iter()
            if local_name(
                element.tag
            )
            == "EventRecordID"
        ]

        if len(ids) != 1:
            raise RuntimeError(
                "DUP-002 parent has unexpected EventRecordID count"
            )

        original_record_id = int(
            (
                ids[
                    0
                ].text
                or ""
            ).strip()
        )

        ids[
            0
        ].text = str(
            original_record_id
            + 1000000
        )

        self.emit(
            "CHAL-DUP-002",
            [
                (
                    "sysmon.xml",
                    serialize_xml(
                        root_a
                    )
                    + serialize_xml(
                        root_b
                    ),
                    [
                        dup2_id,
                    ],
                ),
            ],
            "SEMANTIC_REPEAT_DISTINCT_EVENT_RECORD_ID",
            {
                "original_event_record_id":
                    original_record_id,
                "derived_event_record_id":
                    original_record_id
                    + 1000000,
            },
            "Two separate Sysmon records retain the selected behavior.",
            "A semantic repeat must remain separately accountable.",
        )

        # MAL-001: truncate Security record.
        sec_id = "PARENT-SECURITY-CLOCK-001"
        _, security_record = self.parent(
            sec_id
        )

        retained = max(
            1,
            len(
                security_record
            )
            // 2,
        )

        self.emit(
            "CHAL-MAL-001",
            [
                (
                    "windows-security.txt",
                    security_record[
                        :retained
                    ],
                    [
                        sec_id,
                    ],
                ),
            ],
            "TRUNCATE_RECORD",
            {
                "original_length":
                    len(
                        security_record
                    ),
                "retained_length":
                    retained,
            },
            "The Security export ends mid-record.",
            "Malformed input must be rejected/quarantined or otherwise explicitly accounted for.",
        )

        # MAL-002: malformed XML.
        mal2_id = "PARENT-SYSMON-POWERSHELL-PROCESS-001"
        _, mal2_record = self.parent(
            mal2_id
        )

        text = mal2_record.decode(
            "utf-8",
            errors="strict",
        )

        malformed, count = re.subn(
            r"</Event>\s*$",
            "",
            text,
            count=1,
        )

        if count != 1:
            raise RuntimeError(
                "MAL-002 closing Event tag not found"
            )

        self.emit(
            "CHAL-MAL-002",
            [
                (
                    "sysmon.xml",
                    malformed.encode(
                        "utf-8"
                    ),
                    [
                        mal2_id,
                    ],
                ),
            ],
            "REMOVE_XML_EVENT_CLOSING_TAG",
            {
                "removed":
                    "</Event>",
            },
            "The derived Sysmon XML is not well formed.",
            "Malformed XML must not be silently coerced into a valid event.",
        )

        # MISS-001: Zeek ts unset.
        miss1_id = "PARENT-ZEEK-DEV-IRC-001"
        _, field_names, values = self.zeek(
            miss1_id
        )

        if "ts" not in field_names:
            raise RuntimeError(
                "Zeek ts field missing"
            )

        miss_values = list(
            values
        )

        miss_values[
            field_names.index(
                "ts"
            )
        ] = b"-"

        self.emit(
            "CHAL-MISS-001",
            [
                (
                    "zeek.log",
                    self.zeek_document(
                        miss1_id,
                        miss_values,
                    ),
                    [
                        miss1_id,
                    ],
                ),
            ],
            "REPLACE_ZEEK_TIMESTAMP_WITH_UNSET_MARKER",
            {
                "field":
                    "ts",
                "derived_value":
                    "-",
            },
            "Zeek schema is retained while ts is unset.",
            "No UTC time may be fabricated for an absent timestamp.",
        )

        # MISS-002: remove ScriptBlockText.
        root = parse_xml(
            ps_record
        )

        removed = 0

        for parent_element in root.iter():
            for child in list(
                parent_element
            ):
                if (
                    local_name(
                        child.tag
                    )
                    == "Data"
                    and child.attrib.get(
                        "Name"
                    )
                    == "ScriptBlockText"
                ):
                    parent_element.remove(
                        child
                    )
                    removed += 1

        if removed != 1:
            raise RuntimeError(
                "MISS-002 expected exactly one ScriptBlockText"
            )

        self.emit(
            "CHAL-MISS-002",
            [
                (
                    "powershell.xml",
                    serialize_xml(
                        root
                    ),
                    [
                        ps_id,
                    ],
                ),
            ],
            "REMOVE_SCRIPTBLOCKTEXT_FIELD",
            {
                "field":
                    "ScriptBlockText",
            },
            "Event 4104 remains structured but ScriptBlockText is absent.",
            "Behavior requiring ScriptBlockText must not be invented.",
        )

        # TIME-001: reverse two observed-time Sysmon records.
        early_id = "PARENT-SYSMON-DET005-EARLY"
        late_id = "PARENT-SYSMON-DET005-LATE"

        _, early_record = self.parent(
            early_id
        )

        _, late_record = self.parent(
            late_id
        )

        self.emit(
            "CHAL-TIME-001",
            [
                (
                    "sysmon.xml",
                    newline(
                        late_record
                    )
                    + newline(
                        early_record
                    ),
                    [
                        early_id,
                        late_id,
                    ],
                ),
            ],
            "REVERSE_CHRONOLOGICAL_RECORD_ORDER",
            {
                "first":
                    "LATE",
                "second":
                    "EARLY",
            },
            "File order is opposite the established event-time order.",
            "File adjacency/order must not replace observed event-time semantics.",
        )

        # CLOCK-001: replace the first date/time-like token.
        security_text = security_record.decode(
            "utf-8",
            errors="strict",
        )

        patterns = [
            r"\b20\d{2}-\d{2}-\d{2}[T ][0-9:.+\-Z]+\b",
            r"\b20\d{2}/\d{2}/\d{2}[ T][0-9:.]+\b",
            r"\b\d{1,2}/\d{1,2}/20\d{2}[ T][0-9:.]+\b",
        ]

        clock_mutated = None
        matched_pattern = None

        for pattern in patterns:
            candidate, count = re.subn(
                pattern,
                "INVALID-TIMESTAMP",
                security_text,
                count=1,
            )

            if count == 1:
                clock_mutated = candidate
                matched_pattern = pattern
                break

        if clock_mutated is None:
            raise RuntimeError(
                "CLOCK-001 could not locate the grounded Security time token"
            )

        self.emit(
            "CHAL-CLOCK-001",
            [
                (
                    "windows-security.txt",
                    clock_mutated.encode(
                        "utf-8"
                    ),
                    [
                        sec_id,
                    ],
                ),
            ],
            "REPLACE_SECURITY_TIME_TOKEN_WITH_INVALID_LITERAL",
            {
                "replacement":
                    "INVALID-TIMESTAMP",
                "matched_pattern":
                    matched_pattern,
            },
            "Security record structure is retained while its source time token is invalid.",
            "Clock handling must remain invalid/unresolved or reject the record; UTC must not be fabricated.",
        )

        # UNKNOWN-001: unsupported provider/event.
        unknown_root = parse_xml(
            ps_record
        )

        providers = [
            element
            for element in unknown_root.iter()
            if local_name(
                element.tag
            )
            == "Provider"
        ]

        event_ids = [
            element
            for element in unknown_root.iter()
            if local_name(
                element.tag
            )
            == "EventID"
        ]

        if len(providers) != 1 or len(event_ids) != 1:
            raise RuntimeError(
                "UNKNOWN-001 XML system shape changed"
            )

        providers[
            0
        ].set(
            "Name",
            "TraceSOC-Unsupported-Provider",
        )

        event_ids[
            0
        ].text = "9999"

        self.emit(
            "CHAL-UNKNOWN-001",
            [
                (
                    "powershell.xml",
                    serialize_xml(
                        unknown_root
                    ),
                    [
                        ps_id,
                    ],
                ),
            ],
            "REPLACE_PROVIDER_AND_EVENT_ID",
            {
                "provider":
                    "TraceSOC-Unsupported-Provider",
                "event_id":
                    9999,
            },
            "XML remains well formed but identifies an unsupported provider/event.",
            "Unsupported input must not be coerced into a supported event family.",
        )

        # LABEL-001: preserve exact benign label-bearing context.
        benign_id = "PARENT-ZEEK-BENIGN-ECHO-001"

        self.emit(
            "CHAL-LABEL-001",
            [
                (
                    "zeek.log",
                    self.zeek_document(
                        benign_id
                    ),
                    [
                        benign_id,
                    ],
                ),
            ],
            "PRESERVE_LABEL_BEARING_SOURCE_CONTEXT",
            {
                "publisher_label_value_modified":
                    False,
                "label_used_as_selector":
                    False,
            },
            "One structurally valid benign publisher-derived Zeek record is retained.",
            "Publisher label context alone must not create production detector behavior.",
        )

        # MIX-001: preserve two distinct Zeek source schemas.
        self.emit(
            "CHAL-MIX-001",
            [
                (
                    "development-zeek.log",
                    self.zeek_document(
                        miss1_id
                    ),
                    [
                        miss1_id,
                    ],
                ),
                (
                    "benign-zeek.log",
                    self.zeek_document(
                        benign_id
                    ),
                    [
                        benign_id,
                    ],
                ),
            ],
            "BUNDLE_DISTINCT_ZEEK_INPUTS",
            {
                "physical_inputs":
                    2,
                "single_merged_log":
                    False,
            },
            "Development and benign Zeek records remain in separate schema-preserving inputs.",
            "Processing in one test run must not leak source/label context between events.",
        )

        templates = self.synthetic_templates()

        # Parent-derived semantic values used in synthetic correlation inputs.
        script_text = self.xml_data(
            ps_id,
            "ScriptBlockText",
        )

        process_image = self.xml_data(
            mal2_id,
            "Image",
        )

        # TIME-002 and TIME-003 use grounded CORR002 serializer templates.
        def build_corr002_pair(
            *,
            delta: int,
            host: str,
            local_ip: str,
            principal: str,
        ) -> tuple[
            dict[str, Any],
            dict[str, Any],
        ]:
            ps_obj = copy.deepcopy(
                templates[
                    "corr2_ps"
                ]
            )

            sysmon_obj = copy.deepcopy(
                templates[
                    "corr2_sysmon"
                ]
            )

            self.mutate_common(
                ps_obj,
                timestamp=(
                    "2026-01-10T12:00:"
                    + (
                        "30"
                        if delta == 30
                        else "31"
                    )
                    + "Z"
                ),
                host=host,
            )

            self.mutate_common(
                sysmon_obj,
                timestamp=
                    "2026-01-10T12:00:00Z",
                host=host,
            )

            set_field(
                ps_obj,
                [
                    "local_ip",
                    "src_ip",
                ],
                local_ip,
                "CORR002 PowerShell local IP",
            )

            set_field(
                sysmon_obj,
                [
                    "local_ip",
                    "src_ip",
                ],
                local_ip,
                "CORR002 Sysmon local IP",
            )

            set_field(
                ps_obj,
                [
                    "principal",
                    "user",
                ],
                principal,
                "CORR002 PowerShell principal",
            )

            set_field(
                sysmon_obj,
                [
                    "principal",
                    "user",
                ],
                principal,
                "CORR002 Sysmon principal",
            )

            set_field(
                ps_obj,
                [
                    "script_text",
                    "script_block_text",
                ],
                script_text,
                "CORR002 PowerShell script",
            )

            set_field(
                sysmon_obj,
                [
                    "process_name",
                    "image",
                ],
                process_image,
                "CORR002 Sysmon process",
            )

            return (
                ps_obj,
                sysmon_obj,
            )

        t2_ps, t2_sys = build_corr002_pair(
            delta=30,
            host="SYN-COV10-T2",
            local_ip="10.250.10.20",
            principal="LAB\\cov10-user",
        )

        self.emit(
            "CHAL-TIME-002",
            [
                (
                    "sysmon.jsonl",
                    jsonl_bytes(
                        t2_sys
                    ),
                    [
                        mal2_id,
                    ],
                ),
                (
                    "powershell.jsonl",
                    jsonl_bytes(
                        t2_ps
                    ),
                    [
                        ps_id,
                    ],
                ),
            ],
            "SYNTHESIZE_CORR002_EXACT_TIME_BOUNDARY",
            {
                "maximum_seconds":
                    30,
                "derived_delta_seconds":
                    30,
            },
            "Derived CORR002 identities align at exactly 30 seconds.",
            "The established 30-second CORR002 boundary is tested exactly.",
            [
                str(
                    self.template_paths[
                        "corr2_ps"
                    ].relative_to(
                        self.repo
                    )
                ).replace("\\", "/"),
                str(
                    self.template_paths[
                        "corr2_sysmon"
                    ].relative_to(
                        self.repo
                    )
                ).replace("\\", "/"),
            ],
        )

        t3_ps, t3_sys = build_corr002_pair(
            delta=31,
            host="SYN-COV10-T3",
            local_ip="10.250.10.30",
            principal="LAB\\cov10-user",
        )

        self.emit(
            "CHAL-TIME-003",
            [
                (
                    "sysmon.jsonl",
                    jsonl_bytes(
                        t3_sys
                    ),
                    [
                        mal2_id,
                    ],
                ),
                (
                    "powershell.jsonl",
                    jsonl_bytes(
                        t3_ps
                    ),
                    [
                        ps_id,
                    ],
                ),
            ],
            "SYNTHESIZE_CORR002_JUST_OUTSIDE_TIME_BOUNDARY",
            {
                "maximum_seconds":
                    30,
                "derived_delta_seconds":
                    31,
            },
            "Derived CORR002 identities align except for a 31-second delta.",
            "CORR002 must not silently expand beyond its 30-second bound.",
            [
                str(
                    self.template_paths[
                        "corr2_ps"
                    ].relative_to(
                        self.repo
                    )
                ).replace("\\", "/"),
                str(
                    self.template_paths[
                        "corr2_sysmon"
                    ].relative_to(
                        self.repo
                    )
                ).replace("\\", "/"),
            ],
        )

        # CORR-001 / CORR-002 use grounded CORR001 serializer templates.
        _, zeek_fields, zeek_values = self.zeek(
            miss1_id
        )

        zeek_parent = {
            name:
                zeek_values[
                    index
                ].decode(
                    "utf-8",
                    errors="replace",
                )
            for index, name in enumerate(
                zeek_fields
            )
        }

        def build_corr001_pair(
            *,
            host_ps: str,
            host_zeek: str,
            ps_local_ip: str,
            zeek_src_ip: str,
            destination_ip: str,
            destination_port: int,
            reversed_direction: bool,
        ) -> tuple[
            dict[str, Any],
            dict[str, Any],
        ]:
            ps_obj = copy.deepcopy(
                templates[
                    "corr1_ps"
                ]
            )

            zeek_obj = copy.deepcopy(
                templates[
                    "corr1_zeek"
                ]
            )

            self.mutate_common(
                ps_obj,
                timestamp=
                    "2026-01-11T10:00:00Z",
                host=
                    host_ps,
            )

            self.mutate_common(
                zeek_obj,
                timestamp=
                    "2026-01-11T10:00:20Z",
                host=
                    host_zeek,
            )

            derived_script = (
                "Invoke-WebRequest http://"
                + destination_ip
                + ":"
                + str(
                    destination_port
                )
                + "/cov010.ps1; "
                + script_text
            )

            set_field(
                ps_obj,
                [
                    "script_text",
                    "script_block_text",
                ],
                derived_script,
                "CORR001 PowerShell script",
            )

            set_field(
                ps_obj,
                [
                    "local_ip",
                    "src_ip",
                ],
                ps_local_ip,
                "CORR001 PowerShell local IP",
            )

            if reversed_direction:
                set_field(
                    zeek_obj,
                    [
                        "src_ip",
                    ],
                    destination_ip,
                    "CORR001 Zeek source IP",
                )

                set_field(
                    zeek_obj,
                    [
                        "dst_ip",
                    ],
                    ps_local_ip,
                    "CORR001 Zeek destination IP",
                )

            else:
                set_field(
                    zeek_obj,
                    [
                        "src_ip",
                    ],
                    zeek_src_ip,
                    "CORR001 Zeek source IP",
                )

                set_field(
                    zeek_obj,
                    [
                        "dst_ip",
                    ],
                    destination_ip,
                    "CORR001 Zeek destination IP",
                )

                set_field(
                    zeek_obj,
                    [
                        "dst_port",
                    ],
                    destination_port,
                    "CORR001 Zeek destination port",
                )

            set_optional(
                zeek_obj,
                [
                    "proto",
                ],
                zeek_parent.get(
                    "proto",
                    "tcp",
                ),
            )

            set_optional(
                zeek_obj,
                [
                    "service",
                ],
                zeek_parent.get(
                    "service",
                    "http",
                ),
            )

            return (
                ps_obj,
                zeek_obj,
            )

        c1_ps, c1_zeek = build_corr001_pair(
            host_ps="SYN-COV10-C1-A",
            host_zeek="SYN-COV10-C1-B",
            ps_local_ip="10.250.20.10",
            zeek_src_ip="10.250.20.11",
            destination_ip="198.51.100.220",
            destination_port=8443,
            reversed_direction=False,
        )

        self.emit(
            "CHAL-CORR-001",
            [
                (
                    "powershell.jsonl",
                    jsonl_bytes(
                        c1_ps
                    ),
                    [
                        ps_id,
                    ],
                ),
                (
                    "zeek.jsonl",
                    jsonl_bytes(
                        c1_zeek
                    ),
                    [
                        miss1_id,
                    ],
                ),
            ],
            "SYNTHESIZE_CORR001_SAME_DESTINATION_WRONG_IDENTITY",
            {
                "same_destination":
                    True,
                "same_host":
                    False,
                "same_source_identity":
                    False,
                "delta_seconds":
                    20,
            },
            "Derived PowerShell and Zeek inputs share destination/time but not host/source identity.",
            "Destination/time adjacency alone must not create TRC-CORR-001.",
            [
                str(
                    self.template_paths[
                        "corr1_ps"
                    ].relative_to(
                        self.repo
                    )
                ).replace("\\", "/"),
                str(
                    self.template_paths[
                        "corr1_zeek"
                    ].relative_to(
                        self.repo
                    )
                ).replace("\\", "/"),
            ],
        )

        c2_ps, c2_zeek = build_corr001_pair(
            host_ps="SYN-COV10-C2",
            host_zeek="SYN-COV10-C2",
            ps_local_ip="10.250.20.20",
            zeek_src_ip="10.250.20.20",
            destination_ip="198.51.100.221",
            destination_port=9443,
            reversed_direction=True,
        )

        self.emit(
            "CHAL-CORR-002",
            [
                (
                    "powershell.jsonl",
                    jsonl_bytes(
                        c2_ps
                    ),
                    [
                        ps_id,
                    ],
                ),
                (
                    "zeek.jsonl",
                    jsonl_bytes(
                        c2_zeek
                    ),
                    [
                        miss1_id,
                    ],
                ),
            ],
            "SYNTHESIZE_CORR001_REVERSED_DIRECTION",
            {
                "same_host":
                    True,
                "endpoint_set_preserved":
                    True,
                "zeek_direction":
                    "REMOTE_TO_LOCAL",
                "delta_seconds":
                    20,
            },
            "The network direction is reversed relative to the PowerShell retrieval direction.",
            "TRC-CORR-001 must retain directionality.",
            [
                str(
                    self.template_paths[
                        "corr1_ps"
                    ].relative_to(
                        self.repo
                    )
                ).replace("\\", "/"),
                str(
                    self.template_paths[
                        "corr1_zeek"
                    ].relative_to(
                        self.repo
                    )
                ).replace("\\", "/"),
            ],
        )

        if len(
            self.generated_challenges
        ) != 15:
            raise RuntimeError(
                "expected 15 generated challenge classes"
            )

        if self.generated_inputs != 20:
            raise RuntimeError(
                "expected 20 generated semantic inputs; observed "
                + str(
                    self.generated_inputs
                )
            )

        for source_id, (
            source_path,
            source_bytes,
        ) in self.source_cache.items():
            if sha256_file(
                source_path
            ) != sha256_bytes(
                source_bytes
            ):
                raise RuntimeError(
                    "raw source changed during generation: "
                    + source_id
                )

        corpus_manifest = {
            "record_type":
                "tracesoc-cov010-corpus-manifest-v1",
            "schema_version":
                1,
            "created_utc":
                self.created_utc,
            "tool_script_version":
                VERSION,
            "parent_commit":
                self.parent_commit,
            "challenge_count":
                15,
            "challenge_manifest_count":
                15,
            "generated_input_count":
                20,
            "file_count":
                36,
            "selected_source_ids":
                sorted(
                    self.source_cache
                ),
            "holdout_sources_used":
                0,
            "raw_originals_modified":
                False,
            "challenge_execution":
                "NOT_STARTED",
            "COV_010":
                "DERIVED_CORPUS_PENDING",
            "challenges":
                sorted(
                    self.generated_challenges,
                    key=lambda item:
                        item[
                            "challenge_id"
                        ],
                ),
        }

        (
            self.output
            / "corpus-manifest.json"
        ).write_bytes(
            json_bytes(
                corpus_manifest
            )
        )

        files = [
            path
            for path in self.output.rglob(
                "*"
            )
            if path.is_file()
        ]

        if len(files) != 36:
            raise RuntimeError(
                "expected 36 generated files; observed "
                + str(
                    len(files)
                )
            )


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--repo",
        required=True,
    )

    parser.add_argument(
        "--evidence-root",
        required=True,
    )

    parser.add_argument(
        "--selection",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    parser.add_argument(
        "--created-utc",
        required=True,
    )

    parser.add_argument(
        "--parent-commit",
        required=True,
    )

    args = parser.parse_args()

    repo = Path(
        args.repo
    ).resolve()

    output = Path(
        args.output
    ).resolve()

    if output.exists():
        raise RuntimeError(
            "output path already exists"
        )

    staging = output.with_name(
        output.name
        + ".staging"
    )

    if staging.exists():
        raise RuntimeError(
            "staging output already exists"
        )

    try:
        builder = Builder(
            repo=repo,
            evidence_root=Path(
                args.evidence_root
            ).resolve(),
            selection=Path(
                args.selection
            ).resolve(),
            output=staging,
            created_utc=args.created_utc,
            parent_commit=args.parent_commit,
        )

        builder.generate()

        staging.replace(
            output
        )

    except Exception:
        if staging.exists():
            shutil.rmtree(
                staging
            )

        raise

    print(
        "CHALLENGE_CLASSES_GENERATED=15/15"
    )

    print(
        "CHALLENGE_MANIFESTS_GENERATED=15"
    )

    print(
        "DERIVED_INPUTS_GENERATED=20"
    )

    print(
        "TOTAL_CORPUS_FILES=36"
    )

    print(
        "HOLDOUT_SOURCES_USED=0"
    )

    print(
        "COV010_STATUS=DERIVED_CORPUS_PENDING"
    )

    print(
        "CHALLENGE_EXECUTION=NOT_STARTED"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )