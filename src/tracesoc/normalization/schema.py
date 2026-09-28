from __future__ import annotations

from dataclasses import fields
import hashlib
import json
from typing import Final

from tracesoc.models import (
    CanonicalEvent,
    RawLocator,
    SemanticEvent,
)


NORMALIZATION_SCHEMA_NAME: Final[str] = (
    "tracesoc-canonical-normalization"
)

NORMALIZATION_SCHEMA_VERSION: Final[str] = "1"


# Version 1 names the canonical normalization structure that already
# existed before this explicit version contract was introduced.
#
# This contract does not change any model field or analytic behavior.
# A future incompatible change to one of these canonical structures
# requires an explicit normalization-schema version decision.
NORMALIZATION_SCHEMA_MODELS: Final[
    tuple[
        tuple[
            str,
            tuple[str, ...],
        ],
        ...,
    ]
] = (
    (
        "RawLocator",
        (
            "logical_source",
            "record_index",
            "raw_sha256",
            "adapter_id",
            "input_schema_version",
            "line_number",
            "byte_offset",
            "byte_length",
        ),
    ),
    (
        "CanonicalEvent",
        (
            "event_id",
            "source_type",
            "event_type",
            "clock_state",
            "provenance",
            "event_time_raw",
            "event_time_utc",
            "host",
            "principal",
            "semantic_fields",
            "source_context",
        ),
    ),
    (
        "SemanticEvent",
        (
            "event_id",
            "source_type",
            "event_type",
            "clock_state",
            "event_time_utc",
            "host",
            "principal",
            "fields",
        ),
    ),
)


_MODEL_TYPES = (
    RawLocator,
    CanonicalEvent,
    SemanticEvent,
)


def normalization_schema_manifest() -> dict[str, object]:
    """
    Return the deterministic TraceSOC normalization-schema contract.

    The normalization schema version describes the canonical TraceSOC
    structures listed here. It is intentionally distinct from each
    RawLocator.input_schema_version, which identifies the parser/input
    schema used to derive a canonical record.
    """

    validate_normalization_schema_contract()

    return {
        "schema_name":
            NORMALIZATION_SCHEMA_NAME,

        "schema_version":
            NORMALIZATION_SCHEMA_VERSION,

        "models": [
            {
                "name":
                    model_name,

                "fields":
                    list(
                        field_names
                    ),
            }
            for model_name, field_names
            in NORMALIZATION_SCHEMA_MODELS
        ],

        "input_schema_version_equivalence_claimed":
            False,

        "changes_existing_model_fields":
            False,

        "changes_event_identity":
            False,

        "changes_parser_semantics":
            False,

        "changes_detection_semantics":
            False,

        "changes_correlation_semantics":
            False,

        "changes_clock_semantics":
            False,
    }


def normalization_schema_manifest_json_bytes() -> bytes:
    manifest = normalization_schema_manifest()

    return (
        json.dumps(
            manifest,
            ensure_ascii=True,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
        )
        +
        "\n"
    ).encode(
        "utf-8"
    )


def normalization_schema_manifest_sha256() -> str:
    return hashlib.sha256(
        normalization_schema_manifest_json_bytes()
    ).hexdigest()


def validate_normalization_schema_contract() -> None:
    actual = tuple(
        (
            model_type.__name__,
            tuple(
                field.name
                for field
                in fields(
                    model_type
                )
            ),
        )
        for model_type
        in _MODEL_TYPES
    )

    if actual != NORMALIZATION_SCHEMA_MODELS:
        raise RuntimeError(
            "normalization schema version "
            f"{NORMALIZATION_SCHEMA_VERSION} "
            "does not match the current canonical model structure"
        )