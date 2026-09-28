from __future__ import annotations

import hashlib
import json
import unittest

from tracesoc.normalization.schema import (
    NORMALIZATION_SCHEMA_MODELS,
    NORMALIZATION_SCHEMA_NAME,
    NORMALIZATION_SCHEMA_VERSION,
    normalization_schema_manifest,
    normalization_schema_manifest_json_bytes,
    normalization_schema_manifest_sha256,
    validate_normalization_schema_contract,
)


class NormalizationSchemaContractTests(
    unittest.TestCase
):
    def test_first_explicit_normalization_schema_version(
        self,
    ) -> None:
        self.assertEqual(
            NORMALIZATION_SCHEMA_NAME,
            "tracesoc-canonical-normalization",
        )

        self.assertEqual(
            NORMALIZATION_SCHEMA_VERSION,
            "1",
        )

    def test_version_one_matches_existing_canonical_models(
        self,
    ) -> None:
        self.assertEqual(
            NORMALIZATION_SCHEMA_MODELS,
            (
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
            ),
        )

        validate_normalization_schema_contract()

    def test_manifest_is_deterministic_and_separates_input_schema(
        self,
    ) -> None:
        first = normalization_schema_manifest()
        second = normalization_schema_manifest()

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            first[
                "schema_version"
            ],
            "1",
        )

        self.assertFalse(
            first[
                "input_schema_version_equivalence_claimed"
            ]
        )

        self.assertFalse(
            first[
                "changes_existing_model_fields"
            ]
        )

        self.assertFalse(
            first[
                "changes_event_identity"
            ]
        )

        self.assertFalse(
            first[
                "changes_parser_semantics"
            ]
        )

        self.assertFalse(
            first[
                "changes_detection_semantics"
            ]
        )

        self.assertFalse(
            first[
                "changes_correlation_semantics"
            ]
        )

        self.assertFalse(
            first[
                "changes_clock_semantics"
            ]
        )

        first_bytes = (
            normalization_schema_manifest_json_bytes()
        )

        second_bytes = (
            normalization_schema_manifest_json_bytes()
        )

        self.assertEqual(
            first_bytes,
            second_bytes,
        )

        decoded = json.loads(
            first_bytes.decode(
                "utf-8"
            )
        )

        self.assertEqual(
            decoded,
            first,
        )

        expected_sha = hashlib.sha256(
            first_bytes
        ).hexdigest()

        self.assertEqual(
            normalization_schema_manifest_sha256(),
            expected_sha,
        )


if __name__ == "__main__":
    unittest.main()