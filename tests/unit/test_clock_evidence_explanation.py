from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tracesoc.evidence.clock_explanation import (
    ClockEvidenceExplanationError,
    SERIALIZATION_ID,
    clock_evidence_explanation_json_bytes,
    explain_clock_evidence,
    verify_registered_evidence_reference,
)
from tracesoc.findings.models import EvidenceReference
from tracesoc.models import (
    CanonicalEvent,
    ClockState,
    RawLocator,
    SourceType,
)
from tracesoc.normalization.clock_evidence import (
    ClockEvidence,
    ClockEvidenceState,
)


class ClockEvidenceExplanationTests(
    unittest.TestCase
):
    def setUp(
        self,
    ) -> None:
        self.temporary = TemporaryDirectory()

        self.root = Path(
            self.temporary.name
        )

        self.source_id = "source-one"

        self.prefix = b"prefix\n"
        self.target_bytes = b"alpha\nbeta"
        self.gap = b"\ngap\n"
        self.support_bytes = b"omega"
        self.suffix = b"\n"

        self.payload = (
            self.prefix
            +
            self.target_bytes
            +
            self.gap
            +
            self.support_bytes
            +
            self.suffix
        )

        self.source_path = (
            self.root
            /
            "evidence.log"
        )

        self.source_path.write_bytes(
            self.payload
        )

        self.artifact_sha = hashlib.sha256(
            self.payload
        ).hexdigest()

        self.master_path = (
            self.root
            /
            "master.json"
        )

        self.artifact = {
            "source_id":
                self.source_id,

            "storage_path":
                str(
                    self.source_path
                ),

            "hash_verified":
                True,

            "integrity_status":
                "VERIFIED",

            "expected_sha256":
                self.artifact_sha,

            "observed_sha256":
                self.artifact_sha,
        }

        self._write_master(
            [
                self.artifact,
            ]
        )

        target_offset = len(
            self.prefix
        )

        support_offset = self.payload.index(
            self.support_bytes
        )

        self.target_event = self._event(
            event_id=
                "evt_target",

            source_type=
                SourceType.WINDOWS_SECURITY,

            clock_state=
                ClockState.UNRESOLVED,

            event_time_raw=
                "03/31/2021 12:00:42 PM",

            event_time_utc=
                None,

            record_index=
                1,

            line_number=
                2,

            byte_offset=
                target_offset,

            raw_bytes=
                self.target_bytes,
        )

        self.support_event = self._event(
            event_id=
                "evt_support",

            source_type=
                SourceType.SYSMON,

            clock_state=
                ClockState.OBSERVED,

            event_time_raw=
                "2021-03-31 12:00:42.100",

            event_time_utc=
                datetime(
                    2021,
                    3,
                    31,
                    12,
                    0,
                    42,
                    100000,
                    tzinfo=timezone.utc,
                ),

            record_index=
                2,

            line_number=
                5,

            byte_offset=
                support_offset,

            raw_bytes=
                self.support_bytes,
        )

        self.clock = ClockEvidence(
            evidence_id=
                "clk_test_001",

            state=
                ClockEvidenceState.CORROBORATED,

            method=
                "windows_security_sysmon_process_same_second_zero_offset_v1",

            target_event_id=
                self.target_event.event_id,

            supporting_event_ids=(
                self.support_event.event_id,
            ),

            host=
                "host.example",

            target_event_time_raw=
                "03/31/2021 12:00:42 PM",

            utc_interval_start=
                datetime(
                    2021,
                    3,
                    31,
                    12,
                    0,
                    42,
                    tzinfo=timezone.utc,
                ),

            utc_interval_end_exclusive=
                datetime(
                    2021,
                    3,
                    31,
                    12,
                    0,
                    43,
                    tzinfo=timezone.utc,
                ),

            coordinate_offset_seconds=
                0,

            resolution_seconds=
                1,

            identity_dimensions=(
                "exact_host",
                "process_name_casefold",
                "numeric_process_id",
                "parent_process_casefold",
                "numeric_parent_process_id",
                "exact_principal",
            ),
        )

    def tearDown(
        self,
    ) -> None:
        self.temporary.cleanup()

    def _write_master(
        self,
        artifacts,
    ) -> None:
        self.master_path.write_text(
            json.dumps(
                {
                    "evidence_state": {
                        "artifacts":
                            artifacts,
                    }
                }
            ),
            encoding="utf-8",
        )

    def _event(
        self,
        *,
        event_id,
        source_type,
        clock_state,
        event_time_raw,
        event_time_utc,
        record_index,
        line_number,
        byte_offset,
        raw_bytes,
    ):
        locator = RawLocator(
            logical_source=
                self.source_id,

            record_index=
                record_index,

            raw_sha256=
                hashlib.sha256(
                    raw_bytes
                ).hexdigest(),

            adapter_id=
                "test-adapter",

            input_schema_version=
                "1",

            line_number=
                line_number,

            byte_offset=
                byte_offset,

            byte_length=
                len(
                    raw_bytes
                ),
        )

        return CanonicalEvent(
            event_id=
                event_id,

            source_type=
                source_type,

            event_type=
                "process_create",

            clock_state=
                clock_state,

            provenance=
                locator,

            event_time_raw=
                event_time_raw,

            event_time_utc=
                event_time_utc,

            host=
                "host.example",

            principal=
                "principal",

            semantic_fields={},

            source_context={},
        )

    def _reference_with(
        self,
        reference,
        **changes,
    ):
        values = reference.to_dict()

        values.update(
            changes
        )

        return EvidenceReference(
            event_id=
                values[
                    "event_id"
                ],

            source_type=
                values[
                    "source_type"
                ],

            logical_source=
                values[
                    "logical_source"
                ],

            record_index=
                values[
                    "record_index"
                ],

            line_number=
                values[
                    "line_number"
                ],

            byte_offset=
                values[
                    "byte_offset"
                ],

            byte_length=
                values[
                    "byte_length"
                ],

            raw_sha256=
                values[
                    "raw_sha256"
                ],
        )

    def test_valid_multiline_reference_is_verified(
        self,
    ) -> None:
        reference = (
            EvidenceReference.from_canonical(
                self.target_event
            )
        )

        verified = (
            verify_registered_evidence_reference(
                master_record_path=
                    self.master_path,
                reference=
                    reference,
            )
        )

        self.assertTrue(
            verified[
                "artifact_sha256_verified"
            ]
        )

        self.assertTrue(
            verified[
                "raw_sha256_verified"
            ]
        )

        self.assertTrue(
            verified[
                "line_start_verified"
            ]
        )

        self.assertEqual(
            verified[
                "raw_text"
            ],
            "alpha\nbeta",
        )

    def test_duplicate_source_id_is_rejected(
        self,
    ) -> None:
        self._write_master(
            [
                self.artifact,
                dict(
                    self.artifact
                ),
            ]
        )

        with self.assertRaises(
            ClockEvidenceExplanationError
        ):
            verify_registered_evidence_reference(
                master_record_path=
                    self.master_path,
                reference=
                    EvidenceReference.from_canonical(
                        self.target_event
                    ),
            )

    def test_unregistered_source_is_rejected(
        self,
    ) -> None:
        reference = (
            EvidenceReference.from_canonical(
                self.target_event
            )
        )

        reference = self._reference_with(
            reference,
            logical_source=
                "unregistered-source",
        )

        with self.assertRaises(
            ClockEvidenceExplanationError
        ):
            verify_registered_evidence_reference(
                master_record_path=
                    self.master_path,
                reference=
                    reference,
            )

    def test_unverified_artifact_is_rejected(
        self,
    ) -> None:
        artifact = dict(
            self.artifact
        )

        artifact[
            "hash_verified"
        ] = False

        self._write_master(
            [
                artifact,
            ]
        )

        with self.assertRaises(
            ClockEvidenceExplanationError
        ):
            verify_registered_evidence_reference(
                master_record_path=
                    self.master_path,
                reference=
                    EvidenceReference.from_canonical(
                        self.target_event
                    ),
            )

    def test_registered_expected_observed_hash_disagreement_is_rejected(
        self,
    ) -> None:
        artifact = dict(
            self.artifact
        )

        artifact[
            "observed_sha256"
        ] = (
            "0"
            *
            64
        )

        self._write_master(
            [
                artifact,
            ]
        )

        with self.assertRaises(
            ClockEvidenceExplanationError
        ):
            verify_registered_evidence_reference(
                master_record_path=
                    self.master_path,
                reference=
                    EvidenceReference.from_canonical(
                        self.target_event
                    ),
            )

    def test_current_artifact_hash_change_is_rejected(
        self,
    ) -> None:
        self.source_path.write_bytes(
            self.payload
            +
            b"changed"
        )

        with self.assertRaises(
            ClockEvidenceExplanationError
        ):
            verify_registered_evidence_reference(
                master_record_path=
                    self.master_path,
                reference=
                    EvidenceReference.from_canonical(
                        self.target_event
                    ),
            )

    def test_missing_byte_locator_is_rejected(
        self,
    ) -> None:
        reference = (
            EvidenceReference.from_canonical(
                self.target_event
            )
        )

        reference = self._reference_with(
            reference,
            byte_offset=
                None,
        )

        with self.assertRaises(
            ClockEvidenceExplanationError
        ):
            verify_registered_evidence_reference(
                master_record_path=
                    self.master_path,
                reference=
                    reference,
            )

    def test_record_hash_mismatch_is_rejected(
        self,
    ) -> None:
        reference = (
            EvidenceReference.from_canonical(
                self.target_event
            )
        )

        reference = self._reference_with(
            reference,
            raw_sha256=
                "0"
                *
                64,
        )

        with self.assertRaises(
            ClockEvidenceExplanationError
        ):
            verify_registered_evidence_reference(
                master_record_path=
                    self.master_path,
                reference=
                    reference,
            )

    def test_line_number_must_identify_record_start(
        self,
    ) -> None:
        reference = (
            EvidenceReference.from_canonical(
                self.target_event
            )
        )

        reference = self._reference_with(
            reference,
            line_number=
                1,
        )

        with self.assertRaises(
            ClockEvidenceExplanationError
        ):
            verify_registered_evidence_reference(
                master_record_path=
                    self.master_path,
                reference=
                    reference,
            )

    def test_explanation_preserves_clock_lineage_without_analytic_ids(
        self,
    ) -> None:
        explanation = explain_clock_evidence(
            evidence=
                self.clock,

            canonical_events=[
                self.target_event,
                self.support_event,
            ],

            master_record_path=
                self.master_path,
        )

        self.assertEqual(
            explanation[
                "serialization_id"
            ],
            SERIALIZATION_ID,
        )

        self.assertEqual(
            explanation[
                "clock_evidence"
            ][
                "evidence_id"
            ],
            self.clock.evidence_id,
        )

        self.assertEqual(
            explanation[
                "clock_evidence"
            ][
                "target_event_id"
            ],
            self.target_event.event_id,
        )

        self.assertEqual(
            explanation[
                "clock_evidence"
            ][
                "supporting_event_ids"
            ],
            [
                self.support_event.event_id,
            ],
        )

        self.assertEqual(
            explanation[
                "raw_evidence_reference_count"
            ],
            2,
        )

        self.assertEqual(
            explanation[
                "raw_evidence_hashes_verified"
            ],
            2,
        )

        serialized = (
            clock_evidence_explanation_json_bytes(
                explanation
            )
            .decode(
                "utf-8"
            )
        )

        self.assertNotIn(
            "TRC-DET-",
            serialized,
        )

        self.assertNotIn(
            "TRC-CORR-",
            serialized,
        )

        self.assertNotIn(
            "FINDING-",
            serialized,
        )

        self.assertFalse(
            explanation[
                "analytic_boundary"
            ][
                "malicious_intent_established"
            ]
        )

    def test_serialization_is_deterministic(
        self,
    ) -> None:
        first = explain_clock_evidence(
            evidence=
                self.clock,

            canonical_events=[
                self.target_event,
                self.support_event,
            ],

            master_record_path=
                self.master_path,
        )

        second = explain_clock_evidence(
            evidence=
                self.clock,

            canonical_events=[
                self.support_event,
                self.target_event,
            ],

            master_record_path=
                self.master_path,
        )

        self.assertEqual(
            clock_evidence_explanation_json_bytes(
                first
            ),
            clock_evidence_explanation_json_bytes(
                second
            ),
        )


if __name__ == "__main__":
    unittest.main()