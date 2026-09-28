from __future__ import annotations

import hashlib
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

from tracesoc.evidence.artifacts import (
    Artifact,
    ArtifactImmutabilityState,
    ArtifactProcessingState,
    compute_artifact_id,
)


UTC_TIME = datetime(
    2026,
    9,
    22,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ArtifactContractTests(unittest.TestCase):
    def source_artifact(
        self,
        *,
        raw: bytes = b"evidence",
        path: str = "raw/example.bin",
        artifact_type: str = "UNKNOWN",
        processing_state: ArtifactProcessingState = (
            ArtifactProcessingState.UNSUPPORTED_PRESERVED
        ),
        observed: datetime = UTC_TIME,
    ) -> Artifact:
        return Artifact.create(
            artifact_type=artifact_type,
            source_path_display=path,
            sha256=sha256(raw),
            bytes=len(raw),
            acquired_or_observed_utc=observed,
            immutability_state=(
                ArtifactImmutabilityState.PRESERVED_SOURCE
            ),
            processing_state=processing_state,
        )

    def test_processing_state_contract_is_exact(self) -> None:
        self.assertEqual(
            {state.value for state in ArtifactProcessingState},
            {
                "SUPPORTED_PROCESSED",
                "SUPPORTED_PARTIAL",
                "UNSUPPORTED_PRESERVED",
                "MALFORMED_QUARANTINED",
                "FAILED_EXPLICIT",
            },
        )

    def test_identity_is_deterministic(self) -> None:
        first = self.source_artifact(
            raw=b"same",
            path="raw/same.bin",
        )
        second = self.source_artifact(
            raw=b"same",
            path="raw/same.bin",
            artifact_type="application/octet-stream",
            processing_state=(
                ArtifactProcessingState.SUPPORTED_PROCESSED
            ),
            observed=UTC_TIME + timedelta(seconds=30),
        )
        self.assertEqual(first.artifact_id, second.artifact_id)

    def test_one_byte_change_changes_identity(self) -> None:
        first = self.source_artifact(
            raw=b"A",
            path="raw/change.bin",
        )
        second = self.source_artifact(
            raw=b"B",
            path="raw/change.bin",
        )
        self.assertNotEqual(first.sha256, second.sha256)
        self.assertNotEqual(first.artifact_id, second.artifact_id)

    def test_backslash_path_is_normalized(self) -> None:
        artifact = self.source_artifact(
            path=r"raw\host\event.log",
        )
        self.assertEqual(
            artifact.source_path_display,
            "raw/host/event.log",
        )
        self.assertEqual(
            artifact.artifact_id,
            compute_artifact_id(
                source_path_display="raw/host/event.log",
                sha256=artifact.sha256,
                bytes=artifact.bytes,
            ),
        )

    def test_unsafe_paths_are_rejected(self) -> None:
        bad_paths = (
            r"C:\Evidence\sample.bin",
            "C:relative.bin",
            r"\\server\share\sample.bin",
            "/var/tmp/sample.bin",
            "../sample.bin",
            "raw/../sample.bin",
            "./sample.bin",
            "raw//sample.bin",
            " raw/sample.bin",
            "raw/sample.bin ",
        )
        for bad_path in bad_paths:
            with self.subTest(bad_path=bad_path):
                with self.assertRaises(ValueError):
                    self.source_artifact(path=bad_path)

    def test_all_processing_states_validate(self) -> None:
        for state in ArtifactProcessingState:
            with self.subTest(state=state):
                artifact = self.source_artifact(
                    processing_state=state
                )
                self.assertIs(
                    artifact.processing_state,
                    state,
                )

    def test_zero_byte_artifact_is_valid(self) -> None:
        artifact = self.source_artifact(
            raw=b"",
            path="raw/empty.bin",
        )
        self.assertEqual(artifact.bytes, 0)
        self.assertEqual(
            artifact.sha256,
            hashlib.sha256(b"").hexdigest(),
        )

    def test_source_artifact_cannot_have_derivation_lineage(
        self,
    ) -> None:
        parent = self.source_artifact(
            raw=b"parent",
            path="raw/parent.bin",
        )
        with self.assertRaises(ValueError):
            Artifact.create(
                artifact_type="UNKNOWN",
                source_path_display="raw/child.bin",
                sha256=sha256(b"child"),
                bytes=len(b"child"),
                acquired_or_observed_utc=UTC_TIME,
                immutability_state=(
                    ArtifactImmutabilityState.PRESERVED_SOURCE
                ),
                processing_state=(
                    ArtifactProcessingState.SUPPORTED_PROCESSED
                ),
                parent_artifact_id=parent.artifact_id,
                derivation_method="extract",
                derivation_tool="tracesoc",
                derivation_tool_version="0.4",
            )

    def test_derived_artifact_requires_complete_lineage(
        self,
    ) -> None:
        parent = self.source_artifact(
            raw=b"parent",
            path="raw/parent.eml",
            artifact_type="message/rfc822",
        )
        values = {
            "artifact_type": "application/octet-stream",
            "source_path_display": "derived/attachment.bin",
            "sha256": sha256(b"child"),
            "bytes": len(b"child"),
            "acquired_or_observed_utc": UTC_TIME,
            "immutability_state":
                ArtifactImmutabilityState.PRESERVED_DERIVED,
            "processing_state":
                ArtifactProcessingState.SUPPORTED_PROCESSED,
            "parent_artifact_id": parent.artifact_id,
            "derivation_method": "mime_attachment_extract",
            "derivation_tool": "tracesoc",
            "derivation_tool_version": "0.4",
        }
        for missing in (
            "parent_artifact_id",
            "derivation_method",
            "derivation_tool",
            "derivation_tool_version",
        ):
            with self.subTest(missing=missing):
                incomplete = dict(values)
                incomplete[missing] = None
                with self.assertRaises(ValueError):
                    Artifact.create(**incomplete)

    def test_valid_derived_artifact_preserves_lineage(
        self,
    ) -> None:
        parent = self.source_artifact(
            raw=b"mail",
            path="raw/message.eml",
            artifact_type="message/rfc822",
        )
        child = Artifact.create(
            artifact_type="application/octet-stream",
            source_path_display="derived/attachment.bin",
            sha256=sha256(b"attachment"),
            bytes=len(b"attachment"),
            acquired_or_observed_utc=UTC_TIME,
            immutability_state=(
                ArtifactImmutabilityState.PRESERVED_DERIVED
            ),
            processing_state=(
                ArtifactProcessingState.SUPPORTED_PROCESSED
            ),
            parent_artifact_id=parent.artifact_id,
            derivation_method="mime_attachment_extract",
            derivation_tool="tracesoc",
            derivation_tool_version="0.4",
        )
        self.assertEqual(
            child.parent_artifact_id,
            parent.artifact_id,
        )
        self.assertEqual(
            child.derivation_method,
            "mime_attachment_extract",
        )

    def test_derived_artifact_cannot_be_its_own_parent(
        self,
    ) -> None:
        raw = b"child"
        path = "derived/child.bin"
        own_id = compute_artifact_id(
            source_path_display=path,
            sha256=sha256(raw),
            bytes=len(raw),
        )
        with self.assertRaises(ValueError):
            Artifact.create(
                artifact_type="application/octet-stream",
                source_path_display=path,
                sha256=sha256(raw),
                bytes=len(raw),
                acquired_or_observed_utc=UTC_TIME,
                immutability_state=(
                    ArtifactImmutabilityState.PRESERVED_DERIVED
                ),
                processing_state=(
                    ArtifactProcessingState.SUPPORTED_PROCESSED
                ),
                parent_artifact_id=own_id,
                derivation_method="copy",
                derivation_tool="tracesoc",
                derivation_tool_version="0.4",
            )

    def test_non_lowercase_sha256_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Artifact.create(
                artifact_type="UNKNOWN",
                source_path_display="raw/example.bin",
                sha256=sha256(b"evidence").upper(),
                bytes=len(b"evidence"),
                acquired_or_observed_utc=UTC_TIME,
                immutability_state=(
                    ArtifactImmutabilityState.PRESERVED_SOURCE
                ),
                processing_state=(
                    ArtifactProcessingState.UNSUPPORTED_PRESERVED
                ),
            )

    def test_negative_byte_count_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Artifact.create(
                artifact_type="UNKNOWN",
                source_path_display="raw/example.bin",
                sha256=sha256(b"evidence"),
                bytes=-1,
                acquired_or_observed_utc=UTC_TIME,
                immutability_state=(
                    ArtifactImmutabilityState.PRESERVED_SOURCE
                ),
                processing_state=(
                    ArtifactProcessingState.UNSUPPORTED_PRESERVED
                ),
            )

    def test_time_must_be_utc(self) -> None:
        non_utc = datetime(
            2026,
            9,
            22,
            13,
            0,
            tzinfo=timezone(
                timedelta(hours=1)
            ),
        )
        with self.assertRaises(ValueError):
            self.source_artifact(
                observed=non_utc
            )

    def test_artifact_is_immutable(self) -> None:
        artifact = self.source_artifact()
        with self.assertRaises(FrozenInstanceError):
            artifact.artifact_type = "changed"

    def test_wrong_direct_identity_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Artifact(
                artifact_id="art_" + ("0" * 64),
                artifact_type="UNKNOWN",
                source_path_display="raw/example.bin",
                sha256=sha256(b"evidence"),
                bytes=len(b"evidence"),
                acquired_or_observed_utc=UTC_TIME,
                immutability_state=(
                    ArtifactImmutabilityState.PRESERVED_SOURCE
                ),
                processing_state=(
                    ArtifactProcessingState.UNSUPPORTED_PRESERVED
                ),
            )


if __name__ == "__main__":
    unittest.main()
