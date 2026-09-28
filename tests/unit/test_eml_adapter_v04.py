from __future__ import annotations

import base64
import hashlib
import unittest
from datetime import datetime, timezone

from tracesoc.evidence.artifacts import (
    ArtifactImmutabilityState,
    ArtifactProcessingState,
)
from tracesoc.evidence.locators import (
    LocatorKind,
)
from tracesoc.models import SourceType
from tracesoc.parsers.eml import (
    EMAIL_ADAPTER_ID,
    EMAIL_INPUT_SCHEMA_VERSION,
    EMAIL_MESSAGE_EVENT_TYPE,
    EMAIL_PART_EVENT_TYPE,
    load_eml_bytes,
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


def sha256(
    value: bytes,
) -> str:
    return hashlib.sha256(
        value
    ).hexdigest()


class EmlAdapterTests(
    unittest.TestCase
):
    def test_plain_email_preserves_source_native_headers(
        self,
    ) -> None:
        raw = (
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Date: Tue, 22 Sep 2026 12:00:00 +0000\r\n"
            b"Message-ID: <m1@example.com>\r\n"
            b"Subject: Test message\r\n"
            b"\r\n"
            b"hello\r\n"
        )

        result = load_eml_bytes(
            raw_bytes=raw,
            source_path_display="raw/message.eml",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.SUPPORTED_PROCESSED,
        )

        self.assertEqual(
            result.artifact.sha256,
            sha256(raw),
        )

        self.assertEqual(
            result.artifact.bytes,
            len(raw),
        )

        self.assertIsNotNone(
            result.message
        )

        message = result.message
        assert message is not None

        self.assertIs(
            message.source_type,
            SourceType.EMAIL,
        )

        self.assertEqual(
            message.event_type,
            EMAIL_MESSAGE_EVENT_TYPE,
        )

        self.assertEqual(
            message.message_id,
            "<m1@example.com>",
        )

        self.assertEqual(
            message.date,
            "Tue, 22 Sep 2026 12:00:00 +0000",
        )

        self.assertEqual(
            message.subject,
            "Test message",
        )

        self.assertIs(
            message.locator.locator_kind,
            LocatorKind.BYTE_RANGE,
        )

        self.assertEqual(
            message.locator.byte_offset,
            0,
        )

        self.assertEqual(
            message.locator.byte_length,
            len(raw),
        )

        self.assertEqual(
            message.locator.raw_sha256,
            sha256(raw),
        )

        self.assertEqual(
            len(result.parts),
            1,
        )

        self.assertEqual(
            result.derived_artifacts,
            (),
        )

    def test_missing_date_and_message_id_remain_none(
        self,
    ) -> None:
        raw = (
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Subject: No identifiers\r\n"
            b"\r\n"
            b"hello\r\n"
        )

        result = load_eml_bytes(
            raw_bytes=raw,
            source_path_display="raw/missing.eml",
            acquired_or_observed_utc=UTC_TIME,
        )

        message = result.message
        assert message is not None

        self.assertIsNone(
            message.date
        )

        self.assertIsNone(
            message.message_id
        )

    def test_binary_attachment_creates_derived_artifact_with_parent_lineage(
        self,
    ) -> None:
        attachment = (
            b"\x00\xffpayload\x10"
        )

        encoded = base64.b64encode(
            attachment
        )

        raw = (
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Message-ID: <m2@example.com>\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n"
            b"\r\n"
            b"--BOUND\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"body\r\n"
            b"--BOUND\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=\"sample.bin\"\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            + encoded
            + b"\r\n"
            b"--BOUND--\r\n"
        )

        result = load_eml_bytes(
            raw_bytes=raw,
            source_path_display="raw/attachment.eml",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertEqual(
            len(result.parts),
            2,
        )

        self.assertEqual(
            len(result.derived_artifacts),
            1,
        )

        attachment_part = (
            result.parts[1]
        )

        child = (
            result.derived_artifacts[0]
        )

        self.assertIs(
            attachment_part.source_type,
            SourceType.EMAIL,
        )

        self.assertEqual(
            attachment_part.event_type,
            EMAIL_PART_EVENT_TYPE,
        )

        self.assertIs(
            attachment_part.locator.locator_kind,
            LocatorKind.MIME_PART,
        )

        self.assertEqual(
            attachment_part.locator.mime_part_path,
            (1,),
        )

        self.assertEqual(
            attachment_part.decoded_sha256,
            sha256(attachment),
        )

        self.assertEqual(
            attachment_part.decoded_bytes,
            len(attachment),
        )

        self.assertEqual(
            attachment_part.derived_artifact_id,
            child.artifact_id,
        )

        self.assertEqual(
            child.sha256,
            sha256(attachment),
        )

        self.assertEqual(
            child.bytes,
            len(attachment),
        )

        self.assertIs(
            child.immutability_state,
            ArtifactImmutabilityState.PRESERVED_DERIVED,
        )

        self.assertEqual(
            child.parent_artifact_id,
            result.artifact.artifact_id,
        )

        self.assertEqual(
            child.derivation_method,
            "mime_payload_decode",
        )

        self.assertEqual(
            child.derivation_tool,
            EMAIL_ADAPTER_ID,
        )

        self.assertEqual(
            child.derivation_tool_version,
            EMAIL_INPUT_SCHEMA_VERSION,
        )

    def test_untrusted_attachment_filename_does_not_control_derived_path(
        self,
    ) -> None:
        raw = (
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n"
            b"\r\n"
            b"--BOUND\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=\"../../evil.exe\"\r\n"
            b"\r\n"
            b"payload\r\n"
            b"--BOUND--\r\n"
        )

        result = load_eml_bytes(
            raw_bytes=raw,
            source_path_display="raw/untrusted-name.eml",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertEqual(
            result.parts[0].filename,
            "../../evil.exe",
        )

        child = (
            result.derived_artifacts[0]
        )

        self.assertNotIn(
            "..",
            child.source_path_display,
        )

        self.assertNotIn(
            "evil.exe",
            child.source_path_display,
        )

        self.assertTrue(
            child.source_path_display.startswith(
                "derived/"
                + result.artifact.artifact_id
                + "/mime/"
            )
        )

    def test_malformed_multipart_is_preserved_as_supported_partial(
        self,
    ) -> None:
        raw = (
            b"Content-Type: multipart/mixed; boundary=\"abc\"\r\n"
            b"\r\n"
            b"--abc\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"hello\r\n"
        )

        result = load_eml_bytes(
            raw_bytes=raw,
            source_path_display="raw/malformed.eml",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.SUPPORTED_PARTIAL,
        )

        message = result.message
        assert message is not None

        self.assertIn(
            "CloseBoundaryNotFoundDefect",
            message.defects,
        )

        self.assertIn(
            "parser_defect:CloseBoundaryNotFoundDefect",
            result.errors,
        )

    def test_empty_email_is_explicitly_quarantined(
        self,
    ) -> None:
        result = load_eml_bytes(
            raw_bytes=b"",
            source_path_display="raw/empty.eml",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertIs(
            result.artifact.processing_state,
            ArtifactProcessingState.MALFORMED_QUARANTINED,
        )

        self.assertIsNone(
            result.message
        )

        self.assertEqual(
            result.parts,
            (),
        )

        self.assertEqual(
            result.errors,
            (
                "empty_eml",
            ),
        )

    def test_adapter_is_deterministic(
        self,
    ) -> None:
        raw = (
            b"From: alice@example.com\r\n"
            b"Subject: deterministic\r\n"
            b"\r\n"
            b"body\r\n"
        )

        first = load_eml_bytes(
            raw_bytes=raw,
            source_path_display="raw/deterministic.eml",
            acquired_or_observed_utc=UTC_TIME,
        )

        second = load_eml_bytes(
            raw_bytes=raw,
            source_path_display="raw/deterministic.eml",
            acquired_or_observed_utc=UTC_TIME,
        )

        self.assertEqual(
            first,
            second,
        )

    def test_source_path_validation_is_inherited_from_artifact_contract(
        self,
    ) -> None:
        with self.assertRaises(
            ValueError
        ):
            load_eml_bytes(
                raw_bytes=(
                    b"Subject: x\r\n"
                    b"\r\n"
                    b"body\r\n"
                ),
                source_path_display="../escape.eml",
                acquired_or_observed_utc=UTC_TIME,
            )

    def test_raw_input_must_be_bytes(
        self,
    ) -> None:
        with self.assertRaises(
            TypeError
        ):
            load_eml_bytes(
                raw_bytes="not-bytes",
                source_path_display="raw/type.eml",
                acquired_or_observed_utc=UTC_TIME,
            )

    def test_fixture_style_answer_header_is_not_promoted_to_analytics(
        self,
    ) -> None:
        raw = (
            b"From: alice@example.com\r\n"
            b"X-Expected-Answer: malicious\r\n"
            b"X-Label: attack\r\n"
            b"Subject: ordinary message\r\n"
            b"\r\n"
            b"hello\r\n"
        )

        result = load_eml_bytes(
            raw_bytes=raw,
            source_path_display="raw/labels.eml",
            acquired_or_observed_utc=UTC_TIME,
        )

        message = result.message
        assert message is not None

        for forbidden in (
            "expected_answer",
            "label",
            "malicious",
            "verdict",
            "incident",
        ):
            self.assertFalse(
                hasattr(
                    message,
                    forbidden,
                )
            )

        self.assertEqual(
            message.subject,
            "ordinary message",
        )


if __name__ == "__main__":
    unittest.main()
