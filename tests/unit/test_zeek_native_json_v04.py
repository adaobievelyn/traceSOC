from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tracesoc.evidence.intake import (
    AdapterFamily,
    classify_evidence_bytes,
    ingest_evidence_file,
)
from tracesoc.models import SourceType
from tracesoc.parsers.zeek import (
    NATIVE_JSON_ADAPTER_ID,
    REAL_ADAPTER_ID,
    load_zeek_conn_ascii,
    load_zeek_conn_native_json,
)


FIELDS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
)


def native_payload() -> dict[str, object]:
    return {
        "ts":
            1700000000.125,
        "uid":
            "C-RC2C-001",
        "id.orig_h":
            "10.0.0.5",
        "id.orig_p":
            50123,
        "id.resp_h":
            "198.51.100.20",
        "id.resp_p":
            443,
        "proto":
            "tcp",
        "service":
            "ssl",
        "duration":
            1.25,
        "orig_bytes":
            120,
        "resp_bytes":
            240,
        "conn_state":
            "SF",
        "missed_bytes":
            0,
        "history":
            "ShADadFf",
        "orig_pkts":
            5,
        "orig_ip_bytes":
            380,
        "resp_pkts":
            6,
        "resp_ip_bytes":
            520,

        # Source-native extra context is retained but not promoted.
        "local_orig":
            False,
        "local_resp":
            False,
    }


def ascii_values(
    payload: dict[str, object],
) -> tuple[str, ...]:
    values = []

    for field in FIELDS:
        value = payload.get(
            field
        )

        if value is None:
            values.append(
                "-"
            )
        else:
            values.append(
                str(
                    value
                )
            )

    return tuple(
        values
    )


def ascii_conn_log(
    payload: dict[str, object],
) -> bytes:
    header = (
        "#separator \\x09\n"
        "#fields\t"
        + "\t".join(
            FIELDS
        )
        + "\n"
    )

    row = (
        "\t".join(
            ascii_values(
                payload
            )
        )
        + "\n"
    )

    return (
        header + row
    ).encode(
        "utf-8"
    )


class ZeekNativeJsonTests(
    unittest.TestCase
):
    def test_classifier_recognizes_native_zeek_jsonl(
        self,
    ) -> None:
        raw = (
            json.dumps(
                native_payload(),
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        result = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "conn.jsonl"
                ),
            )
        )

        self.assertIs(
            result.family,
            AdapterFamily.ZEEK_JSON,
        )

        self.assertEqual(
            result.reason,
            "zeek_native_conn_json_profile",
        )

    def test_ascii_and_json_have_same_connection_semantics(
        self,
    ) -> None:
        payload = (
            native_payload()
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            ascii_path = (
                root
                / "conn.log"
            )

            json_path = (
                root
                / "conn.jsonl"
            )

            ascii_path.write_bytes(
                ascii_conn_log(
                    payload
                )
            )

            json_path.write_bytes(
                json.dumps(
                    payload,
                    separators=(",", ":"),
                ).encode(
                    "utf-8"
                )
                + b"\n"
            )

            ascii_batch = (
                load_zeek_conn_ascii(
                    ascii_path,
                    logical_source=(
                        "conn.log"
                    ),
                )
            )

            json_batch = (
                load_zeek_conn_native_json(
                    json_path,
                    logical_source=(
                        "conn.jsonl"
                    ),
                )
            )

        self.assertEqual(
            ascii_batch.accepted_count,
            1,
        )

        self.assertEqual(
            json_batch.accepted_count,
            1,
        )

        self.assertEqual(
            ascii_batch.quarantined_count,
            0,
        )

        self.assertEqual(
            json_batch.quarantined_count,
            0,
        )

        ascii_event = (
            ascii_batch.accepted[0]
        )

        json_event = (
            json_batch.accepted[0]
        )

        self.assertIs(
            ascii_event.source_type,
            SourceType.ZEEK,
        )

        self.assertIs(
            json_event.source_type,
            SourceType.ZEEK,
        )

        self.assertEqual(
            ascii_event.event_type,
            "connection",
        )

        self.assertEqual(
            ascii_event.event_type,
            json_event.event_type,
        )

        self.assertEqual(
            ascii_event.clock_state,
            json_event.clock_state,
        )

        self.assertEqual(
            ascii_event.event_time_utc,
            json_event.event_time_utc,
        )

        self.assertEqual(
            ascii_event.host,
            json_event.host,
        )

        self.assertEqual(
            ascii_event.principal,
            json_event.principal,
        )

        self.assertEqual(
            ascii_event.semantic_fields,
            json_event.semantic_fields,
        )

        self.assertNotEqual(
            ascii_event.event_id,
            json_event.event_id,
        )

        self.assertNotEqual(
            ascii_event.provenance.raw_sha256,
            json_event.provenance.raw_sha256,
        )

        self.assertEqual(
            ascii_event.provenance.adapter_id,
            REAL_ADAPTER_ID,
        )

        self.assertEqual(
            json_event.provenance.adapter_id,
            NATIVE_JSON_ADAPTER_ID,
        )

        self.assertEqual(
            ascii_event.source_context[
                "zeek_fields"
            ][
                "orig_bytes"
            ],
            "120",
        )

        self.assertEqual(
            json_event.source_context[
                "zeek_fields"
            ][
                "orig_bytes"
            ],
            120,
        )

        self.assertFalse(
            json_event.source_context[
                "zeek_fields"
            ][
                "local_orig"
            ]
        )

    def test_generic_intake_routes_jsonl_and_preserves_bytes(
        self,
    ) -> None:
        raw = (
            json.dumps(
                native_payload(),
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "conn.jsonl"
            )

            path.write_bytes(
                raw
            )

            before = (
                path.read_bytes()
            )

            result = (
                ingest_evidence_file(
                    path,
                    root=root,
                    acquired_or_observed_utc=(
                        datetime(
                            2026,
                            9,
                            23,
                            18,
                            0,
                            tzinfo=timezone.utc,
                        )
                    ),
                )
            )

            after = (
                path.read_bytes()
            )

        self.assertEqual(
            before,
            after,
        )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.ZEEK_JSON,
        )

        self.assertEqual(
            len(
                result.canonical_events
            ),
            1,
        )

        self.assertEqual(
            len(
                result.evidence_locators
            ),
            1,
        )

    def test_pretty_single_json_object_is_supported(
        self,
    ) -> None:
        raw = json.dumps(
            native_payload(),
            indent=2,
            sort_keys=True,
        ).encode(
            "utf-8"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "conn.json"
            )

            path.write_bytes(
                raw
            )

            before = (
                path.read_bytes()
            )

            result = (
                ingest_evidence_file(
                    path,
                    root=root,
                    acquired_or_observed_utc=(
                        datetime(
                            2026,
                            9,
                            23,
                            18,
                            0,
                            tzinfo=timezone.utc,
                        )
                    ),
                )
            )

            after = (
                path.read_bytes()
            )

        self.assertEqual(
            before,
            after,
        )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.ZEEK_JSON,
        )

        self.assertEqual(
            len(
                result.canonical_events
            ),
            1,
        )

        event = (
            result.canonical_events[0]
        )

        self.assertEqual(
            event.provenance.byte_offset,
            0,
        )

        self.assertEqual(
            event.provenance.byte_length,
            len(
                raw
            ),
        )

    def test_null_optional_fields_match_ascii_unset_semantics(
        self,
    ) -> None:
        payload = (
            native_payload()
        )

        for field in (
            "service",
            "duration",
            "orig_bytes",
            "resp_bytes",
            "conn_state",
            "missed_bytes",
            "history",
            "orig_pkts",
            "orig_ip_bytes",
            "resp_pkts",
            "resp_ip_bytes",
        ):
            payload[
                field
            ] = None

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            ascii_path = (
                root
                / "conn.log"
            )

            json_path = (
                root
                / "conn.jsonl"
            )

            ascii_path.write_bytes(
                ascii_conn_log(
                    payload
                )
            )

            json_path.write_bytes(
                json.dumps(
                    payload,
                    separators=(",", ":"),
                ).encode(
                    "utf-8"
                )
                + b"\n"
            )

            ascii_batch = (
                load_zeek_conn_ascii(
                    ascii_path,
                    logical_source=(
                        "conn.log"
                    ),
                )
            )

            json_batch = (
                load_zeek_conn_native_json(
                    json_path,
                    logical_source=(
                        "conn.jsonl"
                    ),
                )
            )

        self.assertEqual(
            ascii_batch.accepted_count,
            1,
        )

        self.assertEqual(
            json_batch.accepted_count,
            1,
        )

        self.assertEqual(
            ascii_batch.accepted[
                0
            ].semantic_fields,
            json_batch.accepted[
                0
            ].semantic_fields,
        )

        self.assertEqual(
            set(
                json_batch.accepted[
                    0
                ].semantic_fields
            ),
            {
                "uid",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "proto",
            },
        )

    def test_structurally_recognized_missing_uid_is_quarantined(
        self,
    ) -> None:
        payload = (
            native_payload()
        )

        del payload[
            "uid"
        ]

        raw = (
            json.dumps(
                payload,
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "conn.jsonl"
            )

            path.write_bytes(
                raw
            )

            result = (
                ingest_evidence_file(
                    path,
                    root=root,
                    acquired_or_observed_utc=(
                        datetime(
                            2026,
                            9,
                            23,
                            18,
                            0,
                            tzinfo=timezone.utc,
                        )
                    ),
                )
            )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.ZEEK_JSON,
        )

        self.assertEqual(
            len(
                result.canonical_events
            ),
            0,
        )

        self.assertEqual(
            result.issue_count,
            1,
        )

    def test_valid_row_plus_malformed_row_is_fully_accounted(
        self,
    ) -> None:
        first = (
            json.dumps(
                native_payload(),
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        raw = (
            first
            + b"{not-json}\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(
                tmp
            )

            path = (
                root
                / "conn.jsonl"
            )

            path.write_bytes(
                raw
            )

            result = (
                ingest_evidence_file(
                    path,
                    root=root,
                    acquired_or_observed_utc=(
                        datetime(
                            2026,
                            9,
                            23,
                            18,
                            0,
                            tzinfo=timezone.utc,
                        )
                    ),
                )
            )

        self.assertIs(
            result.adapter_family,
            AdapterFamily.ZEEK_JSON,
        )

        self.assertEqual(
            len(
                result.canonical_events
            ),
            1,
        )

        self.assertEqual(
            result.issue_count,
            1,
        )

        self.assertEqual(
            len(
                result.evidence_locators
            ),
            2,
        )

    def test_legacy_tracesoc_zeek_jsonl_is_not_native_profile(
        self,
    ) -> None:
        legacy = {
            "timestamp":
                "2026-09-23T18:00:00Z",
            "event_type":
                "connection",
            "uid":
                "legacy",
            "src_ip":
                "10.0.0.5",
            "dst_ip":
                "198.51.100.20",
            "dst_port":
                443,
            "proto":
                "tcp",
            "service":
                "ssl",
            "bytes_out":
                120,
            "bytes_in":
                240,
        }

        raw = (
            json.dumps(
                legacy,
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        result = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "legacy-zeek.jsonl"
                ),
            )
        )

        self.assertIs(
            result.family,
            AdapterFamily.UNSUPPORTED,
        )

        self.assertEqual(
            result.reason,
            "no_supported_json_profile",
        )

    def test_windows_event_and_zeek_profiles_in_one_jsonl_fail_closed(
        self,
    ) -> None:
        windows = {
            "System": {
                "Provider": {
                    "Name":
                        "Microsoft-Windows-Sysmon",
                },
                "EventID":
                    1,
                "EventRecordID":
                    99,
                "TimeCreated": {
                    "SystemTime":
                        "2026-09-23T18:00:00Z",
                },
                "Computer":
                    "HOST-RC2C",
                "Channel":
                    "Microsoft-Windows-Sysmon/Operational",
            },
            "EventData": {},
        }

        raw = (
            json.dumps(
                windows,
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
            + json.dumps(
                native_payload(),
                separators=(",", ":"),
            ).encode(
                "utf-8"
            )
            + b"\n"
        )

        result = (
            classify_evidence_bytes(
                raw_bytes=raw,
                logical_source=(
                    "mixed.jsonl"
                ),
            )
        )

        self.assertIs(
            result.family,
            AdapterFamily.UNSUPPORTED,
        )

        self.assertEqual(
            result.reason,
            "ambiguous_json_source_profile",
        )


if __name__ == "__main__":
    unittest.main()
