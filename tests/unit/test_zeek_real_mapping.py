from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from tracesoc.models import ClockState, SourceType
from tracesoc.parsers.zeek import load_zeek_conn_ascii


_FIELDS = (
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
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
)

_TYPES = (
    "time",
    "string",
    "addr",
    "port",
    "addr",
    "port",
    "enum",
    "string",
    "interval",
    "count",
    "count",
    "string",
    "bool",
    "bool",
    "count",
    "string",
    "count",
    "count",
    "count",
    "count",
    "set[string]",
)


def _zeek_log(
    row_values: tuple[str, ...],
    *,
    labels: tuple[str, str] | None,
) -> bytes:
    fields = list(
        _FIELDS
    )
    types = list(
        _TYPES
    )
    values = list(
        row_values
    )

    if labels is not None:
        fields.extend(
            (
                "label",
                "det_label",
            )
        )
        types.extend(
            (
                "string",
                "string",
            )
        )
        values.extend(
            labels
        )

    header = (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#open\t2018-12-21-15-50-14\n"
        "#fields\t"
        + "\t".join(fields)
        + "\n"
        "#types\t"
        + "\t".join(types)
        + "\n"
    )

    row = (
        "\t".join(values)
        + "\n"
    )

    return (
        header
        + row
    ).encode(
        "utf-8"
    )


_BASE_ROW = (
    "1545394014.500000",
    "C123",
    "192.0.2.10",
    "49152",
    "198.51.100.25",
    "80",
    "tcp",
    "http",
    "1.25",
    "100",
    "200",
    "SF",
    "-",
    "-",
    "0",
    "ShADadFf",
    "2",
    "180",
    "3",
    "300",
    "-",
)


class ZeekRealMappingTests(
    unittest.TestCase
):
    def _load(
        self,
        raw: bytes,
    ):
        with tempfile.TemporaryDirectory() as directory:
            path = (
                Path(directory)
                / "conn.log"
            )

            path.write_bytes(
                raw
            )

            return load_zeek_conn_ascii(
                path,
                logical_source="tests/real/conn.log",
            )

    def test_maps_source_native_connection_fields_and_clock(
        self,
    ) -> None:
        batch = self._load(
            _zeek_log(
                _BASE_ROW,
                labels=(
                    "Malicious",
                    "PartOfAHorizontalPortScan",
                ),
            )
        )

        self.assertEqual(
            batch.accepted_count,
            1,
        )
        self.assertEqual(
            batch.quarantined_count,
            0,
        )

        event = batch.accepted[0]

        self.assertEqual(
            event.source_type,
            SourceType.ZEEK,
        )
        self.assertEqual(
            event.event_type,
            "connection",
        )
        self.assertEqual(
            event.clock_state,
            ClockState.OBSERVED,
        )
        self.assertEqual(
            event.event_time_raw,
            "1545394014.500000",
        )
        self.assertEqual(
            event.event_time_utc,
            datetime.fromtimestamp(
                1545394014.5,
                tz=timezone.utc,
            ),
        )

        expected_semantics = {
            "uid": "C123",
            "src_ip": "192.0.2.10",
            "src_port": 49152,
            "dst_ip": "198.51.100.25",
            "dst_port": 80,
            "proto": "tcp",
            "service": "http",
            "duration": 1.25,
            "bytes_out": 100,
            "bytes_in": 200,
            "conn_state": "SF",
            "missed_bytes": 0,
            "history": "ShADadFf",
            "packets_out": 2,
            "ip_bytes_out": 180,
            "packets_in": 3,
            "ip_bytes_in": 300,
        }

        self.assertEqual(
            dict(event.semantic_fields),
            expected_semantics,
        )

        self.assertIsNone(
            event.host
        )
        self.assertIsNone(
            event.principal
        )

    def test_publisher_labels_remain_source_context_only(
        self,
    ) -> None:
        batch = self._load(
            _zeek_log(
                _BASE_ROW,
                labels=(
                    "Malicious",
                    "PartOfAHorizontalPortScan",
                ),
            )
        )

        event = batch.accepted[0]

        self.assertNotIn(
            "label",
            event.semantic_fields,
        )
        self.assertNotIn(
            "det_label",
            event.semantic_fields,
        )

        zeek_fields = event.source_context[
            "zeek_fields"
        ]

        self.assertEqual(
            zeek_fields["label"],
            "Malicious",
        )
        self.assertEqual(
            zeek_fields["det_label"],
            "PartOfAHorizontalPortScan",
        )

    def test_label_mutation_does_not_change_semantic_mapping(
        self,
    ) -> None:
        first = self._load(
            _zeek_log(
                _BASE_ROW,
                labels=(
                    "Malicious",
                    "PartOfAHorizontalPortScan",
                ),
            )
        ).accepted[0]

        second = self._load(
            _zeek_log(
                _BASE_ROW,
                labels=(
                    "Benign",
                    "TotallyDifferentPublisherLabel",
                ),
            )
        ).accepted[0]

        self.assertEqual(
            dict(first.semantic_fields),
            dict(second.semantic_fields),
        )
        self.assertEqual(
            first.event_time_utc,
            second.event_time_utc,
        )

        # Raw bytes differ, therefore provenance/event identity differs.
        # The label changes source identity but not semantic promotion.
        self.assertNotEqual(
            first.event_id,
            second.event_id,
        )

    def test_standard_conn_log_without_publisher_labels_is_accepted(
        self,
    ) -> None:
        batch = self._load(
            _zeek_log(
                _BASE_ROW,
                labels=None,
            )
        )

        self.assertEqual(
            batch.accepted_count,
            1,
        )
        self.assertEqual(
            batch.quarantined_count,
            0,
        )

        event = batch.accepted[0]
        zeek_fields = event.source_context[
            "zeek_fields"
        ]

        self.assertNotIn(
            "label",
            zeek_fields,
        )
        self.assertNotIn(
            "det_label",
            zeek_fields,
        )

        self.assertEqual(
            event.semantic_fields[
                "src_ip"
            ],
            "192.0.2.10",
        )

    def test_invalid_source_native_port_is_quarantined(
        self,
    ) -> None:
        values = list(
            _BASE_ROW
        )
        values[5] = "not-a-port"

        batch = self._load(
            _zeek_log(
                tuple(values),
                labels=None,
            )
        )

        self.assertEqual(
            batch.accepted_count,
            0,
        )
        self.assertEqual(
            batch.quarantined_count,
            1,
        )
        self.assertEqual(
            batch.quarantined[0].reason_code,
            "invalid_field",
        )


if __name__ == "__main__":
    unittest.main()
