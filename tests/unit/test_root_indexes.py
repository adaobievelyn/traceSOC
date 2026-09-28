from __future__ import annotations

import csv
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO = Path(
    __file__
).resolve().parents[2]

SCRIPT = (
    REPO
    / "scripts"
    / "rebuild_root_indexes.py"
)

SPEC = importlib.util.spec_from_file_location(
    "tracesoc_root_indexes",
    SCRIPT,
)

if (
    SPEC is None
    or SPEC.loader is None
):
    raise RuntimeError(
        "cannot load root-index generator"
    )

MODULE = importlib.util.module_from_spec(
    SPEC
)

SPEC.loader.exec_module(
    MODULE
)


def csv_rows(
    data: bytes,
) -> list[dict[str, str]]:
    text = data.decode(
        "utf-8"
    )

    return list(
        csv.DictReader(
            io.StringIO(
                text
            )
        )
    )


class RootIndexTests(
    unittest.TestCase,
):
    def test_headers_match_controlled_root_schemas(
        self,
    ) -> None:
        outputs = MODULE.build_outputs(
            REPO
        )

        expected = {
            "evidence-index.csv":
                MODULE.EVIDENCE_INDEX_HEADER,
            "ioc-set.csv":
                MODULE.IOC_SET_HEADER,
            "timeline.csv":
                MODULE.TIMELINE_HEADER,
        }

        for name, header in expected.items():
            rows = list(
                csv.reader(
                    io.StringIO(
                        outputs[
                            name
                        ].decode(
                            "utf-8"
                        )
                    )
                )
            )

            self.assertGreaterEqual(
                len(
                    rows
                ),
                1,
            )

            self.assertEqual(
                rows[
                    0
                ],
                header,
            )

    def test_generation_is_byte_deterministic(
        self,
    ) -> None:
        first = MODULE.build_outputs(
            REPO
        )

        MODULE.validate_visibility_policy(
            first
        )

        second = MODULE.build_outputs(
            REPO
        )

        MODULE.validate_visibility_policy(
            second
        )

        self.assertEqual(
            first,
            second,
        )

        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(
                directory
            )

            for name, data in first.items():
                MODULE.atomic_write(
                    output_dir
                    / name,
                    data,
                )

            for name, data in second.items():
                self.assertEqual(
                    (
                        output_dir
                        / name
                    ).read_bytes(),
                    data,
                )

    def test_evidence_index_contains_registered_sources_and_real_release_paths(
        self,
    ) -> None:
        outputs = MODULE.build_outputs(
            REPO
        )

        rows = csv_rows(
            outputs[
                "evidence-index.csv"
            ]
        )

        acquisition = MODULE.read_csv_rows(
            REPO
            / "project-control"
            / "evidence-acquisition-register.csv"
        )

        registered_ids = {
            row[
                "source_id"
            ]
            for row in acquisition
        }

        indexed_raw_ids = {
            row[
                "source_id"
            ]
            for row in rows
            if row[
                "record_type"
            ]
            == "RAW_ARTIFACT"
        }

        self.assertEqual(
            indexed_raw_ids,
            registered_ids,
        )

        release_rows = {
            row[
                "detection_ids"
            ]: row
            for row in rows
            if row[
                "record_type"
            ]
            == "REAL_DETECTION_RELEASE_EVIDENCE"
        }

        self.assertEqual(
            set(
                release_rows
            ),
            {
                "TRC-DET-003",
                "TRC-DET-005",
            },
        )

        for row in release_rows.values():
            self.assertEqual(
                row[
                    "evidence_state"
                ],
                "OBSERVED",
            )

            self.assertTrue(
                row[
                    "parent_evidence_ids"
                ]
            )

            self.assertTrue(
                row[
                    "proof_path"
                ]
            )

            self.assertTrue(
                row[
                    "does_not_prove"
                ]
            )

            self.assertTrue(
                row[
                    "residual_uncertainty"
                ]
            )

    def test_timeline_covers_exact_real_release_event_denominator(
        self,
    ) -> None:
        outputs = MODULE.build_outputs(
            REPO
        )

        timeline = csv_rows(
            outputs[
                "timeline.csv"
            ]
        )

        release = json.loads(
            (
                REPO
                / "results"
                / "release"
                / "real-event-level-release-evidence.json"
            ).read_text(
                encoding="utf-8"
            )
        )

        expected_ids = set()

        for release_path in release[
            "release_paths"
        ]:
            for match in release_path[
                "matches"
            ]:
                for reference in MODULE.raw_references(
                    match
                ):
                    expected_ids.add(
                        reference[
                            "event_id"
                        ]
                    )

        actual_ids = {
            row[
                "event_id"
            ]
            for row in timeline
        }

        self.assertEqual(
            actual_ids,
            expected_ids,
        )

        for row in timeline:
            self.assertTrue(
                row[
                    "artifact_path"
                ]
            )

            self.assertIn(
                "byte_offset=",
                row[
                    "exact_locator"
                ],
            )

            self.assertIn(
                "byte_length=",
                row[
                    "exact_locator"
                ],
            )

            self.assertEqual(
                row[
                    "primary_or_supporting"
                ],
                "primary",
            )

            if not row[
                "utc_time"
            ]:
                self.assertEqual(
                    row[
                        "source_timezone"
                    ],
                    "",
                )

                self.assertIn(
                    "utc_time=NOT_ESTABLISHED_FROM_RELEASE_EVIDENCE",
                    row[
                        "notes"
                    ],
                )

            if not row[
                "host"
            ]:
                self.assertIn(
                    "host=UNKNOWN_FROM_RELEASE_EVIDENCE",
                    row[
                        "notes"
                    ],
                )

            if not row[
                "user"
            ]:
                self.assertIn(
                    "user=UNKNOWN_FROM_RELEASE_EVIDENCE",
                    row[
                        "notes"
                    ],
                )

            if not row[
                "attack_technique"
            ]:
                self.assertIn(
                    "attack_technique=NOT_ESTABLISHED_FROM_RELEASE_EVIDENCE",
                    row[
                        "notes"
                    ],
                )

    def test_ioc_view_never_preserves_template_placeholder(
        self,
    ) -> None:
        outputs = MODULE.build_outputs(
            REPO
        )

        rows = csv_rows(
            outputs[
                "ioc-set.csv"
            ]
        )

        for row in rows:
            self.assertNotEqual(
                row[
                    "ioc_id"
                ],
                "IOC-001",
            )

            self.assertTrue(
                row[
                    "type"
                ]
            )

            self.assertTrue(
                row[
                    "value"
                ]
            )


if __name__ == "__main__":
    unittest.main()
