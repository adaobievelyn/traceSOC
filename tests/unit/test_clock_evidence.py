from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import unittest

from tracesoc.models import (
    CanonicalEvent,
    ClockState,
    RawLocator,
    SourceType,
)
from tracesoc.normalization.clock_evidence import (
    ClockEvidenceError,
    ClockEvidenceState,
    derive_windows_security_sysmon_process_clock_evidence,
)


def locator(
    index: int,
) -> RawLocator:
    return RawLocator(
        logical_source=
            "tests/clock-evidence.log",

        record_index=
            index,

        raw_sha256=
            f"{index + 1:064x}"[-64:],

        adapter_id=
            "test-clock-evidence-v1",

        input_schema_version=
            "1",
    )


def security_event(
    *,
    event_id: str = "sec-1",
    index: int = 0,
    raw_time: str = "03/31/2021 12:00:39 PM",
    host: str = "HOST-01",
    principal: str | None = "NT AUTHORITY\\SYSTEM",
    process_name: str = r"C:\Windows\System32\autochk.exe",
    process_id: str = "0x23c",
    parent_process: str = r"C:\Windows\System32\smss.exe",
    parent_process_id: str = "0x1b0",
    clock_state: ClockState = ClockState.UNRESOLVED,
    event_time_utc: datetime | None = None,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=
            event_id,

        source_type=
            SourceType.WINDOWS_SECURITY,

        event_type=
            "process_create",

        clock_state=
            clock_state,

        provenance=
            locator(
                index
            ),

        event_time_raw=
            raw_time,

        event_time_utc=
            event_time_utc,

        host=
            host,

        principal=
            principal,

        semantic_fields={
            "process_name":
                process_name,

            "process_id":
                process_id,

            "parent_process":
                parent_process,

            "parent_process_id":
                parent_process_id,
        },

        source_context={},
    )


def sysmon_event(
    *,
    event_id: str = "sys-1",
    index: int = 100,
    event_time_utc: datetime = datetime(
        2021,
        3,
        31,
        12,
        0,
        39,
        789000,
        tzinfo=timezone.utc,
    ),
    host: str = "HOST-01",
    principal: str | None = "NT AUTHORITY\\SYSTEM",
    process_name: str = r"C:\Windows\System32\autochk.exe",
    process_id: str = "572",
    parent_process: str = r"C:\Windows\System32\smss.exe",
    parent_process_id: str = "432",
    clock_state: ClockState = ClockState.OBSERVED,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=
            event_id,

        source_type=
            SourceType.SYSMON,

        event_type=
            "process_create",

        clock_state=
            clock_state,

        provenance=
            locator(
                index
            ),

        event_time_raw=
            event_time_utc.isoformat(),

        event_time_utc=
            event_time_utc,

        host=
            host,

        principal=
            principal,

        semantic_fields={
            "process_name":
                process_name,

            "process_id":
                process_id,

            "parent_process":
                parent_process,

            "parent_process_id":
                parent_process_id,
        },

        source_context={},
    )


class ClockEvidenceTests(
    unittest.TestCase
):
    def test_valid_pair_creates_interval_without_mutating_parent(
        self,
    ) -> None:
        security = security_event()
        sysmon = sysmon_event()

        result = (
            derive_windows_security_sysmon_process_clock_evidence(
                [
                    security
                ],
                [
                    sysmon
                ],
            )
        )

        self.assertEqual(
            len(result),
            1,
        )

        evidence = result[0]

        self.assertIs(
            evidence.state,
            ClockEvidenceState.CORROBORATED,
        )

        self.assertEqual(
            evidence.target_event_id,
            security.event_id,
        )

        self.assertEqual(
            evidence.supporting_event_ids,
            (
                sysmon.event_id,
            ),
        )

        self.assertEqual(
            evidence.utc_interval_start,
            datetime(
                2021,
                3,
                31,
                12,
                0,
                39,
                tzinfo=timezone.utc,
            ),
        )

        self.assertEqual(
            evidence.utc_interval_end_exclusive,
            datetime(
                2021,
                3,
                31,
                12,
                0,
                40,
                tzinfo=timezone.utc,
            ),
        )

        self.assertIs(
            security.clock_state,
            ClockState.UNRESOLVED,
        )

        self.assertIsNone(
            security.event_time_utc,
        )

        self.assertEqual(
            security.event_time_raw,
            "03/31/2021 12:00:39 PM",
        )

    def test_identity_is_deterministic_under_input_order_changes(
        self,
    ) -> None:
        security_one = security_event(
            event_id=
                "sec-1",

            index=
                1,
        )

        sysmon_one = sysmon_event(
            event_id=
                "sys-1",

            index=
                101,
        )

        security_two = security_event(
            event_id=
                "sec-2",

            index=
                2,

            raw_time=
                "03/31/2021 12:00:41 PM",

            process_name=
                r"C:\Windows\System32\csrss.exe",

            process_id=
                "0x270",

            parent_process_id=
                "0x268",
        )

        sysmon_two = sysmon_event(
            event_id=
                "sys-2",

            index=
                102,

            event_time_utc=
                datetime(
                    2021,
                    3,
                    31,
                    12,
                    0,
                    41,
                    851000,
                    tzinfo=timezone.utc,
                ),

            process_name=
                r"C:\Windows\System32\csrss.exe",

            process_id=
                "624",

            parent_process_id=
                "616",
        )

        first = (
            derive_windows_security_sysmon_process_clock_evidence(
                [
                    security_one,
                    security_two,
                ],
                [
                    sysmon_one,
                    sysmon_two,
                ],
            )
        )

        second = (
            derive_windows_security_sysmon_process_clock_evidence(
                [
                    security_two,
                    security_one,
                ],
                [
                    sysmon_two,
                    sysmon_one,
                ],
            )
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            len(first),
            2,
        )

        self.assertEqual(
            len(
                {
                    item.evidence_id
                    for item in first
                }
            ),
            2,
        )

    def test_ambiguous_identity_is_not_resolved_with_time(
        self,
    ) -> None:
        early = security_event(
            event_id=
                "sec-early",

            index=
                1,

            raw_time=
                "03/31/2021 11:53:56 AM",

            process_name=
                r"C:\Windows\System32\smss.exe",

            process_id=
                "0x2b0",
        )

        late = security_event(
            event_id=
                "sec-late",

            index=
                2,

            raw_time=
                "03/31/2021 12:00:41 PM",

            process_name=
                r"C:\Windows\System32\smss.exe",

            process_id=
                "0x2b0",
        )

        support = sysmon_event(
            event_id=
                "sys-1",

            process_name=
                r"C:\Windows\System32\smss.exe",

            process_id=
                "688",

            event_time_utc=
                datetime(
                    2021,
                    3,
                    31,
                    12,
                    0,
                    41,
                    997000,
                    tzinfo=timezone.utc,
                ),
        )

        result = (
            derive_windows_security_sysmon_process_clock_evidence(
                [
                    early,
                    late,
                ],
                [
                    support,
                ],
            )
        )

        self.assertEqual(
            result,
            (),
        )

    def test_parent_pid_conflict_does_not_produce_evidence(
        self,
    ) -> None:
        security = security_event(
            process_name=
                r"C:\Windows\System32\lsass.exe",

            process_id=
                "0x358",

            parent_process=
                r"C:\Windows\System32\wininit.exe",

            parent_process_id=
                "0x2bc",
        )

        sysmon = sysmon_event(
            process_name=
                r"C:\Windows\System32\lsass.exe",

            process_id=
                "856",

            parent_process=
                r"C:\Windows\System32\wininit.exe",

            parent_process_id=
                "696",
        )

        result = (
            derive_windows_security_sysmon_process_clock_evidence(
                [
                    security
                ],
                [
                    sysmon
                ],
            )
        )

        self.assertEqual(
            result,
            (),
        )

    def test_identity_dimension_mismatch_or_missing_principal_is_rejected(
        self,
    ) -> None:
        with self.subTest(
            "host"
        ):
            result = (
                derive_windows_security_sysmon_process_clock_evidence(
                    [
                        security_event(
                            host=
                                "HOST-A"
                        )
                    ],
                    [
                        sysmon_event(
                            host=
                                "HOST-B"
                        )
                    ],
                )
            )

            self.assertEqual(
                result,
                (),
            )

        with self.subTest(
            "principal"
        ):
            result = (
                derive_windows_security_sysmon_process_clock_evidence(
                    [
                        security_event(
                            principal=
                                "DOMAIN\\alice"
                        )
                    ],
                    [
                        sysmon_event(
                            principal=
                                "DOMAIN\\bob"
                        )
                    ],
                )
            )

            self.assertEqual(
                result,
                (),
            )

        with self.subTest(
            "missing-principal"
        ):
            result = (
                derive_windows_security_sysmon_process_clock_evidence(
                    [
                        security_event(
                            principal=
                                None
                        )
                    ],
                    [
                        sysmon_event()
                    ],
                )
            )

            self.assertEqual(
                result,
                (),
            )

    def test_nonzero_hour_coordinate_does_not_produce_evidence(
        self,
    ) -> None:
        result = (
            derive_windows_security_sysmon_process_clock_evidence(
                [
                    security_event()
                ],
                [
                    sysmon_event(
                        event_time_utc=
                            datetime(
                                2021,
                                3,
                                31,
                                13,
                                0,
                                39,
                                789000,
                                tzinfo=timezone.utc,
                            )
                    )
                ],
            )
        )

        self.assertEqual(
            result,
            (),
        )

    def test_wrong_clock_state_is_rejected(
        self,
    ) -> None:
        security = security_event(
            clock_state=
                ClockState.OBSERVED,

            event_time_utc=
                datetime(
                    2021,
                    3,
                    31,
                    12,
                    0,
                    39,
                    tzinfo=timezone.utc,
                ),
        )

        with self.assertRaises(
            ClockEvidenceError
        ):
            derive_windows_security_sysmon_process_clock_evidence(
                [
                    security
                ],
                [
                    sysmon_event()
                ],
            )

    def test_clock_evidence_is_immutable(
        self,
    ) -> None:
        evidence = (
            derive_windows_security_sysmon_process_clock_evidence(
                [
                    security_event()
                ],
                [
                    sysmon_event()
                ],
            )[0]
        )

        with self.assertRaises(
            FrozenInstanceError
        ):
            evidence.host = "OTHER"