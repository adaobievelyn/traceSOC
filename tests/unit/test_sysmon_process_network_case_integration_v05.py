from datetime import (
    datetime,
    timedelta,
    timezone,
)
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import tracesoc.cli.case as case_module

from tracesoc.models import (
    SourceType,
)


GUID = (
    "{851f2de6-143d-6ab5-4b08-000000005d00}"
)

IMAGE = (
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)

BASE = datetime(
    2026,
    9,
    24,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)


def semantic(
    *,
    event_id,
    event_type,
    seconds,
):
    return SimpleNamespace(
        event_id=event_id,
        source_type=SourceType.SYSMON,
        event_type=event_type,
        host="HOST-01",
        event_time_utc=(
            BASE
            + timedelta(
                seconds=seconds
            )
        ),
        fields={
            "process_guid":
                GUID,
            "process_id":
                "7156",
            "process_name":
                IMAGE,
        },
    )


class SysmonProcessNetworkCaseIntegrationTests(
    unittest.TestCase
):
    def test_case_evaluator_emits_corr006_record_and_projection(
        self,
    ):
        process_token = object()
        network_token = object()

        mapping = {
            id(process_token):
                semantic(
                    event_id="evt_process",
                    event_type="process_create",
                    seconds=0,
                ),

            id(network_token):
                semantic(
                    event_id="evt_network",
                    event_type="network_connection",
                    seconds=2,
                ),
        }

        with patch.object(
            case_module.SemanticEvent,
            "from_canonical",
            side_effect=lambda value:
                mapping[
                    id(value)
                ],
        ):
            records, projections = (
                case_module
                ._evaluate_sysmon_process_network_correlations(
                    (
                        process_token,
                        network_token,
                    )
                )
            )

        self.assertEqual(
            len(records),
            1,
        )

        self.assertEqual(
            records[0]["correlation_id"],
            "TRC-CORR-006",
        )

        self.assertTrue(
            records[0]["matched"]
        )

        self.assertEqual(
            len(projections),
            1,
        )

        self.assertEqual(
            projections[0]
            .legacy_correlation_id,
            "TRC-CORR-006",
        )


if __name__ == "__main__":
    unittest.main()
