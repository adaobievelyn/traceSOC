from datetime import (
    datetime,
    timedelta,
    timezone,
)
from types import SimpleNamespace
import unittest

from tracesoc.correlation.sysmon_process_network import (
    correlate_sysmon_process_with_network_activity,
)
from tracesoc.models import (
    SourceType,
)


GUID = (
    "{851f2de6-143d-6ab5-4b08-000000005d00}"
)

OTHER_GUID = (
    "{11111111-2222-3333-4444-555555555555}"
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


class SysmonProcessNetworkCorrelationTests(
    unittest.TestCase
):
    def event(
        self,
        *,
        event_id,
        event_type,
        guid=GUID,
        host="HOST-01",
        process_id="7156",
        process_name=IMAGE,
        seconds=0,
        source_type=SourceType.SYSMON,
        timed=True,
    ):
        fields = {}

        if guid is not None:
            fields["process_guid"] = guid

        if process_id is not None:
            fields["process_id"] = process_id

        if process_name is not None:
            fields["process_name"] = process_name

        return SimpleNamespace(
            event_id=event_id,
            source_type=source_type,
            event_type=event_type,
            host=host,
            event_time_utc=(
                BASE
                + timedelta(
                    seconds=seconds
                )
                if timed
                else None
            ),
            fields=fields,
        )

    def correlate(
        self,
        process,
        network,
    ):
        return (
            correlate_sysmon_process_with_network_activity(
                process_event=process,
                network_event=network,
            )
        )

    def test_exact_process_guid_matches(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
            ),
            self.event(
                event_id="n",
                event_type="network_connection",
                seconds=2,
            ),
        )

        self.assertTrue(
            result.matched
        )

        self.assertIsNotNone(
            result.edge
        )

        assert result.edge is not None

        self.assertEqual(
            set(
                result.edge.matched_dimensions
            ),
            {
                "process_guid",
                "host",
                "process_id",
                "process_name",
            },
        )

    def test_different_guid_does_not_match(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
            ),
            self.event(
                event_id="n",
                event_type="network_connection",
                guid=OTHER_GUID,
            ),
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "process_guid_mismatch",
        )

    def test_missing_guid_does_not_match(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
                guid=None,
            ),
            self.event(
                event_id="n",
                event_type="network_connection",
            ),
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "source_process_guid_unavailable",
        )

    def test_same_guid_different_host_does_not_match(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
            ),
            self.event(
                event_id="n",
                event_type="network_connection",
                host="HOST-02",
            ),
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "host_mismatch",
        )

    def test_conflicting_pid_does_not_match(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
            ),
            self.event(
                event_id="n",
                event_type="network_connection",
                process_id="9999",
            ),
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "process_id_mismatch",
        )

    def test_conflicting_image_does_not_match(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
            ),
            self.event(
                event_id="n",
                event_type="network_connection",
                process_name=(
                    r"C:\Windows\System32\cmd.exe"
                ),
            ),
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "process_name_mismatch",
        )

    def test_network_before_process_does_not_match(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
                seconds=10,
            ),
            self.event(
                event_id="n",
                event_type="network_connection",
                seconds=5,
            ),
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "network_precedes_process_creation",
        )

    def test_missing_timestamps_do_not_block_guid_identity(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
                timed=False,
            ),
            self.event(
                event_id="n",
                event_type="network_connection",
                timed=False,
            ),
        )

        self.assertTrue(
            result.matched
        )

        self.assertIsNotNone(
            result.edge
        )

        assert result.edge is not None

        self.assertIsNone(
            result.edge.delta_seconds
        )

    def test_timestamp_cannot_substitute_for_guid(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
                guid=GUID,
            ),
            self.event(
                event_id="n",
                event_type="network_connection",
                guid=OTHER_GUID,
            ),
        )

        self.assertFalse(
            result.matched
        )

    def test_wrong_target_event_type_does_not_match(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
            ),
            self.event(
                event_id="n",
                event_type="process_create",
            ),
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "target_event_type_mismatch",
        )

    def test_wrong_source_family_does_not_match(
        self,
    ):
        result = self.correlate(
            self.event(
                event_id="p",
                event_type="process_create",
                source_type=(
                    SourceType.WINDOWS_SECURITY
                ),
            ),
            self.event(
                event_id="n",
                event_type="network_connection",
            ),
        )

        self.assertFalse(
            result.matched
        )

        self.assertEqual(
            result.reason_code,
            "source_type_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
