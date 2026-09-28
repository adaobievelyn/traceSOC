from __future__ import annotations

from pathlib import Path

from tracesoc.correlation.web_retrieval_network import (
    correlate_web_retrieval_with_zeek,
)
from tracesoc.detection.powershell_web_retrieval import (
    detect_powershell_web_retrieval,
)
from tracesoc.findings.builders import build_finding_001
from tracesoc.findings.models import Finding
from tracesoc.models import SemanticEvent
from tracesoc.parsers.powershell import load_powershell_jsonl
from tracesoc.parsers.zeek import load_zeek_jsonl


def build_fixture_finding_001(
    repo: Path,
) -> Finding:
    fixture_root = (
        repo
        / "tests"
        / "fixtures"
        / "tiny"
    )

    powershell_batch = load_powershell_jsonl(
        fixture_root / "powershell.jsonl",
        logical_source=(
            "tests/fixtures/tiny/powershell.jsonl"
        ),
    )

    zeek_batch = load_zeek_jsonl(
        fixture_root / "zeek.jsonl",
        logical_source=(
            "tests/fixtures/tiny/zeek.jsonl"
        ),
    )

    canonical_by_id = {
        event.event_id: event
        for event in (
            *powershell_batch.accepted,
            *zeek_batch.accepted,
        )
    }

    matches = []

    for powershell_canonical in powershell_batch.accepted:
        powershell_semantic = (
            SemanticEvent.from_canonical(
                powershell_canonical
            )
        )

        detection = (
            detect_powershell_web_retrieval(
                powershell_semantic
            )
        )

        if not detection.matched:
            continue

        for zeek_canonical in zeek_batch.accepted:
            zeek_semantic = (
                SemanticEvent.from_canonical(
                    zeek_canonical
                )
            )

            correlation = (
                correlate_web_retrieval_with_zeek(
                    detection=detection,
                    powershell_event=powershell_semantic,
                    zeek_event=zeek_semantic,
                )
            )

            if correlation.matched:
                matches.append(
                    (
                        detection,
                        correlation,
                    )
                )

    if len(matches) != 1:
        raise RuntimeError(
            "fixture vertical slice must produce exactly one "
            f"bounded correlation; observed {len(matches)}"
        )

    detection, correlation = matches[0]

    return build_finding_001(
        detection=detection,
        correlation=correlation,
        canonical_events=canonical_by_id,
    )