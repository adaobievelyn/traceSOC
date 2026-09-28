from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tracesoc.findings.models import Finding


SERIALIZATION_ID = "tracesoc-finding-json-v1"


def finding_json_bytes(
    finding: Finding,
) -> bytes:
    """
    Return the canonical TraceSOC finding byte representation.

    Contract:
    - UTF-8
    - no BOM
    - sorted keys
    - indent=2
    - LF newlines
    - one final LF
    """

    text = (
        json.dumps(
            finding.to_dict(),
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )

    canonical_text = text.replace(
        "\r\n",
        "\n",
    ).replace(
        "\r",
        "\n",
    )

    return canonical_text.encode(
        "utf-8"
    )


def finding_sha256(
    finding: Finding,
) -> str:
    return hashlib.sha256(
        finding_json_bytes(finding)
    ).hexdigest()


def write_finding(
    *,
    path: Path,
    finding: Finding,
) -> str:
    payload = finding_json_bytes(
        finding
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_bytes(
        payload
    )

    return hashlib.sha256(
        payload
    ).hexdigest()