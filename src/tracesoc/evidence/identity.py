from __future__ import annotations

import hashlib
import json

from tracesoc.models import RawLocator, SourceType


IDENTITY_VERSION = 1


def raw_sha256(raw: bytes) -> str:
    """Return the SHA-256 digest for one exact raw evidence record."""

    return hashlib.sha256(raw).hexdigest()


def compute_event_id(
    *,
    locator: RawLocator,
    source_type: SourceType,
    event_type: str,
) -> str:
    """
    Build a deterministic event identity from evidence-backed attributes.

    No fixture identifier, expected result, technique label, verdict, or
    investigation answer participates in identity construction.
    """

    if not event_type.strip():
        raise ValueError("event_type must not be empty")

    identity_material = {
        "identity_version": IDENTITY_VERSION,
        "source_type": source_type.value,
        "event_type": event_type.strip(),
        "locator": {
            "logical_source": locator.logical_source,
            "record_index": locator.record_index,
            "line_number": locator.line_number,
            "byte_offset": locator.byte_offset,
            "raw_sha256": locator.raw_sha256,
            "adapter_id": locator.adapter_id,
            "input_schema_version": locator.input_schema_version,
        },
    }

    encoded = json.dumps(
        identity_material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return "evt_" + hashlib.sha256(encoded).hexdigest()