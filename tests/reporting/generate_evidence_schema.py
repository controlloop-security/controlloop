"""Generates the packaged JSON Schema for `EvidenceArtifact`.

Follows `generate_report_schema.py`'s exact precedent: generated directly
from `EvidenceArtifact.model_json_schema()` and wrapped with the house
`$schema`/`$id`/`title`/`description` metadata, rather than hand-authored
like the ACBOM schema. Every composed model already declares
`extra="forbid"`, so the generated schema already carries
`additionalProperties: false` at every object level.

Run directly to print the current schema, for example when
`EvidenceArtifact`/`EvidenceVersions` change and the packaged file needs
regenerating -- writing to a *new* version directory named after
`CURRENT_EVIDENCE_SCHEMA_VERSION` for a MAJOR/MINOR bump (the
`schemas/baseline/` precedent; this schema's own first such bump was 1.0.0
-> 1.1.0, its second 1.1.0 -> 1.2.0):

    uv run python tests/reporting/generate_evidence_schema.py \\
        > src/controlloop/schemas/evidence/1.6.0/evidence.schema.json

After regenerating, `tests/reporting/test_evidence_schema.py`'s
golden-digest test will fail until its committed digest constant is
updated -- see that test's own docstring before doing so.
"""

from __future__ import annotations

import json

from controlloop.reporting.evidence import (
    CURRENT_EVIDENCE_SCHEMA_VERSION,
    EvidenceArtifact,
)

SCHEMA_ID = (
    f"https://schemas.controlloop.ai/evidence/{CURRENT_EVIDENCE_SCHEMA_VERSION}"
    "/evidence.schema.json"
)


def generate_evidence_schema() -> dict[str, object]:
    wrapped: dict[str, object] = dict(EvidenceArtifact.model_json_schema())
    wrapped["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    wrapped["$id"] = SCHEMA_ID
    wrapped["title"] = "ControlLoop Evidence Artifact"
    wrapped["description"] = (
        "Single retainable artifact that fully explains a gate verdict "
        "after the fact, for ControlLoop evidence schema version "
        f"{CURRENT_EVIDENCE_SCHEMA_VERSION}."
    )
    ordered_keys = ("$schema", "$id", "title", "description")
    return {key: wrapped[key] for key in ordered_keys} | {
        key: value for key, value in wrapped.items() if key not in ordered_keys
    }


if __name__ == "__main__":
    print(json.dumps(generate_evidence_schema(), indent=2, sort_keys=False))
