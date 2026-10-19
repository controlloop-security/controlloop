"""Generates the packaged JSON Schema for `ScanReport`.

Unlike the ACBOM schema
(`src/controlloop/schemas/acbom/1.0.0/acbom.schema.json`, hand-authored),
`report.schema.json` is generated directly from
`ScanReport.model_json_schema()` and then wrapped with the house
`$schema`/`$id`/`title`/`description` metadata every packaged schema in this
repository carries. Every nested model already declares `extra="forbid"`
(`_ReportModel`, `_CapabilityModel`, `_FindingModel`,
`_MaterialSummaryModel`, `_CanonicalModel`), so pydantic's own generated
schema already carries `additionalProperties: false` at every object level
-- the same closed-schema guarantee the hand-authored ACBOM schema enforces
by hand. This is a disclosed design choice, not an oversight: generating
directly from the model keeps the two in lockstep by construction, at the
cost of the ACBOM schema's own hand-written per-field human descriptions.

Run directly to print the current schema, for example when
`ScanReport`/`ReportVersions` change and the packaged file needs
regenerating -- writing to a *new* version directory named after
`CURRENT_REPORT_SCHEMA_VERSION` for a MAJOR/MINOR bump (this schema's own
first such bump was 1.0.0 -> 1.1.0):

    uv run python tests/reporting/generate_report_schema.py \\
        > src/controlloop/schemas/report/1.2.0/report.schema.json

After regenerating, `tests/reporting/test_report_schema.py`'s golden-
digest test will fail until its committed digest constant is updated
-- see that test's own docstring before doing so.
"""

from __future__ import annotations

import json

from controlloop.reporting.report import CURRENT_REPORT_SCHEMA_VERSION, ScanReport

SCHEMA_ID = (
    f"https://schemas.controlloop.ai/report/{CURRENT_REPORT_SCHEMA_VERSION}"
    "/report.schema.json"
)


def generate_report_schema() -> dict[str, object]:
    wrapped: dict[str, object] = dict(ScanReport.model_json_schema())
    wrapped["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    wrapped["$id"] = SCHEMA_ID
    wrapped["title"] = "ControlLoop Scan Report"
    wrapped["description"] = (
        "Stable, versioned, machine-readable scan report for "
        f"ControlLoop report schema version {CURRENT_REPORT_SCHEMA_VERSION}."
    )
    # Reorder so the house metadata leads, matching the hand-authored
    # ACBOM schema's own key order, rather than leaving it wherever
    # `dict.update` happened to place it.
    ordered_keys = ("$schema", "$id", "title", "description")
    return {key: wrapped[key] for key in ordered_keys} | {
        key: value for key, value in wrapped.items() if key not in ordered_keys
    }


if __name__ == "__main__":
    print(json.dumps(generate_report_schema(), indent=2, sort_keys=False))
