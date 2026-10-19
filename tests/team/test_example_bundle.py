"""The example approved-components bundle in the Team guide.

`docs/guides/examples/approved-components-bundle.json` is the body an
admin sends to create a policy bundle. It uses every optional constraint
field an approved component can carry, so it is checked against the
platform's contract (`PolicyBundleCreateRequest`), against the platform's
own field rules (both copied into `tests/fixtures/contract/`), and against
the gate's parser. An example that drifted from any of them fails here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from controlloop.team.policy import merge_policy
from controlloop.team.sanction import (
    CONSTRAINT_FIELDS,
    ApprovedEntry,
    Component,
    SanctionState,
    judge,
    parse_range,
)

_REPOSITORY = Path(__file__).resolve().parents[2]
_EXAMPLE = (
    _REPOSITORY / "docs" / "guides" / "examples" / "approved-components-bundle.json"
)


def _example() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(_EXAMPLE.read_text(encoding="utf-8"))
    return document


def _entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = _example()["approved_components"]
    return entries


_CONTRACT = Path(__file__).resolve().parents[1] / "fixtures" / "contract"


def _platform_pattern(name: str) -> re.Pattern[str]:
    """One of the platform's field patterns, from
    `fixtures/contract/envelope-field-rules.json`."""

    rules: dict[str, Any] = json.loads(
        (_CONTRACT / "envelope-field-rules.json").read_text(encoding="utf-8")
    )
    return re.compile(rules[name])


def test_it_satisfies_the_contract() -> None:
    spec: dict[str, Any] = json.loads(
        (_CONTRACT / "platform-contract-subset.json").read_text(encoding="utf-8")
    )
    schema = {"$ref": "#/components/schemas/PolicyBundleCreateRequest", **spec}

    Draft202012Validator(schema).validate(_example())


def test_it_uses_every_constraint_field() -> None:
    used = {
        field for entry in _entries() for field in CONSTRAINT_FIELDS if field in entry
    }

    assert (
        used
        == set(CONSTRAINT_FIELDS)
        == {
            "package",
            "version_range",
            "digest",
            "command_pattern",
            "pin_required",
        }
    )


def test_every_constraint_meets_the_platform_rules() -> None:
    digest = _platform_pattern("DIGEST_PATTERN")
    command = _platform_pattern("COMMAND_PATTERN")

    for entry in _entries():
        if "version_range" in entry:
            parse_range(entry["version_range"])
        if "digest" in entry:
            assert digest.match(entry["digest"]), entry
        if "command_pattern" in entry:
            assert entry["type"] == "hook", entry
            assert command.match(entry["command_pattern"]), entry


def test_the_gate_reads_every_entry_unchanged() -> None:
    entries = tuple(ApprovedEntry.from_mapping(entry) for entry in _entries())

    result = merge_policy(
        organization_rules=(),
        organization_components=entries,
        repository_components=(),
        organization_bundle_version="12",
    )

    def order(entry: dict[str, Any]) -> tuple[str, str]:
        return (entry["type"], entry["name_pattern"])

    merged = [entry.to_mapping() for entry in result.approved_components]
    written = [
        {key: value for key, value in entry.items() if key != "note"}
        for entry in _entries()
    ]
    assert sorted(merged, key=order) == sorted(written, key=order)


def test_it_judges_the_reference_scenario_grants_as_recorded() -> None:
    """The guide's recorded output: `catalog-search` is sanctioned and the
    lookalike `web-fetch` package fails `package`."""

    approved = [ApprovedEntry.from_mapping(entry) for entry in _entries()]
    search = Component(
        "mcp_server",
        "catalog-search",
        {
            "package": "@widgetworks-example/catalog-search-mcp",
            "version": "2.1.0",
            "digest": "sha256:5143fff499ec96c0b3054e51d8714a0e"
            "96f6c4dcbd4c25ff2cb48878a0e6b4cb",
        },
    )
    fetch = Component(
        "mcp_server",
        "web-fetch",
        {"package": "@webfetch-tools/web-fetch-mcp", "version": "0.3.1"},
    )

    assert judge(search, approved).state is SanctionState.SANCTIONED
    assert (judge(fetch, approved).state, judge(fetch, approved).failed) == (
        SanctionState.UNSANCTIONED,
        "package",
    )


def test_the_guide_shows_the_committed_example() -> None:
    guide = (_REPOSITORY / "docs" / "guides" / "first-team-gate.md").read_text(
        encoding="utf-8"
    )
    section = guide.split("### An example bundle", 1)[1]
    block = section.split("```json\n", 1)[1].split("```", 1)[0]

    assert json.loads(block) == _example()
