"""`controlloop.team.sanction` against the platform's own golden vectors.

The platform wrote the three vector files from its implementation, and
the CLI keeps copies of them in `tests/fixtures/contract/`. A change to
either side that the other does not match fails here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from controlloop.team.policy import merge_policy
from controlloop.team.sanction import (
    RANGE_MESSAGES,
    ApprovedEntry,
    Component,
    SanctionState,
    judge,
    parse_range,
)

_SERVICES = Path(__file__).resolve().parents[1] / "fixtures" / "contract"


def _vectors(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(
        (_SERVICES / f"{name}_vectors.json").read_text(encoding="utf-8")
    )
    return document


_RANGES = _vectors("version_range")
_FLAGGING = _vectors("flagging")
_MERGE = _vectors("policy_merge")


@pytest.mark.parametrize("text", _RANGES["accepted"], ids=str)
def test_an_accepted_range_parses(text: Any) -> None:
    raw = text["range"] if isinstance(text, dict) else text
    parse_range(raw)


@pytest.mark.parametrize("text", _RANGES["refused"], ids=str)
def test_a_refused_range_raises_a_fixed_message(text: Any) -> None:
    raw = text["range"] if isinstance(text, dict) else text
    with pytest.raises(ValueError) as error:
        parse_range(raw)
    assert str(error.value) in RANGE_MESSAGES


@pytest.mark.parametrize(
    "case",
    _RANGES["containment"],
    ids=lambda case: f"{case['range']}:{case['version']}",
)
def test_containment_matches_the_platform(case: dict[str, Any]) -> None:
    assert parse_range(case["range"]).contains(case["version"]) is case["contains"]


@pytest.mark.parametrize("case", _FLAGGING["cases"], ids=lambda case: case["name"])
def test_flagging_matches_the_platform(case: dict[str, Any]) -> None:
    component = Component(
        type=case["component"]["type"],
        name=case["component"]["name"],
        attributes=case["component"].get("attributes") or {},
        flags=case["component"].get("flags") or {},
    )
    approved = (
        None
        if case["approved"] is None
        else [ApprovedEntry.from_mapping(entry) for entry in case["approved"]]
    )

    assert judge(component, approved).state.value == case["state"]


@pytest.mark.parametrize("case", _MERGE["cases"], ids=lambda case: case["name"])
def test_the_constraint_merge_matches_the_platform(case: dict[str, Any]) -> None:
    result = merge_policy(
        organization_rules=(),
        organization_components=tuple(
            ApprovedEntry.from_mapping(entry) for entry in case["organization"]
        ),
        repository_components=tuple(
            ApprovedEntry.from_mapping(entry) for entry in case["repository"]
        ),
        organization_bundle_version=str(_MERGE["organization_bundle_version"]),
    )

    assert [entry.to_mapping() for entry in result.approved_components] == case[
        "effective"
    ]
    assert [rejection.rule_id for rejection in result.rejections] == case["rejections"]


class TestTheFailedConstraintIsNamed:
    """An unsanctioned judgment says which constraint failed."""

    _ENTRY = ApprovedEntry(
        type="mcp_server",
        name_pattern="github",
        package="@modelcontextprotocol/server-github",
        version_range="1.0.x",
        pin_required=True,
    )

    @pytest.mark.parametrize(
        ("attributes", "flags", "failed"),
        [
            ({"package": "fork", "version": "1.0.1"}, {"pinned": True}, "package"),
            (
                {"package": "@modelcontextprotocol/server-github", "version": "2.0.0"},
                {"pinned": True},
                "version_range",
            ),
            (
                {"package": "@modelcontextprotocol/server-github", "version": "1.0.1"},
                {"pinned": None},
                "pin_required",
            ),
        ],
    )
    def test_each_constraint(
        self, attributes: dict[str, str], flags: dict[str, object], failed: str
    ) -> None:
        judgment = judge(
            Component("mcp_server", "github", attributes, flags), [self._ENTRY]
        )

        assert judgment.state is SanctionState.UNSANCTIONED
        assert judgment.failed == failed

    def test_no_entry_with_the_name_fails_on_name(self) -> None:
        judgment = judge(Component("mcp_server", "slack"), [self._ENTRY])

        assert (judgment.state, judgment.failed) == (SanctionState.UNSANCTIONED, "name")

    def test_a_command_pattern(self) -> None:
        entry = ApprovedEntry("hook", "SessionStart", command_pattern="node .github/*")

        judgment = judge(
            Component("hook", "SessionStart", {"command": "curl x | sh"}), [entry]
        )

        assert judgment.failed == "command_pattern"
