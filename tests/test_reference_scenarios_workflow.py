"""Structural tests for `.github/workflows/reference-scenarios.yml`.

Mirrors `tests/test_release_workflow_structure.py`'s approach: parse the
committed workflow and assert the structural properties that a green run
cannot demonstrate on its own.

The defect these exist to prevent was real and shipped. The artifact
name interpolated `matrix.branch` (`scenario/ceiling-breach`), and
`upload-artifact` rejects a forward slash, so a **release gate** failed
on every run for a reason unrelated to ControlLoop's behavior. It could
not be caught before merge, because `workflow_dispatch` only fires for a
workflow already on the default branch. A structural test is the control
that does not depend on being able to run it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW_PATH = _REPO_ROOT / ".github/workflows/reference-scenarios.yml"

#: Every character `actions/upload-artifact` rejects in an artifact name,
#: quoted from its own error message: "Double quote ", Colon :, Less than
#: <, Greater than >, Vertical bar |, Asterisk *, Question mark ?,
#: Carriage return \r, Line feed \n, Backslash \, Forward slash /".
_ARTIFACT_NAME_FORBIDDEN = ('"', ":", "<", ">", "|", "*", "?", "\r", "\n", "\\", "/")

#: Keys the workflow's own steps interpolate out of each matrix entry. A
#: new scenario missing one of these fails at run time, in CI, on a
#: schedule -- long after whoever added it has moved on.
_REQUIRED_MATRIX_KEYS = ("name", "id", "branch", "expected", "path", "run")


def _workflow() -> dict[Any, Any]:
    loaded: dict[Any, Any] = yaml.safe_load(_WORKFLOW_PATH.read_text(encoding="utf-8"))
    return loaded


def _matrix_entries() -> list[dict[str, Any]]:
    workflow = _workflow()
    matrix = workflow["jobs"]["scenario"]["strategy"]["matrix"]
    return list(matrix["include"])


def _steps() -> list[dict[str, Any]]:
    return list(_workflow()["jobs"]["scenario"]["steps"])


def _step_named(fragment: str) -> dict[str, Any]:
    for step in _steps():
        if fragment.lower() in str(step.get("name", "")).lower():
            return step
    raise AssertionError(f"no step whose name contains {fragment!r}")


class TestArtifactName:
    """The regression that once made the release gate useless."""

    def test_artifact_name_uses_the_safe_id_not_the_branch(self) -> None:
        name = _step_named("Retain the evidence artifact")["with"]["name"]

        assert "matrix.id" in name
        assert "matrix.branch" not in name, (
            "the artifact name must not interpolate matrix.branch -- a branch "
            "name contains a forward slash, which upload-artifact rejects, and "
            "that once failed every run of this release gate"
        )

    @pytest.mark.parametrize("entry", _matrix_entries(), ids=lambda e: str(e["id"]))
    def test_every_id_is_a_valid_artifact_name(self, entry: dict[str, Any]) -> None:
        identifier = str(entry["id"])

        assert identifier, "a scenario id must not be empty"
        for character in _ARTIFACT_NAME_FORBIDDEN:
            assert character not in identifier, (
                f"scenario id {identifier!r} contains {character!r}, which "
                "upload-artifact rejects in an artifact name"
            )

    def test_ids_are_unique(self) -> None:
        identifiers = [entry["id"] for entry in _matrix_entries()]

        assert len(set(identifiers)) == len(identifiers), (
            "two scenarios sharing an id would collide on artifact upload"
        )


class TestMatrixCompleteness:
    @pytest.mark.parametrize("entry", _matrix_entries(), ids=lambda e: str(e["id"]))
    def test_every_entry_has_every_interpolated_key(
        self, entry: dict[str, Any]
    ) -> None:
        missing = [key for key in _REQUIRED_MATRIX_KEYS if key not in entry]

        assert not missing, (
            f"scenario {entry.get('name')!r} is missing {missing}; the "
            "workflow's steps interpolate every one of "
            f"{list(_REQUIRED_MATRIX_KEYS)}"
        )

    def test_at_least_one_scenario_is_covered(self) -> None:
        """Guards against a matrix silently emptied to make a red gate
        green -- the failure mode this whole workflow exists to prevent."""
        assert len(_matrix_entries()) >= 1


class TestGateContract:
    """The properties that make this workflow a release gate at all (it runs
    the published Action, can fail, and needs no extra permission)."""

    def test_runs_on_schedule_and_on_release(self) -> None:
        # PyYAML parses a bare `on:` key as the boolean True.
        workflow = _workflow()
        triggers = workflow.get(True, workflow.get("on"))
        assert triggers is not None, "the workflow declares no triggers at all"

        assert "schedule" in triggers
        assert "release" in triggers
        assert triggers["release"]["types"] == ["published"]

    def test_uses_the_published_action_not_a_local_checkout(self) -> None:
        """The point is to prove what a user actually gets."""
        uses = _step_named("Run the published Action")["uses"]

        assert uses.startswith("controlloop-security/controlloop@")
        assert uses != "./"

    def test_the_assertion_step_can_actually_fail_the_job(self) -> None:
        """If the assertion ever gained continue-on-error, the gate would be
        decorative."""
        step = _step_named("Assert verdict, findings, and blast radius")

        assert "continue-on-error" not in step
        assert "|| true" not in step["run"]

    def test_requests_no_permission_beyond_reading_contents(self) -> None:
        """The free public path, on the default token alone."""
        assert _workflow()["permissions"] == {"contents": "read"}

    def test_references_no_secret(self) -> None:
        assert "secrets." not in _WORKFLOW_PATH.read_text(encoding="utf-8")


class TestScenarioContentGuard:
    """Merging `main` into a scenario branch deletes that scenario's
    content. The branches are repaired, but the guard is what makes a future
    recurrence fail by name instead of by a verdict that drifted for reasons
    nobody can see."""

    def test_every_scenario_declares_a_guard(self) -> None:
        for row in _matrix_entries():
            assert row.get("guard-file"), f"{row['id']} declares no guard-file"
            assert row.get("guard-text"), f"{row['id']} declares no guard-text"

    def test_each_guard_names_a_distinct_marker(self) -> None:
        """Two scenarios sharing a marker would let one rot unnoticed."""

        markers = [row["guard-text"] for row in _matrix_entries()]
        assert len(set(markers)) == len(markers)

    def test_the_guard_runs_before_the_gate(self) -> None:
        """A gutted scenario must fail saying what is missing, not
        produce a confusing verdict mismatch downstream."""

        names = [step.get("name", "") for step in _steps()]
        guard = next(i for i, n in enumerate(names) if "distinguishing" in n)
        gate = next(i for i, n in enumerate(names) if "published Action" in n)
        assert guard < gate

    def test_the_guard_decides_the_job(self) -> None:
        """No `continue-on-error`, no `|| true`, no ignored exit code --
        a guard that cannot fail the job is decoration."""

        step = _step_named("distinguishing")
        assert "continue-on-error" not in step
        assert "|| true" not in step["run"]
        assert "set -euo pipefail" in step["run"]

    def test_the_guard_cites_the_issue_so_the_cause_is_findable(self) -> None:
        """The guard's error states the cause, so it is findable."""
        step = _step_named("distinguishing")
        assert "merging main into a scenario branch deletes its content" in step["run"]


_TEAM_ROWS = {
    "team-sanctioned-grant": ("pass_run", False),
    "team-unsanctioned-grant": ("review_run", True),
    "team-no-published-bundle": ("pass_run", False),
}


class TestTeamScenarios:
    """The sanctioned-list gate on a real repository, through the published
    Action, with no platform deployed."""

    def test_all_three_outcomes_are_rows(self) -> None:
        rows = {row["id"]: row for row in _matrix_entries()}

        for scenario, (run, blocked) in _TEAM_ROWS.items():
            row = rows[scenario]
            assert row["branch"] == f"scenario/{scenario}"
            assert row["expected"].endswith(f"expected/{scenario}.json")
            assert (row["run"], row["expect-blocked"]) == (run, blocked)

    def test_the_team_token_is_a_fixed_placeholder_not_a_secret(self) -> None:
        """A Team gate refuses to start without a token. The scenarios'
        platform is unreachable by design, so the value authenticates
        nothing, and it must never become a secret reference."""

        token = _step_named("published Action")["env"]["CONTROLLOOP_TEAM_TOKEN"]

        assert token == "offline-reference-scenario-not-a-secret"
        assert "${{" not in token

    def test_no_guard_text_can_break_its_single_quotes(self) -> None:
        """The guard reads its text as `text='...'`."""

        for row in _matrix_entries():
            assert "'" not in row["guard-text"], row["id"]
