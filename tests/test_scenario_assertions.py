"""Tests for `action-scripts/assert_scenario_expectations.py`.

The script is what makes the scheduled reference-scenario proof mean
anything: if it cannot fail, a green run proves nothing. So the tests
that matter here are the negative ones -- each asserts that a specific,
realistic regression is actually caught, with a message naming what
changed.

Runs the real script as a subprocess, mirroring
`tests/test_action_scripts.py`'s own style, rather than importing it --
it is a standalone CI script, and the exit code is part of its contract.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "action-scripts"
    / "assert_scenario_expectations.py"
)

_FINDING_ID = f"clp:finding:sha256:{'0' * 64}"
_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"

_CAPABILITY_PATH: dict[str, Any] = {
    "schema_version": "1.0.0",
    "agent_id": _AGENT_ID,
    "target_id": _TOOL_ID,
    "target_type": "tool",
    "hops": [],
    "confidence": "high",
}


def _expected() -> dict[str, Any]:
    return {
        "blocking_run": {
            "verdict": "deployment_blocked",
            "gate_exit_code": 1,
            "blast_radius": {
                "material_class": "financial-action",
                "target_name": "Issue a refund",
            },
            "ceiling_finding": {
                "rule_id": "policy.capability-ceiling",
                "id": _FINDING_ID,
                "severity": "critical",
                "confidence": "high",
                "message": "agent 'a' reaches 'b', which is prohibited",
                "capability_path": _CAPABILITY_PATH,
            },
            "suppressed_pattern_rules": ["policy.undeclared-tools"],
        }
    }


def _evidence() -> dict[str, Any]:
    return {
        "verdict": "deployment_blocked",
        "findings": [
            {
                "id": _FINDING_ID,
                "rule_id": "policy.capability-ceiling",
                "severity": "critical",
                "confidence": "high",
                "message": "agent 'a' reaches 'b', which is prohibited",
                "capability_path": _CAPABILITY_PATH,
            },
            {
                "id": f"clp:finding:sha256:{'1' * 64}",
                "rule_id": "policy.undeclared-tools",
                "severity": "medium",
                "confidence": "high",
                "message": "Tool 'x' is reachable but not declared.",
                "capability_path": None,
            },
        ],
    }


def _sarif() -> dict[str, Any]:
    return {
        "runs": [
            {
                "properties": {
                    "controlloop": {
                        "blastRadius": [
                            "! WORST REACHABLE  financial-action: "
                            "widgetworks-order-support-agent can invoke "
                            "Issue a refund"
                        ]
                    }
                }
            }
        ]
    }


def _run(
    tmp_path: Path,
    *,
    expected: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    sarif: dict[str, Any] | None = None,
    exit_code: int = 1,
) -> subprocess.CompletedProcess[str]:
    paths = {}
    for name, payload in (
        ("expected", expected if expected is not None else _expected()),
        ("evidence", evidence if evidence is not None else _evidence()),
        ("sarif", sarif if sarif is not None else _sarif()),
    ):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        paths[name] = path

    return subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--expected",
            str(paths["expected"]),
            "--evidence",
            str(paths["evidence"]),
            "--sarif",
            str(paths["sarif"]),
            "--exit-code",
            str(exit_code),
            "--run",
            "blocking_run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


class TestMatchingOutput:
    def test_real_matching_output_passes(self, tmp_path: Path) -> None:
        result = _run(tmp_path)

        assert result.returncode == 0, result.stderr
        assert "matched real output exactly" in result.stdout


class TestCaughtRegressions:
    """Each case is a regression the scheduled run exists to catch. If
    any of these ever passes, the proof is decorative."""

    def test_gate_stopped_blocking(self, tmp_path: Path) -> None:
        result = _run(tmp_path, exit_code=0)

        assert result.returncode == 1
        assert "gate exit code" in result.stderr

    def test_verdict_changed(self, tmp_path: Path) -> None:
        evidence = _evidence()
        evidence["verdict"] = "passed"

        result = _run(tmp_path, evidence=evidence)

        assert result.returncode == 1
        assert "verdict" in result.stderr

    def test_expected_finding_disappeared(self, tmp_path: Path) -> None:
        evidence = _evidence()
        evidence["findings"] = [
            f
            for f in evidence["findings"]
            if f["rule_id"] != "policy.capability-ceiling"
        ]

        result = _run(tmp_path, evidence=evidence)

        assert result.returncode == 1
        assert "expected finding is absent" in result.stderr

    def test_finding_severity_was_downgraded(self, tmp_path: Path) -> None:
        evidence = _evidence()
        evidence["findings"][0]["severity"] = "low"

        result = _run(tmp_path, evidence=evidence)

        assert result.returncode == 1
        assert "finding.severity" in result.stderr

    def test_capability_path_changed(self, tmp_path: Path) -> None:
        evidence = _evidence()
        evidence["findings"][0]["capability_path"] = {
            **_CAPABILITY_PATH,
            "target_type": "resource",
        }

        result = _run(tmp_path, evidence=evidence)

        assert result.returncode == 1
        assert "finding.capability_path" in result.stderr

    def test_blast_radius_lost_its_material_class(self, tmp_path: Path) -> None:
        """The exact regression that reverting the material-class fix would
        represent."""
        sarif = _sarif()
        sarif["runs"][0]["properties"]["controlloop"]["blastRadius"] = [
            "• no material capability is reachable"
        ]

        result = _run(tmp_path, sarif=sarif)

        assert result.returncode == 1
        assert "does not name the expected material class" in result.stderr

    def test_sarif_carries_no_blast_radius_property_at_all(
        self, tmp_path: Path
    ) -> None:
        result = _run(tmp_path, sarif={"runs": [{"properties": {}}]})

        assert result.returncode == 1
        assert "no runs[0].properties.controlloop.blastRadius" in result.stderr

    def test_an_unexpected_rule_started_firing(self, tmp_path: Path) -> None:
        """A new rule firing on the scenario is a real change in
        behavior, not incidental drift."""
        evidence = _evidence()
        evidence["findings"].append(
            {
                "id": f"clp:finding:sha256:{'2' * 64}",
                "rule_id": "policy.hardcoded-secrets",
                "severity": "high",
                "confidence": "high",
                "message": "something new",
                "capability_path": None,
            }
        )

        result = _run(tmp_path, evidence=evidence)

        assert result.returncode == 1
        assert "other rules that fired" in result.stderr


class TestMalformedInput:
    def test_a_missing_expected_file_fails_loudly(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(_SCRIPT),
                "--expected",
                str(tmp_path / "absent.json"),
                "--evidence",
                str(tmp_path / "absent.json"),
                "--sarif",
                str(tmp_path / "absent.json"),
                "--exit-code",
                "1",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 1
        assert "does not exist" in result.stderr

    def test_an_unknown_run_name_fails_loudly(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(_SCRIPT),
                "--expected",
                str(tmp_path / "e.json"),
                "--evidence",
                str(tmp_path / "e.json"),
                "--sarif",
                str(tmp_path / "e.json"),
                "--exit-code",
                "1",
                "--run",
                "no_such_run",
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=tmp_path,
        )
        (tmp_path / "e.json").write_text(json.dumps(_expected()), encoding="utf-8")

        assert result.returncode == 1

    @pytest.mark.parametrize("payload", ["not json at all", "[]", "null"])
    def test_malformed_json_fails_loudly(self, tmp_path: Path, payload: str) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text(payload, encoding="utf-8")

        result = subprocess.run(
            [
                sys.executable,
                str(_SCRIPT),
                "--expected",
                str(broken),
                "--evidence",
                str(broken),
                "--sarif",
                str(broken),
                "--exit-code",
                "1",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 1


_STATEMENT = (
    "This change gives Claude Code the power to run `node .github/setup.js` "
    "on every session start (`.claude/settings.json`, hook `SessionStart`). "
    "No approval is recorded."
)


def _authority_expected() -> dict[str, Any]:
    run = _expected()["blocking_run"]
    run.pop("ceiling_finding")
    run.pop("suppressed_pattern_rules")
    run["rules_fired"] = ["policy.capability-ceiling", "policy.undeclared-tools"]
    run["authority_statements"] = [_STATEMENT]
    run["blast_radius"]["contains"] = ["over-privileged workflow claude-review"]
    return {"blocking_run": run}


def _authority_sarif(*, statements: list[str] | None = None) -> dict[str, Any]:
    sarif = _sarif()
    namespace = sarif["runs"][0]["properties"]["controlloop"]
    namespace["blastRadius"] = [
        namespace["blastRadius"][0] + "; also from over-privileged workflow "
        "claude-review"
    ]
    namespace["authorityDelta"] = [
        {"statement": text}
        for text in (statements if statements is not None else [_STATEMENT])
    ]
    return sarif


class TestAgentAuthorityExpectations:
    """The agent-authority scenarios also assert the rules that fired, the
    authority statements, and blast-radius clauses."""

    def test_matching_output_passes(self, tmp_path: Path) -> None:
        result = _run(
            tmp_path, expected=_authority_expected(), sarif=_authority_sarif()
        )

        assert result.returncode == 0, result.stderr

    def test_a_changed_statement_is_caught(self, tmp_path: Path) -> None:
        result = _run(
            tmp_path,
            expected=_authority_expected(),
            sarif=_authority_sarif(statements=[_STATEMENT.replace("No", "An")]),
        )

        assert result.returncode == 1
        assert "authority statements" in result.stderr

    def test_a_missing_statement_is_caught(self, tmp_path: Path) -> None:
        result = _run(
            tmp_path,
            expected=_authority_expected(),
            sarif=_authority_sarif(statements=[]),
        )

        assert result.returncode == 1
        assert "authority statements" in result.stderr

    def test_a_rule_that_stopped_firing_is_caught(self, tmp_path: Path) -> None:
        evidence = _evidence()
        evidence["findings"] = evidence["findings"][:1]

        result = _run(
            tmp_path,
            expected=_authority_expected(),
            evidence=evidence,
            sarif=_authority_sarif(),
        )

        assert result.returncode == 1
        assert "rules that fired" in result.stderr

    def test_a_dropped_blast_radius_clause_is_caught(self, tmp_path: Path) -> None:
        sarif = _authority_sarif()
        sarif["runs"][0]["properties"]["controlloop"]["blastRadius"] = _sarif()["runs"][
            0
        ]["properties"]["controlloop"]["blastRadius"]

        result = _run(tmp_path, expected=_authority_expected(), sarif=sarif)

        assert result.returncode == 1
        assert "clause" in result.stderr


_UNSANCTIONED = (
    "The mcp_server `web-fetch` is not approved by organization policy "
    "version 12: its package is not the approved package (constraint `package`)."
)


def _judgments() -> list[dict[str, Any]]:
    return [
        {
            "component_type": "mcp_server",
            "component_name": "catalog-search",
            "state": "sanctioned",
            "failed_constraint": None,
            "judged_by_policy_version": "12",
        },
        {
            "component_type": "mcp_server",
            "component_name": "web-fetch",
            "state": "unsanctioned",
            "failed_constraint": "package",
            "judged_by_policy_version": "12",
        },
    ]


def _team_expected() -> dict[str, Any]:
    run = _expected()["blocking_run"]
    run["suppressed_pattern_rules"] = sorted(
        [*run["suppressed_pattern_rules"], "policy.unsanctioned-agent-component"]
    )
    run["team"] = {
        "organization_bundle_version": "12",
        "policy_source": "stale_cache",
        "entitlement_state": "unreachable",
        "sanction_note": None,
        "sanction_judgments": _judgments(),
    }
    run["finding_messages"] = {"policy.unsanctioned-agent-component": [_UNSANCTIONED]}
    return {"blocking_run": run}


def _team_evidence() -> dict[str, Any]:
    evidence = _evidence()
    evidence["findings"].append(
        {
            "id": f"clp:finding:sha256:{'2' * 64}",
            "rule_id": "policy.unsanctioned-agent-component",
            "severity": "medium",
            "message": _UNSANCTIONED,
        }
    )
    evidence["team"] = {
        "organization_bundle_version": "12",
        "policy_source": "stale_cache",
        "entitlement_state": "unreachable",
        "sanction_note": None,
        "sanction_judgments": [
            {"component_stable_id": f"clp:tool:sha256:{index * 64}", **judgment}
            for index, judgment in zip("cd", _judgments(), strict=True)
        ],
    }
    return evidence


class TestTeamExpectations:
    """The Team scenarios also assert the sanction judgments, the bundle
    version, and the offline policy source."""

    def test_matching_output_passes(self, tmp_path: Path) -> None:
        result = _run(tmp_path, expected=_team_expected(), evidence=_team_evidence())

        assert result.returncode == 0, result.stderr

    def test_a_grant_that_became_sanctioned_is_caught(self, tmp_path: Path) -> None:
        evidence = _team_evidence()
        evidence["team"]["sanction_judgments"][1]["state"] = "sanctioned"
        evidence["team"]["sanction_judgments"][1]["failed_constraint"] = None

        result = _run(tmp_path, expected=_team_expected(), evidence=evidence)

        assert result.returncode == 1
        assert "team.sanction_judgments" in result.stderr

    def test_a_different_failed_constraint_is_caught(self, tmp_path: Path) -> None:
        evidence = _team_evidence()
        evidence["team"]["sanction_judgments"][1]["failed_constraint"] = "name"

        result = _run(tmp_path, expected=_team_expected(), evidence=evidence)

        assert result.returncode == 1
        assert "team.sanction_judgments" in result.stderr

    def test_a_different_bundle_version_is_caught(self, tmp_path: Path) -> None:
        evidence = _team_evidence()
        evidence["team"]["organization_bundle_version"] = "13"

        result = _run(tmp_path, expected=_team_expected(), evidence=evidence)

        assert result.returncode == 1
        assert "team.organization_bundle_version" in result.stderr

    def test_a_missing_unevaluated_note_is_caught(self, tmp_path: Path) -> None:
        expected = _team_expected()
        expected["blocking_run"]["team"]["sanction_note"] = "unevaluated: ..."

        result = _run(tmp_path, expected=expected, evidence=_team_evidence())

        assert result.returncode == 1
        assert "team.sanction_note" in result.stderr

    def test_a_changed_finding_message_is_caught(self, tmp_path: Path) -> None:
        evidence = _team_evidence()
        evidence["findings"][-1]["message"] = _UNSANCTIONED.replace("12", "11")

        result = _run(tmp_path, expected=_team_expected(), evidence=evidence)

        assert result.returncode == 1
        assert "messages of policy.unsanctioned-agent-component" in result.stderr

    def test_a_community_run_is_caught(self, tmp_path: Path) -> None:
        evidence = _team_evidence()
        evidence["team"] = None

        result = _run(tmp_path, expected=_team_expected(), evidence=evidence)

        assert result.returncode == 1
        assert "no `team` section" in result.stderr
