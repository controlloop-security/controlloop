"""Assert one reference-agent scenario's real gate output against its own
committed expectations.

Reads three real artifacts produced by the **published** ControlLoop
Action (never a local checkout -- ensuring that is the workflow's job, not
this script's): the evidence artifact, the SARIF log, and the action's own
reported exit code. Compares them against the `expected/<name>.json`
file committed alongside the scenario in
`controlloop-security/controlloop-reference-agent`.

Exits non-zero on any mismatch, with the expected and actual values
printed, so a red scheduled run says what regressed rather than only
that something did. That non-zero exit is what blocks the release;
nothing here swallows a failure.

Deliberately strict about three things -- verdict, findings, and the
blast-radius statement -- and deliberately silent about everything else,
so incidental drift in an unasserted field does not produce a red run
nobody trusts.

Three optional keys serve the agent-authority scenarios: `rules_fired`
(the sorted set of rule IDs in the evidence), `authority_statements`
(the exact statements, in order, from the SARIF document's
`runs[0].properties.controlloop.authorityDelta`), and
`blast_radius.contains` (further text the blast-radius statement must
include, such as a bypass or over-privileged-workflow clause).

Two more serve the Team sanctioned-list scenarios, both read from the
evidence artifact:

- `team`: the organization bundle version, where the policy came from,
  the entitlement state, the sanction note, and every sanction judgment
  (component type and name, state, failed constraint, and the policy
  version that judged it), each compared exactly and in order.
- `finding_messages`: for each rule ID named, the exact messages of that
  rule's findings, sorted.

Usage:

    python assert_scenario_expectations.py \\
        --expected  <scenario>/expected/<name>.json \\
        --evidence  <evidence.json from the action> \\
        --sarif     <sarif.json from the action> \\
        --exit-code <the action's reported exit code> \\
        --run       blocking_run
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class _Mismatch(Exception):
    """One asserted expectation did not hold."""


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise _Mismatch(f"{path} does not exist") from None
    except (OSError, json.JSONDecodeError) as error:
        raise _Mismatch(f"{path} could not be read as JSON: {error}") from None


def _require(label: str, expected: object, actual: object) -> None:
    if expected != actual:
        raise _Mismatch(
            f"{label}\n"
            f"  expected: {json.dumps(expected, sort_keys=True)}\n"
            f"  actual:   {json.dumps(actual, sort_keys=True)}"
        )


def _blast_radius_from_sarif(sarif: Any) -> Any:
    """The blast-radius statement as the Action itself publishes it --
    `runs[0].properties.controlloop.blastRadius`. The
    evidence artifact does not carry it, so SARIF is the only place a
    consumer can read it back."""

    try:
        return sarif["runs"][0]["properties"]["controlloop"]["blastRadius"]
    except (KeyError, IndexError, TypeError):
        raise _Mismatch(
            "the SARIF document carries no "
            "runs[0].properties.controlloop.blastRadius property at all"
        ) from None


def _authority_statements_from_sarif(sarif: Any) -> list[str]:
    """The authority statements as the Action publishes them -- an empty
    list when the change granted nothing, which omits the property."""

    try:
        namespace = sarif["runs"][0].get("properties", {}).get("controlloop", {})
    except (KeyError, IndexError, TypeError, AttributeError):
        return []
    entries = namespace.get("authorityDelta", []) if isinstance(namespace, dict) else []
    return [
        entry["statement"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("statement"), str)
    ]


#: The `team.sanction_judgments` fields a scenario asserts. The component's
#: stable ID is left out: it is a digest a reader cannot check by eye, and
#: the type and name already say which grant was judged.
_JUDGMENT_FIELDS = (
    "component_type",
    "component_name",
    "state",
    "failed_constraint",
    "judged_by_policy_version",
)

#: The `team` scalars a scenario asserts.
_TEAM_FIELDS = (
    "organization_bundle_version",
    "policy_source",
    "entitlement_state",
    "sanction_note",
)


def _assert_team(expected: dict[str, Any], evidence: dict[str, Any]) -> None:
    team = evidence.get("team")
    if not isinstance(team, dict):
        raise _Mismatch(
            "expected a Team gate, but the evidence artifact records no `team` "
            f"section (team = {json.dumps(team)})"
        )
    for field in _TEAM_FIELDS:
        if field in expected:
            _require(f"team.{field}", expected[field], team.get(field))
    if "sanction_judgments" in expected:
        actual = [
            {field: judgment.get(field) for field in _JUDGMENT_FIELDS}
            for judgment in team.get("sanction_judgments") or []
            if isinstance(judgment, dict)
        ]
        _require("team.sanction_judgments", expected["sanction_judgments"], actual)


def _assert_finding_messages(
    expected: dict[str, list[str]], evidence: dict[str, Any]
) -> None:
    findings = evidence.get("findings") or []
    for rule_id, messages in expected.items():
        actual = sorted(
            str(finding.get("message"))
            for finding in findings
            if isinstance(finding, dict) and finding.get("rule_id") == rule_id
        )
        _require(f"messages of {rule_id}", messages, actual)


def _assert_run(
    expectations: dict[str, Any],
    evidence: dict[str, Any],
    sarif: Any,
    exit_code: int,
) -> None:
    _require("verdict", expectations["verdict"], evidence.get("verdict"))
    _require("gate exit code", expectations["gate_exit_code"], exit_code)

    expected_finding = expectations.get("ceiling_finding")
    if expected_finding is not None:
        findings = evidence.get("findings") or []
        matching = [f for f in findings if f.get("id") == expected_finding["id"]]
        if not matching:
            raise _Mismatch(
                "the expected finding is absent from the evidence artifact\n"
                f"  expected id: {expected_finding['id']}\n"
                f"  actual ids:  {json.dumps([f.get('id') for f in findings])}"
            )
        actual = matching[0]
        for field in ("rule_id", "severity", "confidence", "message"):
            _require(f"finding.{field}", expected_finding[field], actual.get(field))
        _require(
            "finding.capability_path",
            expected_finding["capability_path"],
            actual.get("capability_path"),
        )

    expected_rules = expectations.get("suppressed_pattern_rules")
    if expected_rules is not None:
        ceiling_rule = (expected_finding or {}).get("rule_id")
        actual_rules = sorted(
            {
                f.get("rule_id")
                for f in (evidence.get("findings") or [])
                if f.get("rule_id") != ceiling_rule
            }
        )
        _require("other rules that fired", expected_rules, actual_rules)

    if "rules_fired" in expectations:
        actual_fired = sorted(
            {f.get("rule_id") for f in (evidence.get("findings") or [])}
        )
        _require("rules that fired", expectations["rules_fired"], actual_fired)

    if "team" in expectations:
        _assert_team(expectations["team"], evidence)

    if "finding_messages" in expectations:
        _assert_finding_messages(expectations["finding_messages"], evidence)

    if "authority_statements" in expectations:
        _require(
            "authority statements",
            expectations["authority_statements"],
            _authority_statements_from_sarif(sarif),
        )

    if "blast_radius" in expectations:
        expected_blast = expectations["blast_radius"]
        actual_blast = _blast_radius_from_sarif(sarif)
        if expected_blast is None:
            # The Action renders the statement as text lines, so "no
            # statement" is the explicit no-material-capability line,
            # never an absent property.
            if not any(
                "no material capability" in str(line) for line in actual_blast or []
            ):
                raise _Mismatch(
                    "expected no material capability to be reachable, but the "
                    f"SARIF blast radius was {json.dumps(actual_blast)}"
                )
        else:
            expected_class = expected_blast.get("material_class")
            expected_target = expected_blast.get("target_name")
            rendered = " ".join(str(line) for line in actual_blast or [])
            needles = [
                (expected_class, "material class"),
                (expected_target, "target name"),
            ] + [(text, "clause") for text in expected_blast.get("contains", [])]
            for needle, label in needles:
                if needle and needle not in rendered:
                    raise _Mismatch(
                        f"the SARIF blast-radius statement does not name the "
                        f"expected {label}\n"
                        f"  expected to contain: {needle}\n"
                        f"  actual:              {rendered}"
                    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--sarif", required=True, type=Path)
    parser.add_argument("--exit-code", required=True, type=int)
    parser.add_argument("--run", default="blocking_run")
    args = parser.parse_args(argv)

    try:
        expected_document = _load(args.expected)
        if args.run not in expected_document:
            raise _Mismatch(
                f"{args.expected} has no '{args.run}' section; it has "
                f"{sorted(k for k in expected_document if not k.startswith('_'))}"
            )
        _assert_run(
            expected_document[args.run],
            _load(args.evidence),
            _load(args.sarif),
            args.exit_code,
        )
    except _Mismatch as mismatch:
        print(f"::error::scenario expectation failed -- {mismatch}", file=sys.stderr)
        return 1

    print(f"OK: {args.expected.name} [{args.run}] matched real output exactly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
