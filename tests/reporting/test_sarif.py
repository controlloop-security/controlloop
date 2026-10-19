"""Tests for controlloop.reporting.sarif."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from jsonschema import Draft4Validator, ValidationError  # type: ignore[import-untyped]
from test_terminal import _finding

from controlloop.acbom import Evidence, Generator
from controlloop.reporting.sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    render_sarif_log,
)

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SARIF_SCHEMA_PATH = _CLI_ROOT / "tests/fixtures/sarif/sarif-schema-2.1.0.json"
_SARIF_SCHEMA = cast(
    dict[str, object], json.loads(_SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))
)
_VALIDATOR = Draft4Validator(_SARIF_SCHEMA)

_TOOL = Generator(name="controlloop", version="0.1.0")


class TestLogDocumentStructure:
    """A complete SARIF 2.1.0 log document."""

    def test_version_and_schema_are_set(self) -> None:
        log = render_sarif_log((), tool=_TOOL)

        assert log["version"] == SARIF_VERSION == "2.1.0"
        assert log["$schema"] == SARIF_SCHEMA_URI

    def test_driver_carries_tool_identity(self) -> None:
        log = render_sarif_log((), tool=_TOOL)

        driver = cast(dict[str, object], log["runs"][0]["tool"]["driver"])  # type: ignore[index]
        assert driver["name"] == "controlloop"
        assert driver["version"] == "0.1.0"

    def test_information_uri_included_only_when_supplied(self) -> None:
        without = render_sarif_log((), tool=_TOOL)
        with_uri = render_sarif_log(
            (), tool=_TOOL, information_uri="https://controlloop.dev"
        )

        driver_without = without["runs"][0]["tool"]["driver"]  # type: ignore[index]
        driver_with = with_uri["runs"][0]["tool"]["driver"]  # type: ignore[index]
        assert "informationUri" not in driver_without
        assert driver_with["informationUri"] == "https://controlloop.dev"

    def test_each_finding_produces_one_result(self) -> None:
        findings = (
            _finding(id=f"clp:finding:sha256:{'a' * 64}"),
            _finding(id=f"clp:finding:sha256:{'b' * 64}"),
        )

        log = render_sarif_log(findings, tool=_TOOL)

        assert len(log["runs"][0]["results"]) == 2  # type: ignore[index]


class TestRuleMetadata:
    """Each result names its rule, and rule metadata
    (including help URIs) is emitted once per unique rule in the
    driver section."""

    def test_each_result_names_a_rule_id_and_level_and_message(self) -> None:
        log = render_sarif_log((_finding(),), tool=_TOOL)

        result = log["runs"][0]["results"][0]  # type: ignore[index]
        assert result["ruleId"] == "policy.undeclared-tools"
        assert result["level"]
        assert result["message"]["text"]

    def test_rules_include_help_uri_and_version(self) -> None:
        finding = _finding(
            rule_id="policy.example-rule",
            documentation_url="https://docs.controlloop.ai/rules/example-rule",
        )

        log = render_sarif_log((finding,), tool=_TOOL)

        rules = log["runs"][0]["tool"]["driver"]["rules"]  # type: ignore[index]
        assert len(rules) == 1
        assert rules[0]["id"] == "policy.example-rule"
        assert rules[0]["helpUri"] == "https://docs.controlloop.ai/rules/example-rule"
        assert rules[0]["properties"]["controlloop"]["ruleVersion"] == "1.0.0"

    def test_findings_sharing_a_rule_produce_one_descriptor(self) -> None:
        findings = (
            _finding(id=f"clp:finding:sha256:{'a' * 64}", rule_id="policy.shared"),
            _finding(id=f"clp:finding:sha256:{'b' * 64}", rule_id="policy.shared"),
        )

        log = render_sarif_log(findings, tool=_TOOL)

        rules = log["runs"][0]["tool"]["driver"]["rules"]  # type: ignore[index]
        assert len(rules) == 1
        assert len(log["runs"][0]["results"]) == 2  # type: ignore[index]

    def test_rules_are_sorted_deterministically(self) -> None:
        findings = (
            _finding(id=f"clp:finding:sha256:{'a' * 64}", rule_id="policy.zzz"),
            _finding(id=f"clp:finding:sha256:{'b' * 64}", rule_id="policy.aaa"),
        )

        log = render_sarif_log(findings, tool=_TOOL)

        rule_ids = [rule["id"] for rule in log["runs"][0]["tool"]["driver"]["rules"]]  # type: ignore[index]
        assert rule_ids == ["policy.aaa", "policy.zzz"]


class TestNoFabricatedLocation:
    """A finding with no file location emits a valid result
    without a fabricated location."""

    def test_a_finding_with_only_document_digest_evidence_has_no_locations(
        self,
    ) -> None:
        finding = _finding(
            evidence=(Evidence(adapter="mcp", document_digest=f"sha256:{'a' * 64}"),)
        )

        log = render_sarif_log((finding,), tool=_TOOL)

        result = log["runs"][0]["results"][0]  # type: ignore[index]
        assert result["locations"] == []


class TestSchemaValidation:
    """Output validates against the real SARIF 2.1.0 schema,
    vendored locally for offline validation."""

    def test_a_populated_log_validates(self) -> None:
        log = render_sarif_log((_finding(),), tool=_TOOL)

        _VALIDATOR.validate(log)

    def test_an_empty_findings_log_still_validates(self) -> None:
        log = render_sarif_log((), tool=_TOOL)

        _VALIDATOR.validate(log)

    def test_the_validator_actually_rejects_an_invalid_document(self) -> None:
        """Boundary/negative control: proves the schema check above is
        a real, discriminating assertion, not one that would pass
        anything."""

        invalid = {"$schema": SARIF_SCHEMA_URI, "runs": []}

        try:
            _VALIDATOR.validate(invalid)
        except ValidationError:
            pass
        else:
            raise AssertionError("expected a missing 'version' to be rejected")


class TestBlastRadiusProperty:
    """`blast_radius_lines`: embedded as
    `runs[0].properties.controlloop.blastRadius`, reusing this module's
    own existing `properties.controlloop` extension namespace."""

    def test_omitted_by_default(self) -> None:
        log = render_sarif_log((), tool=_TOOL)

        run = cast(dict[str, object], log["runs"][0])  # type: ignore[index]
        assert "properties" not in run

    def test_embedded_when_supplied(self) -> None:
        lines = ("• no material capability is reachable",)
        log = render_sarif_log((), tool=_TOOL, blast_radius_lines=lines)

        run = cast(dict[str, object], log["runs"][0])  # type: ignore[index]
        properties = cast(dict[str, object], run["properties"])
        controlloop = cast(dict[str, object], properties["controlloop"])
        assert controlloop["blastRadius"] == list(lines)

    def test_document_with_blast_radius_still_validates_against_schema(self) -> None:
        lines = ("• the worst reachable material capability is X",)
        log = render_sarif_log((_finding(),), tool=_TOOL, blast_radius_lines=lines)

        _VALIDATOR.validate(log)


class TestDeterminism:
    def test_identical_input_produces_identical_output(self) -> None:
        findings = (_finding(),)

        first = json.dumps(render_sarif_log(findings, tool=_TOOL), sort_keys=True)
        second = json.dumps(render_sarif_log(findings, tool=_TOOL), sort_keys=True)

        assert first == second
