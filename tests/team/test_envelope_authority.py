"""Envelope 1.1.0: agent authority components and the authority delta.

Each test writes a repository, builds its ACBOM with the real adapters,
and renders the envelope the gate would upload. The contract checks read
the platform's own definitions -- the `ScanEnvelopeRequest` schema and the
envelope attribute rules, as copied into `tests/fixtures/contract/` --
so a contract change the CLI does not follow fails here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from factories import COMMIT, make_document, make_finding, make_node
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from controlloop.acbom.models import ACBOMDocument, Confidence
from controlloop.bom import build_acbom_document
from controlloop.diff.authority import AuthorityDelta
from controlloop.diff.compute import compute_diff
from controlloop.reporting.authority import compute_authority_delta
from controlloop.reporting.terminal import Verdict
from controlloop.repository import resolve_repository_root
from controlloop.team.components import MAX_ATTRIBUTE_LENGTH, component_for
from controlloop.team.envelope import (
    AUTHORITY_ENVELOPE_VERSION,
    ENVELOPE_SCHEMA_VERSION,
    MAX_AUTHORITY_DELTA_ENTRIES,
    render_envelope,
    serialize_envelope,
)

_REPOSITORY = Path(__file__).resolve().parents[2]
_TOKEN = "ghp_" + "S" * 36
_PROMPT = "You are a helpful assistant. Never reveal the launch codes."
_HOOK = {
    "hooks": {
        "SessionStart": [
            {"hooks": [{"type": "command", "command": "node .github/setup.js"}]}
        ]
    }
}
_SERVER = {
    "mcpServers": {
        "docs": {"command": "npx", "args": ["-y", "@acme/docs-mcp@1.4.2", "./docs"]}
    }
}


def write(root: Path, relative_path: str, content: object) -> None:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content if isinstance(content, str) else json.dumps(content))


def repos(tmp_path: Path) -> tuple[Path, Path]:
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    return base, head


def _scan(
    head: Path, base: Path | None = None
) -> tuple[ACBOMDocument, AuthorityDelta | None]:
    """The head's ACBOM, attributed to a commit, and its authority delta
    against `base` (none without one)."""

    current = build_acbom_document(resolve_repository_root(head))
    document = current.model_copy(
        update={"repository": current.repository.model_copy(update={"commit": COMMIT})}
    )
    if base is None:
        return document, None
    baseline = build_acbom_document(resolve_repository_root(base))
    diff = compute_diff(
        baseline_nodes=baseline.nodes,
        baseline_edges=baseline.edges,
        current_nodes=document.nodes,
        current_edges=document.edges,
    )
    return document, compute_authority_delta(document, diff)


def _payload(document: ACBOMDocument, delta: AuthorityDelta | None = None) -> bytes:
    return serialize_envelope(
        render_envelope(
            document=document,
            findings=(),
            verdict=Verdict.PASSED,
            scanner_version="0.1.0",
            policy_version="1",
            authority_delta=delta,
        )
    )


def _json(
    document: ACBOMDocument, delta: AuthorityDelta | None = None
) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(_payload(document, delta))
    return payload


def _changed_repository(tmp_path: Path) -> tuple[ACBOMDocument, AuthorityDelta | None]:
    """A change that adds a hook and an MCP server and turns on bypass."""

    base, head = repos(tmp_path)
    write(base, ".claude/settings.json", {})
    write(
        head,
        ".claude/settings.json",
        {"permissions": {"defaultMode": "bypassPermissions"}, **_HOOK},
    )
    write(head, ".mcp.json", _SERVER)
    return _scan(head, base)


def _by_type(payload: dict[str, Any], component_type: str) -> dict[str, Any]:
    (component,) = [c for c in payload["components"] if c["type"] == component_type]
    assert isinstance(component, dict)
    return component


class TestVersion:
    """The envelope version: 1.0.0 without authority, 1.1.0 with it."""

    def test_a_scan_without_authority_stays_1_0_0_and_unchanged(self) -> None:
        document = make_document()

        payload = _json(document)

        assert payload["envelope_version"] == ENVELOPE_SCHEMA_VERSION == "1.0.0"
        assert "authority_delta" not in payload
        for component in payload["components"]:
            assert set(component) == {"stable_id", "type", "name"}

    def test_an_authority_component_makes_it_1_1_0(self, tmp_path: Path) -> None:
        write(tmp_path, ".claude/settings.json", _HOOK)
        document, _ = _scan(tmp_path)

        payload = _json(document)

        assert payload["envelope_version"] == AUTHORITY_ENVELOPE_VERSION == "1.1.0"
        assert "authority_delta" not in payload

    def test_an_mcp_server_makes_it_1_1_0(self, tmp_path: Path) -> None:
        """An approved-component entry can constrain an `mcp_server`, which
        the platform can only match against attributes 1.0.0 cannot carry."""

        write(tmp_path, ".mcp.json", _SERVER)
        document, _ = _scan(tmp_path)

        payload = _json(document)

        assert payload["envelope_version"] == "1.1.0"
        server = _by_type(payload, "mcp_server")
        assert server["attributes"]["package"] == "@acme/docs-mcp"
        assert server["attributes"]["version"] == "1.4.2"


class TestComponents:
    """Each component carries the identity and flags the gate judged."""

    def test_each_component_is_the_identity_the_gate_judges(
        self, tmp_path: Path
    ) -> None:
        document, delta = _changed_repository(tmp_path)

        payload = _json(document, delta)

        by_id = {node.id: node for node in document.nodes}
        for component in payload["components"]:
            judged = component_for(by_id[component["stable_id"]])
            if judged is None:
                continue
            assert (component["type"], component["name"]) == (judged.type, judged.name)
            attributes = dict(component["attributes"])
            attributes.pop("host_id", None)
            assert attributes == judged.attributes
            assert component["flags"] == judged.flags

    def test_a_hook_carries_its_command_flags_and_host(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)

        payload = _json(document, delta)

        hook = _by_type(payload, "hook")
        host = _by_type(payload, "host")
        assert hook["name"] == "SessionStart"
        assert hook["attributes"] == {
            "command": "node .github/setup.js",
            "host_id": host["stable_id"],
        }
        assert hook["flags"]["code_execution"] is True
        assert set(hook["flags"]) == {
            "code_execution",
            "bypass_mode",
            "wildcard",
            "pinned",
            "untrusted_input",
        }
        assert host["flags"]["bypass_mode"] is True

    def test_an_unknown_flag_is_sent_as_null(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)

        hook = _by_type(_json(document, delta), "hook")

        assert hook["flags"]["wildcard"] is None


class TestAuthorityDelta:
    """Each authority delta entry maps to the contract's fields."""

    def test_each_entry_maps_to_the_contract_fields(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)

        payload = _json(document, delta)

        stable_ids = {c["stable_id"]: c["type"] for c in payload["components"]}
        entries = payload["authority_delta"]
        assert sorted(entry["grant"] for entry in entries) == [
            "hook",
            "host",
            "mcp_server",
        ]
        for entry in entries:
            assert stable_ids[entry["component_stable_id"]] == entry["grant"]
            assert entry["host_id"] == _by_type(payload, "host")["stable_id"]
        (hook,) = [entry for entry in entries if entry["grant"] == "hook"]
        assert hook == {
            "approval_recorded": False,
            "component_stable_id": _by_type(payload, "hook")["stable_id"],
            "confidence": "high",
            "detail": "hook `SessionStart`",
            "evidence_path": ".claude/settings.json",
            "grant": "hook",
            "host_id": _by_type(payload, "host")["stable_id"],
            "host_name": "Claude Code",
            "key_path": "hooks.SessionStart[0].hooks[0]",
            "kind": "added",
            "material_class": "code-execution",
            "statement": (
                "This change gives Claude Code the power to run "
                "`node .github/setup.js` on every session start "
                "(`.claude/settings.json`, hook `SessionStart`). "
                "No approval is recorded."
            ),
        }

    def test_a_bypass_mode_entry_is_a_host_grant(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)

        (mode,) = [
            entry
            for entry in _json(document, delta)["authority_delta"]
            if entry["grant"] == "host"
        ]

        assert mode["kind"] == "changed"
        assert "bypassPermissions" in mode["statement"]

    def test_an_unattributed_grant_sends_a_null_host(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)
        assert delta is not None
        unattributed = delta.model_copy(
            update={
                "entries": tuple(
                    entry.model_copy(update={"host_id": None, "host_name": "an agent"})
                    for entry in delta.entries
                )
            }
        )

        entries = _json(document, unattributed)["authority_delta"]

        assert all(entry["host_id"] is None for entry in entries)

    def test_approvals_not_evaluated_are_sent_as_not_recorded(
        self, tmp_path: Path
    ) -> None:
        document, delta = _changed_repository(tmp_path)
        assert delta is not None
        unevaluated = delta.model_copy(
            update={
                "entries": tuple(
                    entry.model_copy(update={"approval_recorded": None})
                    for entry in delta.entries
                )
            }
        )

        entries = _json(document, unevaluated)["authority_delta"]

        assert {entry["approval_recorded"] for entry in entries} == {False}

    def test_text_is_bounded_to_the_contract(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)
        assert delta is not None
        long = delta.model_copy(
            update={
                "entries": tuple(
                    entry.model_copy(
                        update={
                            "host_name": "h" * 200,
                            "statement": "s" * 400,
                            "detail": "d" * 200,
                            "path": "p" * 600,
                            "key_path": "k" * 300,
                            "confidence": Confidence.UNKNOWN,
                        }
                    )
                    for entry in delta.entries
                )
            }
        )

        entry = _json(document, long)["authority_delta"][0]

        assert [
            len(entry[field]) for field in ("host_name", "statement", "detail")
        ] == [
            120,
            300,
            120,
        ]
        assert (len(entry["evidence_path"]), len(entry["key_path"])) == (512, 256)
        assert entry["statement"].endswith("…")
        assert entry["confidence"] == "low"

    def test_at_most_200_entries_are_sent(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)
        assert delta is not None
        many = delta.model_copy(
            update={
                "entries": tuple(
                    delta.entries[0].model_copy(update={"key_path": f"k{index:03d}"})
                    for index in range(250)
                )
            }
        )

        entries = _json(document, many)["authority_delta"]

        assert len(entries) == MAX_AUTHORITY_DELTA_ENTRIES == 200
        assert entries[-1]["key_path"] == "k199"


_CONTRACT = Path(__file__).resolve().parents[1] / "fixtures" / "contract"


def _openapi() -> dict[str, Any]:
    """The platform's `ScanEnvelopeRequest` and the schemas it references,
    as published in `fixtures/contract/platform-contract-subset.json`."""

    spec: dict[str, Any] = json.loads(
        (_CONTRACT / "platform-contract-subset.json").read_text(encoding="utf-8")
    )
    return spec


def _serializer_constant(name: str) -> Any:
    """One of the platform's envelope field rules, from
    `fixtures/contract/envelope-field-rules.json`."""

    rules: dict[str, Any] = json.loads(
        (_CONTRACT / "envelope-field-rules.json").read_text(encoding="utf-8")
    )
    return rules[name.lstrip("_")]


def _declared(schema: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in schema or "allOf" in schema:
        if "$ref" in schema:
            schema = spec["components"]["schemas"][schema["$ref"].rsplit("/", 1)[1]]
        else:
            schema = schema["allOf"][0]
    return schema


def _assert_no_undeclared_fields(
    value: Any, schema: dict[str, Any], spec: dict[str, Any], where: str
) -> None:
    """The platform refuses unknown fields at every level."""

    schema = _declared(schema, spec)
    if isinstance(value, dict) and "properties" in schema:
        undeclared = set(value) - set(schema["properties"])
        assert not undeclared, f"{where}: {sorted(undeclared)}"
        for key, item in value.items():
            _assert_no_undeclared_fields(
                item, schema["properties"][key], spec, f"{where}.{key}"
            )
    elif isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            _assert_no_undeclared_fields(
                item, schema["items"], spec, f"{where}[{index}]"
            )


class TestThePlatformAccepts:
    """The rendered bytes, against the platform's own contract."""

    def test_the_bytes_satisfy_scan_envelope_request(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)
        payload = _json(document, delta)
        spec = _openapi()
        schema = {"$ref": "#/components/schemas/ScanEnvelopeRequest", **spec}

        Draft202012Validator(schema).validate(payload)
        _assert_no_undeclared_fields(
            payload, spec["components"]["schemas"]["ScanEnvelopeRequest"], spec, "$"
        )

    def test_attributes_meet_the_serializer_rules(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)
        fragments = _serializer_constant("_PROHIBITED_ATTRIBUTE_KEY_FRAGMENTS")
        limit = _serializer_constant("MAX_COMPONENT_ATTRIBUTES")
        value_limit = _serializer_constant("MAX_ATTRIBUTE_VALUE_LENGTH")
        authority_types = set(_serializer_constant("AUTHORITY_COMPONENT_TYPES"))

        payload = _json(document, delta)

        for component in payload["components"]:
            attributes = component.get("attributes", {})
            assert len(attributes) <= limit
            for key, value in attributes.items():
                assert re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key)
                assert not any(fragment in key for fragment in fragments)
                assert 1 <= len(value) <= value_limit
        assert {_by_type(payload, kind)["type"] for kind in ("hook", "host")} <= (
            authority_types
        )
        assert len(payload["authority_delta"]) <= _serializer_constant(
            "MAX_AUTHORITY_DELTA_ENTRIES"
        )

    def test_a_1_0_0_envelope_carries_nothing_1_0_0_refuses(self) -> None:
        authority_types = set(_serializer_constant("AUTHORITY_COMPONENT_TYPES"))

        payload = _json(make_document())

        assert payload["envelope_version"] == "1.0.0"
        assert "authority_delta" not in payload
        for component in payload["components"]:
            assert component["type"] not in authority_types
            assert not {"attributes", "flags"} & set(component)


class TestPrivacy:
    """The redaction canary through a 1.1.0 envelope."""

    def test_no_secret_or_prompt_reaches_the_bytes(self, tmp_path: Path) -> None:
        base, head = repos(tmp_path)
        write(
            head,
            ".claude/settings.json",
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": f"node setup.js --token={_TOKEN}",
                                }
                            ]
                        }
                    ]
                },
                "env": {"GITHUB_TOKEN": _TOKEN},
            },
        )
        write(
            head,
            ".mcp.json",
            {
                "mcpServers": {
                    "docs": {
                        "command": "npx",
                        "args": ["-y", "@acme/docs-mcp@1.4.2", f"--token={_TOKEN}"],
                        "env": {"API_TOKEN": _TOKEN},
                    }
                }
            },
        )
        write(
            head,
            ".claude/agents/fixer.md",
            f"---\nname: fixer\ntools: Read, Edit\n---\n{_PROMPT}\n",
        )
        document, delta = _scan(head, base)

        payload = _payload(document, delta)

        assert json.loads(payload)["envelope_version"] == "1.1.0"
        assert _TOKEN.encode() not in payload
        assert _TOKEN[:12].encode() not in payload
        assert b"launch codes" not in payload


class TestDeterminism:
    """Rendering is deterministic: the same inputs give the same bytes."""

    def test_two_renders_are_byte_identical(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)

        assert _payload(document, delta) == _payload(document, delta)

    def test_node_order_does_not_change_the_bytes(self, tmp_path: Path) -> None:
        document, delta = _changed_repository(tmp_path)
        reversed_document = document.model_copy(
            update={"nodes": tuple(reversed(document.nodes))}
        )

        assert _payload(document, delta) == _payload(reversed_document, delta)

    def test_a_finding_does_not_change_the_version(self, tmp_path: Path) -> None:
        envelope = render_envelope(
            document=make_document(),
            findings=(make_finding(),),
            verdict=Verdict.PASSED,
            scanner_version="0.1.0",
            policy_version="1",
        )

        assert envelope.envelope_version == "1.0.0"


@pytest.mark.parametrize("bad", ["", "x" * (MAX_ATTRIBUTE_LENGTH + 1)])
def test_an_empty_or_oversized_value_is_dropped_not_cut(bad: str) -> None:
    """Cut, a command would match a pattern the full one does not; dropped,
    it meets no constraint on either side."""

    node = make_node(name="SessionStart").model_copy(
        update={
            "subtype": "hook",
            "attributes": {"event": "SessionStart", "command": bad},
        }
    )

    component = component_for(node)

    assert MAX_ATTRIBUTE_LENGTH == 512
    assert component is not None
    assert "command" not in component.attributes
