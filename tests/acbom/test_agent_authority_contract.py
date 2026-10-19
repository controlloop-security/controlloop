"""ACBOM 1.2.0 agent authority contract.

Every new shape is checked through both halves of the contract, the
packaged JSON Schema and the Pydantic models, so neither can drift from
the other unnoticed. The version-drift and generated-document tests pin
the packaged schema to what this codebase actually writes, not only to a
hand-written fixture.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import (  # type: ignore[import-untyped]
    ValidationError as JsonSchemaValidationError,
)
from pydantic import ValidationError as PydanticValidationError

from controlloop.acbom import (
    ATTRIBUTE_TRUNCATION_MARKER,
    AUTHORITY_SUBTYPE_RULES,
    MAX_ATTRIBUTE_VALUE_LENGTH,
    MAX_NODE_ATTRIBUTES,
    ACBOMDocument,
    AuthoritySubtype,
    NodeType,
    authority_component_node_id,
    bound_attribute_text,
    compute_digest,
    host_node_id,
    load_acbom_document,
    serialize_document,
    with_digest,
)
from controlloop.acbom.models import Node

type JsonObject = dict[str, object]

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA = cast(
    JsonObject,
    json.loads(
        (_CLI_ROOT / "src/controlloop/schemas/acbom/1.2.0/acbom.schema.json").read_text(
            encoding="utf-8"
        )
    ),
)
_VALIDATOR = Draft202012Validator(_SCHEMA)
_VERSION_DRIFT_FIXTURE = _CLI_ROOT / "tests/fixtures/acbom/version-drift-1.1.0.json"
_GOLDEN_ROOT = _CLI_ROOT / "tests/fixtures/golden"

_SECRET_CANARY = "ghp_" + "Z" * 36

#: One valid example per subtype: the attributes and flags its rule requires.
_EXAMPLES: dict[AuthoritySubtype, tuple[dict[str, str], dict[str, object]]] = {
    AuthoritySubtype.HOST: (
        {
            "host": "claude-code",
            "docs_snapshot": "2026-10-17",
            "default_mode": "default",
        },
        {"bypass_mode": False},
    ),
    AuthoritySubtype.SUBAGENT: (
        {"permission_mode": "bypassPermissions"},
        {"bypass_mode": True},
    ),
    AuthoritySubtype.HOOK: (
        {"event": "SessionStart", "hook_type": "command", "command": "node setup.js"},
        {"code_execution": True, "requires_approval": "unknown"},
    ),
    AuthoritySubtype.HELPER_COMMAND: (
        {"setting": "apiKeyHelper", "command": "./get-key.sh"},
        {"code_execution": True},
    ),
    AuthoritySubtype.PLUGIN: ({"source_type": "github"}, {"pinned": False}),
    AuthoritySubtype.MARKETPLACE: (
        {"source_type": "git-subdir"},
        {"pinned": "unknown"},
    ),
    AuthoritySubtype.SKILL: ({}, {}),
    AuthoritySubtype.WORKFLOW_RUNTIME: (
        {
            "action": "anthropics/claude-code-action",
            "job_permissions": "contents:write,id-token:write",
        },
        {"untrusted_input": True, "bypass_mode": True},
    ),
    AuthoritySubtype.PERMISSION_RULE: (
        {"effect": "allow", "pattern": "Bash(*)"},
        {"wildcard": True, "code_execution": True},
    ),
}


def _node(
    subtype: AuthoritySubtype,
    *,
    attributes: dict[str, str] | None = None,
    flags: dict[str, object] | None = None,
    node_type: str | None = None,
) -> JsonObject:
    example_attributes, example_flags = _EXAMPLES[subtype]
    resolved_type = node_type or AUTHORITY_SUBTYPE_RULES[subtype].node_type.value
    node: JsonObject = {
        "id": f"clp:{resolved_type}:sha256:" + "a" * 64,
        "type": resolved_type,
        "subtype": subtype.value,
        "name": f"example {subtype.value}",
        "security_attributes": dict(example_flags if flags is None else flags),
        "confidence": "high",
        "evidence": [{"adapter": "claude-code", "path": ".claude/settings.json"}],
    }
    resolved_attributes = example_attributes if attributes is None else attributes
    if resolved_attributes:
        node["attributes"] = dict(resolved_attributes)
    return node


def _document(*nodes: JsonObject) -> JsonObject:
    return {
        "schema_version": "1.2.0",
        "generator": {"name": "controlloop", "version": "0.1.0"},
        "repository": {"commit": "abc123", "root_digest": "sha256:" + "d" * 64},
        "nodes": list(nodes),
        "edges": [],
        "diagnostics": [],
        "digest": "sha256:" + "0" * 64,
    }


def _model(document: JsonObject) -> ACBOMDocument:
    return ACBOMDocument.model_validate_json(json.dumps(document))


def _assert_both_reject(document: JsonObject) -> None:
    with pytest.raises(JsonSchemaValidationError):
        _VALIDATOR.validate(document)
    with pytest.raises(PydanticValidationError):
        _model(document)


@pytest.mark.parametrize("subtype", list(AuthoritySubtype))
def test_every_authority_subtype_validates_through_schema_and_model(
    subtype: AuthoritySubtype,
) -> None:
    """A canonical shape exists for every authority subtype."""

    document = _document(_node(subtype))

    _VALIDATOR.validate(document)
    node = _model(document).nodes[0]
    assert node.subtype == subtype.value


def test_the_schema_declares_the_same_subtype_rules_as_the_model() -> None:
    """Parity: each `allOf` branch of the node definition mirrors one
    entry of `AUTHORITY_SUBTYPE_RULES`, and nothing else."""

    definitions = cast(JsonObject, _SCHEMA["$defs"])
    branches = cast(list[JsonObject], cast(JsonObject, definitions["node"])["allOf"])
    declared: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {}
    for branch in branches:
        condition = cast(JsonObject, cast(JsonObject, branch["if"])["properties"])
        subtype = cast(str, cast(JsonObject, condition["subtype"])["const"])
        then = cast(JsonObject, cast(JsonObject, branch["then"])["properties"])
        node_type = cast(str, cast(JsonObject, then["type"])["const"])
        attributes = cast(JsonObject, then.get("attributes", {}))
        flags = cast(JsonObject, then.get("security_attributes", {}))
        declared[subtype] = (
            node_type,
            tuple(cast(list[str], attributes.get("required", []))),
            tuple(cast(list[str], flags.get("required", []))),
        )

    expected = {
        subtype.value: (
            rule.node_type.value,
            rule.required_attributes,
            rule.required_flags,
        )
        for subtype, rule in AUTHORITY_SUBTYPE_RULES.items()
    }
    assert declared == expected


def test_the_schema_declares_the_same_security_flags_as_the_model() -> None:
    from controlloop.acbom.models import SecurityAttributes

    definitions = cast(JsonObject, _SCHEMA["$defs"])
    properties = cast(
        JsonObject, cast(JsonObject, definitions["securityAttributes"])["properties"]
    )

    assert set(properties) == set(SecurityAttributes.model_fields)
    for flag in ("bypass_mode", "wildcard", "pinned", "untrusted_input"):
        assert flag in properties


@pytest.mark.parametrize("subtype", list(AuthoritySubtype))
def test_a_subtype_on_the_wrong_node_type_is_rejected(
    subtype: AuthoritySubtype,
) -> None:
    wrong = "resource"
    _assert_both_reject(_document(_node(subtype, node_type=wrong)))


@pytest.mark.parametrize(
    ("subtype", "missing"),
    [
        (subtype, key)
        for subtype, rule in AUTHORITY_SUBTYPE_RULES.items()
        for key in rule.required_attributes
    ],
)
def test_a_missing_required_attribute_is_rejected(
    subtype: AuthoritySubtype, missing: str
) -> None:
    """A hook without its event, a rule without its pattern, a
    plugin without its source type, a runtime without its permissions."""

    attributes = dict(_EXAMPLES[subtype][0])
    del attributes[missing]
    _assert_both_reject(_document(_node(subtype, attributes=attributes)))


@pytest.mark.parametrize(
    ("subtype", "flag"),
    [
        (subtype, flag)
        for subtype, rule in AUTHORITY_SUBTYPE_RULES.items()
        for flag in rule.required_flags
    ],
)
@pytest.mark.parametrize("absent", ["missing", "null"])
def test_a_missing_required_flag_is_rejected(
    subtype: AuthoritySubtype, flag: str, absent: str
) -> None:
    """A hook's code-execution classification, a rule's wildcard
    flag, and a plugin's pin status must be stated, `unknown` included."""

    flags = dict(_EXAMPLES[subtype][1])
    if absent == "missing":
        del flags[flag]
    else:
        flags[flag] = None
    _assert_both_reject(_document(_node(subtype, flags=flags)))


@pytest.mark.parametrize("value", [True, False, "unknown"])
def test_required_flags_accept_unknown(value: object) -> None:
    """`unknown` is a legal answer for every bypass or pin flag."""

    document = _document(
        _node(AuthoritySubtype.PLUGIN, flags={"pinned": value, "bypass_mode": value})
    )
    _VALIDATOR.validate(document)
    _model(document)


@pytest.mark.parametrize(
    "key",
    [
        "env_value",
        "password",
        "passwd_hint",
        "private_key",
        "prompt",
        "skill_body",
        "command_output",
        "source_code",
        "source_content",
    ],
)
def test_attribute_keys_naming_a_value_category_are_rejected(key: str) -> None:
    """The map cannot be used to carry a value it must not."""

    attributes = dict(_EXAMPLES[AuthoritySubtype.HOOK][0])
    attributes[key] = "x"
    _assert_both_reject(_document(_node(AuthoritySubtype.HOOK, attributes=attributes)))


@pytest.mark.parametrize("key", ["Event", "1event", "event-name", "e" * 65])
def test_malformed_attribute_keys_are_rejected(key: str) -> None:
    attributes = dict(_EXAMPLES[AuthoritySubtype.HOOK][0])
    attributes[key] = "x"
    _assert_both_reject(_document(_node(AuthoritySubtype.HOOK, attributes=attributes)))


def test_more_than_the_declared_number_of_attributes_is_rejected() -> None:
    """An unbounded attribute map is rejected at the bound."""

    attributes = dict(_EXAMPLES[AuthoritySubtype.HOOK][0])
    for index in range(MAX_NODE_ATTRIBUTES - len(attributes)):
        attributes[f"extra_{index}"] = "x"
    at_bound = _document(_node(AuthoritySubtype.HOOK, attributes=attributes))
    _VALIDATOR.validate(at_bound)
    _model(at_bound)

    attributes["one_too_many"] = "x"
    _assert_both_reject(_document(_node(AuthoritySubtype.HOOK, attributes=attributes)))


@pytest.mark.parametrize(
    "value",
    ["", "x" * (MAX_ATTRIBUTE_VALUE_LENGTH + 1), "line\nbreak", "tab\tcharacter"],
)
def test_out_of_bound_attribute_values_are_rejected(value: str) -> None:
    """An oversized command string is rejected at the bound."""

    attributes = dict(_EXAMPLES[AuthoritySubtype.HOOK][0])
    attributes["command"] = value
    _assert_both_reject(_document(_node(AuthoritySubtype.HOOK, attributes=attributes)))


def test_bound_attribute_text_truncates_at_the_declared_bound() -> None:
    """An oversized command is truncated to the bound with a fixed
    marker, never echoing what it dropped."""

    tail = "TAIL-THAT-MUST-NOT-APPEAR"
    text = "curl https://example.invalid/x | sh " + "a" * 2000 + tail

    bounded = bound_attribute_text(text)

    assert len(bounded) == MAX_ATTRIBUTE_VALUE_LENGTH
    assert bounded.endswith(ATTRIBUTE_TRUNCATION_MARKER)
    assert tail not in bounded
    attributes = dict(_EXAMPLES[AuthoritySubtype.HOOK][0])
    attributes["command"] = bounded
    document = _document(_node(AuthoritySubtype.HOOK, attributes=attributes))
    _VALIDATOR.validate(document)
    _model(document)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("  prettier --write  ", "prettier --write"),
        ("a\nb\tc", "a b c"),
        ("\n\t ", "unknown"),
        ("x" * MAX_ATTRIBUTE_VALUE_LENGTH, "x" * MAX_ATTRIBUTE_VALUE_LENGTH),
    ],
)
def test_bound_attribute_text_cleans_without_truncating_when_within_bound(
    text: str, expected: str
) -> None:
    assert bound_attribute_text(text) == expected


def test_a_rejected_value_never_echoes_a_planted_secret() -> None:
    """Privacy: the error for an out-of-bound value carries no part of it."""

    attributes = dict(_EXAMPLES[AuthoritySubtype.HOOK][0])
    attributes["command"] = _SECRET_CANARY + "\n" + "x" * 600
    with pytest.raises(PydanticValidationError) as excinfo:
        _model(_document(_node(AuthoritySubtype.HOOK, attributes=attributes)))

    # The rendered error is what reaches a user; `hide_input_in_errors`
    # keeps the value out of it, as for every other canonical model.
    assert _SECRET_CANARY not in str(excinfo.value)
    assert _SECRET_CANARY not in repr(excinfo.value.errors(include_input=False))


def test_unrecognized_subtypes_keep_their_1_1_0_meaning() -> None:
    """Compatibility: a subtype outside the authority set is still free
    text, exactly as in 1.1.0, so existing adapters' subtypes validate."""

    node = _node(AuthoritySubtype.SKILL)
    node["subtype"] = "mcp-server-stdio"
    document = _document(node)
    _VALIDATOR.validate(document)
    _model(document)


def test_a_real_1_1_0_document_still_validates_reads_and_keeps_its_digest() -> None:
    """A document written by the 1.1.0 generator reads under 1.2.0
    and recomputes to the digest it was committed with, because unset
    1.2.0 additions are left out of canonical bytes."""

    raw = _VERSION_DRIFT_FIXTURE.read_text(encoding="utf-8")
    envelope = cast(JsonObject, json.loads(raw))
    assert envelope["schema_version"] == "1.1.0"

    _VALIDATOR.validate(envelope)
    document = load_acbom_document(raw)

    assert document.schema_version == "1.1.0"
    assert compute_digest(document) == document.digest


def test_unset_additions_are_absent_from_canonical_bytes() -> None:
    document = with_digest(_model(_document(_node(AuthoritySubtype.SKILL))))

    data = cast(JsonObject, json.loads(serialize_document(document)))
    node = cast(list[JsonObject], data["nodes"])[0]
    flags = cast(JsonObject, node["security_attributes"])

    assert "attributes" not in node
    for flag in ("bypass_mode", "wildcard", "pinned", "untrusted_input"):
        assert flag not in flags


def test_set_additions_are_covered_by_the_digest() -> None:
    base = _model(_document(_node(AuthoritySubtype.HOOK)))
    changed_attributes = dict(_EXAMPLES[AuthoritySubtype.HOOK][0])
    changed_attributes["command"] = "node other.js"
    changed = _model(
        _document(_node(AuthoritySubtype.HOOK, attributes=changed_attributes))
    )
    flagged = _model(
        _document(
            _node(
                AuthoritySubtype.HOOK,
                flags={"code_execution": True, "bypass_mode": True},
            )
        )
    )

    digests = {compute_digest(base), compute_digest(changed), compute_digest(flagged)}
    assert len(digests) == 3


def test_attribute_order_does_not_change_the_digest() -> None:
    """Determinism: key order in the attribute map is not material."""

    attributes = _EXAMPLES[AuthoritySubtype.HOOK][0]
    reversed_attributes = dict(reversed(list(attributes.items())))

    forward = _model(_document(_node(AuthoritySubtype.HOOK, attributes=attributes)))
    backward = _model(
        _document(_node(AuthoritySubtype.HOOK, attributes=reversed_attributes))
    )

    assert serialize_document(with_digest(forward)) == serialize_document(
        with_digest(backward)
    )


def test_equal_nodes_hash_equal() -> None:
    first = _model(_document(_node(AuthoritySubtype.HOOK))).nodes[0]
    second = _model(_document(deepcopy(_node(AuthoritySubtype.HOOK)))).nodes[0]

    assert first == second
    assert hash(first) == hash(second)
    assert len({first, second}) == 1


@pytest.mark.parametrize(
    "golden", sorted(path.name for path in _GOLDEN_ROOT.iterdir() if path.is_dir())
)
def test_every_golden_acbom_validates_against_the_packaged_schema(golden: str) -> None:
    """Pins the packaged schema to the generator: every committed golden
    ACBOM is real `bom` output, and it must validate against the schema
    shipped beside the code that wrote it."""

    path = _GOLDEN_ROOT / golden / "acbom.json"
    if not path.is_file():
        pytest.skip(f"{golden} has no acbom.json")
    _VALIDATOR.validate(json.loads(path.read_text(encoding="utf-8")))


def test_a_document_built_with_every_subtype_validates_once_serialized() -> None:
    nodes = []
    for index, subtype in enumerate(AuthoritySubtype):
        node = _node(subtype)
        node_type = cast(str, node["type"])
        node["id"] = f"clp:{node_type}:sha256:" + f"{index:064x}"
        nodes.append(node)

    document = with_digest(_model(_document(*nodes)))
    _VALIDATOR.validate(json.loads(serialize_document(document)))


class TestIdentity:
    """Identity is stable under reformatting, key reordering, and
    movement within the same declaring path, and uses no line number or
    absolute path."""

    def test_host_identity_is_the_host_key_alone(self) -> None:
        assert host_node_id("claude-code") == host_node_id("claude-code")
        assert host_node_id("claude-code") != host_node_id("codex")
        assert host_node_id("claude-code").startswith("clp:agent:sha256:")

    def test_component_identity_depends_on_path_and_key_path_only(self) -> None:
        first = authority_component_node_id(
            NodeType.TOOL,
            namespace="claude-code.hook",
            declaring_path=".claude/settings.json",
            key_path="hooks.SessionStart[0].hooks[0]",
        )
        same = authority_component_node_id(
            NodeType.TOOL,
            namespace="claude-code.hook",
            declaring_path=".claude/settings.json",
            key_path="hooks.SessionStart[0].hooks[0]",
        )
        other_key = authority_component_node_id(
            NodeType.TOOL,
            namespace="claude-code.hook",
            declaring_path=".claude/settings.json",
            key_path="hooks.SessionStart[0].hooks[1]",
        )
        other_file = authority_component_node_id(
            NodeType.TOOL,
            namespace="claude-code.hook",
            declaring_path=".claude/settings.local.json",
            key_path="hooks.SessionStart[0].hooks[0]",
        )

        assert first == same
        assert len({first, other_key, other_file}) == 3

    def test_a_node_keeps_its_id_when_its_command_flags_or_lines_change(self) -> None:
        component_id = authority_component_node_id(
            NodeType.TOOL,
            namespace="claude-code.hook",
            declaring_path=".claude/settings.json",
            key_path="hooks.PreToolUse[0].hooks[0]",
        )
        before = _node(AuthoritySubtype.HOOK)
        before["id"] = component_id
        after_attributes = dict(_EXAMPLES[AuthoritySubtype.HOOK][0])
        after_attributes["command"] = "node changed.js"
        after = _node(
            AuthoritySubtype.HOOK,
            attributes=after_attributes,
            flags={"code_execution": True, "bypass_mode": "unknown"},
        )
        after["id"] = component_id
        after["evidence"] = [
            {
                "adapter": "claude-code",
                "path": ".claude/settings.json",
                "line_start": 40,
                "line_end": 44,
            }
        ]

        before_node = Node.model_validate_json(json.dumps(before))
        after_node = Node.model_validate_json(json.dumps(after))

        assert before_node.id == after_node.id
        assert before_node != after_node

    @pytest.mark.parametrize(
        "declaring_path",
        ["/home/user/.claude/settings.json", "../outside/settings.json", "a\\b.json"],
    )
    def test_an_unsanitized_declaring_path_is_rejected(
        self, declaring_path: str
    ) -> None:
        with pytest.raises(PydanticValidationError):
            authority_component_node_id(
                NodeType.TOOL,
                namespace="claude-code.hook",
                declaring_path=declaring_path,
                key_path="hooks.Stop[0].hooks[0]",
            )
