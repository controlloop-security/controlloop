"""Environment components in the Team envelope and the local Team judge.

The devcontainer, pre-commit, and editor startup adapters record what
they install as `plugin` nodes with a `source_type`. The envelope sends
them as `plugin` with that `source_type` and the attributes the
adapters recorded; the platform files the first three kinds under
`editor_extension`, `devcontainer_feature`, and `pre_commit_hook`, and
the gate judges them under the same types so an organization approval
matches locally as it does on the platform.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from factories import make_node

from controlloop.acbom import Node
from controlloop.bom import build_acbom_document
from controlloop.diff.compute import compute_diff
from controlloop.findings.models import FindingChangeState
from controlloop.policy.models import RuleContext, SanctionContext
from controlloop.policy.rules import unsanctioned_agent_component_findings
from controlloop.reporting.authority import compute_authority_delta
from controlloop.repository import resolve_repository_root
from controlloop.team.components import (
    ENVIRONMENT_COMPONENT_TYPES,
    component_for,
    judged_component,
)
from controlloop.team.sanction import ApprovedEntry, SanctionState, judge

_SHA = "2c9f875913ee60ca25ce70243dc24d5b6415598c"
_DIGEST = "sha256:" + "a" * 64


def _write(root: Path, relative_path: str, content: object) -> None:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content if isinstance(content, str) else json.dumps(content))


def _nodes(root: Path) -> dict[str, Node]:
    document = build_acbom_document(resolve_repository_root(root))
    return {node.name: node for node in document.nodes}


def _environment(root: Path) -> None:
    _write(
        root,
        ".devcontainer/devcontainer.json",
        {
            "customizations": {"vscode": {"extensions": ["ms-python.python@2024.2.1"]}},
            "features": {
                f"ghcr.io/devcontainers/features/node@{_DIGEST}": {},
                "ghcr.io/devcontainers/features/go:1": {},
            },
            "postCreateCommand": "npm ci",
        },
    )
    _write(root, ".vscode/extensions.json", {"recommendations": ["acme.tool"]})
    _write(
        root,
        ".pre-commit-config.yaml",
        "repos:\n"
        "  - repo: https://github.com/psf/black\n"
        "    rev: v24.2.0\n"
        "    hooks:\n"
        "      - id: black\n"
        '        additional_dependencies: ["click==8.1.7"]\n'
        "  - repo: https://github.com/acme/hooks\n"
        f"    rev: {_SHA}\n"
        "    hooks:\n"
        "      - id: check\n",
    )
    _write(
        root,
        ".idea/externalDependencies.xml",
        '<project version="4"><component name="ExternalDependencies">'
        '<plugin id="org.jetbrains.kotlin" min-version="2.0.0" max-version="2.0.0" />'
        '<plugin id="com.intellij" min-version="262.8665.258" />'
        "</component></project>",
    )
    _write(root, ".nvim.lua", "vim.opt.tabstop = 4\n")


@pytest.fixture
def nodes(tmp_path: Path) -> dict[str, Node]:
    _environment(tmp_path)
    return _nodes(tmp_path)


def _component(nodes: dict[str, Node], name: str) -> tuple[str, str, dict[str, str]]:
    component = component_for(nodes[name])
    assert component is not None
    return component.type, component.name, dict(component.attributes)


class TestEnvelopeAttributes:
    def test_an_extension_is_a_plugin_named_by_its_id(
        self, nodes: dict[str, Node]
    ) -> None:
        assert _component(nodes, "editor extension ms-python.python") == (
            "plugin",
            "ms-python.python",
            {
                "source_type": "editor-extension",
                "extension_id": "ms-python.python",
                "ref": "2024.2.1",
                "package": "ms-python.python",
                "version": "2024.2.1",
            },
        )

    def test_a_feature_pinned_by_digest_sends_the_digest(
        self, nodes: dict[str, Node]
    ) -> None:
        component_type, name, attributes = _component(
            nodes, "devcontainer feature ghcr.io/devcontainers/features/node"
        )

        assert (component_type, name) == (
            "plugin",
            "ghcr.io/devcontainers/features/node",
        )
        assert attributes["digest"] == _DIGEST
        assert attributes["package"] == "ghcr.io/devcontainers/features/node"
        assert attributes["origin"] == "registry"
        assert attributes["registry"] == "ghcr.io"
        assert "version" not in attributes

    def test_a_floating_tag_sends_no_version(self, nodes: dict[str, Node]) -> None:
        _, _, attributes = _component(
            nodes, "devcontainer feature ghcr.io/devcontainers/features/go"
        )

        assert attributes["ref"] == "1"
        assert "version" not in attributes
        assert "digest" not in attributes

    def test_a_v_prefixed_rev_sends_a_bare_version(
        self, nodes: dict[str, Node]
    ) -> None:
        _, name, attributes = _component(
            nodes, "pre-commit hook repository github.com/psf/black"
        )

        assert name == "github.com/psf/black"
        assert attributes["ref"] == "v24.2.0"
        assert attributes["version"] == "24.2.0"
        assert attributes["hook_ids"] == "black"

    def test_a_sha_rev_is_neither_a_version_nor_a_digest(
        self, nodes: dict[str, Node]
    ) -> None:
        _, _, attributes = _component(
            nodes, "pre-commit hook repository github.com/acme/hooks"
        )

        assert attributes["ref"] == _SHA
        assert "version" not in attributes
        assert "digest" not in attributes

    def test_a_jetbrains_plugin_sends_its_bounds(self, nodes: dict[str, Node]) -> None:
        _, name, exact = _component(nodes, "editor plugin org.jetbrains.kotlin")
        _, _, ranged = _component(nodes, "editor plugin com.intellij")

        assert name == "org.jetbrains.kotlin"
        assert exact["version"] == "2.0.0"
        assert (exact["min_version"], exact["max_version"]) == ("2.0.0", "2.0.0")
        assert ranged["min_version"] == "262.8665.258"
        assert "version" not in ranged

    def test_a_recommendation_says_so(self, nodes: dict[str, Node]) -> None:
        _, _, attributes = _component(nodes, "editor extension acme.tool")

        assert attributes["recommended_only"] == "true"
        assert attributes["package"] == "acme.tool"

    def test_a_dependency_stays_a_plain_plugin(self, nodes: dict[str, Node]) -> None:
        name = "pre-commit dependency click for hook black"

        assert _component(nodes, name) == (
            "plugin",
            name,
            {
                "source_type": "pre-commit-dependency",
                "dependency": "click",
                "ref": "click==8.1.7",
            },
        )

    def test_a_helper_command_sends_its_event(self, nodes: dict[str, Node]) -> None:
        assert _component(nodes, "postCreateCommand command")[2] == {
            "command": "npm ci",
            "event": "postCreateCommand",
        }
        assert _component(nodes, ".nvim.lua command")[2] == {
            "command": ".nvim.lua",
            "event": "project-open",
        }

    def test_a_claude_code_plugin_is_unchanged(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            ".claude/settings.json",
            {"enabledPlugins": {"formatter@team": True}},
        )

        node = _nodes(tmp_path)["plugin formatter@team"]
        component = component_for(node)

        assert component is not None
        assert (component.type, component.name, dict(component.attributes)) == (
            "plugin",
            "formatter@team",
            {},
        )
        assert judged_component(node) == component


class TestJudgedType:
    @pytest.mark.parametrize(
        ("name", "judged_type"),
        [
            ("editor extension ms-python.python", "editor_extension"),
            ("editor extension acme.tool", "editor_extension"),
            ("editor plugin org.jetbrains.kotlin", "editor_extension"),
            (
                "devcontainer feature ghcr.io/devcontainers/features/node",
                "devcontainer_feature",
            ),
            ("pre-commit hook repository github.com/psf/black", "pre_commit_hook"),
            ("pre-commit dependency click for hook black", "plugin"),
        ],
    )
    def test_the_judge_uses_the_platform_type(
        self, nodes: dict[str, Node], name: str, judged_type: str
    ) -> None:
        component = judged_component(nodes[name])

        assert component is not None
        assert component.type == judged_type
        assert component_for(nodes[name]) == replace(component, type="plugin")

    def test_the_mapping_names_the_platform_types(self) -> None:
        assert ENVIRONMENT_COMPONENT_TYPES == {
            "editor-extension": "editor_extension",
            "devcontainer-feature": "devcontainer_feature",
            "pre-commit-hook": "pre_commit_hook",
        }

    def test_an_editor_extension_approval_with_a_version_range_matches(
        self, nodes: dict[str, Node]
    ) -> None:
        component = judged_component(nodes["editor extension ms-python.python"])
        assert component is not None

        approved = [
            ApprovedEntry(
                type="editor_extension",
                name_pattern="ms-python.*",
                package="ms-python.python",
                version_range=">=2024.0.0 <2025.0.0",
                pin_required=True,
            )
        ]

        assert judge(component, approved).state is SanctionState.SANCTIONED

    def test_a_plugin_approval_does_not_cover_an_editor_extension(
        self, nodes: dict[str, Node]
    ) -> None:
        component = judged_component(nodes["editor extension ms-python.python"])
        assert component is not None

        judgment = judge(component, [ApprovedEntry(type="plugin", name_pattern="*")])

        assert judgment.state is SanctionState.UNSANCTIONED
        assert judgment.failed == "name"


class TestUnsanctionedRule:
    """The rule judges through `judge_delta`, so an organization approval
    of type `editor_extension` clears it with no change to the rule."""

    def _context(self, tmp_path: Path, approved: list[ApprovedEntry]) -> RuleContext:
        base, head = tmp_path / "base", tmp_path / "head"
        base.mkdir()
        head.mkdir()
        _write(
            head,
            ".devcontainer/devcontainer.json",
            {
                "customizations": {
                    "vscode": {"extensions": ["ms-python.python@2024.2.1"]}
                }
            },
        )
        current = build_acbom_document(resolve_repository_root(head))
        baseline = build_acbom_document(resolve_repository_root(base))
        diff = compute_diff(
            baseline_nodes=baseline.nodes,
            baseline_edges=baseline.edges,
            current_nodes=current.nodes,
            current_edges=current.edges,
        )
        return RuleContext(
            acbom=current,
            policy_version="test",
            diff=diff,
            sanction=SanctionContext(
                approved=tuple(approved),
                organization_bundle_version="7",
                delta=compute_authority_delta(current, diff),
            ),
        )

    def test_an_approved_extension_is_not_reported(self, tmp_path: Path) -> None:
        context = self._context(
            tmp_path,
            [
                ApprovedEntry(type="host", name_pattern="Dev Containers"),
                ApprovedEntry(
                    type="editor_extension",
                    name_pattern="ms-python.python",
                    version_range=">=2024.0.0 <2025.0.0",
                ),
            ],
        )

        assert unsanctioned_agent_component_findings(context) == ()

    def test_an_unapproved_extension_is_reported_under_its_platform_type(
        self, tmp_path: Path
    ) -> None:
        context = self._context(
            tmp_path, [ApprovedEntry(type="host", name_pattern="Dev Containers")]
        )

        (finding,) = unsanctioned_agent_component_findings(context)

        assert finding.change_state is FindingChangeState.ADDED
        assert finding.message == (
            "The editor_extension `ms-python.python` is not approved by "
            "organization policy version 7: no approved entry has its type and "
            "name (constraint `name`)."
        )


def test_a_recorded_package_or_version_wins_over_a_derived_one() -> None:
    node = make_node(name="component").model_copy(
        update={
            "subtype": "plugin",
            "attributes": {
                "source_type": "editor-extension",
                "extension_id": "a.b",
                "ref": "1.0.0",
                "package": "a.b",
                "version": "9.9.9",
            },
        }
    )

    component = judged_component(node)

    assert component is not None
    assert component.type == "editor_extension"
    assert (component.attributes["package"], component.attributes["version"]) == (
        "a.b",
        "9.9.9",
    )
