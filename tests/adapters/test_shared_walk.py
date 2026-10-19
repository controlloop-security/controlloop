"""One repository walk per scan, shared by every adapter.

Each adapter's candidate-path helper used to call
`walk_repository(context.root)` itself, so a scan with 15 registered
adapters walked the repository 20 times (some adapters walk in both
`detect` and `discover`), on top of `build_acbom_document`'s own walk.
Each walk is ~70 ms of `pathlib` on the 100,000-line benchmark
repository, about 0.93 s of a 2.05 s scan.

These tests pin the replacement: `ScanContext.repository_files()` walks
at most once per context, `build_acbom_document` seeds it from its own
walk when that walk used the default bounds adapters have always seen,
and no adapter module may call the walker directly again.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

import controlloop.adapters as adapters_package
import controlloop.adapters.framework as framework_module
import controlloop.bom as bom_module
from controlloop import repository
from controlloop.acbom import Diagnostic
from controlloop.adapters import ALL_ADAPTERS, ScanContext, run_adapters
from controlloop.adapters.framework import RepositoryFile
from controlloop.repository import (
    RepositoryRootError,
    TraversalBounds,
    resolve_repository_root,
)

_ADAPTERS_DIRECTORY = Path(adapters_package.__file__).parent


def _write(root: Path, relative_path: str, content: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def agent_repository(tmp_path: Path) -> Path:
    """A small repository that several adapters claim, so `discover`
    runs (and used to walk again) for more than one of them."""

    _write(
        tmp_path,
        ".mcp.json",
        json.dumps({"mcpServers": {"files": {"command": "npx", "args": ["fs"]}}}),
    )
    _write(
        tmp_path,
        "openapi.json",
        json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "orders", "version": "1"},
                "paths": {"/orders": {"get": {"operationId": "listOrders"}}},
            }
        ),
    )
    _write(
        tmp_path,
        ".claude/settings.json",
        json.dumps({"permissions": {"allow": ["Bash(git status)"]}}),
    )
    _write(tmp_path, ".codex/config.toml", 'model = "o4-mini"\n')
    _write(tmp_path, "src/app.py", "print('hello')\n")
    return tmp_path


def _count_walks(monkeypatch: pytest.MonkeyPatch, *modules: object) -> list[object]:
    """Wrap the real walker wherever `modules` reference it by name and
    record one entry per walk started."""

    calls: list[object] = []
    real = repository.walk_repository

    def counting(*args: object, **kwargs: object) -> Iterator[Path | Diagnostic]:
        calls.append(kwargs.get("bounds"))
        return real(*args, **kwargs)  # type: ignore[arg-type]

    for module in modules:
        monkeypatch.setattr(module, "walk_repository", counting)
    return calls


class TestOneWalkPerContext:
    def test_a_full_adapter_pass_walks_once(
        self, agent_repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every registered adapter, one walk."""

        walks = _count_walks(monkeypatch, framework_module)
        context = ScanContext(root=resolve_repository_root(agent_repository))

        result = run_adapters([cls() for cls in ALL_ADAPTERS], context)

        assert len(walks) == 1
        # The adapters really ran their discovery, not only detection:
        # the MCP, OpenAPI, Claude Code, and Codex adapters each found
        # something from the one shared walk.
        subtypes = {node.subtype for node in result.nodes}
        expected = {"mcp-server-stdio", "openapi-operation", "permission-rule", "host"}
        assert expected <= subtypes, subtypes

    def test_repeated_calls_replay_one_immutable_tuple(
        self, agent_repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        walks = _count_walks(monkeypatch, framework_module)
        context = ScanContext(root=resolve_repository_root(agent_repository))

        first = context.repository_files()
        second = context.repository_files()

        assert first is second
        assert isinstance(first, tuple)
        assert len(walks) == 1

    def test_files_match_what_each_adapter_used_to_compute(
        self, agent_repository: Path
    ) -> None:
        """The same paths, in the same order, with the same
        repository-relative form every adapter derived on its own."""

        root = resolve_repository_root(agent_repository)
        expected = [
            RepositoryFile(item, item.relative_to(root.path).as_posix())
            for item in repository.walk_repository(root)
            if isinstance(item, Path)
        ]

        assert list(ScanContext(root=root).repository_files()) == expected
        assert ".codex/config.toml" in {file.relative for file in expected}

    def test_a_seeded_context_never_walks(
        self, agent_repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A caller's default-bounds walk is reused as is."""

        root = resolve_repository_root(agent_repository)
        walked = tuple(
            item for item in repository.walk_repository(root) if isinstance(item, Path)
        )
        walks = _count_walks(monkeypatch, framework_module)

        context = ScanContext(root=root, walked_files=walked)
        files = context.repository_files()

        assert walks == []
        assert tuple(file.path for file in files) == walked

    def test_seeding_does_not_change_equality(self, agent_repository: Path) -> None:
        root = resolve_repository_root(agent_repository)

        assert ScanContext(root=root) == ScanContext(root=root, walked_files=())

    def test_a_failed_walk_is_not_cached(
        self, agent_repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A walk that raises leaves the cache empty, so the next adapter
        walks again -- the per-adapter failure isolation `run_adapters`
        always had."""

        real = repository.walk_repository
        attempts: list[int] = []

        def fails_once(*args: object, **kwargs: object) -> Iterator[Path | Diagnostic]:
            attempts.append(1)
            if len(attempts) == 1:
                raise RepositoryRootError("simulated unlistable root")
            return real(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(framework_module, "walk_repository", fails_once)
        context = ScanContext(root=resolve_repository_root(agent_repository))

        with pytest.raises(RepositoryRootError):
            context.repository_files()
        assert context.repository_files()
        assert len(attempts) == 2


class TestBuildAcbomDocumentWalksOnce:
    def test_default_bounds_walk_once_in_total(
        self, agent_repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`bom`'s own walk is handed to the adapters."""

        walks = _count_walks(monkeypatch, bom_module, framework_module)
        root = resolve_repository_root(agent_repository)

        bom_module.build_acbom_document(root)
        assert len(walks) == 1

        walks.clear()
        bom_module.build_acbom_document(root, bounds=TraversalBounds())
        assert len(walks) == 1

    def test_non_default_bounds_keep_the_adapters_default_walk(
        self, agent_repository: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Not changed: adapters have always walked with default
        bounds, whatever `bom` was given, and still do."""

        walks = _count_walks(monkeypatch, bom_module, framework_module)
        root = resolve_repository_root(agent_repository)
        custom = TraversalBounds(max_file_count=TraversalBounds().max_file_count + 1)

        bom_module.build_acbom_document(root, bounds=custom)

        assert walks == [custom, None]

    def test_seeded_and_unseeded_scans_produce_the_same_document(
        self, agent_repository: Path
    ) -> None:
        """Reusing `bom`'s walk changes nothing in the output.
        Bounds one file above the default are non-default (so unseeded)
        and still admit every file of this small repository."""

        root = resolve_repository_root(agent_repository)
        seeded = bom_module.build_acbom_document(root)
        unseeded = bom_module.build_acbom_document(
            root,
            bounds=TraversalBounds(max_file_count=TraversalBounds().max_file_count + 1),
        )

        assert seeded.digest == unseeded.digest
        assert seeded.nodes


def _walker_references(source: str) -> list[str]:
    """Names under which a module imports or calls `walk_repository`."""

    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "walk_repository" for alias in node.names
        ):
            found.append(f"imports it from {node.module}")
        elif isinstance(node, ast.Attribute) and node.attr == "walk_repository":
            found.append("references it as an attribute")
    return found


def test_no_adapter_walks_the_repository_itself() -> None:
    """A new adapter must read `context.repository_files()`. Calling the
    walker directly would quietly bring back one walk per adapter, which
    nothing else would notice until the benchmark drifted again."""

    offenders = {
        path.name: references
        for path in sorted(_ADAPTERS_DIRECTORY.glob("*.py"))
        if path.name != "framework.py"
        and (references := _walker_references(path.read_text(encoding="utf-8")))
    }

    assert offenders == {}, offenders


def test_the_guard_detects_a_direct_walk() -> None:
    """The guard above is only worth having if it fires."""

    source = (
        "from controlloop.repository import walk_repository\n"
        "import controlloop.repository as repo\n"
        "def _claimed(context):\n"
        "    return list(repo.walk_repository(context.root))\n"
    )

    assert _walker_references(source) == [
        "imports it from controlloop.repository",
        "references it as an attribute",
    ]
