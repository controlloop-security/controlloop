"""Tests for repository root resolution and read-boundary enforcement.

Covers root resolution, containment, and minimal walking; configurable
per-file-size, total-bytes, total-file-count, and depth bounds;
content-based binary/archive classification; the `walk_repository`-level
integration for ignore-file precedence (unit-level precedence coverage
lives in `test_ignore.py`); symlink loop termination/reporting and
dedicated device/socket/FIFO classification (several symlink cases were
already covered by the existing containment mechanisms, verified by
investigation rather than assumed); the diagnostic registry and
deterministic skip summary; and hostile filenames and encodings, which
cannot crash the scanner (two of those cases were each a real, previously
undiscovered crash bug, found by investigation before any fix was
written).
"""

from __future__ import annotations

import gzip
import os
import socket
import stat as stat_module
import sys
import time
from pathlib import Path
from typing import Any, ClassVar

import pytest

import controlloop.repository as repository_module
from controlloop.acbom import Diagnostic, DiagnosticSeverity
from controlloop.repository import (
    DIAGNOSTIC_REGISTRY,
    ContainmentError,
    RepositoryRootError,
    TraversalBounds,
    _case_collision_diagnostics,
    _special_file_kind,
    assert_within_root,
    resolve_repository_root,
    summarize_skips,
    walk_repository,
)

# Captured at collection time, before the offline harness's autouse
# fixture (conftest.py) patches socket.socket for the duration of each
# test. A bound AF_UNIX socket is local filesystem IPC, not network
# access, but the harness's denial is a blanket one on the constructor
# itself; this reference lets a test create one as a fixture without
# weakening or bypassing what the harness protects for actual scan code.
_real_socket_class = socket.socket

_running_as_root = hasattr(os, "geteuid") and os.geteuid() == 0
_posix_permission_checks = pytest.mark.skipif(
    _running_as_root, reason="permission checks are bypassed when running as root"
)


def _touch(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


class TestResolveRepositoryRoot:
    def test_explicit_path_wins_even_inside_a_git_repo(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        nested = tmp_path / "nested"
        nested.mkdir()
        explicit = tmp_path / "elsewhere"
        explicit.mkdir()

        result = resolve_repository_root(explicit, start=nested)

        assert result.path == explicit.resolve()

    def test_falls_back_to_enclosing_git_root(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)

        result = resolve_repository_root(start=nested)

        assert result.path == tmp_path.resolve()

    def test_falls_back_to_start_when_no_git_ancestor(self, tmp_path: Path) -> None:
        isolated = tmp_path / "isolated"
        isolated.mkdir()

        result = resolve_repository_root(start=isolated)

        assert result.path == isolated.resolve()

    def test_nonexistent_path_raises_exit_code_2(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"

        with pytest.raises(RepositoryRootError) as error:
            resolve_repository_root(missing)

        assert error.value.exit_code == 2

    def test_file_path_raises_exit_code_2(self, tmp_path: Path) -> None:
        file_path = tmp_path / "file.txt"
        file_path.write_text("not a directory")

        with pytest.raises(RepositoryRootError) as error:
            resolve_repository_root(file_path)

        assert error.value.exit_code == 2

    @_posix_permission_checks
    def test_unreadable_directory_raises_exit_code_2(self, tmp_path: Path) -> None:
        unreadable = tmp_path / "unreadable"
        unreadable.mkdir()
        unreadable.chmod(0o000)
        try:
            with pytest.raises(RepositoryRootError) as error:
                resolve_repository_root(unreadable)
            assert error.value.exit_code == 2
        finally:
            unreadable.chmod(0o755)


class TestAssertWithinRoot:
    def test_path_inside_root_returns_canonical_form(self, tmp_path: Path) -> None:
        file_path = tmp_path / "sub" / "file.txt"
        _touch(file_path)
        root = resolve_repository_root(tmp_path)

        result = assert_within_root(root, file_path)

        assert result == file_path.resolve()

    def test_relative_escape_raises(self, tmp_path: Path) -> None:
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        root = resolve_repository_root(root_dir)

        with pytest.raises(ContainmentError):
            assert_within_root(root, root_dir / ".." / "outside.txt")

    def test_symlink_escape_raises(self, tmp_path: Path) -> None:
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        link = root_dir / "escape"
        link.symlink_to(outside)
        root = resolve_repository_root(root_dir)

        with pytest.raises(ContainmentError):
            assert_within_root(root, link)


class TestWalkRepository:
    def test_yields_every_file_sorted(self, tmp_path: Path) -> None:
        _touch(tmp_path / "b.txt")
        _touch(tmp_path / "a.txt")
        _touch(tmp_path / "sub" / "c.txt")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        assert results == [
            (tmp_path / "a.txt").resolve(),
            (tmp_path / "b.txt").resolve(),
            (tmp_path / "sub" / "c.txt").resolve(),
        ]

    def test_deterministic_regardless_of_creation_order(self, tmp_path: Path) -> None:
        first, second = tmp_path / "first", tmp_path / "second"
        for name in ("zeta.txt", "alpha.txt", "mid/file.txt"):
            _touch(first / name)
        for name in ("alpha.txt", "mid/file.txt", "zeta.txt"):
            _touch(second / name)

        first_root = resolve_repository_root(first)
        second_root = resolve_repository_root(second)

        first_relative = [
            path.relative_to(first_root.path)
            for path in walk_repository(first_root)
            if isinstance(path, Path)
        ]
        second_relative = [
            path.relative_to(second_root.path)
            for path in walk_repository(second_root)
            if isinstance(path, Path)
        ]

        assert first_relative == second_relative

    def test_symlink_outside_root_yields_boundary_diagnostic(
        self, tmp_path: Path
    ) -> None:
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret-canary-value")
        (root_dir / "escape").symlink_to(outside)
        root = resolve_repository_root(root_dir)

        results = list(walk_repository(root))

        assert len(results) == 1
        diagnostic = results[0]
        assert isinstance(diagnostic, Diagnostic)
        assert diagnostic.code == "DISC-BOUNDARY-ESCAPE"
        assert diagnostic.evidence[0].path == "escape"
        assert "secret-canary-value" not in diagnostic.message
        assert str(outside) not in diagnostic.message

    def test_same_root_symlink_cycle_is_skipped_not_followed_forever(
        self, tmp_path: Path
    ) -> None:
        root_dir = tmp_path / "root"
        (root_dir / "child").mkdir(parents=True)
        (root_dir / "child" / "loop").symlink_to(root_dir, target_is_directory=True)
        root = resolve_repository_root(root_dir)

        results = list(walk_repository(root))

        assert any(
            isinstance(item, Diagnostic) and item.code == "DISC-POSSIBLE-CYCLE"
            for item in results
        )

    @_posix_permission_checks
    def test_unreadable_subdirectory_yields_diagnostic_and_continues(
        self, tmp_path: Path
    ) -> None:
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        _touch(root_dir / "visible.txt")
        blocked = root_dir / "blocked"
        blocked.mkdir()
        (blocked / "hidden.txt").write_text("secret")
        blocked.chmod(0o000)

        try:
            results = list(walk_repository(resolve_repository_root(root_dir)))
        finally:
            blocked.chmod(0o755)

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert (root_dir / "visible.txt").resolve() in paths
        assert any(d.code == "DISC-UNREADABLE-ENTRY" for d in diagnostics)

    @_posix_permission_checks
    def test_root_unreadable_at_walk_time_raises_root_error(
        self, tmp_path: Path
    ) -> None:
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        root = resolve_repository_root(root_dir)
        root_dir.chmod(0o000)

        try:
            with pytest.raises(RepositoryRootError):
                list(walk_repository(root))
        finally:
            root_dir.chmod(0o755)


class TestOfflineEvidence:
    """Direct offline evidence for root resolution and walking, alongside
    the suite-wide offline-denial harness."""

    def test_root_resolution_and_walk_never_touch_the_network(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _touch(tmp_path / "a.txt")
        _touch(tmp_path / "sub" / "b.txt")

        def _deny(*args: object, **kwargs: object) -> None:
            raise AssertionError("unexpected network access during a core scan path")

        monkeypatch.setattr(socket, "socket", _deny)
        monkeypatch.setattr(socket, "create_connection", _deny)

        root = resolve_repository_root(tmp_path)
        results = list(walk_repository(root))

        assert len(results) == 2


class TestTraversalBounds:
    def test_rejects_a_bound_below_one(self) -> None:
        with pytest.raises(ValueError, match="max_depth"):
            TraversalBounds(max_depth=0)

    def test_defaults_are_positive(self) -> None:
        bounds = TraversalBounds()

        assert bounds.max_file_size_bytes > 0
        assert bounds.max_total_bytes > 0
        assert bounds.max_file_count > 0
        assert bounds.max_depth > 0


class TestFileSizeBound:
    def test_oversized_file_is_skipped_sibling_still_yielded(
        self, tmp_path: Path
    ) -> None:
        _touch(tmp_path / "small.txt", "ok")
        (tmp_path / "large.txt").write_bytes(b"x" * 1000)
        root = resolve_repository_root(tmp_path)

        results = list(
            walk_repository(root, bounds=TraversalBounds(max_file_size_bytes=100))
        )

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert (tmp_path / "small.txt").resolve() in paths
        assert (tmp_path / "large.txt").resolve() not in paths
        assert len(diagnostics) == 1
        assert diagnostics[0].code == "DISC-FILE-TOO-LARGE"
        assert diagnostics[0].incomplete is True
        assert diagnostics[0].evidence[0].path == "large.txt"


class TestFileCountBound:
    def test_stops_after_the_configured_count(self, tmp_path: Path) -> None:
        _touch(tmp_path / "a.txt")
        _touch(tmp_path / "b.txt")
        _touch(tmp_path / "c.txt")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root, bounds=TraversalBounds(max_file_count=2)))

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert paths == [
            (tmp_path / "a.txt").resolve(),
            (tmp_path / "b.txt").resolve(),
        ]
        assert len(diagnostics) == 1
        assert diagnostics[0].code == "DISC-FILE-COUNT-EXCEEDED"
        assert diagnostics[0].incomplete is True


class TestTotalBytesBound:
    def test_stops_before_exceeding_the_configured_total(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_bytes(b"x" * 60)
        (tmp_path / "b.txt").write_bytes(b"x" * 60)
        root = resolve_repository_root(tmp_path)

        results = list(
            walk_repository(root, bounds=TraversalBounds(max_total_bytes=100))
        )

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert paths == [(tmp_path / "a.txt").resolve()]
        assert len(diagnostics) == 1
        assert diagnostics[0].code == "DISC-TOTAL-BYTES-EXCEEDED"
        assert diagnostics[0].incomplete is True


class TestDepthBound:
    def test_deep_subtree_is_skipped_shallow_sibling_still_yielded(
        self, tmp_path: Path
    ) -> None:
        _touch(tmp_path / "shallow.txt")
        deep = tmp_path
        for level in range(5):
            deep = deep / f"level{level}"
        _touch(deep / "buried.txt")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root, bounds=TraversalBounds(max_depth=2)))

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert (tmp_path / "shallow.txt").resolve() in paths
        assert not any("buried.txt" in str(item) for item in paths)
        assert any(d.code == "DISC-DEPTH-EXCEEDED" for d in diagnostics)
        assert all(d.incomplete for d in diagnostics)

    def test_pathological_depth_completes_without_recursion_error(
        self, tmp_path: Path
    ) -> None:
        """A pathologically deep tree completes within the bound.

        Python's own recursion limit is deliberately crushed far below the
        fixture's depth here. A recursive walker would raise
        `RecursionError` long before reaching this test's configured
        `max_depth`; the iterative implementation must not, because it
        never uses the Python call stack for traversal depth at all.
        """

        deep = tmp_path
        for level in range(80):
            deep = deep / f"d{level}"
        deep.mkdir(parents=True)
        (deep / "buried.txt").write_text("x")
        root = resolve_repository_root(tmp_path)

        original_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(50)
        try:
            results = list(walk_repository(root, bounds=TraversalBounds(max_depth=200)))
        finally:
            sys.setrecursionlimit(original_limit)

        paths = [item for item in results if isinstance(item, Path)]
        assert (deep / "buried.txt").resolve() in paths


class TestBoundsAreDeterministic:
    def test_same_fixture_and_bounds_produce_identical_stop_point(
        self, tmp_path: Path
    ) -> None:
        for name in ("a.txt", "b.txt", "c.txt", "d.txt"):
            _touch(tmp_path / name)
        root = resolve_repository_root(tmp_path)
        bounds = TraversalBounds(max_file_count=2)

        def _summarize(results: list[Path | Diagnostic]) -> list[tuple[str, str]]:
            return [
                (
                    type(item).__name__,
                    str(item) if isinstance(item, Path) else item.code,
                )
                for item in results
            ]

        first = _summarize(list(walk_repository(root, bounds=bounds)))
        second = _summarize(list(walk_repository(root, bounds=bounds)))

        assert first == second


class TestBinaryDetection:
    def test_binary_file_is_skipped_with_informational_diagnostic(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "binary.dat").write_bytes(b"\x00\x01\x02\x03not text")
        _touch(tmp_path / "text.txt", "hello")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert (tmp_path / "text.txt").resolve() in paths
        assert (tmp_path / "binary.dat").resolve() not in paths
        assert len(diagnostics) == 1
        assert diagnostics[0].code == "DISC-BINARY-SKIPPED"
        assert diagnostics[0].severity == DiagnosticSeverity.INFO
        assert diagnostics[0].incomplete is False

    def test_binary_skip_does_not_count_toward_file_count_bound(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "binary.dat").write_bytes(b"\x00binary")
        _touch(tmp_path / "a.txt")
        _touch(tmp_path / "b.txt")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root, bounds=TraversalBounds(max_file_count=2)))

        paths = [item for item in results if isinstance(item, Path)]
        assert len(paths) == 2


class TestArchiveDetection:
    _SIGNATURES: ClassVar[dict[str, bytes]] = {
        "zip": b"PK\x03\x04\x14\x00\x00\x00",
        "gzip": b"\x1f\x8b\x08\x00\x00\x00\x00\x00",
        "bzip2": b"BZh91AY&SY",
        "xz": b"\xfd7zXZ\x00\x00\x00\x00\x00",
        "zstd": b"\x28\xb5\x2f\xfd\x00\x00\x00\x00",
        "7z": b"7z\xbc\xaf\x27\x1c\x00\x00\x00\x00",
        "tar": b"\x00" * 257 + b"ustar\x00" + b"\x00" * 8,
    }

    @pytest.mark.parametrize("format_name", sorted(_SIGNATURES))
    def test_each_signature_is_classified_as_an_unexamined_archive(
        self, tmp_path: Path, format_name: str
    ) -> None:
        (tmp_path / f"payload.{format_name}").write_bytes(self._SIGNATURES[format_name])
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        assert len(results) == 1
        diagnostic = results[0]
        assert isinstance(diagnostic, Diagnostic)
        assert diagnostic.code == "DISC-ARCHIVE-UNEXAMINED"
        assert diagnostic.incomplete is True
        assert format_name in diagnostic.message

    def test_archive_skip_does_not_count_toward_total_bytes_bound(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "big.zip").write_bytes(self._SIGNATURES["zip"] + b"x" * 1000)
        _touch(tmp_path / "small.txt", "ok")
        root = resolve_repository_root(tmp_path)

        results = list(
            walk_repository(root, bounds=TraversalBounds(max_total_bytes=10))
        )

        paths = [item for item in results if isinstance(item, Path)]
        assert (tmp_path / "small.txt").resolve() in paths


class TestDecompressionBombSafety:
    def test_gzip_bomb_is_classified_without_decompression(
        self, tmp_path: Path
    ) -> None:
        """A decompression-bomb fixture is handled without resource
        exhaustion.

        A real gzip stream compressing 50 MB of zeros to a tiny file. This
        module never decompresses anything it classifies as an archive, so
        walking it only ever reads its first `_SNIFF_BYTES` bytes -- this
        completes quickly and yields only a diagnostic, never inflating
        the payload.
        """

        bomb_path = tmp_path / "bomb.gz"
        with gzip.open(bomb_path, "wb", compresslevel=9) as handle:
            handle.write(b"\x00" * 50_000_000)
        root = resolve_repository_root(tmp_path)

        start = time.monotonic()
        results = list(walk_repository(root))
        elapsed = time.monotonic() - start

        assert elapsed < 5.0
        assert len(results) == 1
        diagnostic = results[0]
        assert isinstance(diagnostic, Diagnostic)
        assert diagnostic.code == "DISC-ARCHIVE-UNEXAMINED"
        assert "gzip" in diagnostic.message


class TestContentOverridesExtension:
    """Classification never depends on a file's name or extension."""

    def test_txt_extension_with_archive_content_is_classified_as_archive(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "data.txt").write_bytes(b"PK\x03\x04\x14\x00\x00\x00")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        assert len(results) == 1
        assert isinstance(results[0], Diagnostic)
        assert results[0].code == "DISC-ARCHIVE-UNEXAMINED"

    def test_zip_extension_with_text_content_is_classified_as_text(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "archive.zip").write_text("just plain text, not a zip")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        assert results == [(tmp_path / "archive.zip").resolve()]


class TestSpecialFileGuard:
    """The sniff step's own `open()` call must never block on a FIFO.

    A minimal `is_file()` guard keeps the sniff step's `open()` call from
    hanging. Special-file classification later gave FIFOs (and other special
    files) their own dedicated diagnostic (`DISC-SPECIAL-FILE-SKIPPED`)
    instead of the generic `DISC-UNREADABLE-ENTRY` this test originally
    asserted -- updated here to match, not a silent behavior change.
    """

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
    def test_fifo_is_skipped_not_opened(self, tmp_path: Path) -> None:
        os.mkfifo(tmp_path / "pipe")
        _touch(tmp_path / "normal.txt")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert (tmp_path / "normal.txt").resolve() in paths
        assert any(d.code == "DISC-SPECIAL-FILE-SKIPPED" for d in diagnostics)


class TestIgnoreFileIntegration:
    """`walk_repository`-level integration for ignore files. Precedence
    rules themselves are unit-tested directly against `controlloop.ignore`
    in `test_ignore.py`; this class proves the walker wires them in
    correctly, including behavior that only exists at the walk level (never
    descending into an excluded directory at all)."""

    def test_ignored_file_is_skipped_sibling_still_yielded(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / ".gitignore").write_text("*.log\n")
        _touch(tmp_path / "debug.log")
        _touch(tmp_path / "keep.txt")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert (tmp_path / "keep.txt").resolve() in paths
        assert (tmp_path / "debug.log").resolve() not in paths
        ignored = [d for d in diagnostics if d.code == "DISC-IGNORED"]
        assert len(ignored) == 1
        assert ignored[0].severity == DiagnosticSeverity.INFO
        assert ignored[0].incomplete is False

    def test_ignored_directory_contents_never_appear(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("build/\n")
        _touch(tmp_path / "build" / "output.txt")
        _touch(tmp_path / "src.py")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert (tmp_path / "src.py").resolve() in paths
        assert not any("build" in path.parts for path in paths)
        ignored = [d for d in diagnostics if d.code == "DISC-IGNORED"]
        assert len(ignored) == 1
        assert ignored[0].evidence[0].path == "build"

    def test_cannot_reinclude_inside_an_excluded_parent_directory(
        self, tmp_path: Path
    ) -> None:
        """A well-known, deliberate real-git constraint: a deeper
        `.gitignore` cannot resurrect a path inside a directory the
        parent already excluded, because the directory is never
        descended into at all."""

        (tmp_path / ".gitignore").write_text("build/\n")
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / ".gitignore").write_text("!important.txt\n")
        _touch(tmp_path / "build" / "important.txt")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        paths = [item for item in results if isinstance(item, Path)]
        assert not any(path.name == "important.txt" for path in paths)

    def test_controlloopignore_overrides_gitignore_at_walk_level(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / ".gitignore").write_text("*.log\n")
        (tmp_path / ".controlloopignore").write_text("!keep.log\n")
        _touch(tmp_path / "keep.log")
        _touch(tmp_path / "drop.log")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        paths = [item for item in results if isinstance(item, Path)]
        assert (tmp_path / "keep.log").resolve() in paths
        assert (tmp_path / "drop.log").resolve() not in paths

    def test_nested_gitignore_precedence_through_the_walker(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / ".gitignore").write_text("*.log\n")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / ".gitignore").write_text("!keep.log\n")
        _touch(tmp_path / "sub" / "keep.log")
        _touch(tmp_path / "sub" / "drop.log")
        _touch(tmp_path / "top.log")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        paths = [item for item in results if isinstance(item, Path)]
        assert (tmp_path / "sub" / "keep.log").resolve() in paths
        assert (tmp_path / "sub" / "drop.log").resolve() not in paths
        assert (tmp_path / "top.log").resolve() not in paths

    def test_cli_exclusions_apply_last_and_can_reinclude(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("*.log\n")
        _touch(tmp_path / "important.log")
        _touch(tmp_path / "other.log")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root, cli_exclusions=["!important.log"]))

        paths = [item for item in results if isinstance(item, Path)]
        assert (tmp_path / "important.log").resolve() in paths
        assert (tmp_path / "other.log").resolve() not in paths

    def test_cli_exclusions_can_exclude_something_not_otherwise_ignored(
        self, tmp_path: Path
    ) -> None:
        _touch(tmp_path / "secret.env")
        _touch(tmp_path / "normal.txt")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root, cli_exclusions=["secret.env"]))

        paths = [item for item in results if isinstance(item, Path)]
        assert (tmp_path / "normal.txt").resolve() in paths
        assert (tmp_path / "secret.env").resolve() not in paths

    def test_dot_git_at_root_is_always_excluded(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        _touch(tmp_path / ".git" / "config")
        _touch(tmp_path / "real.py")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert (tmp_path / "real.py").resolve() in paths
        assert not any(".git" in path.parts for path in paths)
        assert any(
            d.code == "DISC-IGNORED" and d.evidence[0].path == ".git"
            for d in diagnostics
        )

    def test_gitignore_file_itself_is_still_a_normal_walkable_entry(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / ".gitignore").write_text("*.log\n")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        paths = [item for item in results if isinstance(item, Path)]
        assert (tmp_path / ".gitignore").resolve() in paths

    def test_oversized_ignore_file_reported_and_contributes_no_rules(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / ".gitignore").write_text("*.log\n" + "#pad\n" * 10)
        _touch(tmp_path / "a.log")
        root = resolve_repository_root(tmp_path)

        results = list(
            walk_repository(root, bounds=TraversalBounds(max_file_size_bytes=5))
        )

        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert any(d.code == "DISC-IGNORE-FILE-UNUSABLE" for d in diagnostics)

    def test_determinism_with_ignore_rules(self, tmp_path: Path) -> None:
        first, second = tmp_path / "first", tmp_path / "second"
        for base in (first, second):
            base.mkdir()
            (base / ".gitignore").write_text("*.log\n")
        for name in ("z.txt", "a.log", "m.txt"):
            _touch(first / name)
        for name in ("a.log", "m.txt", "z.txt"):
            _touch(second / name)

        first_root = resolve_repository_root(first)
        second_root = resolve_repository_root(second)

        first_relative = [
            path.relative_to(first_root.path)
            for path in walk_repository(first_root)
            if isinstance(path, Path)
        ]
        second_relative = [
            path.relative_to(second_root.path)
            for path in walk_repository(second_root)
            if isinstance(path, Path)
        ]

        assert first_relative == second_relative


class TestIgnoredFileNeverOpened:
    """A file excluded by ignore rules is never opened."""

    def test_ignored_file_is_never_opened(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / ".gitignore").write_text("secret.bin\n")
        secret = tmp_path / "secret.bin"
        secret.write_bytes(b"do not open me")
        _touch(tmp_path / "normal.txt", "hello")
        root = resolve_repository_root(tmp_path)

        opened: list[Path] = []
        original_open = Path.open

        def _tracking_open(self: Path, *args: Any, **kwargs: Any) -> Any:
            opened.append(self.resolve())
            return original_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", _tracking_open)

        list(walk_repository(root))

        assert secret.resolve() not in opened
        assert (tmp_path / "normal.txt").resolve() in opened


class TestSymlinkLoopTermination:
    """Symlink loops terminate and are reported."""

    def test_self_referential_symlink_does_not_crash_the_walk(
        self, tmp_path: Path
    ) -> None:
        self_link = tmp_path / "loop"
        os.symlink(self_link, self_link)
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        assert len(results) == 1
        diagnostic = results[0]
        assert isinstance(diagnostic, Diagnostic)
        assert diagnostic.code == "DISC-SYMLINK-LOOP"

    def test_assert_within_root_refuses_a_self_referential_symlink(
        self, tmp_path: Path
    ) -> None:
        self_link = tmp_path / "loop"
        os.symlink(self_link, self_link)
        root = resolve_repository_root(tmp_path)

        with pytest.raises(ContainmentError):
            assert_within_root(root, self_link)

    def test_indirect_cross_reference_loop_still_terminates(
        self, tmp_path: Path
    ) -> None:
        """A loop that is not a literal ancestor relationship: a/link -> b,
        b/link -> a. Regression proof this already worked before dedicated
        symlink-loop reporting existed -- the per-ancestor-chain `visited`
        set accumulates every directory entered on the current path, not
        only literal filesystem ancestors."""

        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        os.symlink(tmp_path / "b", tmp_path / "a" / "to_b")
        os.symlink(tmp_path / "a", tmp_path / "b" / "to_a")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert len(diagnostics) == 2
        assert all(d.code == "DISC-POSSIBLE-CYCLE" for d in diagnostics)

    def test_multi_hop_chain_enforces_containment_on_final_target(
        self, tmp_path: Path
    ) -> None:
        """Containment is enforced on the fully canonicalized
        target, not the first hop's link text."""

        root_dir = tmp_path / "root"
        root_dir.mkdir()
        outside_target = tmp_path / "outside.txt"
        outside_target.write_text("secret-canary-value")
        hop2 = root_dir / "hop2"
        hop1 = root_dir / "hop1"
        os.symlink(outside_target, hop2)
        os.symlink(hop2, hop1)
        root = resolve_repository_root(root_dir)

        results = list(walk_repository(root))

        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert len(diagnostics) == 2
        assert all(d.code == "DISC-BOUNDARY-ESCAPE" for d in diagnostics)
        escaped_paths = {d.evidence[0].path for d in diagnostics}
        assert escaped_paths == {"hop1", "hop2"}


class TestSpecialFileClassification:
    """A symlink to a device, socket, or FIFO is skipped without being
    opened, classified by kind."""

    def test_symlink_to_a_real_fifo_is_classified(self, tmp_path: Path) -> None:
        fifo = tmp_path / "real_fifo"
        os.mkfifo(fifo)
        link = tmp_path / "link_to_fifo"
        link.symlink_to(fifo)
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        special = [d for d in diagnostics if d.code == "DISC-SPECIAL-FILE-SKIPPED"]
        assert len(special) == 2
        assert all("fifo" in d.message for d in special)
        assert all(d.severity == DiagnosticSeverity.INFO for d in special)
        assert all(d.incomplete is False for d in special)

    def test_symlink_to_a_real_bound_unix_socket_is_classified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # AF_UNIX bind paths are limited to a short, platform-specific
        # length (~104-108 bytes), and pytest's own tmp_path is often
        # already deeper than that on its own. bind() resolves a relative
        # path against the process's current directory, so chdir-ing into
        # tmp_path and binding a one-character relative name keeps the
        # string passed to bind() short regardless of the real absolute
        # depth -- the socket still ends up inside the repository root,
        # which a separate short-but-elsewhere temp directory could not
        # do (that would make the symlink an out-of-root escape instead
        # of exercising the classification this test is for).
        monkeypatch.chdir(tmp_path)
        server = _real_socket_class(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind("s")
            sock_path = tmp_path / "s"
            link = tmp_path / "link_to_sock"
            link.symlink_to(sock_path)
            root = resolve_repository_root(tmp_path)

            results = list(walk_repository(root))
        finally:
            server.close()

        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        special = [d for d in diagnostics if d.code == "DISC-SPECIAL-FILE-SKIPPED"]
        assert len(special) == 2
        assert all("socket" in d.message for d in special)

    def test_special_file_kind_classifies_device_modes(self) -> None:
        """Device nodes cannot be created inside a test fixture without
        privileges a test process does not have and should not be
        granted, so device classification is proven directly against
        `_special_file_kind` with synthetic `stat()` mode values instead
        -- the same real constants `os.stat()` would report."""

        char_device_mode = stat_module.S_IFCHR | 0o666
        block_device_mode = stat_module.S_IFBLK | 0o660
        regular_file_mode = stat_module.S_IFREG | 0o644

        assert _special_file_kind(char_device_mode) == "device"
        assert _special_file_kind(block_device_mode) == "device"
        assert _special_file_kind(regular_file_mode) is None

    def test_special_file_kind_classifies_socket_and_fifo_modes(self) -> None:
        socket_mode = stat_module.S_IFSOCK | 0o755
        fifo_mode = stat_module.S_IFIFO | 0o644

        assert _special_file_kind(socket_mode) == "socket"
        assert _special_file_kind(fifo_mode) == "fifo"

    def test_special_file_skip_does_not_count_toward_file_count_bound(
        self, tmp_path: Path
    ) -> None:
        os.mkfifo(tmp_path / "pipe")
        _touch(tmp_path / "a.txt")
        _touch(tmp_path / "b.txt")
        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root, bounds=TraversalBounds(max_file_count=2)))

        paths = [item for item in results if isinstance(item, Path)]
        assert len(paths) == 2


class TestDiagnosticRegistry:
    """Every skipped path is reported with a reason code drawn from the
    diagnostic registry. These tests keep that true structurally: a new
    `_XXX_CODE` constant that forgets to register itself fails here, not
    silently."""

    @staticmethod
    def _code_constants() -> dict[str, str]:
        return {
            name: value
            for name, value in vars(repository_module).items()
            if name.endswith("_CODE") and isinstance(value, str)
        }

    def test_every_code_constant_is_registered(self) -> None:
        code_constants = self._code_constants()
        assert code_constants
        for name, code in code_constants.items():
            assert code in DIAGNOSTIC_REGISTRY, f"{name} ({code!r}) is not registered"

    def test_registry_has_no_orphan_entries(self) -> None:
        assert set(DIAGNOSTIC_REGISTRY) == set(self._code_constants().values())

    def test_every_description_is_nonempty(self) -> None:
        assert all(description.strip() for description in DIAGNOSTIC_REGISTRY.values())


class TestSummarizeSkips:
    """The skip summary is deterministically ordered, independent of
    traversal order."""

    def test_sorted_by_path(self, tmp_path: Path) -> None:
        (tmp_path / "z.bin").write_bytes(b"\x00binary")
        (tmp_path / "a.bin").write_bytes(b"\x00binary")
        root = resolve_repository_root(tmp_path)

        summary = summarize_skips(walk_repository(root))

        paths = [
            path
            for path in (diagnostic.evidence[0].path for diagnostic in summary)
            if path is not None
        ]
        assert len(paths) == len(summary)
        assert paths == sorted(paths)

    def test_only_diagnostics_are_returned(self, tmp_path: Path) -> None:
        _touch(tmp_path / "a.txt")
        (tmp_path / "b.bin").write_bytes(b"\x00binary")
        root = resolve_repository_root(tmp_path)

        summary = summarize_skips(walk_repository(root))

        assert len(summary) == 1
        assert isinstance(summary[0], Diagnostic)

    def test_deterministic_across_repeated_calls(self, tmp_path: Path) -> None:
        (tmp_path / "a.bin").write_bytes(b"\x00binary")
        (tmp_path / "z.bin").write_bytes(b"\x00binary")
        root = resolve_repository_root(tmp_path)

        first = summarize_skips(list(walk_repository(root)))
        second = summarize_skips(list(walk_repository(root)))

        assert first == second


class TestHostileFilenames:
    """Adversarial filenames and encodings cannot crash the scanner or
    corrupt its output. The first two tests are regressions for real crash
    bugs found by investigation before any fix was written."""

    def test_control_character_and_rtl_override_do_not_crash(
        self, tmp_path: Path
    ) -> None:
        weird_name = "a\x01b‮c.txt"
        (tmp_path / weird_name).write_bytes(b"x" * 1000)
        root = resolve_repository_root(tmp_path)

        results = list(
            walk_repository(root, bounds=TraversalBounds(max_file_size_bytes=10))
        )

        assert len(results) == 1
        diagnostic = results[0]
        assert isinstance(diagnostic, Diagnostic)
        evidence_path = diagnostic.evidence[0].path
        assert evidence_path is not None
        assert "\x01" not in evidence_path
        assert "‮" not in evidence_path
        assert "<U+0001>" in evidence_path
        assert "<U+202E>" in evidence_path

    def test_long_nested_path_is_bounded_not_a_crash(self, tmp_path: Path) -> None:
        deep = tmp_path
        for i in range(30):
            deep = deep / ("segment_" + str(i) * 5)
        deep.mkdir(parents=True)
        long_name = "b" * 100 + ".txt"
        (deep / long_name).write_bytes(b"x" * 1000)
        root = resolve_repository_root(tmp_path)

        results = list(
            walk_repository(root, bounds=TraversalBounds(max_file_size_bytes=10))
        )

        assert len(results) == 1
        diagnostic = results[0]
        assert isinstance(diagnostic, Diagnostic)
        evidence_path = diagnostic.evidence[0].path
        assert evidence_path is not None
        assert len(evidence_path) <= 512
        assert evidence_path.startswith("[truncated]")
        assert evidence_path.endswith(long_name)

    def test_non_utf8_filename_handled_without_raising(self, tmp_path: Path) -> None:
        raw_path = os.fsencode(str(tmp_path)) + b"/file-\xff\xfe-bad.txt"
        try:
            file_descriptor = os.open(raw_path, os.O_CREAT | os.O_WRONLY)
            os.close(file_descriptor)
        except OSError:
            pytest.skip("this filesystem does not allow non-UTF-8 filenames")

        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        assert len(results) == 1
        assert isinstance(results[0], Path)

    def test_non_utf8_filename_in_a_diagnostic_is_escaped_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        raw_path = os.fsencode(str(tmp_path)) + b"/big-\xff\xfe-bad.txt"
        try:
            file_descriptor = os.open(raw_path, os.O_CREAT | os.O_WRONLY)
            os.write(file_descriptor, b"x" * 1000)
            os.close(file_descriptor)
        except OSError:
            pytest.skip("this filesystem does not allow non-UTF-8 filenames")

        root = resolve_repository_root(tmp_path)

        results = list(
            walk_repository(root, bounds=TraversalBounds(max_file_size_bytes=10))
        )

        assert len(results) == 1
        diagnostic = results[0]
        assert isinstance(diagnostic, Diagnostic)
        assert diagnostic.evidence[0].path is not None


class TestCaseCollisionDiagnostic:
    """Case-insensitive filesystem collisions do not produce duplicate or
    lost nodes. The walker was already safe here (no case-folding anywhere
    -- verified by reading the module); this adds a proactive diagnostic so
    the portability risk is visible rather than silently depending on which
    filesystem the scan happens to run on."""

    def test_synthetic_collision_is_detected(self) -> None:
        entries = [Path("/tmp/File.txt"), Path("/tmp/FILE.txt"), Path("/tmp/other.txt")]

        diagnostics = list(_case_collision_diagnostics("", entries))

        assert len(diagnostics) == 1
        diagnostic = diagnostics[0]
        assert diagnostic.code == "DISC-CASE-COLLISION"
        assert diagnostic.severity == DiagnosticSeverity.WARNING
        assert diagnostic.incomplete is False
        paths = {evidence.path for evidence in diagnostic.evidence}
        assert paths == {"File.txt", "FILE.txt"}

    def test_no_collision_among_distinct_names(self) -> None:
        entries = [Path("/tmp/a.txt"), Path("/tmp/b.txt"), Path("/tmp/c.txt")]

        assert list(_case_collision_diagnostics("", entries)) == []

    def test_collision_evidence_is_scoped_to_its_directory(self) -> None:
        entries = [Path("/tmp/sub/A.txt"), Path("/tmp/sub/a.txt")]

        diagnostics = list(_case_collision_diagnostics("sub", entries))

        assert len(diagnostics) == 1
        paths = {evidence.path for evidence in diagnostics[0].evidence}
        assert paths == {"sub/A.txt", "sub/a.txt"}

    def test_case_variant_entries_that_coexist_are_both_walked(
        self, tmp_path: Path
    ) -> None:
        """On a case-sensitive filesystem, both entries genuinely coexist
        on disk and must both still be walked as distinct nodes -- not
        merely detected by the diagnostic helper in isolation, as the
        other tests in this class do. This development environment's
        filesystem is case-insensitive-but-preserving (confirmed during
        investigation: a second write silently aliases the first), so
        this is gated on a runtime capability probe rather than assumed;
        it exercises the real path end to end on a filesystem (such as
        this repository's Linux CI runner) where it can."""

        (tmp_path / "File.txt").write_text("upper")
        (tmp_path / "file.txt").write_text("lower")
        # `.exists()` is itself resolved case-insensitively by a
        # case-insensitive filesystem, so it cannot detect the collision
        # it would need to skip on; list the directory instead and check
        # both exact-case names actually appear as separate entries.
        listed_names = {entry.name for entry in tmp_path.iterdir()}
        if not {"File.txt", "file.txt"}.issubset(listed_names):
            pytest.skip("this filesystem does not keep case-variant entries distinct")

        root = resolve_repository_root(tmp_path)

        results = list(walk_repository(root))

        paths = [item for item in results if isinstance(item, Path)]
        diagnostics = [item for item in results if isinstance(item, Diagnostic)]
        assert len(paths) == 2
        assert any(d.code == "DISC-CASE-COLLISION" for d in diagnostics)
