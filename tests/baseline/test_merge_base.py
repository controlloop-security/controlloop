"""Tests for controlloop.baseline.merge_base.

Fixtures build real git repositories with `subprocess.run(["git", ...])`,
mirroring `tests/test_bom.py`'s existing `_init_repo`/`_commit_all`
helper style rather than diverging from it. The shallow-clone fixture in
`TestResolveMergeBase.test_shallow_clone_reports_shallow_as_likely_cause`
was verified empirically against the actual installed git during authoring
(`git clone --no-single-branch --depth 1 --branch <name> file://<origin>
<dest>` genuinely reproduces both `git rev-parse
--is-shallow-repository` reporting `true` and `git merge-base` failing
with no common ancestor found) -- a plain path-based local clone silently
ignores `--depth` ("--depth is ignored in local clones"), so every clone
fixture below uses an explicit `file://` URL to force real shallow
behavior.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from controlloop.acbom import serialize_document
from controlloop.baseline.merge_base import (
    MergeBaseResolution,
    MergeBaseResolutionError,
    NoGitHistoryError,
    build_acbom_at_revision,
    build_merge_base_acbom,
    resolve_merge_base,
    resolve_revision_commit,
)
from controlloop.exit_codes import ExitCode
from controlloop.repository import resolve_repository_root


def _init_repo(path: Path, *, branch: str = "main") -> None:
    subprocess.run(["git", "init", "-q", "-b", branch], cwd=path, check=True)


def _commit_all(path: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@t.com",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            message,
        ],
        cwd=path,
        check=True,
    )


def _checkout_new_branch(path: Path, branch: str) -> None:
    subprocess.run(["git", "checkout", "-q", "-b", branch], cwd=path, check=True)


def _checkout(path: Path, ref: str) -> None:
    subprocess.run(["git", "checkout", "-q", ref], cwd=path, check=True)


def _head(path: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _clone(source: Path, dest: Path, *extra_args: str) -> None:
    subprocess.run(
        ["git", "clone", "-q", *extra_args, f"file://{source}", str(dest)],
        check=True,
        capture_output=True,
    )


class TestResolveMergeBase:
    def test_auto_detects_origin_main_and_resolves_merge_base(
        self, tmp_path: Path
    ) -> None:
        origin = tmp_path / "origin"
        origin.mkdir()
        _init_repo(origin)
        (origin / "a.txt").write_text("a\n")
        _commit_all(origin, "c1")
        shared_commit = _head(origin)

        dest = tmp_path / "dest"
        _clone(origin, dest)
        _checkout_new_branch(dest, "feature")
        (dest / "b.txt").write_text("b\n")
        _commit_all(dest, "c2 on feature")

        root = resolve_repository_root(dest)
        resolution = resolve_merge_base(root)

        assert resolution.default_branch_ref == "origin/main"
        assert resolution.merge_base_commit == shared_commit
        assert resolution.head_commit == _head(dest)

    def test_explicit_default_branch_override_resolves_same_commit(
        self, tmp_path: Path
    ) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        shared_commit = _head(repo)
        _checkout_new_branch(repo, "feature")
        (repo / "b.txt").write_text("b\n")
        _commit_all(repo, "c2 on feature")

        root = resolve_repository_root(repo)
        resolution = resolve_merge_base(root, default_branch="main")

        assert resolution.default_branch_ref == "main"
        assert resolution.merge_base_commit == shared_commit

    def test_explicit_default_branch_falls_back_to_its_remote_tracking_ref(
        self, tmp_path: Path
    ) -> None:
        # The shape actions/checkout leaves on a pull_request event: HEAD
        # detached at the pull request's commit, the target branch present
        # only as origin/main, and no local main branch at all.
        origin = tmp_path / "origin"
        origin.mkdir()
        _init_repo(origin)
        (origin / "a.txt").write_text("a\n")
        _commit_all(origin, "c1")
        shared_commit = _head(origin)

        dest = tmp_path / "dest"
        _clone(origin, dest)
        _checkout_new_branch(dest, "feature")
        (dest / "b.txt").write_text("b\n")
        _commit_all(dest, "c2 on feature")
        _checkout(dest, "--detach")
        subprocess.run(
            ["git", "branch", "-q", "-D", "main", "feature"], cwd=dest, check=True
        )

        root = resolve_repository_root(dest)
        resolution = resolve_merge_base(root, default_branch="main")

        assert resolution.default_branch_ref == "origin/main"
        assert resolution.merge_base_commit == shared_commit

    def test_explicit_default_branch_prefers_the_name_as_given(
        self, tmp_path: Path
    ) -> None:
        origin = tmp_path / "origin"
        origin.mkdir()
        _init_repo(origin)
        (origin / "a.txt").write_text("a\n")
        _commit_all(origin, "c1")

        dest = tmp_path / "dest"
        _clone(origin, dest)
        (origin / "c.txt").write_text("c\n")
        _commit_all(origin, "c3 on origin only")
        subprocess.run(["git", "fetch", "-q"], cwd=dest, check=True)
        local_main = _head(dest)

        root = resolve_repository_root(dest)
        resolution = resolve_merge_base(root, default_branch="main")

        assert resolution.default_branch_ref == "main"
        assert resolution.merge_base_commit == local_main

    def test_explicit_default_branch_that_does_not_exist_raises(
        self, tmp_path: Path
    ) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")

        root = resolve_repository_root(repo)

        with pytest.raises(MergeBaseResolutionError) as exc_info:
            resolve_merge_base(root, default_branch="does-not-exist")

        assert exc_info.value.exit_code is ExitCode.INVALID_INPUT
        assert "does-not-exist" in str(exc_info.value)

    def test_no_resolvable_default_branch_raises(self, tmp_path: Path) -> None:
        repo = tmp_path
        _init_repo(repo, branch="trunk")
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")

        root = resolve_repository_root(repo)

        with pytest.raises(MergeBaseResolutionError) as exc_info:
            resolve_merge_base(root)

        assert exc_info.value.exit_code is ExitCode.INVALID_INPUT
        assert "default branch" in str(exc_info.value)

    def test_shallow_clone_reports_shallow_as_likely_cause(
        self, tmp_path: Path
    ) -> None:
        """A shallow, multi-branch-tip clone that genuinely fails
        `git merge-base` -- verified empirically to reproduce
        `git rev-parse --is-shallow-repository` reporting `true` -- gets a
        message naming the shallow clone specifically, plus the concrete
        remediation, not a generic failure."""

        origin = tmp_path / "origin"
        origin.mkdir()
        _init_repo(origin)
        (origin / "a.txt").write_text("a\n")
        _commit_all(origin, "c1")
        _checkout_new_branch(origin, "feature")
        (origin / "b.txt").write_text("b\n")
        _commit_all(origin, "c2 on feature")
        (origin / "c.txt").write_text("c\n")
        _commit_all(origin, "c3 on feature")
        _checkout(origin, "main")

        dest = tmp_path / "dest"
        _clone(
            origin, dest, "--no-single-branch", "--depth", "1", "--branch", "feature"
        )

        root = resolve_repository_root(dest)

        with pytest.raises(MergeBaseResolutionError) as exc_info:
            resolve_merge_base(root)

        assert exc_info.value.exit_code is ExitCode.INVALID_INPUT
        message = str(exc_info.value).lower()
        assert "shallow clone" in message
        assert "fetch --unshallow" in message or "fetch-depth" in message

    def test_zero_commits_raises_no_git_history(self, tmp_path: Path) -> None:
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)

        root = resolve_repository_root(tmp_path)

        with pytest.raises(NoGitHistoryError) as exc_info:
            resolve_merge_base(root)

        assert exc_info.value.exit_code is ExitCode.INCOMPLETE_ANALYSIS

    def test_non_git_directory_raises_no_git_history(self, tmp_path: Path) -> None:
        root = resolve_repository_root(tmp_path)

        with pytest.raises(NoGitHistoryError):
            resolve_merge_base(root)

    def test_unrelated_histories_report_general_cause_when_not_shallow(
        self, tmp_path: Path
    ) -> None:
        """The other failure: `git merge-base` can also fail with a
        complete, non-shallow repository when the two revisions genuinely
        share no history (an orphan branch). `git rev-parse
        --is-shallow-repository` reports `false` here, so the message
        must describe the more general cause, not assert shallow."""

        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        subprocess.run(
            ["git", "checkout", "-q", "--orphan", "unrelated"], cwd=repo, check=True
        )
        subprocess.run(["git", "rm", "-rf", "-q", "."], cwd=repo, check=True)
        (repo / "b.txt").write_text("b\n")
        _commit_all(repo, "c2 on an unrelated orphan branch")

        root = resolve_repository_root(repo)

        with pytest.raises(MergeBaseResolutionError) as exc_info:
            resolve_merge_base(root, default_branch="main")

        message = str(exc_info.value).lower()
        assert "this repository is a shallow clone" not in message
        assert "no common ancestor" in message

    def test_git_unavailable_raises_no_git_history(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = resolve_repository_root(tmp_path)
        monkeypatch.setenv("PATH", "")

        with pytest.raises(NoGitHistoryError):
            resolve_merge_base(root)

    def test_directory_without_own_git_nested_in_unrelated_repo_raises(
        self, tmp_path: Path
    ) -> None:
        """A plain (non-git) directory nested inside some OTHER git
        repository's working tree must not silently borrow that
        enclosing repository's history via git's own upward `.git`
        search -- every git subprocess this module runs uses
        `cwd=root.path`, and git's default discovery behavior searches
        upward from cwd for the nearest `.git` when `root.path` has none
        of its own. This must report "no git history here," the same as
        if no enclosing repository existed at all, never silently
        resolve against the unrelated enclosing repository's HEAD and
        merge-base."""

        enclosing = tmp_path / "unrelated-outer-repo"
        enclosing.mkdir()
        _init_repo(enclosing)
        (enclosing / "outer.txt").write_text("outer\n")
        _commit_all(enclosing, "outer c1")

        nested = enclosing / "scratch" / "no-git-here"
        nested.mkdir(parents=True)
        (nested / "inner.txt").write_text("inner\n")

        root = resolve_repository_root(nested)

        with pytest.raises(NoGitHistoryError) as exc_info:
            resolve_merge_base(root)

        assert exc_info.value.exit_code is ExitCode.INCOMPLETE_ANALYSIS


class TestBuildMergeBaseAcbom:
    def test_produces_acbom_for_the_resolved_revision(self, tmp_path: Path) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / ".mcp.json").write_text('{"mcpServers": {"files": {"command": "npx"}}}')
        _commit_all(repo, "c1")
        merge_base_commit = _head(repo)
        _checkout_new_branch(repo, "feature")
        (repo / "other.txt").write_text("later\n")
        _commit_all(repo, "c2 on feature, after the merge-base")

        root = resolve_repository_root(repo)
        resolution = resolve_merge_base(root, default_branch="main")

        document = build_merge_base_acbom(root, resolution)

        assert document.repository.commit == merge_base_commit
        # The server, plus the Claude Code host that `.mcp.json` declares.
        assert sorted(node.name for node in document.nodes) == ["Claude Code", "files"]
        assert document.digest.startswith("sha256:")

    def test_nonexistent_commit_raises(self, tmp_path: Path) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        root = resolve_repository_root(repo)
        fake_resolution = MergeBaseResolution(
            merge_base_commit="0" * 40,
            head_commit=_head(repo),
            default_branch_ref="main",
        )

        with pytest.raises(MergeBaseResolutionError):
            build_merge_base_acbom(root, fake_resolution)

    def test_repeated_calls_produce_identical_digest(self, tmp_path: Path) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        root = resolve_repository_root(repo)
        resolution = resolve_merge_base(root, default_branch="main")

        first = build_merge_base_acbom(root, resolution)
        second = build_merge_base_acbom(root, resolution)

        assert first.digest == second.digest

    def test_secret_shaped_content_never_appears_in_serialized_document(
        self, tmp_path: Path
    ) -> None:
        """Privacy canary for the new materialization path specifically
        (not only the already-tested adapter/redaction behavior
        `build_acbom_document` itself covers): a secret-shaped value
        written into a tracked file at the merge-base commit -- reusing
        this codebase's existing synthetic GitHub-token-shaped canary
        convention (`tests/baseline/test_baseline_models.py`,
        `tests/test_redaction.py`) -- must never appear in the
        resulting ACBOM's serialized bytes."""

        canary = "ghp_" + "a" * 36
        repo = tmp_path
        _init_repo(repo)
        (repo / "notes.txt").write_text(f"token={canary}\n")
        _commit_all(repo, "c1")
        root = resolve_repository_root(repo)
        resolution = resolve_merge_base(root, default_branch="main")

        document = build_merge_base_acbom(root, resolution)
        serialized = serialize_document(document)

        assert canary.encode("utf-8") not in serialized

    def test_git_unavailable_during_materialization_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        root = resolve_repository_root(repo)
        resolution = resolve_merge_base(root, default_branch="main")

        monkeypatch.setenv("PATH", "")

        with pytest.raises(MergeBaseResolutionError):
            build_merge_base_acbom(root, resolution)


class TestResolveRevisionCommit:
    """Tests for `resolve_revision_commit`, which backs the
    `controlloop diff --baseline VALUE` disambiguation: a `VALUE` that is
    not an existing file is tried as a git revision here."""

    def test_resolves_a_branch_name_to_its_commit(self, tmp_path: Path) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        expected = _head(repo)
        root = resolve_repository_root(repo)

        assert resolve_revision_commit(root, "main") == expected

    def test_resolves_a_tag_to_its_commit(self, tmp_path: Path) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        expected = _head(repo)
        subprocess.run(["git", "tag", "v1"], cwd=repo, check=True)
        root = resolve_repository_root(repo)

        assert resolve_revision_commit(root, "v1") == expected

    def test_resolves_head_relative_expressions(self, tmp_path: Path) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        first_commit = _head(repo)
        (repo / "b.txt").write_text("b\n")
        _commit_all(repo, "c2")
        root = resolve_repository_root(repo)

        assert resolve_revision_commit(root, "HEAD~1") == first_commit

    def test_nonexistent_revision_returns_none_not_an_exception(
        self, tmp_path: Path
    ) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        root = resolve_repository_root(repo)

        assert resolve_revision_commit(root, "no-such-branch-or-tag") is None

    def test_empty_repository_returns_none(self, tmp_path: Path) -> None:
        repo = tmp_path
        _init_repo(repo)
        root = resolve_repository_root(repo)

        assert resolve_revision_commit(root, "HEAD") is None

    def test_directory_without_own_git_nested_in_unrelated_repo_returns_none(
        self, tmp_path: Path
    ) -> None:
        """Same guard as `TestResolveMergeBase`'s equivalent test, for
        this function's own direct `_run_git` usage: a directory with no
        `.git` of its own, nested inside an unrelated repository, must
        not resolve `"HEAD"` (or any other revision) against that
        unrelated repository's history."""

        enclosing = tmp_path / "unrelated-outer-repo"
        enclosing.mkdir()
        _init_repo(enclosing)
        (enclosing / "outer.txt").write_text("outer\n")
        _commit_all(enclosing, "outer c1")

        nested = enclosing / "scratch" / "no-git-here"
        nested.mkdir(parents=True)
        (nested / "inner.txt").write_text("inner\n")

        root = resolve_repository_root(nested)

        assert resolve_revision_commit(root, "HEAD") is None


class TestBuildAcbomAtRevision:
    """Tests for `build_acbom_at_revision`, which backs the
    `controlloop diff --baseline VALUE` explicit-revision path.
    Deliberately independent of `resolve_merge_base`:
    these tests resolve an arbitrary named revision directly, never a
    merge-base with a default branch."""

    def test_produces_acbom_for_an_arbitrary_resolved_revision(
        self, tmp_path: Path
    ) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / ".mcp.json").write_text('{"mcpServers": {"files": {"command": "npx"}}}')
        _commit_all(repo, "c1")
        first_commit = _head(repo)
        (repo / "other.txt").write_text("later\n")
        _commit_all(repo, "c2")
        root = resolve_repository_root(repo)

        document = build_acbom_at_revision(root, first_commit)

        assert document.repository.commit == first_commit
        # The server, plus the Claude Code host that `.mcp.json` declares.
        assert sorted(node.name for node in document.nodes) == ["Claude Code", "files"]
        assert document.digest.startswith("sha256:")

    def test_nonexistent_commit_raises(self, tmp_path: Path) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        root = resolve_repository_root(repo)

        with pytest.raises(MergeBaseResolutionError):
            build_acbom_at_revision(root, "0" * 40)

    def test_repeated_calls_produce_identical_digest(self, tmp_path: Path) -> None:
        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        commit = _head(repo)
        root = resolve_repository_root(repo)

        first = build_acbom_at_revision(root, commit)
        second = build_acbom_at_revision(root, commit)

        assert first.digest == second.digest

    def test_end_to_end_from_a_resolved_revision_string(self, tmp_path: Path) -> None:
        """`resolve_revision_commit` feeding `build_acbom_at_revision`
        directly, the exact composition `controlloop diff --baseline
        VALUE` uses for its explicit-revision path."""

        repo = tmp_path
        _init_repo(repo)
        (repo / "a.txt").write_text("a\n")
        _commit_all(repo, "c1")
        first_commit = _head(repo)
        subprocess.run(["git", "tag", "v1"], cwd=repo, check=True)
        (repo / "b.txt").write_text("b\n")
        _commit_all(repo, "c2")
        root = resolve_repository_root(repo)

        commit = resolve_revision_commit(root, "v1")
        assert commit is not None
        document = build_acbom_at_revision(root, commit)

        assert document.repository.commit == first_commit

    def test_secret_shaped_content_never_appears_in_serialized_document(
        self, tmp_path: Path
    ) -> None:
        """Privacy canary, mirroring `TestBuildMergeBaseAcbom`'s own for
        `build_merge_base_acbom` (both materialize the same way)."""

        canary = "ghp_" + "a" * 36
        repo = tmp_path
        _init_repo(repo)
        (repo / "notes.txt").write_text(f"token={canary}\n")
        _commit_all(repo, "c1")
        commit = _head(repo)
        root = resolve_repository_root(repo)

        document = build_acbom_at_revision(root, commit)
        serialized = serialize_document(document)

        assert canary.encode("utf-8") not in serialized

    def test_directory_without_own_git_nested_in_unrelated_repo_raises(
        self, tmp_path: Path
    ) -> None:
        """Defense in depth for `_materialize_revision`'s own guard: even
        given a commit resolved from the unrelated enclosing repository
        directly (bypassing `resolve_revision_commit`'s own equivalent
        guard), `build_acbom_at_revision` must refuse to archive it
        rather than materializing that unrelated repository's tree --
        the original crash this module's fix exists to prevent."""

        enclosing = tmp_path / "unrelated-outer-repo"
        enclosing.mkdir()
        _init_repo(enclosing)
        (enclosing / "outer.txt").write_text("outer\n")
        _commit_all(enclosing, "outer c1")
        unrelated_commit = _head(enclosing)

        nested = enclosing / "scratch" / "no-git-here"
        nested.mkdir(parents=True)
        (nested / "inner.txt").write_text("inner\n")

        root = resolve_repository_root(nested)

        with pytest.raises(NoGitHistoryError):
            build_acbom_at_revision(root, unrelated_commit)


class TestTrackedSubdirectoryScan:
    """A scan root that is a *tracked subdirectory* of a
    repository must be able to resolve a merge base and compare its own
    past against its present.

    The refusal these tests relax is the one
    `TestResolveMergeBase::test_directory_without_own_git_nested_in_unrelated_repo_raises`
    protects, and that test still passes unchanged: an **untracked**
    nested directory is still refused. The line moved from "does this
    directory have its own `.git`" to "is this directory tracked in the
    repository that contains it", which is the question that actually
    distinguishes a scoped comparison from a borrowed one.
    """

    def _repo_with_scenario(self, tmp_path: Path) -> Path:
        repo = tmp_path / "reference"
        (repo / "scenarios" / "alpha").mkdir(parents=True)
        _init_repo(repo)
        (repo / "scenarios" / "alpha" / "agent-card.json").write_text(
            '{"protocolVersion": "0.2", "name": "alpha", "skills": '
            '[{"id": "read", "name": "Read"}]}\n'
        )
        (repo / "root-file.txt").write_text("not part of the scenario\n")
        _commit_all(repo, "base")
        return repo

    def test_a_tracked_subdirectory_resolves_a_merge_base(self, tmp_path: Path) -> None:
        repo = self._repo_with_scenario(tmp_path)
        root = resolve_repository_root(repo / "scenarios" / "alpha")

        resolution = resolve_merge_base(root)

        assert resolution.merge_base_commit

    def test_the_baseline_is_the_subdirectory_not_the_whole_repository(
        self, tmp_path: Path
    ) -> None:
        """The scope guarantee. A subdirectory scan must never compare
        against the enclosing repository's full tree -- `root-file.txt`
        lives outside the scenario and must not appear."""

        repo = self._repo_with_scenario(tmp_path)
        root = resolve_repository_root(repo / "scenarios" / "alpha")

        document = build_merge_base_acbom(root, resolve_merge_base(root))

        paths = {
            evidence.path
            for node in document.nodes
            for evidence in node.evidence
            if evidence.path is not None
        }
        assert paths
        assert not any("root-file" in path for path in paths)

    def test_a_change_inside_the_subdirectory_is_seen(self, tmp_path: Path) -> None:
        """The point of the fix: a capability removed from the scenario
        is visible as a difference against its own past."""

        repo = self._repo_with_scenario(tmp_path)
        card = repo / "scenarios" / "alpha" / "agent-card.json"
        card.write_text(
            '{"protocolVersion": "0.2", "name": "alpha", "skills": '
            '[{"id": "read", "name": "Read"}, {"id": "write", "name": "Write"}]}\n'
        )
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=repo, check=True)
        _commit_all(repo, "add a skill")
        root = resolve_repository_root(repo / "scenarios" / "alpha")

        baseline = build_merge_base_acbom(root, resolve_merge_base(root))

        names = {node.name for node in baseline.nodes}
        assert "Read" in names
        assert "Write" not in names

    def test_an_untracked_subdirectory_is_still_refused(self, tmp_path: Path) -> None:
        """The safety property the old guard existed for, restated at
        the level that actually distinguishes the cases."""

        repo = self._repo_with_scenario(tmp_path)
        scratch = repo / "scratch" / "untracked"
        scratch.mkdir(parents=True)
        (scratch / "note.txt").write_text("never committed\n")
        root = resolve_repository_root(scratch)

        with pytest.raises(NoGitHistoryError):
            resolve_merge_base(root)

    def test_a_subdirectory_added_after_the_merge_base_is_refused(
        self, tmp_path: Path
    ) -> None:
        """A scenario that did not exist at the merge base has no prior
        state, which is an honest absence rather than an empty
        comparison against the repository root."""

        repo = self._repo_with_scenario(tmp_path)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=repo, check=True)
        new = repo / "scenarios" / "beta"
        new.mkdir(parents=True)
        (new / "agent-card.json").write_text(
            '{"protocolVersion": "0.2", "name": "beta", "skills": []}\n'
        )
        _commit_all(repo, "add a new scenario")
        root = resolve_repository_root(new)

        with pytest.raises((NoGitHistoryError, MergeBaseResolutionError)):
            resolve_merge_base(root)
