"""Merge-base baseline resolution, the sibling fallback path to
`controlloop.baseline.resolution`'s committed-baseline resolution: "with
no committed baseline, ControlLoop scans the merge-base of the default
branch and uses that."

This module answers two questions:

1. What commit is "the merge-base of the default branch" for this
   repository right now? (`resolve_merge_base`)
2. What does a full ACBOM of that commit look like?
   (`build_merge_base_acbom`)

Both are resolved through local git plumbing only -- `git rev-parse`,
`git symbolic-ref`, `git merge-base`, `git rev-parse
--is-shallow-repository`, and `git archive` -- never `git fetch`, never a
remote URL, and this module imports no networking primitive anywhere.
The autouse `_deny_network_access` fixture in `tests/conftest.py`
covers every test in this module's own test file the same way it covers
the rest of `tests/`.

## Why `git archive`, not `git worktree add`

`git worktree add --detach <tmpdir> <sha>` is one way to materialize the
merge-base revision's tree without touching the user's actual working
directory. This module deliberately does not use it. A `git worktree
add` run from inside one worktree still writes into the *shared* main
repository's `.git/worktrees/` administrative directory -- every
worktree of one repository shares one object database and one
worktree-admin area. With several worktrees of the same repository in
use at once, a `git worktree add`/`remove` pair executed from production
code would be a shared, mutable git-state race -- and it buys nothing
here that `git archive` does not already give more simply: `git archive
--format=tar <commit>` reads git objects read-only and writes only into
a throwaway `tempfile.TemporaryDirectory`, touching no shared repository
state at all, while producing identical materialized tree content (the
complete tracked tree at that commit, honoring `.gitattributes
export-ignore` the same way a real checkout of that commit would).

## What scanning a past revision does and does not require inventing

`controlloop.bom.build_acbom_document(root, *, bounds=None,
commit_override=None)` is the one function `controlloop bom` itself calls
to walk a `RepositoryRoot` and run every registered adapter. It already
accepts any `RepositoryRoot`, not necessarily the process's own cwd or
git root, so "produced by scanning that revision, using the same
scanner and adapter versions as the current scan" does not require a
second, parallel scan pipeline -- it requires supplying that one function
a `RepositoryRoot` pointing at a materialized copy of the merge-base
revision's tree, which is exactly what `build_merge_base_acbom` does.
"Same scanner and adapter versions" is true by construction: both the
live scan and this one run `build_acbom_document` in the same process,
against the same installed `controlloop` package and the same
`ALL_ADAPTERS` registry -- there is no second copy of either that could
drift.

`commit_override` (a new, additive, backward-compatible optional
parameter on `build_acbom_document` itself, default `None`, every
existing call site and test unaffected) exists because the materialized
merge-base copy is a plain directory, not itself a git checkout --
`build_acbom_document`'s own `_resolve_commit` would otherwise report
`"unknown"` for it, even though the caller here knows precisely which
commit it is. `build_merge_base_acbom` passes
`resolution.merge_base_commit` so the resulting document's
`repository.commit` field is honest rather than needlessly `"unknown"`.

## No history is not zero changes

"A repository with no git history and no committed baseline reports that
no comparison is possible, rather than reporting zero changes." That
outcome describes what a *comparison-producing command* prints to a
user, so this module does not decide it. Reading both `resolve_baseline`
and this module's `resolve_merge_base` to decide what a user-facing
report says is comparison-command orchestration, not baseline
resolution. This module supplies the *structural* precondition instead:
`NoGitHistoryError`, raised whenever `HEAD` itself cannot be resolved
(zero commits, or not a git repository at all), distinctly from
`MergeBaseResolutionError`'s "some history exists, but not enough to
find a merge-base" case.

`controlloop diff` is the comparison command: it catches
`NoGitHistoryError`, combines it with a `None` result from
`resolve_baseline`, and reports "no comparison is possible" plainly,
distinct from "zero changes" -- see `controlloop.cli` and
`docs/reference/cli.md#diff`.

No CLI command wires a `--default-branch` option to `resolve_merge_base`;
`diff` always resolves the default branch automatically for its no-
`--baseline` automatic-resolution path.
"""

from __future__ import annotations

import io
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from controlloop.acbom import ACBOMDocument
from controlloop.acbom.models import CommitIdentifier
from controlloop.bom import build_acbom_document
from controlloop.exit_codes import ExitCode
from controlloop.repository import (
    RepositoryRoot,
    TraversalBounds,
    resolve_repository_root,
)

_GIT_TIMEOUT_SECONDS = 10
_ARCHIVE_TIMEOUT_SECONDS = 60

_GIT_MARKER = ".git"

_DEFAULT_BRANCH_CANDIDATES: tuple[str, ...] = (
    "origin/main",
    "origin/master",
    "main",
    "master",
)
"""Fixed, documented, local-only fallback candidates tried in order when
`default_branch` is not supplied and `refs/remotes/origin/HEAD` cannot be
read. Not a new approved product concept -- an explicit `default_branch`
argument, the seam a future CLI flag would use, always overrides this
heuristic entirely."""

_SHALLOW_REMEDIATION = (
    "Fetch full history before running controlloop -- for example, "
    "`git fetch --unshallow`, or set `fetch-depth: 0` in your CI checkout "
    "step (GitHub Actions' actions/checkout defaults to fetch-depth: 1)."
)


class MergeBaseResolutionError(RuntimeError):
    """Merge-base resolution could not proceed for an actionable reason:
    the default branch could not be determined, or `git
    merge-base` found no common ancestor. Also raised by
    `build_merge_base_acbom` when materializing the resolved revision
    fails.

    Carries `exit_code = ExitCode.INVALID_INPUT`, mirroring
    `controlloop.baseline.resolution.BaselineResolutionError`'s own
    documented pattern.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INVALID_INPUT


class NoGitHistoryError(RuntimeError):
    """No git history is available at all: `HEAD` cannot be resolved to a
    commit, whether because the repository has zero commits or because
    the resolved root is not a git repository at all (the structural
    precondition described in the module docstring's "No history is not
    zero changes" section).

    Deliberately distinct from `MergeBaseResolutionError`: "no history
    at all" and "some history, but not enough to find a merge-base" are
    different conditions with different remediations, and a comparison
    command needs them told apart rather than folded into one generic
    failure.

    Carries `exit_code = ExitCode.INCOMPLETE_ANALYSIS`, matching that exit
    code's documented meaning ("analysis was incomplete") -- nothing
    about a caller's input is invalid here; there is simply nothing to
    compare against.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INCOMPLETE_ANALYSIS


@dataclass(frozen=True, slots=True)
class MergeBaseResolution:
    """The outcome of a successful `resolve_merge_base` call."""

    merge_base_commit: CommitIdentifier
    """The commit `git merge-base` returned between `head_commit` and
    `default_branch_ref` -- "the merge-base ... is resolved through
    git"."""

    head_commit: CommitIdentifier
    """The current revision's resolved `HEAD` commit."""

    default_branch_ref: str
    """The exact ref name resolution used (for example `"origin/main"` or
    an explicitly supplied value) -- kept alongside the result so a
    caller can name it without re-deriving it."""


@dataclass(frozen=True, slots=True)
class _GitScope:
    """Where git runs, and which subtree of it was actually scanned.

    `work_tree` is the repository git commands run in. `subpath` is
    `root.path` relative to it, POSIX-style, or `None` when they are the
    same directory.

    The distinction is the whole point. A scan of `repo/scenarios/x`
    must compare `x`-as-it-was against `x`-as-it-is, never the whole
    repository -- so `subpath` becomes a `git archive` pathspec, and the
    materialized baseline is scanned at that same subpath.
    """

    work_tree: Path
    subpath: str | None


def _resolve_git_scope(root: RepositoryRoot) -> _GitScope | None:
    """The git repository `root.path` belongs to, or `None` if it belongs
    to none.

    `_has_own_git_repository` used to answer this as a boolean, refusing
    any `root.path` without a `.git` of its own. Its reasoning was sound
    -- git searches upward from cwd, and a plain directory nested inside
    an unrelated repository would otherwise silently compare against
    that repository's history, a scope mismatch with what was scanned.

    The refusal was too broad, and this is what it cost: a repository of
    scenario subdirectories can never compute material change at all,
    which makes a capability reduction unreportable no matter what else
    is wired up.

    The mismatch that guard feared is a *scope* problem, not a
    *discovery* problem, so it is fixed at the scope: git may run in the
    enclosing repository, and everything read from it is confined to the
    subpath that was actually scanned. Comparing a subdirectory's past
    against its present is not a mismatch; it is the comparison the user
    asked for.
    """

    if (root.path / _GIT_MARKER).exists():
        return _GitScope(work_tree=root.path, subpath=None)

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root.path,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None

    top_level = result.stdout.strip()
    if not top_level:
        return None

    try:
        work_tree = Path(top_level).resolve(strict=True)
        scanned = root.path.resolve(strict=True)
        relative = scanned.relative_to(work_tree)
    except (OSError, ValueError):
        # `relative_to` raising means git named a directory that does not
        # contain the scan root. Refuse rather than guess.
        return None

    subpath = relative.as_posix()
    return _GitScope(work_tree=work_tree, subpath=subpath if subpath != "." else None)


def _subpath_is_tracked(root: RepositoryRoot, revision: str) -> bool:
    """Whether the scanned subpath exists in `revision`'s tree.

    A scan root that is a subdirectory of a repository can only be
    compared against its own past, so a subpath that is untracked, or
    that did not exist at the revision, has no prior state. Every entry
    point below refuses that case identically -- an untracked directory
    nested inside some unrelated repository is indistinguishable from
    one that simply predates the commit, and both mean the same thing:
    nothing to compare against.

    A scan root that is itself a repository has no subpath and is always
    considered present.
    """

    scope = _resolve_git_scope(root)
    if scope is None:
        return False
    if scope.subpath is None:
        return True
    return (
        _run_git(root, ["ls-tree", "-d", "--name-only", revision, "--", scope.subpath])
        is not None
    )


def _run_git(root: RepositoryRoot, args: list[str]) -> str | None:
    """Run a bounded, local, read-only git plumbing command and return its
    stripped stdout, or `None` on any failure (nonzero exit, missing
    `git`, a timeout, or `root.path` having no `.git` of its own -- see
    `_resolve_git_scope`). Never raises itself -- callers decide
    whether a failure here means "expected absence" or "fatal," matching
    `controlloop.bom._resolve_commit`'s existing pattern for the same
    kind of call.
    """

    scope = _resolve_git_scope(root)
    if scope is None:
        return None

    try:
        result = subprocess.run(
            ["git", *args],
            cwd=scope.work_tree,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    return output or None


def checked_out_branch(root: RepositoryRoot) -> str | None:
    """The branch checked out at `root`, or `None` on a detached `HEAD`,
    outside a git repository, or when `git` is unavailable. Read-only and
    local, like every other call here."""

    return _run_git(root, ["symbolic-ref", "--quiet", "--short", "HEAD"])


def _is_shallow(root: RepositoryRoot) -> bool:
    return _run_git(root, ["rev-parse", "--is-shallow-repository"]) == "true"


def _resolve_default_branch_ref(
    root: RepositoryRoot, default_branch: str | None
) -> str:
    if default_branch is not None:
        # A pull-request checkout (GitHub Actions' actions/checkout on a
        # `pull_request` event) has the target branch only as a
        # remote-tracking ref, so a bare name like `main` is also tried as
        # `origin/main`. The name as given always wins when it resolves.
        candidates: tuple[str, ...] = (default_branch,)
        if not default_branch.startswith(("origin/", "refs/")):
            candidates += (f"origin/{default_branch}",)
    else:
        symbolic = _run_git(
            root, ["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"]
        )
        candidates = ((symbolic,) if symbolic else ()) + _DEFAULT_BRANCH_CANDIDATES

    for candidate in candidates:
        if _run_git(
            root, ["rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}"]
        ):
            return candidate

    if default_branch is not None:
        raise MergeBaseResolutionError(
            f"the supplied default branch {default_branch!r} could not be "
            "resolved to a commit locally. This commonly happens in CI when "
            "the checkout never fetched that branch's ref. " + _SHALLOW_REMEDIATION
        )
    raise MergeBaseResolutionError(
        "could not determine the repository's default branch: no local "
        "refs/remotes/origin/HEAD symbolic ref was found, and none of the "
        f"common candidate branches ({', '.join(_DEFAULT_BRANCH_CANDIDATES)}) "
        "resolve locally either. This commonly happens in CI when the "
        "checkout uses a shallow or single-branch fetch that never "
        "retrieved the default branch's own ref (for example, GitHub "
        "Actions' actions/checkout with its default fetch-depth: 1 and no "
        "explicit ref list). " + _SHALLOW_REMEDIATION
    )


def resolve_merge_base(
    root: RepositoryRoot, *, default_branch: str | None = None
) -> MergeBaseResolution:
    """Resolve the merge-base between the current revision and the
    default branch, purely through local git.

    Raises `NoGitHistoryError` if `HEAD` itself cannot be resolved (zero
    commits, or not a git repository at all). Raises
    `MergeBaseResolutionError` if the default branch cannot be determined,
    or if `git merge-base` finds no common ancestor -- the latter checks
    `git rev-parse --is-shallow-repository` to name a shallow clone
    definitively when confirmed, or describe the more general
    "insufficient or unrelated history" case otherwise.
    """

    head = _run_git(root, ["rev-parse", "--verify", "--quiet", "HEAD"])
    if head is None:
        raise NoGitHistoryError(
            "no git history is available at this repository root: HEAD "
            "could not be resolved to a commit. There is nothing to "
            "compute a merge-base baseline against."
        )

    branch_ref = _resolve_default_branch_ref(root, default_branch)

    merge_base = _run_git(root, ["merge-base", head, branch_ref])
    if merge_base is None:
        if _is_shallow(root):
            raise MergeBaseResolutionError(
                f"could not resolve a merge-base between HEAD ({head}) and "
                f"{branch_ref!r}: this repository is a shallow clone "
                "(`git rev-parse --is-shallow-repository` reports true), "
                "which is the likely cause -- a shallow clone strips "
                "exactly the shared commit history a merge-base needs. "
                + _SHALLOW_REMEDIATION
            )
        raise MergeBaseResolutionError(
            f"could not resolve a merge-base between HEAD ({head}) and "
            f"{branch_ref!r}: git found no common ancestor. This commonly "
            "happens in CI when the checkout uses a shallow or partial "
            "fetch that never retrieved shared history, or, more rarely, "
            "when the two revisions genuinely share no history (for "
            "example, an orphan branch). " + _SHALLOW_REMEDIATION
        )

    if not _subpath_is_tracked(root, merge_base):
        # Checked against the merge-base commit rather than HEAD: a
        # subdirectory added *after* the merge base is tracked now but
        # has no prior state, and an untracked directory is in neither.
        # Both mean the same thing -- nothing to compare against.
        raise NoGitHistoryError(
            f"{root.path} does not exist in the merge-base commit "
            f"({merge_base}), so it has no prior state to compute a "
            "baseline from."
        )

    return MergeBaseResolution(
        merge_base_commit=merge_base, head_commit=head, default_branch_ref=branch_ref
    )


def build_merge_base_acbom(
    root: RepositoryRoot,
    resolution: MergeBaseResolution,
    *,
    bounds: TraversalBounds | None = None,
) -> ACBOMDocument:
    """Produce a complete ACBOM for `resolution.merge_base_commit`, using
    the exact same scan pipeline (`controlloop.bom.build_acbom_document`)
    the live scan uses -- see the module docstring's "What scanning a past
    revision does and does not require inventing".

    Materializes the commit's complete tracked tree into an isolated
    `tempfile.TemporaryDirectory` via `git archive` (never the caller's
    actual working directory, and never `git worktree add` -- see the
    module docstring's "Why `git archive`" section) and scans that copy.
    The temporary directory, and everything under it, is removed before
    this function returns, on every path including failure.

    Raises `MergeBaseResolutionError` if `git archive` fails (an invalid
    or missing commit, a timeout, or `git` unavailable).
    """

    with tempfile.TemporaryDirectory(prefix="controlloop-merge-base-") as tmp_name:
        dest = Path(tmp_name)
        _materialize_revision(root, resolution.merge_base_commit, dest)
        # `git archive` preserves the pathspec prefix, so a subdirectory
        # scan finds its baseline tree at the same relative location it
        # was scanned from. A subdirectory that did not
        # exist at the merge-base commit yields no such directory, which
        # is a real and honest "nothing to compare against".
        scope = _resolve_git_scope(root)
        scanned = (
            dest if scope is None or scope.subpath is None else dest / scope.subpath
        )
        if not scanned.is_dir():
            raise MergeBaseResolutionError(
                f"commit {resolution.merge_base_commit} contains no "
                "tree at the scanned path, so there is no prior state "
                "of it to compare against"
            )
        merge_base_root = resolve_repository_root(scanned)
        return build_acbom_document(
            merge_base_root,
            bounds=bounds,
            commit_override=resolution.merge_base_commit,
        )


def _materialize_revision(root: RepositoryRoot, commit: str, dest: Path) -> None:
    """Extract `commit`'s complete tracked tree into the existing, empty
    directory `dest`, read-only from git's perspective (no network;
    `git archive` never contacts a remote).

    Raises `NoGitHistoryError` if `root.path` has no `.git` of its own --
    see `_resolve_git_scope`. This call runs `git archive` directly
    (not through `_run_git`), so it needs the same guard applied
    explicitly: `build_acbom_at_revision` can reach here with a commit
    resolved from an unrelated enclosing repository if a caller bypasses
    `resolve_merge_base`'s own equivalent guard (for example by supplying
    a commit obtained some other way), and archiving that commit with no
    pathspec would otherwise materialize a completely unrelated tree --
    the original failure mode this module's `NoGitHistoryError` handling
    exists to prevent.
    """

    scope = _resolve_git_scope(root)
    if scope is None or not _subpath_is_tracked(root, commit):
        raise NoGitHistoryError(
            f"{root.path} does not belong to a git repository, or is not "
            f"tracked in the one that contains it. Refusing to read "
            f"commit {commit} from git, which would otherwise rely on "
            "git's own upward repository search and risk materializing "
            "an unrelated tree."
        )

    # A subdirectory scan archives only that subdirectory, so the
    # baseline tree is the scanned subtree as it was -- never the whole
    # repository, which is the scope mismatch the old guard refused
    # outright rather than bounding.
    pathspec = [scope.subpath] if scope.subpath is not None else []

    try:
        result = subprocess.run(
            ["git", "archive", "--format=tar", commit, *pathspec],
            cwd=scope.work_tree,
            capture_output=True,
            timeout=_ARCHIVE_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise MergeBaseResolutionError(
            f"could not read commit {commit} from git: {type(error).__name__}"
        ) from error

    if result.returncode != 0:
        raise MergeBaseResolutionError(
            f"git archive failed for commit {commit} (exit "
            f"{result.returncode}); this commit may not exist in this "
            "repository's object database"
        )

    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
        archive.extractall(path=dest, filter="data")


def resolve_revision_commit(
    root: RepositoryRoot, revision: str
) -> CommitIdentifier | None:
    """Resolve `revision` (a branch, tag, short or full SHA, or any other
    git revision expression) to a full commit id through local git alone,
    or `None` if it does not resolve to a commit at all -- never raises
    itself, mirroring `_run_git`'s own "never raises; caller decides
    what absence means" contract.

    Used by `controlloop diff --baseline VALUE`: `--baseline` accepts
    either a file path or a git revision, and a value that is not an
    existing file is tried here as the revision half of that
    disambiguation. Deliberately independent of `resolve_merge_base`'s
    own default-branch heuristic -- an explicitly supplied revision is
    compared against directly, never reinterpreted as "the default
    branch to find a merge-base with"."""

    commit = _run_git(
        root, ["rev-parse", "--verify", "--quiet", f"{revision}^{{commit}}"]
    )
    if commit is None or not _subpath_is_tracked(root, commit):
        # A revision that does not contain the scanned subpath is not a
        # revision *of what was scanned*, so it resolves to
        # nothing rather than to a commit whose tree excludes it.
        return None
    return commit


def build_acbom_at_revision(
    root: RepositoryRoot,
    commit: CommitIdentifier,
    *,
    bounds: TraversalBounds | None = None,
) -> ACBOMDocument:
    """Produce a complete ACBOM for `commit`, an already-resolved
    revision that is not necessarily a merge-base -- the same
    materialize-then-scan shape `build_merge_base_acbom` uses (reusing
    its own `_materialize_revision` helper unmodified), but for any
    commit a caller has already resolved by its own means rather than
    specifically "the merge-base of the default branch."

    Used by `controlloop diff --baseline VALUE`'s explicit-revision
    path, alongside `resolve_revision_commit`
    above. `build_merge_base_acbom` itself is unmodified and does not
    call this function; the two exist side by side because they answer
    different questions ("the merge-base with the default branch" versus
    "this exact revision the caller named"), even though both ultimately
    materialize a commit and scan it the same way.

    Raises `MergeBaseResolutionError` if `git archive` fails (an invalid
    or missing commit, a timeout, or `git` unavailable) -- the same
    exception `build_merge_base_acbom` raises for the same underlying
    failure, so a caller can handle both identically.
    """

    with tempfile.TemporaryDirectory(prefix="controlloop-revision-") as tmp_name:
        dest = Path(tmp_name)
        _materialize_revision(root, commit, dest)
        revision_root = resolve_repository_root(dest)
        return build_acbom_document(
            revision_root, bounds=bounds, commit_override=commit
        )
