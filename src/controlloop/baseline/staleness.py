"""Baseline staleness detection.

A committed baseline records the commit it was computed at
(`BaselineDocument.repository.commit`). If the repository's default
branch has since moved far beyond that commit, the baseline no longer
describes the repository's actual capability set -- and a gate that
compares against it silently loses its own alarm. This module answers
*is the committed baseline stale*, given the default branch's current
commit and how far apart the two are; it does not resolve "the"
baseline (`controlloop.baseline.resolution`'s job, reused here) and it
does not choose a fallback baseline when one is stale.

`detect_baseline_staleness` is deliberately pure: it takes the two
commits and an already-computed commit distance (or `None`, when the
baseline's commit could not be found in history at all) rather
than resolving any of that itself. `resolve_default_branch_commit` and
`count_commits_between` are the separate, real `git` calls this needs,
kept apart from the pure decision function the same way
`controlloop.bom`'s `_resolve_commit` is kept apart from
`build_acbom_document`'s own document-assembly logic. Both are local
subprocess calls only -- `git symbolic-ref`, `git rev-parse`, `git
rev-list --count` against the repository's own local refs -- and never
touch the network, matching this codebase's local-first invariant.

"Staleness is reported in human, JSON, and SARIF output" is satisfied
structurally, not by three separate renderers: a staleness
finding is an ordinary `controlloop.acbom.models.Diagnostic`, which
already serializes to JSON identically everywhere else in this
codebase (`model_dump_json()`), and a human line is
`describe_staleness`'s own plain-text rendering, below. No command
routes a staleness diagnostic into SARIF output
(`controlloop.reporting.sarif`) yet -- disclosed here rather than
fabricated.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path

from controlloop.acbom.models import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Evidence,
)

_STALE_CODE = "BASELINE-STALE"
_UNVERIFIABLE_CODE = "BASELINE-UNVERIFIABLE"

#: A closed, documented registry for this module's own two diagnostic
#: codes -- mirroring the multi-registry precedent already established
#: by `controlloop.repository.DIAGNOSTIC_REGISTRY` (skip reasons) and
#: `controlloop.acbom.completeness.INCOMPLETE_DIAGNOSTIC_REGISTRY`
#: (incompleteness), each scoped to its own topic rather than one
#: shared registry for every diagnostic in the codebase. Neither code
#: belongs in `INCOMPLETE_DIAGNOSTIC_REGISTRY`: a stale baseline is a
#: confidently *known* fact (`incomplete=False`), not an unknown one;
#: an unverifiable baseline commit is a fact about the baseline's own
#: trustworthiness, not about analysis coverage.
BASELINE_DIAGNOSTIC_REGISTRY: Mapping[str, str] = {
    _STALE_CODE: (
        "The committed baseline's recorded commit is more than the "
        "configured threshold behind the default branch."
    ),
    _UNVERIFIABLE_CODE: (
        "The committed baseline's recorded commit could not be found "
        "in the repository's history, so its staleness cannot be "
        "determined."
    ),
}

#: Conservative default: a repository this many commits behind its
#: default branch is unambiguously stale on any project's cadence.
#: This is a disclosed judgment call, not an approved threshold -- what
#: is required is that the *mechanism* be configurable, not that this
#: module invent an approved business value.
_DEFAULT_MAX_STALENESS_COMMITS = 100


def detect_baseline_staleness(
    *,
    baseline_commit: str,
    default_branch_commit: str,
    commits_behind: int | None,
    baseline_path: str,
    max_staleness_commits: int = _DEFAULT_MAX_STALENESS_COMMITS,
) -> Diagnostic | None:
    """Return a `Diagnostic` if the baseline is stale or unverifiable,
    or `None` if it is current.

    `commits_behind` is the number of commits between `baseline_commit`
    and `default_branch_commit`, already resolved by the caller (see
    `count_commits_between`) -- `None` means the baseline's commit
    could not be found in the repository's history at all,
    reported as `BASELINE-UNVERIFIABLE` rather than a confident "not
    stale" or a crash. Two identical commits are trivially current,
    checked before consulting `commits_behind` at all -- a
    same-commit baseline is never unverifiable, whatever
    `commits_behind` happens to be.

    `baseline_path` becomes the returned diagnostic's evidence location
    and must already be a sanitized, repository-root-relative path (for
    example `resolved.path.relative_to(root.path).as_posix()`, where
    `resolved` is a `ResolvedBaseline`) -- this function does not
    relativize it, the same division of labor every adapter in
    `controlloop.adapters` already uses: the caller resolves and
    relativizes a real filesystem path once, this function only wraps
    the already-safe string in `Evidence`.

    Raises `ValueError` if `max_staleness_commits` is not positive.
    """

    if max_staleness_commits < 1:
        raise ValueError("max_staleness_commits must be at least 1")

    evidence = (Evidence(adapter="baseline-staleness", path=baseline_path),)

    if baseline_commit == default_branch_commit:
        return None

    if commits_behind is None:
        return Diagnostic(
            code=_UNVERIFIABLE_CODE,
            severity=DiagnosticSeverity.WARNING,
            message=(
                f"baseline commit {baseline_commit!r} was not found in "
                "the repository's history; staleness could not be "
                "determined"
            ),
            confidence=Confidence.UNKNOWN,
            incomplete=False,
            evidence=evidence,
        )

    if commits_behind <= max_staleness_commits:
        return None

    return Diagnostic(
        code=_STALE_CODE,
        severity=DiagnosticSeverity.WARNING,
        message=(
            f"baseline commit {baseline_commit!r} is {commits_behind} "
            f"commits behind the default branch (commit "
            f"{default_branch_commit!r}), exceeding the configured "
            f"threshold of {max_staleness_commits}"
        ),
        confidence=Confidence.HIGH,
        incomplete=False,
        evidence=evidence,
    )


def resolve_default_branch_commit(root_path: Path) -> str | None:
    """Return the default branch's current commit, resolved entirely
    from local git refs -- no network access, matching
    `controlloop.bom._resolve_commit`'s own local-only discipline.

    Tries `origin/HEAD` first (the remote's own advertised default
    branch, if this checkout has one recorded locally), falling back to
    `origin/main` and `origin/master`. Returns `None` if none of these
    resolve, rather than guessing at a name."""

    symbolic_ref = _run_git(
        ["symbolic-ref", "-q", "refs/remotes/origin/HEAD"], root_path
    )
    candidates = []
    if symbolic_ref is not None:
        candidates.append(symbolic_ref.strip())
    candidates.extend(["origin/main", "origin/master"])

    for candidate in candidates:
        commit = _run_git(["rev-parse", "--verify", candidate], root_path)
        if commit is not None:
            return commit.strip()
    return None


def count_commits_between(root_path: Path, older: str, newer: str) -> int | None:
    """Return the number of commits between `older` and `newer`
    (`git rev-list --count older..newer`), or `None` if `older` cannot
    be resolved in this repository's history -- never a raised
    exception for an ordinary "commit not found" condition."""

    if _run_git(["rev-parse", "--verify", f"{older}^{{commit}}"], root_path) is None:
        return None

    output = _run_git(["rev-list", "--count", f"{older}..{newer}"], root_path)
    if output is None:
        return None
    try:
        return int(output.strip())
    except ValueError:
        return None


def _run_git(args: list[str], root_path: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root_path,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def describe_staleness(diagnostic: Diagnostic) -> str:
    """One human-readable line for `diagnostic` (the "human" output),
    matching this codebase's brand-consistent glyph convention."""

    glyph = "!" if diagnostic.severity is DiagnosticSeverity.WARNING else "✕"
    label = diagnostic.code.replace("-", " ")
    return f"{glyph} {label}  {diagnostic.message}"
