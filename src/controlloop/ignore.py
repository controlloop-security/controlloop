"""Ignore-file evaluation: `.gitignore`, `.controlloopignore`, precedence.

This module answers one question: given the chain of ignore files from a
repository's root down to a path's containing directory, plus any
command-line exclusions, is the path excluded?

Precedence matches real `git` behavior, not an approximation of it:

- Within one directory's rules, `.controlloopignore` is evaluated after
  `.gitignore`, so it can override it for the same path.
- Across directories, a deeper level's rule overrides a shallower one for
  the same path -- patterns closer to the file win.
- Command-line exclusions are evaluated last, across the whole path, and
  can re-include a path an ignore file excluded.
- A directory that is itself excluded is never listed or descended into,
  so nothing inside it can be re-included by a deeper `.gitignore` --
  matching a well-known, deliberate real-git constraint ("It is not
  possible to re-include a file if a parent directory of that file is
  excluded"), not an attempt to improve on it.

Pattern matching itself is delegated to `pathspec`'s `"gitignore"`
pattern factory (`GitIgnoreSpecPattern`) rather than hand-rolled,
specifically because negation interacting with directory exclusion, `**`
wildcards, and anchoring are easy to get subtly wrong. `"gitwildmatch"`,
the older factory name, is deprecated in the installed `pathspec`
version in favor of `"gitignore"`; this module uses the current name.
This module drives `pathspec` through its public API only
(`PathSpec.patterns`, each pattern's public `.include` and
`.match_file`), not its private backend, so it keeps working across
`pathspec` versions that preserve that public contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pathspec

_GITIGNORE_NAME = ".gitignore"
_CONTROLLOOPIGNORE_NAME = ".controlloopignore"

# pathspec.PathSpec is generic over its pattern type; from_lines() with the
# "gitignore" factory always produces one over the base Pattern type.
type _Spec = pathspec.PathSpec[pathspec.Pattern]

LoadStatus = Literal["ok", "too-large", "unreadable"]


@dataclass(frozen=True, slots=True)
class IgnoreLevel:
    """Compiled ignore rules scoped to one directory."""

    relative_dir: str
    gitignore: _Spec | None
    controlloopignore: _Spec | None


@dataclass(frozen=True, slots=True)
class UnusableFile:
    """An ignore file that exists but could not be used as a rule source."""

    name: str
    status: LoadStatus


def load_ignore_level(
    directory: Path, relative_dir: str, *, max_bytes: int
) -> tuple[IgnoreLevel, tuple[UnusableFile, ...]]:
    """Compile whatever `.gitignore`/`.controlloopignore` exist in
    ``directory``, bounded to ``max_bytes`` each.

    Returns the compiled level plus any files that existed but could not
    be used (for the caller to turn into diagnostics) -- a missing file is
    simply absent from that tuple, not a problem, and a successfully
    loaded file is not reported either, only a genuinely unusable one.
    """

    problems: list[UnusableFile] = []
    gitignore = _load_one(
        directory / _GITIGNORE_NAME, _GITIGNORE_NAME, max_bytes, problems
    )
    controlloopignore = _load_one(
        directory / _CONTROLLOOPIGNORE_NAME,
        _CONTROLLOOPIGNORE_NAME,
        max_bytes,
        problems,
    )
    level = IgnoreLevel(
        relative_dir=relative_dir,
        gitignore=gitignore,
        controlloopignore=controlloopignore,
    )
    return level, tuple(problems)


def _load_one(
    path: Path, name: str, max_bytes: int, problems: list[UnusableFile]
) -> _Spec | None:
    if not path.is_file():
        return None

    try:
        size = path.stat().st_size
    except OSError:
        problems.append(UnusableFile(name=name, status="unreadable"))
        return None

    if size > max_bytes:
        problems.append(UnusableFile(name=name, status="too-large"))
        return None

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        problems.append(UnusableFile(name=name, status="unreadable"))
        return None

    return pathspec.PathSpec.from_lines("gitignore", text.splitlines())


def compile_exclusions(patterns: list[str]) -> _Spec | None:
    """Compile command-line exclusion patterns, or ``None`` for an
    empty list."""

    if not patterns:
        return None
    return pathspec.PathSpec.from_lines("gitignore", patterns)


def is_ignored(
    levels: tuple[IgnoreLevel, ...],
    relative_path: str,
    *,
    is_directory: bool,
    cli_exclusions: _Spec | None = None,
) -> bool:
    """Return whether ``relative_path`` is excluded.

    ``levels`` must be ordered root-first, deepest-last: the ancestor
    chain from the repository root down to and including the path's
    containing directory's own ignore level.
    """

    verdict = False
    for level in levels:
        level_relative = _relative_to_level(relative_path, level.relative_dir)
        tested = f"{level_relative}/" if is_directory else level_relative
        for spec in (level.gitignore, level.controlloopignore):
            if spec is None:
                continue
            result = _spec_verdict(spec, tested)
            if result is not None:
                verdict = result

    if cli_exclusions is not None:
        tested = f"{relative_path}/" if is_directory else relative_path
        result = _spec_verdict(cli_exclusions, tested)
        if result is not None:
            verdict = result

    return verdict


def _relative_to_level(relative_path: str, level_relative_dir: str) -> str:
    if not level_relative_dir:
        return relative_path
    return relative_path[len(level_relative_dir) + 1 :]


def _spec_verdict(spec: _Spec, tested_path: str) -> bool | None:
    verdict: bool | None = None
    for pattern in spec.patterns:
        if pattern.match_file(tested_path) is not None:
            verdict = pattern.include
    return verdict
