"""Committed baseline resolution.

Finds "the" baseline for a repository, given its resolved root and an
optional explicit path, and validates whatever it finds. This module
answers *which* baseline applies and *where it came from*; it does not
compare a baseline against a live scan, and it does not read, write,
or commit anything -- that is the job of
`controlloop.baseline.integrity` and of the comparison code, reused
here rather than reimplemented.

Resolution order:

1. An explicit path, if supplied, always wins -- discovery at the
   conventional path is skipped entirely, not merely overridden after the
   fact.
2. Otherwise, the conventional path relative to the *resolved repository
   root* (`controlloop.repository.resolve_repository_root`, not the
   current working directory) is checked:
   `<repository root>/.controlloop/baseline.json`. If nothing exists
   there, there is no committed baseline yet -- `resolve_baseline`
   returns `None`, which is a legitimate, expected outcome (a repository
   that has not committed a baseline), not an error.

Whichever source is selected, its bytes are parsed and
integrity-checked by
`controlloop.baseline.integrity.load_baseline_document` -- the exact
function already built and tested for tamper/truncation detection --
not a second, parallel validation path. A baseline that fails that
check raises `BaselineIntegrityError` (already
`exit_code = ExitCode.INVALID_INPUT`) straight through this module with
no `except` clause around it: it returns exit 2 rather than falling
back silently to another source -- there is structurally no fallback
code path here for this module to fall back through.

`BaselineResolutionError` covers the other way resolution can fail: the
selected path (explicit or conventional) exists as a name but cannot be
read as a baseline document at all -- missing, a directory, or otherwise
unreadable. It carries the same `exit_code = ExitCode.INVALID_INPUT`,
mirroring `BaselineIntegrityError`'s own documented pattern, so a caller
can treat both exceptions identically at the CLI boundary.

`ResolvedBaseline.source` is a `BaselineSource` naming which of the
two paths above supplied the returned document. The resolved baseline
source is named in every report, which needs this as a structural
property of every successful resolution, ready for a report-producing
command to read and print. This module does not print anything itself.

`controlloop.cli` calls this function to resolve the baseline behind its
`--baseline` option; comparing the resolved baseline against a live scan
happens there, not here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from controlloop.baseline.integrity import load_baseline_document
from controlloop.baseline.models import BaselineDocument
from controlloop.exit_codes import ExitCode
from controlloop.repository import RepositoryRoot

CONVENTIONAL_BASELINE_RELATIVE_PATH = ".controlloop/baseline.json"
"""Repository-root-relative path a committed baseline is discovered
at. Always resolved against `RepositoryRoot.path`, never the current
working directory, matching how every other repository-relative path
in this codebase is resolved."""


class BaselineSource(StrEnum):
    """Which resolution path supplied a `ResolvedBaseline`."""

    COMMITTED = "committed"
    """Discovered automatically at `CONVENTIONAL_BASELINE_RELATIVE_PATH`."""

    EXPLICIT = "explicit"
    """Supplied via an explicit path that overrode discovery."""


@dataclass(frozen=True, slots=True)
class ResolvedBaseline:
    """The outcome of a successful `resolve_baseline` call.

    `path` is the exact path the document was read from (the explicit
    path as given, or the conventional path under the repository root),
    kept alongside `source` so a caller can name both *how* the baseline
    was selected and *where* it lives without re-deriving either.
    """

    document: BaselineDocument
    source: BaselineSource
    path: Path


class BaselineResolutionError(ValueError):
    """The selected baseline path could not be read as a document at all.

    Distinct from `BaselineIntegrityError`: this covers a missing,
    unreadable, or non-file path (an `OSError` while opening it); a
    document that *is* readable but fails structural or integrity
    validation raises `BaselineIntegrityError` instead, unmodified, from
    `controlloop.baseline.integrity.load_baseline_document`. Both carry
    `exit_code = ExitCode.INVALID_INPUT` so a caller can treat them
    identically, mirroring `BaselineIntegrityError`'s own documented
    pattern of carrying its intended CLI exit code before any command
    consumes it.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INVALID_INPUT


def resolve_baseline(
    root: RepositoryRoot,
    *,
    explicit_path: str | os.PathLike[str] | None = None,
) -> ResolvedBaseline | None:
    """Resolve "the" baseline for a repository.

    Returns `None` if `explicit_path` is not given and no baseline exists
    at the conventional path -- a repository simply has not committed one
    yet, which is an expected outcome, not an error.

    Raises `BaselineResolutionError` if the selected path cannot be read
    (missing, a directory, or otherwise unreadable), or
    `BaselineIntegrityError` (from `controlloop.baseline.integrity`,
    unmodified) if it can be read but fails structural, version, or
    tamper/truncation validation. Neither exception triggers a fallback
    to a different source: an explicit path that fails is never silently
    replaced by the conventional one, and a conventional baseline that
    fails is never silently treated as absent.
    """

    if explicit_path is not None:
        return _load_from(Path(explicit_path), BaselineSource.EXPLICIT)

    conventional = root.path / CONVENTIONAL_BASELINE_RELATIVE_PATH
    if not conventional.exists():
        return None
    return _load_from(conventional, BaselineSource.COMMITTED)


def _load_from(path: Path, source: BaselineSource) -> ResolvedBaseline:
    try:
        raw = path.read_bytes()
    except OSError as error:
        reason = error.strerror or str(error)
        raise BaselineResolutionError(
            f"baseline at {path} could not be read: {reason}"
        ) from error

    document = load_baseline_document(raw)
    return ResolvedBaseline(document=document, source=source, path=path)
