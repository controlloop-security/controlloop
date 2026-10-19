"""Repository root resolution and read-boundary enforcement.

This module answers two questions all discovery depends on:

1. Where is the repository root? (`resolve_repository_root`)
2. Is a given path inside it? If not, it must never be read or followed.

`assert_within_root` is the hard invariant every actual file read in this
codebase must pass before opening a file: if it fails, an upstream caller
tried to read something that should already have been excluded, which is a
bug, so it raises. `walk_repository` is the graceful counterpart used during
discovery itself: encountering an entry that would resolve outside the root
(directly, or through a symlink) is an expected condition, so it is reported
as a canonical `Diagnostic` and skipped, never followed.

`walk_repository` also enforces configurable resource bounds: per-file
size, total bytes, total file count, and traversal depth
(`TraversalBounds`). Per-file size and depth are local bounds -- exceeding
one skips only the offending file or subtree, with a diagnostic, and the
walk continues elsewhere. Total file count and total bytes are global,
cumulative bounds -- exceeding one stops the whole walk, with a diagnostic
naming the bound, rather than raising or silently truncating without
saying so. Every bound diagnostic marks the affected analysis incomplete
so a completeness policy can see it, never a silent, confident omission.

The traversal itself is an explicit stack, not Python function recursion,
specifically so a caller-configured depth bound larger than Python's own
recursion limit cannot defeat the safety goal this module exists to
deliver -- a recursive implementation would crash with `RecursionError` on
a sufficiently deep tree before ever reaching this module's own depth
check. Cycle detection remains per-ancestor-chain (a symlink is only a
cycle if it points back to one of its own ancestors in the current path,
not merely to somewhere already visited elsewhere in the tree), matching
the semantics established when this walker was first introduced.

`walk_repository` also classifies every candidate file by content -- never
by extension -- using a bounded read of at most `_SNIFF_BYTES` regardless
of the file's actual size: a documented, signature-based baseline of
archive magic bytes (ZIP, GZIP, BZIP2, XZ, Zstandard, 7z, POSIX tar),
falling back to a null-byte heuristic for binary content, falling back to
text. A binary file is skipped with an informational, complete
classification (it was not incomplete analysis, just not source). An
archive is skipped with a warning, incomplete-marked diagnostic naming the
matched format -- it is never expanded, so a decompression bomb is handled
by construction, not by a size limit that could itself be bypassed.
Neither classification counts toward the file-count or total-bytes budget,
since neither will ever actually be read by a future adapter.

`walk_repository` also honors `.gitignore` and `.controlloopignore`
(real `gitwildmatch` semantics -- negation, directory-only patterns,
`**`, nested per-directory precedence -- via `controlloop.ignore`), plus
an optional list of command-line-style exclusion patterns applied last
and able to re-include a path an ignore file excluded. An excluded
directory is never listed or descended into -- nothing inside it can
later be re-included by a deeper `.gitignore`, matching real git's own
"cannot re-include inside an excluded parent" constraint rather than
trying to improve on it. An excluded file is skipped before any
`.stat()` or content sniff, so it is never opened. The repository root's
own `.git` directory is always excluded, the same way real git always
treats it, regardless of any `.gitignore` content.

`walk_repository` reports a same-root symlink loop with a dedicated
diagnostic rather than crashing -- including the case a naive containment
check misses: a symlink that resolves through no ancestor relationship at
all but still cycles (`a/link -> b`, `b/link -> a`), and a symlink
pointing directly at itself, which makes Python's own path resolution
raise `RuntimeError` rather than the `OSError` every other unreadable-entry
case raises, so it is caught and reported specifically rather than left to
crash the whole walk. A symlink (or a direct entry) that resolves to a
device, socket, or FIFO is classified by its resolved `stat()` mode, never
opened, and reported by kind -- never folded into the generic
unreadable-entry diagnostic that remains as a catch-all for anything this
baseline does not name.

`walk_repository` does not normalize filenames or handle encodings
beyond what the standard library already does, apart from the
evidence-path escaping described below, and nothing here weakens the
containment guarantee made above.

Every skip this module can produce is registered in
`DIAGNOSTIC_REGISTRY` (a closed, documented set of reason codes), and
`summarize_skips` turns a walk's interleaved path/diagnostic results into
a deterministically ordered skip report -- paths and reasons only, the
same guarantee every diagnostic already keeps, never skipped content.

Every `Evidence.path` this module constructs is escaped and length-bounded
before it is built (`_escape_hostile_characters`, `_bound_evidence_path`):
a control character or Unicode bidi/format character (for example a
right-to-left override) is replaced with a printable `<U+XXXX>` marker
rather than passed through raw, and a path longer than the canonical
`RelativePath` contract allows is truncated, keeping the end closest to
the actual filename, rather than left to raise past this module uncaught.
This is what stands between a hostile filename and a crash: without it, a
skip diagnostic for such a file would fail to construct at all. A
directory listing that contains two or more sibling names differing only
by case is flagged with its own diagnostic -- both/all entries are still
walked normally, since this reports a portability risk (a case-insensitive
filesystem could later collide or lose one of them), not an analysis gap
in this scan.
"""

from __future__ import annotations

import os
import stat as stat_module
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

from controlloop import ignore
from controlloop.acbom.models import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Evidence,
)

_GIT_MARKER = ".git"
_ADAPTER = "repository-walker"
_ESCAPE_CODE = "DISC-BOUNDARY-ESCAPE"
_CYCLE_CODE = "DISC-POSSIBLE-CYCLE"
_SYMLINK_LOOP_CODE = "DISC-SYMLINK-LOOP"
_UNREADABLE_CODE = "DISC-UNREADABLE-ENTRY"
_SPECIAL_FILE_CODE = "DISC-SPECIAL-FILE-SKIPPED"
_FILE_TOO_LARGE_CODE = "DISC-FILE-TOO-LARGE"
_DEPTH_EXCEEDED_CODE = "DISC-DEPTH-EXCEEDED"
_FILE_COUNT_EXCEEDED_CODE = "DISC-FILE-COUNT-EXCEEDED"
_TOTAL_BYTES_EXCEEDED_CODE = "DISC-TOTAL-BYTES-EXCEEDED"
_BINARY_CODE = "DISC-BINARY-SKIPPED"
_ARCHIVE_CODE = "DISC-ARCHIVE-UNEXAMINED"
_IGNORED_CODE = "DISC-IGNORED"
_IGNORE_FILE_UNUSABLE_CODE = "DISC-IGNORE-FILE-UNUSABLE"
_CASE_COLLISION_CODE = "DISC-CASE-COLLISION"

# The closed set of reason codes `walk_repository` can emit. Every entry
# here reuses the module constant above rather
# than a fresh string literal, so this registry cannot silently drift
# from what the walker actually produces -- a test asserts every
# `_XXX_CODE` constant defined in this module is a key here.
DIAGNOSTIC_REGISTRY: Mapping[str, str] = {
    _ESCAPE_CODE: (
        "An entry resolves outside the repository root and was skipped, never followed."
    ),
    _CYCLE_CODE: (
        "A directory was already visited on this path and was skipped to "
        "avoid a possible symlink cycle."
    ),
    _SYMLINK_LOOP_CODE: (
        "A symlink could not be resolved because of a loop and was skipped."
    ),
    _UNREADABLE_CODE: (
        "An entry could not be read (permission, a race, or an "
        "unsupported type) and was skipped."
    ),
    _SPECIAL_FILE_CODE: (
        "An entry resolves to a device, socket, or FIFO and was skipped "
        "without being opened."
    ),
    _FILE_TOO_LARGE_CODE: (
        "A file exceeds the configured per-file size bound and was skipped."
    ),
    _DEPTH_EXCEEDED_CODE: (
        "A subtree exceeds the configured traversal depth bound and was not explored."
    ),
    _FILE_COUNT_EXCEEDED_CODE: (
        "The configured total file count bound was reached; the scan stopped."
    ),
    _TOTAL_BYTES_EXCEEDED_CODE: (
        "The configured total bytes bound was reached; the scan stopped."
    ),
    _BINARY_CODE: "A file's content is binary and was skipped.",
    _ARCHIVE_CODE: ("A file matches a known archive signature and was not expanded."),
    _IGNORED_CODE: (
        "A path is excluded by .gitignore, .controlloopignore, an "
        "explicit exclusion, or the implicit .git exclusion."
    ),
    _IGNORE_FILE_UNUSABLE_CODE: (
        "An ignore file exists but could not be used as a rule source."
    ),
    _CASE_COLLISION_CODE: (
        "Two or more sibling entries differ only by case and may collide, "
        "duplicate, or silently lose one another on a case-insensitive "
        "filesystem; all are still walked normally here."
    ),
}

# Conservative, documented, fully overridable starting points -- ordinary
# engineering safety defaults, not an approved business or retention
# threshold. See TraversalBounds.
_DEFAULT_MAX_FILE_SIZE_BYTES = 10_000_000
_DEFAULT_MAX_TOTAL_BYTES = 500_000_000
_DEFAULT_MAX_FILE_COUNT = 50_000
_DEFAULT_MAX_DEPTH = 100

# The prefix read for content classification, regardless of file size. Long
# enough to cover every signature below (POSIX tar's is furthest out, at
# offset 257) with margin, short enough to never approximate "reading the
# file." Never grown to accommodate a larger or later-offset signature
# without deliberately reconsidering this bound.
_SNIFF_BYTES = 8192
_BINARY_NULL_BYTE = b"\x00"

# A documented, signature-based (not extension-based) baseline of archive
# and compression formats: (name, magic bytes, offset). Matching is a
# format either has this exact byte sequence at this exact offset or it
# does not, so unlike an entropy heuristic this needs no confidence
# threshold. Expanding this set is a separate, deliberate change, the same
# rule that governs every other detection surface in this repository.
_ARCHIVE_SIGNATURES: tuple[tuple[str, bytes, int], ...] = (
    ("zip", b"PK\x03\x04", 0),
    ("zip-empty", b"PK\x05\x06", 0),
    ("zip-spanned", b"PK\x07\x08", 0),
    ("gzip", b"\x1f\x8b", 0),
    ("bzip2", b"BZh", 0),
    ("xz", b"\xfd7zXZ\x00", 0),
    ("zstd", b"\x28\xb5\x2f\xfd", 0),
    ("7z", b"7z\xbc\xaf\x27\x1c", 0),
    ("tar", b"ustar", 257),
)


class RepositoryRootError(Exception):
    """The supplied or resolved repository root cannot be scanned.

    Carries the exit code (2) the CLI command layer uses when translating
    this into process exit behavior. This module never prints; it only
    raises.
    """

    exit_code = 2


class ContainmentError(Exception):
    """A path about to be read does not resolve inside the repository root.

    Raised only by `assert_within_root`. Not the mechanism `walk_repository`
    uses to skip an expected escape attempt during discovery -- see there.
    """


@dataclass(frozen=True, slots=True)
class RepositoryRoot:
    """A resolved, existing, readable repository root."""

    path: Path


@dataclass(frozen=True, slots=True)
class TraversalBounds:
    """Configurable resource bounds for `walk_repository`.

    ``max_file_size_bytes`` and ``max_depth`` are local bounds: exceeding
    one skips only the offending file or subtree. ``max_total_bytes`` and
    ``max_file_count`` are global, cumulative bounds: exceeding one stops
    the whole walk. Defaults are conservative starting points, not
    approved business thresholds -- every value is overridable per call.
    """

    max_file_size_bytes: int = _DEFAULT_MAX_FILE_SIZE_BYTES
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES
    max_file_count: int = _DEFAULT_MAX_FILE_COUNT
    max_depth: int = _DEFAULT_MAX_DEPTH

    def __post_init__(self) -> None:
        for field_name, value in (
            ("max_file_size_bytes", self.max_file_size_bytes),
            ("max_total_bytes", self.max_total_bytes),
            ("max_file_count", self.max_file_count),
            ("max_depth", self.max_depth),
        ):
            if value < 1:
                raise ValueError(f"{field_name} must be at least 1")


def resolve_repository_root(
    explicit_path: str | os.PathLike[str] | None = None,
    *,
    start: Path | None = None,
) -> RepositoryRoot:
    """Resolve the repository root and validate it.

    Resolution order: ``explicit_path`` if given; else the nearest ancestor
    of ``start`` (default: the current working directory) containing a
    ``.git`` entry; else ``start`` itself.
    """

    search_start = start if start is not None else Path.cwd()
    if explicit_path is not None:
        candidate = Path(explicit_path)
    else:
        candidate = _find_enclosing_git_root(search_start) or search_start

    if not candidate.exists():
        raise RepositoryRootError(f"repository root does not exist: {candidate}")
    if not candidate.is_dir():
        raise RepositoryRootError(f"repository root is not a directory: {candidate}")
    if not os.access(candidate, os.R_OK | os.X_OK):
        raise RepositoryRootError(f"repository root is not readable: {candidate}")

    return RepositoryRoot(path=candidate.resolve(strict=False))


def _find_enclosing_git_root(start: Path) -> Path | None:
    current = start.resolve()
    while True:
        if (current / _GIT_MARKER).exists():
            return current
        parent = current.parent
        if parent == current:
            return None
        current = parent


def assert_within_root(root: RepositoryRoot, path: Path) -> Path:
    """Return ``path`` canonicalized, only if it resolves inside ``root``.

    This is the hard read-boundary invariant: every actual file read must
    call this first. A failure here means an upstream caller tried to read
    something the walker should already have excluded, so this raises
    rather than returning a diagnostic.
    """

    try:
        resolved = path.resolve(strict=False)
    except RuntimeError as error:
        # `Path.resolve()` raises RuntimeError, not OSError, specifically
        # for a symlink loop (CPython converts the ELOOP OSError from its
        # own internal stat() call). Not safe to read, so this is a
        # containment refusal like any other, not a crash.
        raise ContainmentError(
            f"refusing to read an unresolvable symlink: {path}"
        ) from error
    try:
        resolved.relative_to(root.path)
    except ValueError:
        raise ContainmentError(
            f"refusing to read outside the repository root: {path}"
        ) from None
    return resolved


def walk_repository(
    root: RepositoryRoot,
    *,
    bounds: TraversalBounds | None = None,
    cli_exclusions: list[str] | None = None,
) -> Iterator[Path | Diagnostic]:
    """Yield repository-relative file paths, skipping anything that would
    resolve outside ``root`` instead of following it, enforcing ``bounds``
    (default: ``TraversalBounds()``) along the way, and honoring
    `.gitignore`, `.controlloopignore`, and ``cli_exclusions``.

    Order is deterministic -- sorted by name at every level -- regardless
    of filesystem iteration order.
    """

    active_bounds = bounds if bounds is not None else TraversalBounds()
    cli_exclusion_spec = ignore.compile_exclusions(cli_exclusions or [])

    try:
        root_entries = sorted(
            root.path.iterdir(), key=lambda entry: entry.name, reverse=True
        )
    except OSError as error:
        raise RepositoryRootError(
            f"repository root could not be listed: {root.path}"
        ) from error

    yield from _case_collision_diagnostics("", root_entries)

    root_ignore_level, root_problems = ignore.load_ignore_level(
        root.path, "", max_bytes=active_bounds.max_file_size_bytes
    )
    for problem in root_problems:
        yield _ignore_file_unusable_diagnostic(problem)

    # An explicit stack, not recursion: each frame is one directory's
    # remaining entries (stored reversed so `.pop()` yields ascending sorted
    # order), its repository-relative path, its depth, the set of canonical
    # directories visited on the path from the root to here (not a single
    # walk-wide set -- see the module docstring on cycle scope), and the
    # chain of ignore levels from the root down to and including this
    # directory's own `.gitignore`/`.controlloopignore`.
    stack: list[
        tuple[list[Path], str, int, frozenset[Path], tuple[ignore.IgnoreLevel, ...]]
    ] = [(root_entries, "", 0, frozenset({root.path}), (root_ignore_level,))]
    total_bytes = 0
    file_count = 0

    while stack:
        entries, relative_dir, depth, visited, ignore_levels = stack[-1]
        if not entries:
            stack.pop()
            continue
        entry = entries.pop()
        entry_relative = f"{relative_dir}/{entry.name}" if relative_dir else entry.name

        if not relative_dir and entry.name == _GIT_MARKER:
            yield _diagnostic(
                _IGNORED_CODE,
                entry_relative,
                "the repository root's .git is always excluded",
                severity=DiagnosticSeverity.INFO,
                incomplete=False,
            )
            continue

        try:
            resolved_entry = entry.resolve(strict=False)
        except OSError:
            yield _diagnostic(
                _UNREADABLE_CODE, entry_relative, "entry could not be resolved"
            )
            continue
        except RuntimeError:
            # `Path.resolve()` raises RuntimeError, not OSError,
            # specifically for a symlink loop -- reported by name, not
            # folded into the generic unreadable case, and not left to
            # crash the walk.
            yield _diagnostic(
                _SYMLINK_LOOP_CODE,
                entry_relative,
                "entry is a symlink that could not be resolved because of "
                "a loop; it was skipped",
            )
            continue

        try:
            resolved_entry.relative_to(root.path)
        except ValueError:
            yield _diagnostic(
                _ESCAPE_CODE,
                entry_relative,
                "entry resolves outside the repository root",
            )
            continue

        is_dir = entry.is_dir()
        if ignore.is_ignored(
            ignore_levels,
            entry_relative,
            is_directory=is_dir,
            cli_exclusions=cli_exclusion_spec,
        ):
            yield _diagnostic(
                _IGNORED_CODE,
                entry_relative,
                "excluded by .gitignore, .controlloopignore, or an explicit exclusion",
                severity=DiagnosticSeverity.INFO,
                incomplete=False,
            )
            continue

        if is_dir:
            if resolved_entry in visited:
                yield _diagnostic(
                    _CYCLE_CODE,
                    entry_relative,
                    "directory already visited on this path; skipping a "
                    "possible symlink cycle",
                )
                continue

            child_depth = depth + 1
            if child_depth > active_bounds.max_depth:
                yield _diagnostic(
                    _DEPTH_EXCEEDED_CODE,
                    entry_relative,
                    f"traversal depth {child_depth} exceeds the configured "
                    f"bound of {active_bounds.max_depth}; this subtree was "
                    "not explored",
                )
                continue

            try:
                child_entries = sorted(
                    entry.iterdir(), key=lambda child: child.name, reverse=True
                )
            except OSError:
                yield _diagnostic(
                    _UNREADABLE_CODE, entry_relative, "directory could not be listed"
                )
                continue

            yield from _case_collision_diagnostics(entry_relative, child_entries)

            child_ignore_level, child_problems = ignore.load_ignore_level(
                entry, entry_relative, max_bytes=active_bounds.max_file_size_bytes
            )
            for problem in child_problems:
                yield _ignore_file_unusable_diagnostic(problem, entry_relative)

            stack.append(
                (
                    child_entries,
                    entry_relative,
                    child_depth,
                    visited | {resolved_entry},
                    (*ignore_levels, child_ignore_level),
                )
            )
            continue

        try:
            entry_stat = resolved_entry.stat()
        except OSError:
            yield _diagnostic(
                _UNREADABLE_CODE, entry_relative, "entry could not be resolved"
            )
            continue

        special_kind = _special_file_kind(entry_stat.st_mode)
        if special_kind is not None:
            yield _diagnostic(
                _SPECIAL_FILE_CODE,
                entry_relative,
                f"entry resolves to a {special_kind} and was skipped "
                "without being opened",
                severity=DiagnosticSeverity.INFO,
                incomplete=False,
            )
            continue

        entry_size = entry_stat.st_size
        if entry_size > active_bounds.max_file_size_bytes:
            yield _diagnostic(
                _FILE_TOO_LARGE_CODE,
                entry_relative,
                f"file size {entry_size} bytes exceeds the configured "
                f"per-file bound of {active_bounds.max_file_size_bytes} "
                "bytes; this file was skipped",
            )
            continue

        if not resolved_entry.is_file():
            yield _diagnostic(
                _UNREADABLE_CODE,
                entry_relative,
                "entry is not a regular file and was not opened",
            )
            continue

        try:
            classification, archive_format = _sniff_content(resolved_entry)
        except OSError:
            yield _diagnostic(
                _UNREADABLE_CODE, entry_relative, "entry could not be resolved"
            )
            continue

        if classification == "archive":
            yield _diagnostic(
                _ARCHIVE_CODE,
                entry_relative,
                f"file matches the {archive_format} archive signature and "
                "was not expanded; this region is unexamined",
            )
            continue

        if classification == "binary":
            yield _diagnostic(
                _BINARY_CODE,
                entry_relative,
                "file content is binary and was skipped",
                severity=DiagnosticSeverity.INFO,
                incomplete=False,
            )
            continue

        if file_count + 1 > active_bounds.max_file_count:
            yield _diagnostic(
                _FILE_COUNT_EXCEEDED_CODE,
                entry_relative,
                "total file count would exceed the configured bound of "
                f"{active_bounds.max_file_count} files; the scan stopped "
                "here",
            )
            return

        if total_bytes + entry_size > active_bounds.max_total_bytes:
            yield _diagnostic(
                _TOTAL_BYTES_EXCEEDED_CODE,
                entry_relative,
                "total bytes read would exceed the configured bound of "
                f"{active_bounds.max_total_bytes} bytes; the scan stopped "
                "here",
            )
            return

        file_count += 1
        total_bytes += entry_size
        yield resolved_entry


def summarize_skips(
    results: Iterable[Path | Diagnostic],
) -> tuple[Diagnostic, ...]:
    """Return every skip diagnostic from a `walk_repository` call's
    results, deterministically ordered.

    `walk_repository` itself yields diagnostics interleaved with paths in
    traversal order; this filters and re-sorts by (path, code) so a
    caller who wants just the skips, independent of where in the
    traversal each one happened to occur, gets a stable, repeatable
    order. Every returned diagnostic's code is a `DIAGNOSTIC_REGISTRY`
    member and carries only a path and a reason, never skipped content
    -- the same guarantee every diagnostic in this module
    already keeps; this function does not add or relax it.
    """

    diagnostics = [item for item in results if isinstance(item, Diagnostic)]
    return tuple(
        sorted(
            diagnostics,
            key=lambda diagnostic: (diagnostic.evidence[0].path, diagnostic.code),
        )
    )


def _special_file_kind(mode: int) -> str | None:
    """Classify a `stat()` mode as a special file kind, or ``None``.

    Operates on an already-resolved target's mode, so it uniformly covers
    a direct special file and a symlink to one -- no symlink-specific
    branching needed.
    """

    if stat_module.S_ISCHR(mode) or stat_module.S_ISBLK(mode):
        return "device"
    if stat_module.S_ISSOCK(mode):
        return "socket"
    if stat_module.S_ISFIFO(mode):
        return "fifo"
    return None


def _sniff_content(path: Path) -> tuple[str, str | None]:
    """Classify a file's content from a bounded prefix, never its name.

    Returns ``("archive", format_name)``, ``("binary", None)``, or
    ``("text", None)``. Reads at most `_SNIFF_BYTES`, regardless of the
    file's actual size -- never a full read, and never a decompression
    attempt of anything matched as an archive.
    """

    with path.open("rb") as handle:
        prefix = handle.read(_SNIFF_BYTES)

    for name, magic, offset in _ARCHIVE_SIGNATURES:
        end = offset + len(magic)
        if len(prefix) >= end and prefix[offset:end] == magic:
            return "archive", name

    if _BINARY_NULL_BYTE in prefix:
        return "binary", None

    return "text", None


def _ignore_file_unusable_diagnostic(
    problem: ignore.UnusableFile, relative_dir: str = ""
) -> Diagnostic:
    relative_path = f"{relative_dir}/{problem.name}" if relative_dir else problem.name
    reason = (
        "exceeds the per-file size bound"
        if problem.status == "too-large"
        else "could not be read"
    )
    return _diagnostic(
        _IGNORE_FILE_UNUSABLE_CODE,
        relative_path,
        f"ignore file {reason} and contributed no rules",
        incomplete=False,
    )


def _diagnostic(
    code: str,
    relative_path: str,
    message: str,
    *,
    severity: DiagnosticSeverity = DiagnosticSeverity.WARNING,
    incomplete: bool = True,
) -> Diagnostic:
    return Diagnostic(
        code=code,
        severity=severity,
        message=message,
        confidence=Confidence.HIGH,
        incomplete=incomplete,
        evidence=(Evidence(adapter=_ADAPTER, path=_safe_evidence_path(relative_path)),),
    )


# Unicode general categories treated as hostile: Cc (control, including the
# ASCII control range RelativePath itself already rejects), Cf (format --
# right-to-left/left-to-right override, zero-width characters, and similar),
# and Cs (surrogate -- what Python's surrogateescape error handler produces
# for a filesystem byte that is not valid UTF-8, e.g. a non-UTF-8 filename
# on a filesystem that permits one; a lone surrogate cannot even be encoded
# as a Python string for pydantic-core's own validation, so this is not
# optional hardening, it is the same category of crash this escaping
# exists to prevent).
_HOSTILE_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})

# RelativePath's own compatibility-sensitive contract (controlloop.acbom.models):
# this module never emits an Evidence.path that could fail it, so this bound
# mirrors that contract's max_length rather than inventing an independent one.
_MAX_EVIDENCE_PATH_LENGTH = 512
_TRUNCATION_PREFIX = "[truncated]"


def _escape_hostile_characters(text: str) -> str:
    """Replace control and Unicode bidi/format characters with a printable
    marker, never a raw pass-through.

    Deliberately does not use a backslash-based escape (`\\xHH`):
    `RelativePath`'s own pattern rejects any backslash, so a fix that used
    one would just move the crash this exists to prevent, not remove it.
    """

    escaped_characters = [
        f"<U+{ord(character):04X}>"
        if unicodedata.category(character) in _HOSTILE_UNICODE_CATEGORIES
        else character
        for character in text
    ]
    return "".join(escaped_characters)


def _bound_evidence_path(escaped: str) -> str:
    """Truncate an already-escaped path to fit `RelativePath`'s length
    limit, keeping the end closest to the actual
    filename rather than a directory prefix that identifies nothing."""

    if len(escaped) <= _MAX_EVIDENCE_PATH_LENGTH:
        return escaped
    keep = _MAX_EVIDENCE_PATH_LENGTH - len(_TRUNCATION_PREFIX)
    return _TRUNCATION_PREFIX + escaped[-keep:]


def _safe_evidence_path(relative_path: str) -> str:
    return _bound_evidence_path(_escape_hostile_characters(relative_path))


def _case_collision_diagnostics(
    relative_dir: str, entries: list[Path]
) -> Iterator[Diagnostic]:
    """Flag sibling entries that differ only by case.

    Both/all colliding entries are still walked normally by the caller
    afterward -- this reports a portability risk (a case-insensitive
    filesystem elsewhere could collide or lose one of them), it does not
    drop either one from this scan's own results.
    """

    groups: dict[str, list[str]] = {}
    for entry in entries:
        groups.setdefault(entry.name.casefold(), []).append(entry.name)

    for names in groups.values():
        if len(names) < 2:
            continue
        ordered_names = sorted(names)
        yield Diagnostic(
            code=_CASE_COLLISION_CODE,
            severity=DiagnosticSeverity.WARNING,
            message=(
                f"{len(ordered_names)} entries in this directory differ "
                "only by case and may collide, duplicate, or silently "
                "lose one another on a case-insensitive filesystem"
            ),
            confidence=Confidence.HIGH,
            incomplete=False,
            evidence=tuple(
                Evidence(
                    adapter=_ADAPTER,
                    path=_safe_evidence_path(
                        f"{relative_dir}/{name}" if relative_dir else name
                    ),
                )
                for name in ordered_names
            ),
        )
