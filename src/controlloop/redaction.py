"""Single redaction boundary for user-facing ControlLoop emission.

This module is the one place allowed to know what a secret, a source line,
or a full ACBOM document looks like well enough to keep it out of anything a
user or CI system sees. Everything else must go through it:

- ``redirected_streams`` wraps process stdout/stderr so every line this
  process writes -- through ``print``, ``click``/``typer`` echo, or a direct
  ``sys.stdout.write`` -- is scanned for known credential shapes before it
  reaches the real stream. No call site can opt out once the wrapper is
  installed, because the wrapper *is* ``sys.stdout``/``sys.stderr`` for the
  duration of the ``with`` block.
- ``redact_text`` is the scan-and-replace primitive the streams use, and is
  also available directly for text that will not pass through stdout/stderr
  (for example, a future structured report renderer).
- ``source_reference`` builds the only sanctioned textual description of a
  source location: a path and an optional line range. Its signature has no
  parameter for the line's content, so a caller cannot pass source text
  through it even by mistake.
- ``document_reference`` and ``acbom_document_reference`` build the only
  sanctioned textual description of an ACBOM document: its canonical SHA-256
  digest. Neither accepts document content.
- ``scan_credential_shapes`` is the one sanctioned way
  for another module to ask "does this text contain something shaped like a
  known credential, and where" -- returning each match's shape ``name`` and
  character offsets only, never the matched substring, so a caller (for
  example ``controlloop.secret_scan``) can report a location without this
  module ever handing back the value it protects.

Known-credential-shape matching in this module is signature based (fixed
prefixes and formats published by the issuing services), not entropy based,
so it needs no confidence threshold: a match either has the shape of a real
credential format or it does not. The pattern set is an initial, intentionally
narrow baseline and grows only through a separate, explicitly approved
change, the same rule that governs every other detection surface in this
repository.
"""

from __future__ import annotations

import hashlib
import io
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TextIO

from controlloop.acbom.models import ACBOMDocument
from controlloop.acbom.serialization import compute_digest

_PLACEHOLDER_SALT = b"controlloop.redaction.v1"
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class _CredentialShape:
    """One known, signature-matched credential format."""

    name: str
    pattern: re.Pattern[str]


_CREDENTIAL_SHAPES: tuple[_CredentialShape, ...] = (
    _CredentialShape(
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    _CredentialShape(
        "github-token",
        re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{36}\b"),
    ),
    _CredentialShape(
        "github-fine-grained-token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
    ),
    _CredentialShape(
        "slack-token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b"),
    ),
    _CredentialShape(
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    _CredentialShape(
        "stripe-secret-key",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,99}\b"),
    ),
    _CredentialShape(
        "private-key-block",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
            r"[\s\S]*?"
            r"-----END [A-Z ]*PRIVATE KEY-----"
        ),
    ),
    _CredentialShape(
        "json-web-token",
        re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    # Neither vendor publishes a formal key grammar; these
    # follow the secret-scanning rules the industry uses. Anthropic keys
    # are a versioned prefix, 93 characters, and a fixed `AA` tail.
    _CredentialShape(
        "anthropic-api-key",
        re.compile(r"\bsk-ant-api03-[A-Za-z0-9_-]{93}AA\b"),
    ),
    _CredentialShape(
        "anthropic-admin-key",
        re.compile(r"\bsk-ant-admin01-[A-Za-z0-9_-]{93}AA\b"),
    ),
    # OpenAI keys embed `T3BlbkFJ` (base64 of "OpenAI"). Scoped keys put
    # it between two segments whose length has changed before, so the
    # segments are a bounded range rather than one fixed length.
    _CredentialShape(
        "openai-api-key",
        re.compile(
            r"\bsk-(?:proj|svcacct|admin|None)-"
            r"[A-Za-z0-9_-]{20,200}T3BlbkFJ[A-Za-z0-9_-]{20,200}\b"
        ),
    ),
    _CredentialShape(
        "openai-legacy-api-key",
        re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    ),
)


def known_credential_shapes() -> tuple[str, ...]:
    """Return the names of every known credential shape this boundary detects."""

    return tuple(shape.name for shape in _CREDENTIAL_SHAPES)


#: `scan_credential_shapes`'s own performance primitive (a real, measured
#: need: `controlloop.secret_scan` calls
#: this once per repository file, and a naive implementation that ran
#: each of `_CREDENTIAL_SHAPES`' patterns as its own independent full-text
#: `finditer` pass -- as `redact_text` above still deliberately does, since
#: its own already-audited substitution behavior is not touched here --
#: measurably regressed this repository's own committed `scan` performance
#: benchmark on a realistic repository size). One pre-compiled alternation
#: over every shape's own unmodified pattern source, each wrapped in its
#: own named group, so one `finditer` pass finds every shape in a single
#: left-to-right scan of `text` instead of `len(_CREDENTIAL_SHAPES)` full
#: passes. Each shape's own pattern is embedded unchanged (no shape is
#: redefined here, only combined), and every shape below is anchored by a
#: distinct literal prefix (`AKIA`/`ASIA`, `gh[oprsu]_`, `github_pat_`,
#: `xox[baprs]-`, `AIza`, `sk_(?:live|test)_`, `-----BEGIN`, `ey`,
#: `sk-ant-api03-`, `sk-ant-admin01-`, `sk-(?:proj|svcacct|admin|None)-`,
#: and `sk-` followed by an alphanumeric run -- the legacy OpenAI shape,
#: which therefore cannot match where `sk-ant-` or `sk-proj-` begins,
#: because a hyphen follows those prefixes' first word), so
#: combining them via top-level alternation cannot change *which*
#: substrings match relative to running each pattern independently --
#: only, harmlessly, the *order* distinct shapes are reported in when more
#: than one appears in the same text (position-in-text order across all
#: shapes, rather than shape-declaration order then position -- disclosed
#: since `scan_credential_shapes` has no other caller yet to depend on the
#: original ordering).
_COMBINED_CREDENTIAL_PATTERN = re.compile(
    "|".join(
        f"(?P<shape{index}>{shape.pattern.pattern})"
        for index, shape in enumerate(_CREDENTIAL_SHAPES)
    )
)
_SHAPE_NAME_BY_GROUP: dict[str, str] = {
    f"shape{index}": shape.name for index, shape in enumerate(_CREDENTIAL_SHAPES)
}


@dataclass(frozen=True, slots=True)
class CredentialShapeMatch:
    """One known-credential-shape match location -- **never** the matched
    value itself. Carries only the shape's own stable ``name`` (from
    ``known_credential_shapes()``) and the half-open character offsets
    ``[start, end)`` into the scanned text, so a caller (for example
    ``controlloop.secret_scan``) can compute a line number and build
    evidence without this module ever handing back the substring that
    matched.
    """

    name: str
    start: int
    end: int


def scan_credential_shapes(text: str) -> tuple[CredentialShapeMatch, ...]:
    """Return every known-credential-shape match in ``text``, as name and
    offsets only.

    This is the one sanctioned way for another module to ask "does this
    text contain something shaped like a known credential, and where" --
    reusing the exact signature-based pattern set ``redact_text`` already
    uses (each shape's own pattern source, unmodified, combined into one
    pre-compiled alternation for performance -- see
    ``_COMBINED_CREDENTIAL_PATTERN``'s own comment), rather than a second
    copy of it living somewhere else in this codebase. The matched
    substring itself is never returned, stored, or otherwise exposed by
    this function; only its shape name and location. Matches are returned
    in left-to-right position order across every shape -- deterministic
    for identical input, never dependent on Python's own regex engine
    internals beyond ordinary left-to-right, non-overlapping
    ``re.finditer`` semantics.
    """

    matches: list[CredentialShapeMatch] = []
    for match in _COMBINED_CREDENTIAL_PATTERN.finditer(text):
        group_name = match.lastgroup
        assert group_name is not None  # every alternative is a named group
        matches.append(
            CredentialShapeMatch(
                name=_SHAPE_NAME_BY_GROUP[group_name],
                start=match.start(),
                end=match.end(),
            )
        )
    return tuple(matches)


def stable_placeholder(secret: str) -> str:
    """Return a stable, non-reversible placeholder for a matched secret value.

    The same input always produces the same placeholder, so a reviewer can
    tell that two redacted occurrences came from the same secret without
    ever seeing the secret. The placeholder is a salted SHA-256 digest of the
    full value; nothing is truncated or partially retained.
    """

    if not secret:
        raise ValueError("redaction placeholder requires a nonempty secret value")
    digest = hashlib.sha256(
        _PLACEHOLDER_SALT + secret.encode("utf-8", errors="surrogatepass")
    ).hexdigest()
    return f"[controlloop:redacted:sha256:{digest}]"


def _replace_match(match: re.Match[str]) -> str:
    return stable_placeholder(match.group(0))


def redact_text(text: str) -> str:
    """Return ``text`` with every known credential shape replaced in place.

    Each match is replaced in full; no prefix, suffix, or length-revealing
    fragment of the original value is retained.
    """

    redacted = text
    for shape in _CREDENTIAL_SHAPES:
        redacted = shape.pattern.sub(_replace_match, redacted)
    return redacted


class RedactingTextIO:
    """A write-only text stream that redacts before delegating to a target."""

    def __init__(self, target: TextIO) -> None:
        self._target = target
        self.encoding = getattr(target, "encoding", "utf-8") or "utf-8"
        self.errors = getattr(target, "errors", "strict") or "strict"

    def write(self, text: str) -> int:
        self._target.write(redact_text(text))
        return len(text)

    def flush(self) -> None:
        self._target.flush()

    def isatty(self) -> bool:
        isatty = getattr(self._target, "isatty", None)
        return bool(isatty()) if isatty is not None else False

    def fileno(self) -> int:
        fileno = getattr(self._target, "fileno", None)
        if fileno is None:
            raise io.UnsupportedOperation("fileno")
        return int(fileno())

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False


@contextmanager
def redirected_streams(
    *,
    target_stdout: TextIO | None = None,
    target_stderr: TextIO | None = None,
) -> Iterator[None]:
    """Install the redaction boundary as process stdout and stderr.

    Every line written through ``sys.stdout``/``sys.stderr`` for the
    duration of the ``with`` block -- regardless of which emission API a
    caller uses -- is redacted before it reaches ``target_stdout`` /
    ``target_stderr`` (the real streams by default). The previous streams
    are restored on exit, including on an exception.
    """

    previous_stdout, previous_stderr = sys.stdout, sys.stderr
    sys.stdout = RedactingTextIO(
        target_stdout if target_stdout is not None else previous_stdout
    )
    sys.stderr = RedactingTextIO(
        target_stderr if target_stderr is not None else previous_stderr
    )
    try:
        yield
    finally:
        sys.stdout = previous_stdout
        sys.stderr = previous_stderr


def source_reference(
    path: str, *, line_start: int | None = None, line_end: int | None = None
) -> str:
    """Return the only sanctioned text description of a source location.

    This always renders as a path, optionally followed by a line or line
    range. There is no parameter for the line's own content, so a caller
    cannot pass source text through this function even by mistake.
    """

    if line_start is None and line_end is not None:
        raise ValueError("source reference line end requires a line start")
    if line_start is not None and line_end is not None and line_end < line_start:
        raise ValueError("source reference line end must not precede line start")
    if line_start is None:
        return path
    if line_end is None or line_end == line_start:
        return f"{path}:{line_start}"
    return f"{path}:{line_start}-{line_end}"


def document_reference(digest: str) -> str:
    """Return the only sanctioned text description of an ACBOM document.

    This accepts a canonical ``sha256:<hex>`` digest, never a document or
    its serialized content, and rejects anything that is not already in
    that digest shape.
    """

    if not _DIGEST_PATTERN.fullmatch(digest):
        raise ValueError("document reference requires a canonical sha256 digest")
    return f"document:{digest}"


def acbom_document_reference(document: ACBOMDocument) -> str:
    """Return the sanctioned digest reference for a canonical ACBOM document."""

    return document_reference(compute_digest(document))
