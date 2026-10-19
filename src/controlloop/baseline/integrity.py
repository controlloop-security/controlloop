"""Tamper and truncation detection for baseline documents.

A supplied baseline is either fully verified or rejected outright at
exit 2 (`ExitCode.INVALID_INPUT`); `load_baseline_document` never
returns a partially parsed or partially validated document. Three
distinct failure categories are all normalized to the same outcome:

- truncated or unreadable bytes (invalid JSON, or a non-UTF-8 decode);
- a malformed document (an incompatible schema version, or a document
  that fails `BaselineDocument`'s structural validation); and
- a tampered document (parses and validates structurally, but its
  declared `digest` does not match a fresh recomputation over its own
  canonical bytes).

This module verifies already-supplied bytes/text; it does not open a
file, resolve a path, or wire into any CLI command -- reading a baseline
from disk and resolving "the" baseline for a repository are
`controlloop.baseline.resolution`'s job.
"""

from __future__ import annotations

import json

from pydantic import ValidationError as PydanticValidationError

from controlloop.acbom.versioning import (
    IncompatibleSchemaVersionError,
    check_schema_version_compatible,
)
from controlloop.baseline.models import (
    CURRENT_BASELINE_SCHEMA_VERSION,
    BaselineDocument,
)
from controlloop.baseline.serialization import (
    canonicalize_baseline,
    compute_baseline_digest,
)
from controlloop.bounded_recursion import bounded_recursion
from controlloop.exit_codes import ExitCode


class BaselineIntegrityError(ValueError):
    """A baseline document cannot be trusted: truncated, malformed, an
    incompatible schema version, or tampered (digest mismatch).

    Carries `exit_code = ExitCode.INVALID_INPUT` so every caller maps
    this condition to the same exit code without re-deriving it,
    mirroring
    `controlloop.acbom.versioning.IncompatibleSchemaVersionError`'s own
    pattern of documenting its intended CLI exit code before any command
    consumes it.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INVALID_INPUT


def load_baseline_document(
    raw: str | bytes,
    *,
    reader_version: str = CURRENT_BASELINE_SCHEMA_VERSION,
) -> BaselineDocument:
    """Return the parsed, integrity-verified `BaselineDocument` in `raw`.

    Never returns a document whose declared digest does not match a
    fresh recomputation, and never partially parses an incompatible
    schema version or a structurally malformed document. Raises
    `BaselineIntegrityError` (exit 2) for every failure category.
    """

    try:
        # bounded_recursion caps how many recursive calls the JSON
        # decoder can make before raising, independent of per-frame
        # overhead (coverage, profilers) -- otherwise pathologically deep
        # nesting (e.g. a long run of "[") can take arbitrarily long to
        # raise its own RecursionError rather than failing fast. The
        # margin (500) is far beyond any legitimate
        # baseline document's nesting depth.
        with bounded_recursion(margin=500):
            envelope = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        # RecursionError is not a JSONDecodeError -- caught here too so
        # nothing but BaselineIntegrityError is ever raised.
        raise BaselineIntegrityError(
            "baseline document is truncated or not valid JSON"
        ) from error

    document_version = (
        envelope.get("schema_version") if isinstance(envelope, dict) else None
    )
    if not isinstance(document_version, str):
        raise BaselineIntegrityError(
            "baseline document has no readable schema_version field"
        )

    try:
        check_schema_version_compatible(document_version, reader_version=reader_version)
    except IncompatibleSchemaVersionError as error:
        raise BaselineIntegrityError(str(error)) from error

    try:
        # `model_validate_json` (not `model_validate` on the already-parsed
        # `envelope` dict) so JSON-mode list -> tuple coercion applies under
        # this model's `strict=True` config -- the same reason
        # `controlloop.acbom.versioning.load_acbom_document` validates the
        # original raw text rather than a pre-parsed object.
        document = BaselineDocument.model_validate_json(raw)
    except PydanticValidationError as error:
        raise BaselineIntegrityError(
            "baseline document failed structural validation"
        ) from error

    canonical = canonicalize_baseline(document)
    recomputed_digest = compute_baseline_digest(canonical)
    if recomputed_digest != canonical.digest:
        raise BaselineIntegrityError(
            "baseline digest does not match its recomputed canonical "
            "digest -- the document is tampered or corrupted"
        )

    return canonical
