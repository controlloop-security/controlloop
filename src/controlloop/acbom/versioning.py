"""Schema version compatibility for canonical ACBOM documents.

`schema_version` follows semantic versioning. A reader can always read a
document at or below its own version within the same major line; a
document from a different major, or a newer minor within the same major,
is rejected before any full parse is attempted, rather than surfacing a
confusing `extra_forbidden` error partway through one (`_CanonicalModel`
uses `extra="forbid"`, so an older reader cannot simply ignore a field it
does not recognize). The full policy is documented in
`docs/reference/schema-versioning.md`.
"""

from __future__ import annotations

import json

from pydantic import ValidationError as PydanticValidationError

from controlloop.acbom.models import ACBOMDocument
from controlloop.acbom.serialization import canonicalize_document, compute_digest
from controlloop.exit_codes import ExitCode

CURRENT_SCHEMA_VERSION = "1.2.0"
"""Bumped from 1.1.0 for the agent authority
contract (four `SecurityAttributes` flags, `Node.attributes`, and the
`AuthoritySubtype` shapes), all optional and backward-compatible. The
frozen 1.0.0 and 1.1.0 schema files are never edited;
`src/controlloop/schemas/acbom/1.2.0/` is the current schema. Bumped
from 1.0.0 to 1.1.0 for `ACBOMDocument.schema_url`."""

CURRENT_SCHEMA_URL = (
    f"https://schemas.controlloop.ai/acbom/{CURRENT_SCHEMA_VERSION}/acbom.schema.json"
)
"""The permanent, versioned URL this exact schema version is published
at. Every document this codebase generates populates `ACBOMDocument.
schema_url` with this value."""


class IncompatibleSchemaVersionError(ValueError):
    """A document's schema version cannot be read by this reader.

    Carries the exit code this condition maps to (`ExitCode.INVALID_INPUT`)
    so the intended CLI behavior is documented and tested even before any
    command reads a real ACBOM document.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INVALID_INPUT


class ACBOMIntegrityError(ValueError):
    """A document that is not a well-formed, untampered ACBOM: invalid
    JSON, a structure the schema rejects, or a declared `digest` that does
    not match a fresh recomputation.

    The message is always one line of plain text, so a caller can show it
    to an operator as-is. Carries `ExitCode.INVALID_INPUT`, like
    `IncompatibleSchemaVersionError`.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INVALID_INPUT


def _schema_error_summary(error: PydanticValidationError) -> str:
    """One line naming the first schema error's location and reason,
    plus how many more there are -- pydantic's own rendering spans
    several lines and links to its documentation."""

    errors = error.errors(include_url=False)
    if not errors:
        return "the document does not match the ACBOM schema"
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "document"
    reason = " ".join(str(first.get("msg", "invalid value")).split())
    summary = f"the document does not match the ACBOM schema at {location}: {reason}"
    remaining = len(errors) - 1
    if remaining:
        summary += f" (and {remaining} more error{'s' if remaining != 1 else ''})"
    return summary


def _major_minor(version: str, *, label: str) -> tuple[int, int]:
    try:
        major_text, minor_text = version.split(".", 2)[:2]
        return int(major_text), int(minor_text)
    except (ValueError, IndexError):
        raise IncompatibleSchemaVersionError(
            f"{label} {version!r} is not a readable schema version"
        ) from None


def check_schema_version_compatible(
    document_version: str,
    *,
    reader_version: str = CURRENT_SCHEMA_VERSION,
) -> None:
    """Raise `IncompatibleSchemaVersionError` unless `document_version`
    is readable by `reader_version`.

    Compatible means the same major version, and a document minor at or
    below the reader's minor -- a document from a newer minor may carry
    an additive field this reader does not know about.
    """

    document_major, document_minor = _major_minor(document_version, label="document")
    reader_major, reader_minor = _major_minor(reader_version, label="reader")

    if document_major != reader_major:
        raise IncompatibleSchemaVersionError(
            f"schema version {document_version} has a different major "
            f"version than this reader supports ({reader_version})"
        )
    if document_minor > reader_minor:
        raise IncompatibleSchemaVersionError(
            f"schema version {document_version} is newer than this "
            f"reader supports ({reader_version})"
        )


def load_acbom_document(
    raw: str | bytes,
    *,
    reader_version: str = CURRENT_SCHEMA_VERSION,
) -> ACBOMDocument:
    """Return the parsed `ACBOMDocument` in `raw`, after checking schema
    version compatibility -- never partially parsing an incompatible
    document -- and its integrity.

    Raises `IncompatibleSchemaVersionError` for a version this reader
    cannot read, and `ACBOMIntegrityError` for invalid JSON, a document
    the schema rejects, or a declared `digest` that does not match the
    document's content: an ACBOM edited after it was generated is never
    returned as if it were the one ControlLoop produced. Both are
    `ValueError`s with a single-line message.
    """

    try:
        envelope = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise ACBOMIntegrityError(
            "the document is truncated or not valid JSON"
        ) from None
    document_version = (
        envelope.get("schema_version") if isinstance(envelope, dict) else None
    )
    if not isinstance(document_version, str):
        raise IncompatibleSchemaVersionError(
            "document has no readable schema_version field"
        )
    check_schema_version_compatible(document_version, reader_version=reader_version)
    try:
        document = ACBOMDocument.model_validate_json(raw)
    except PydanticValidationError as error:
        raise ACBOMIntegrityError(_schema_error_summary(error)) from None
    if compute_digest(canonicalize_document(document)) != document.digest:
        raise ACBOMIntegrityError(
            "the document's digest does not match its content -- it was "
            "edited after it was generated, or is corrupted"
        )
    return document
