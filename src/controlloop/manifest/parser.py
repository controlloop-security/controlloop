"""Parses and validates a `controlloop.yaml` manifest.

Checks schema-version compatibility before attempting a full parse,
mirroring `controlloop.acbom.versioning.load_acbom_document`'s own order
exactly, and reuses `check_schema_version_compatible` directly (already
generic, not ACBOM-specific) rather than a second copy of the same
compatibility policy -- so the manifest follows the ACBOM's
compatibility policy by construction. Error messages never echo raw
YAML/pydantic exception text or manifest field values, matching the
adapters' "no source snippets or raw parser errors in output" discipline
(`docs/adapters/readme.md`).
"""

from __future__ import annotations

import json

import yaml
from pydantic import ValidationError

from controlloop.acbom import (
    IncompatibleSchemaVersionError,
    check_schema_version_compatible,
)
from controlloop.bounded_recursion import bounded_recursion
from controlloop.exit_codes import ExitCode
from controlloop.manifest.models import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    ManifestDocument,
)


class ManifestValidationError(ValueError):
    """`path` could not be validated as a `controlloop.yaml` manifest.

    Carries `exit_code = ExitCode.INVALID_INPUT`, mirroring
    `IncompatibleSchemaVersionError`'s existing shape.
    """

    def __init__(self, message: str, *, path: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INVALID_INPUT
        self.path = path


def load_manifest(
    raw: str,
    *,
    path: str,
    reader_version: str = CURRENT_MANIFEST_SCHEMA_VERSION,
) -> ManifestDocument:
    """Return the parsed `ManifestDocument` in `raw`, after checking
    schema version compatibility -- never partially parsing an
    incompatible or malformed document."""

    try:
        # bounded_recursion caps how many recursive calls PyYAML's
        # pure-Python parser can make before raising, independent of
        # per-frame overhead (coverage, profilers) -- otherwise a
        # pathologically deep flow-collection nesting (e.g. a long run
        # of "{") can take arbitrarily long to raise its own
        # RecursionError rather than failing fast. The margin (500) is
        # far beyond any legitimate manifest's nesting depth.
        with bounded_recursion(margin=500):
            payload = yaml.safe_load(raw)
    except (yaml.YAMLError, RecursionError):
        # RecursionError is not a yaml.YAMLError -- caught here too so
        # nothing but ManifestValidationError ever escapes.
        raise ManifestValidationError(
            f"{path} could not be parsed as YAML", path=path
        ) from None

    if not isinstance(payload, dict):
        raise ManifestValidationError(
            f"{path} did not parse into a document", path=path
        )

    document_version = payload.get("schema_version")
    if not isinstance(document_version, str):
        raise ManifestValidationError(
            f"{path} has no readable schema_version field", path=path
        )

    try:
        check_schema_version_compatible(document_version, reader_version=reader_version)
    except IncompatibleSchemaVersionError:
        raise ManifestValidationError(
            f"{path} declares a schema version this reader cannot read", path=path
        ) from None

    try:
        # model_validate_json (not model_validate on the raw YAML-parsed
        # Python object) so a YAML sequence -- a Python list -- validates
        # against a tuple-typed field under strict mode, exactly matching
        # controlloop.acbom.versioning.load_acbom_document's own approach.
        return ManifestDocument.model_validate_json(json.dumps(payload))
    except ValidationError:
        raise ManifestValidationError(
            f"{path} does not match the manifest schema", path=path
        ) from None
