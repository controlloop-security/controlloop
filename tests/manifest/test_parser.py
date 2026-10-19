"""Tests for controlloop.manifest.parser."""

from __future__ import annotations

import pytest

from controlloop.exit_codes import ExitCode
from controlloop.manifest import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    ManifestValidationError,
    load_manifest,
)

_VALID_MANIFEST = f"""
schema_version: "{CURRENT_MANIFEST_SCHEMA_VERSION}"
owner: security-team
"""


def test_valid_manifest_parses() -> None:
    """A minimal valid manifest parses."""
    document = load_manifest(_VALID_MANIFEST, path="controlloop.yaml")

    assert document.owner == "security-team"


def test_invalid_yaml_raises_with_exit_code_and_path() -> None:
    """Exit 2, naming the failing path."""
    with pytest.raises(ManifestValidationError) as excinfo:
        load_manifest("{ not valid yaml : [", path="controlloop.yaml")

    assert excinfo.value.exit_code == ExitCode.INVALID_INPUT
    assert excinfo.value.path == "controlloop.yaml"


def test_non_mapping_document_is_rejected() -> None:
    """A document that is not a mapping is rejected with exit 2."""
    with pytest.raises(ManifestValidationError) as excinfo:
        load_manifest("- just\n- a\n- list\n", path="controlloop.yaml")

    assert excinfo.value.exit_code == ExitCode.INVALID_INPUT


def test_missing_schema_version_is_rejected() -> None:
    """A document without `schema_version` is rejected with exit 2."""
    with pytest.raises(ManifestValidationError) as excinfo:
        load_manifest("owner: security-team\n", path="controlloop.yaml")

    assert excinfo.value.exit_code == ExitCode.INVALID_INPUT


def test_schema_violation_is_rejected() -> None:
    """A document with a syntactically valid but schema-invalid shape (owner
    is not a string) is still rejected with exit 2."""
    with pytest.raises(ManifestValidationError) as excinfo:
        load_manifest(
            f'schema_version: "{CURRENT_MANIFEST_SCHEMA_VERSION}"\nowner: [1, 2]\n',
            path="controlloop.yaml",
        )

    assert excinfo.value.exit_code == ExitCode.INVALID_INPUT


def test_different_major_version_is_rejected() -> None:
    """Same compatibility policy as the ACBOM -- a different major version
    is never readable."""
    with pytest.raises(ManifestValidationError):
        load_manifest(
            'schema_version: "2.0.0"\nowner: security-team\n',
            path="controlloop.yaml",
        )


def test_newer_minor_version_is_rejected() -> None:
    """A newer minor version than the reader's is rejected."""
    with pytest.raises(ManifestValidationError):
        load_manifest(
            'schema_version: "1.99.0"\nowner: security-team\n',
            path="controlloop.yaml",
        )


def test_older_minor_version_is_readable() -> None:
    """A document at or below the reader's minor is always readable,
    matching `check_schema_version_compatible`'s policy."""
    document = load_manifest(
        'schema_version: "1.0.0"\nowner: security-team\n',
        path="controlloop.yaml",
        reader_version="1.5.0",
    )

    assert document.owner == "security-team"


def test_error_message_never_echoes_manifest_content() -> None:
    """Privacy discipline: no raw YAML/pydantic parser error text or
    manifest field values in the exception message, matching the
    adapters' 'no source snippets or raw parser errors' rule."""
    planted_secret = "AKIA-planted-secret-shaped-value-should-never-appear"
    with pytest.raises(ManifestValidationError) as excinfo:
        load_manifest(f"owner: {planted_secret}\n", path="controlloop.yaml")

    assert planted_secret not in str(excinfo.value)
