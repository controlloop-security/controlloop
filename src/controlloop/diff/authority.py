"""The authority delta's data model.

Kept apart from `controlloop.reporting.authority`, which computes it, so
`controlloop.diff.report.DiffReport` can carry the section without the
diff layer importing the reporting layer.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from controlloop.acbom.models import Confidence, SemanticVersion
from controlloop.capability.taxonomy import MaterialCapabilityClass

CURRENT_AUTHORITY_DELTA_SCHEMA_VERSION = "1.0.0"


class _AuthorityModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class AuthorityEntry(_AuthorityModel):
    """One new or changed grant. `node_id` is the ACBOM node that holds it,
    so a finding about the same component can carry the statement."""

    node_id: str
    host_id: str | None
    host_name: str
    kind: str
    change: str
    grant: str
    #: The kind of power the grant hands over, in the material capability
    #: taxonomy's vocabulary (`docs/reference/material-capability-taxonomy.md`).
    material_class: MaterialCapabilityClass
    statement: str
    path: str
    key_path: str
    detail: str
    approval_recorded: bool | None
    confidence: Confidence


class AuthorityDelta(_AuthorityModel):
    """Every new or changed grant in a change, ordered by host, file, and
    key path. Never empty: an empty delta is `None`."""

    schema_version: SemanticVersion
    entries: tuple[AuthorityEntry, ...]


__all__ = [
    "CURRENT_AUTHORITY_DELTA_SCHEMA_VERSION",
    "AuthorityDelta",
    "AuthorityEntry",
]
