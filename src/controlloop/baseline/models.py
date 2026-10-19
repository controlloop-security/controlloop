"""Immutable canonical models for the baseline artifact, schema version
1.1.0, including approval provenance.

A baseline is the versioned, canonical record of an approved capability
set: the ACBOM digest and schema version it was computed from, the
direct effective authority set it asserts (`controlloop.capability`'s
already-tested model, not redefined here), the scanner that produced
it, the commit it describes, and (from schema 1.1.0 on) who approved
it, when, and at what commit. It reuses `controlloop.acbom`'s own
envelope primitives (`Generator`, `Repository`, `Sha256Digest`,
`SemanticVersion`, `SafeText`) rather than redefining them, and follows
the same model discipline (`extra="forbid", frozen=True, strict=True`)
as both `controlloop.acbom.models._CanonicalModel` and
`controlloop.capability.models._CapabilityModel`.

See docs/reference/baseline-artifact-format.md, written before this
model so that the versioned contract was defined before
implementation, not after.

## Why the schema version is 1.1.0, not 1.0.0

Schema 1.1.0 adds a new optional field (`provenance`) to
`BaselineDocument`. Per docs/reference/schema-versioning.md, a
backward-compatible addition is a MINOR bump: "a reader can read any
document at or below its own minor version, within the same major."
Leaving `CURRENT_BASELINE_SCHEMA_VERSION` at `"1.0.0"` while adding a
field would be actively wrong, not merely conservative -- every canonical
model here uses `extra="forbid"`, so a genuinely older `"1.0.0"`
implementation handed a document carrying an unrecognized `provenance`
field would raise a raw, confusing `extra_forbidden` error instead of the
clean version-gate rejection
`controlloop.baseline.integrity.load_baseline_document` is built to give.
Bumping to `"1.1.0"` keeps that guarantee: an old `"1.0.0"` document (no
`provenance` field at all, such as this package's own
`minimal-baseline.json` fixture) is still read successfully by the
current `"1.1.0"` default reader -- `provenance` simply resolves to
`None`, which is the "missing provenance" case, not an error.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from controlloop.acbom.models import (
    Generator,
    Repository,
    SafeText,
    SemanticVersion,
    Sha256Digest,
)
from controlloop.capability.models import EffectiveAuthorityEntry

CURRENT_BASELINE_SCHEMA_VERSION = "1.1.0"

_MAX_EFFECTIVE_AUTHORITY_ENTRIES = 10_000
"""Mirrors `ACBOMDocument.nodes`'s bound: effective authority entries are
keyed by (agent, resource) pairs drawn from the same node population a
single ACBOM can carry, so the same ceiling is a natural, generous bound
here too."""


class _BaselineModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class ApproverSource(StrEnum):
    """Whether a recorded approver identity was directly supplied by a
    human, or inferred by some future automated mechanism. An approver
    identity is recorded as supplied and is never inferred from git
    history without saying it was inferred.

    No code in this repository infers an approver identity from git
    history or anywhere else today; this enum exists so that if a
    future change adds inference, it has an honest, structurally
    available way to say so, and so `controlloop.baseline.provenance`'s
    render helper can always qualify a displayed approver as one or the
    other rather than asserting an unqualified identity.

    Deliberately *not* the type of `ApprovalProvenance.approver_source`
    below -- see that field's docstring for why.
    """

    SUPPLIED = "supplied"
    INFERRED = "inferred"


class ApprovalProvenance(_BaselineModel):
    """Who approved this baseline's capability set, when, and at what
    commit.

    Every field is optional bounded free text (`SafeText`: 1-1024
    characters, no control characters -- already used elsewhere in this
    codebase, e.g. `controlloop.acbom.models.Diagnostic.message`), and
    deliberately *not* a closed enum or a pattern-constrained identifier
    like `Repository.commit`'s `CommitIdentifier`, even though
    `approver_source` only has two meaningful values
    (`ApproverSource.SUPPLIED`/`ApproverSource.INFERRED`) and
    `approved_commit` is conceptually a commit reference. A stricter
    type on any of these fields would make a malformed value reject the
    *entire* baseline document at parse time -- but a baseline with
    missing or malformed provenance must be usable but reported as
    unattributed, not rejected outright. Whether this provenance is
    complete, well-formed, and therefore attributable is a semantic
    judgment `controlloop.baseline.provenance.describe_provenance` makes
    on the already-loaded values, never a Pydantic validation failure.

    `None` on `BaselineDocument.provenance` itself means no provenance
    was ever recorded at all (the "missing" case, including every
    baseline written under schema 1.0.0). A present
    `ApprovalProvenance` with some fields `None`, or a value that
    fails to parse as what it claims to be (e.g. `approved_at` that is
    not a real timestamp), is the "malformed" case -- still a valid,
    loadable document.
    """

    approver: SafeText | None = None
    """The approver's identity exactly as supplied (a name, a handle, an
    email address, or any other free-text identifier a human or a
    calling tool provided) -- never derived, normalized, or looked up."""

    approver_source: SafeText | None = None
    """Expected to be `ApproverSource.SUPPLIED.value` or
    `ApproverSource.INFERRED.value`; any other value (including one that
    is present but unrecognized) is treated as not stating a source at
    all by `describe_provenance`, which is the safe default -- an
    approver whose source cannot be confirmed as "supplied" must never
    be rendered as if it were."""

    approved_at: SafeText | None = None
    """The approval timestamp exactly as supplied. Expected to be RFC
    3339 (e.g. `2026-08-19T00:00:00Z`), but not enforced as such here --
    `describe_provenance` parses it leniently and reports it as
    unattributed, not rejected, when it does not parse."""

    approved_commit: SafeText | None = None
    """The commit the approver attested to, exactly as supplied. May
    differ from `BaselineDocument.repository.commit` in a stale or
    hand-edited baseline; this model does not compare the two, only
    records and renders what was supplied."""


class BaselineDocument(_BaselineModel):
    """Complete immutable baseline artifact.

    `schema_version` is this baseline format's own version.
    `acbom_schema_version` is the schema version of the ACBOM
    `acbom_digest` was computed from -- recorded separately from
    `schema_version` because a baseline format version bump and an
    ACBOM schema version bump are independent events: the baseline
    format is now "1.1.0" (which added `provenance`) while an ACBOM
    computed under ACBOM schema "1.0.0" is still perfectly valid to
    record a digest of.

    `digest` is this document's own self-referential integrity digest,
    excluded from its own computation, the exact same pattern
    `controlloop.acbom.models.ACBOMDocument.digest` uses -- the
    foundation the tamper/truncation detection in
    `controlloop.baseline.integrity` is built on. `provenance` is an
    ordinary field like any other here, so it is covered by that same
    digest with no special-casing.
    """

    schema_version: SemanticVersion
    generator: Generator
    repository: Repository
    acbom_schema_version: SemanticVersion
    acbom_digest: Sha256Digest
    effective_authority: Annotated[
        tuple[EffectiveAuthorityEntry, ...],
        Field(max_length=_MAX_EFFECTIVE_AUTHORITY_ENTRIES),
    ]
    provenance: ApprovalProvenance | None = None
    digest: Sha256Digest

    @model_validator(mode="after")
    def validate_effective_authority_is_deduplicated(self) -> Self:
        """A baseline records an already-deduplicated fact set --
        `compute_effective_authority` guarantees this on construction
        (`controlloop.capability.compute`) -- so a duplicate
        `(agent_id, action, resource_id, permitting_identity_id)` tuple
        here indicates a corrupted or hand-crafted document, not a
        legitimate case, and is rejected rather than silently accepted."""

        keys = [
            (
                entry.agent_id,
                entry.action,
                entry.resource_id,
                entry.permitting_identity_id,
            )
            for entry in self.effective_authority
        ]
        if len(set(keys)) != len(keys):
            raise ValueError(
                "effective authority entries must be unique by "
                "(agent_id, action, resource_id, permitting_identity_id)"
            )
        return self
