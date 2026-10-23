"""Immutable canonical models for the `controlloop.yaml` security
manifest, schema version 1.3.0.

## Naming a discovered node

Every field below that names a discovered agent, tool, or resource is
`SafeText`, never `SafeIdentifier`, and that is deliberate. Each is
matched against a node's `name`, which is a **human display name** --
`a2a.py` takes it from the skill card's own `name` field, so real
agents have tools called `Issue a refund`. `SafeIdentifier`'s pattern
(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`) forbids spaces, so an
identifier-typed field cannot name those tools at all, and the manifest
fails to parse outright rather than silently missing them.

`ToolCapabilityDeclaration.tool` and `ToolLoggingDeclaration.tool` were
widened first; an audit found the remaining eleven and widened them
together, so no node-naming field is left identifier-typed.

Fields that name a person, a team, a log destination, or the manifest's
own label stay `SafeIdentifier`: `TrustBoundary.name`,
`ManifestDocument.owner`, `Approval.approver`, and
`ToolLoggingDeclaration.audit_path`. None is compared to a node name.

Mirrors the ACBOM's own model discipline (`_CanonicalModel`'s
`extra="forbid", frozen=True, strict=True`) so an older reader cannot
silently ignore a field it does not recognize, the same reasoning
`docs/reference/schema-versioning.md` documents for the ACBOM. Reuses
`SafeIdentifier`/`SemanticVersion` from the ACBOM's own models and
`EdgeType`/`Sensitivity` directly, rather than inventing parallel types,
since "prohibited capabilities" and "data classification" are the same
concepts the ACBOM already models -- only the source (a human-authored
declaration, not discovered evidence) differs.
"""

from __future__ import annotations

from datetime import date
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

from controlloop.acbom import EdgeType, Sensitivity
from controlloop.acbom.models import (
    KnownBoolean,
    SafeIdentifier,
    SafeText,
    SemanticVersion,
)

CURRENT_MANIFEST_SCHEMA_VERSION = "1.3.0"

#: A suppression's declared target: the exact
#: shape `controlloop.findings.models.FindingId` already uses
#: (`clp:finding:sha256:<hex>`), duplicated here as a local pattern
#: rather than imported -- `controlloop.manifest` sits below
#: `controlloop.policy`/`controlloop.findings` in this codebase's own
#: layering (`RuleContext.manifest` already depends on a manifest type,
#: never the reverse), and importing `FindingId` here would invert that.
#: Strict equality against a real `Finding.id` is the only way a
#: suppression can ever match (`controlloop.policy.suppressions.
#: apply_suppressions`) -- no wildcard, glob, or prefix matching exists
#: anywhere in this codebase for this field, which is what makes "cannot
#: broaden beyond its declared scope" true by construction
#: rather than by convention.
SuppressionTarget = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=r"^clp:finding:sha256:[0-9a-f]{64}$",
    ),
]

#: A suppression's declared expiry: a strict
#: `YYYY-MM-DD` calendar date, validated as a real date (not just a
#: shape) by `Suppression.validate_expires_at_is_a_real_date` below --
#: unlike `Approval.expires_at` (`SafeText`, lenient, optional, RFC 3339
#: timestamp-shaped but never strictly parsed), a suppression's expiry
#: is REQUIRED (a missing expiry is a missing required field, exit 2)
#: and its whole purpose is being compared against today's real date
#: to decide whether the suppression still has effect, so a
#: malformed date must be rejected at parse time, not silently
#: misinterpreted later.
SuppressionExpiry = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^\d{4}-\d{2}-\d{2}$"),
]


class _ManifestModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class TrustBoundary(_ManifestModel):
    """A named boundary an agent belongs to."""

    name: SafeIdentifier
    agents: tuple[SafeText, ...] = ()


class Approval(_ManifestModel):
    """A human-owned approval record for a named capability.

    `expires_at` (an additive extension that kept schema version `1.0.0`
    -- a new optional field is minor-compatible, not breaking, the same
    precedent the `ceilings` field already set) is the approval's
    expiration
    timestamp exactly as supplied, expected to be RFC 3339 (for example
    `2026-12-31T00:00:00Z`) but not strictly enforced here -- the same
    lenient-but-honest posture `controlloop.baseline.models.ApprovalProvenance
    .approved_at` already established, so one malformed value does not
    reject an otherwise-valid manifest at parse time. `None` means the
    approval never expires. Whether an approval "is currently active" is
    a semantic judgment a caller makes with an explicit reference time
    (`controlloop.manifest.approvals.is_approval_active`/
    `active_approvals`), never a Pydantic validation outcome and never
    something this model or the deterministic rule engine decides using
    its own clock -- see that module's own docstring."""

    capability: SafeText
    approver: SafeIdentifier
    expires_at: SafeText | None = None


class ProhibitedCapability(_ManifestModel):
    """A capability an agent must never hold, named by the same
    agent/target-name vocabulary discovery already uses."""

    agent: SafeText
    edge_type: EdgeType
    target: SafeText


class AllowedDelegation(_ManifestModel):
    """The set of delegation targets an agent is permitted to reach."""

    agent: SafeText
    targets: tuple[SafeText, ...]


class DataClassificationDeclaration(_ManifestModel):
    """A declared sensitivity classification for a named resource."""

    resource: SafeText
    sensitivity: Sensitivity


class ToolLoggingDeclaration(_ManifestModel):
    """A declared logging or audit path for a named tool. `audit_path`
    is a free-form `SafeIdentifier`: a repository-relative log path or a
    system identifier (for example `datadog:agent-audit-log`), never
    validated against a real filesystem or service -- this manifest is a
    declaration, not something this scanner verifies by connecting to
    anything.

    `tool` was widened from `SafeIdentifier` to `SafeText`.
    It is matched against a discovered `TOOL` node's `name`, which is a
    human display name -- `a2a.py` takes it from the skill's own `name`
    field, producing tools called `Issue a refund`. `SafeIdentifier`
    forbids spaces, so this field could never name an a2a skill, and the
    reference agent's own `logged_tools: - tool: issue-refund` had always
    been dead configuration that matched nothing.

    That became load-bearing once `tool_capabilities` let a
    repository declare a tool privileged: `policy.missing-action-logging`
    then demands a `logged_tools` entry for it, and with an
    identifier-only field there was no way to write one for any a2a
    skill. Widening is backward compatible in the direction that matters
    -- every value that validated before still validates -- so it is a
    relaxation, not a breaking change."""

    tool: SafeText
    audit_path: SafeIdentifier


class ToolCapabilityDeclaration(_ManifestModel):
    """What a named tool actually does, declared by the repository.

    ## Why this field has to exist

    `controlloop.capability.taxonomy.classify_material_capability`
    classifies a capability from the **target node's** own
    `SecurityAttributes`. No shipped offline adapter sets `destructive`,
    `financial_action`, `read_only`, or `sensitivity` on anything, and
    the two attributes adapters do set -- `code_execution` on an MCP
    server, `external_communication` on an external delegation target --
    sit on nodes no agent has an edge to. So before this field, no real
    repository scan could ever classify a capability as material, and
    `compute_blast_radius` always returned `None`.

    ## Why tools, and not resources

    An agent's own edges are `invokes` (to its tools) and `delegates-to`.
    `_TRANSITIVE_EDGE_TYPES` does not include `READS` or `WRITES`, so a
    resource behind `tool --writes--> resource` is not reachable from any
    agent at all -- which is why the existing, `resource:`-keyed
    `DataClassificationDeclaration` could not be reused for this. A tool
    an agent invokes is reachable in exactly one hop, so annotating tools
    makes the agent's real capability surface classifiable without
    touching `compute_transitive_capability_paths`' established
    traversal contract.

    ## Matching

    `tool` is matched against a discovered `TOOL` node's **`name`**, the
    same way `ToolLoggingDeclaration` and the capability-ceiling rule
    already match theirs -- one consistent rule across this manifest, not
    a third convention. A declaration naming a tool discovery did not
    find produces an `unverified` diagnostic rather than silently doing
    nothing.

    It is typed `SafeText`, **not** `SafeIdentifier`, and that is
    deliberate. A discovered tool node's `name` is a human display name:
    `a2a.py` sets it from the skill's own `name` field, so the real
    reference agent has tools called `Issue a refund` and `Look up an
    order`. `SafeIdentifier`'s pattern
    (`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`) forbids spaces, so an
    identifier-typed field can never name those tools at all -- it can
    only ever match identifier-shaped names like an MCP server's
    `order-support-tools` or an OpenAPI operation's `issueRefund`. Since
    a2a skills are precisely the tools an agent has `invokes` edges to,
    an identifier-typed field here would be unable to annotate the only
    nodes this feature exists to annotate. `SafeText` is still bounded
    (1-1024 characters) and still rejects control characters.

    `ToolLoggingDeclaration.tool` is `SafeText` for the same reason.

    Every attribute is optional and independently settable. An omitted
    attribute leaves the discovered node's own value untouched; it never
    asserts `False`. `"unknown"` is available on each boolean, so a
    repository can say "this tool might be destructive and we have not
    established it" rather than being forced into a confident answer --
    the taxonomy maps that to `UNCLASSIFIED`, which it ranks worst of
    all.
    """

    tool: SafeText
    destructive: KnownBoolean | None = None
    financial_action: KnownBoolean | None = None
    code_execution: KnownBoolean | None = None
    external_communication: KnownBoolean | None = None
    read_only: KnownBoolean | None = None
    privileged: KnownBoolean | None = None
    requires_approval: KnownBoolean | None = None
    sensitivity: Sensitivity | None = None
    data_classes: tuple[SafeIdentifier, ...] = ()

    @model_validator(mode="after")
    def validate_unique_data_classes(self) -> Self:
        if len(set(self.data_classes)) != len(self.data_classes):
            raise ValueError("declared data classes must be unique")
        return self


class ExternalInputDeclaration(_ManifestModel):
    """Where a named agent's input comes from, declared by the repository.

    ## Why this field has to exist

    `controlloop.policy.rules.exfiltration_triangle` reads an agent's
    untrusted-input leg from a `receives-from` edge. Discovery produces
    that edge for an agent-running workflow (the event that starts it)
    and, as an inference only, for an A2A card that publishes an
    endpoint. Nothing in a repository states that a support agent is
    wired to a public inbox, a webhook or a chat channel; like what a
    tool does (`ToolCapabilityDeclaration`), it is a fact only the
    repository's authors know. So they declare it here, and the
    declaration is authoritative: `controlloop.manifest.inputs` adds one
    trigger node and one `receives-from` edge per declaration, carrying
    `untrusted_input=True`.

    ## What it means

    A declared external input is untrusted by definition. There is no
    `trusted` switch: an input a repository would call trusted is not an
    *external* input, and is simply not declared. An inferred input (an
    A2A endpoint) is never confused with a declared one: it is reported
    as unknown, at lower severity, until a declaration confirms or
    rules it out.

    ## Matching

    `agent` is matched against a discovered `AGENT` node's `name`, the
    same human display name every other node-naming field here matches
    on, so it is `SafeText`, not `SafeIdentifier`. A declaration naming
    an agent discovery did not find produces an `unverified` diagnostic
    rather than silently doing nothing. `source` is the human name of
    the input (`customer support inbox`, `public webhook`), used as the
    trigger node's name and as part of its identity; `description` is
    free text for reviewers and takes no part in identity.
    """

    agent: SafeText
    source: SafeText
    description: SafeText | None = None


class CapabilityCeiling(_ManifestModel):
    """The maximum authority an agent (or, with `agent` unset, every
    agent in the repository) may ever hold.
    `edge_type` reuses the ACBOM's own vocabulary for "actions" rather
    than a parallel taxonomy; `sensitivity` reuses `Sensitivity` for
    "data classes" the same way `DataClassificationDeclaration` does.
    "External destinations" have no existing canonical shape to reuse,
    so they are free-form `SafeIdentifier` strings (a domain or
    endpoint identifier)."""

    agent: SafeText | None = None
    prohibited_resources: tuple[SafeText, ...] = ()
    prohibited_actions: tuple[EdgeType, ...] = ()
    prohibited_external_destinations: tuple[SafeText, ...] = ()
    prohibited_data_classes: tuple[Sensitivity, ...] = ()
    prohibited_delegation_targets: tuple[SafeText, ...] = ()


class Suppression(_ManifestModel):
    """One repo-local, expiring suppression of a specific finding.

    Every field is required with no default ("a suppression
    requires rule identifier, a scoped target, a written reason, and an
    expiry date; any missing field returns exit 2" -- an omitted field
    is a missing required field, which Pydantic's own strict,
    defaultless-field behavior already rejects at parse time through
    `controlloop.manifest.parser.load_manifest`'s existing
    `ManifestValidationError` path, `exit_code = ExitCode.INVALID_INPUT`,
    with no new error-handling code needed here).

    `rule_id` and `target` together are this suppression's entire
    matching contract: a real `Finding` is suppressed only when *both*
    `finding.rule_id == rule_id` and `finding.id == target` -- exact
    string equality, evaluated in
    `controlloop.policy.suppressions.apply_suppressions`. `target`'s own
    type (`SuppressionTarget`) is already shape-constrained to a real
    `Finding.id` pattern, so this suppression can never name a finding
    that could not exist; combined with exact-equality matching (never
    a prefix, glob, or wildcard anywhere in this codebase), "cannot
    broaden beyond its declared scope" holds by construction,
    not merely by convention -- there is no mechanism here a suppression
    author could even attempt to broaden.

    `rule_id` is not redundant with `target` despite `target` already
    uniquely identifying one finding (whose own identity already embeds
    its rule): it is this declaration's own human-auditable statement of
    *which* rule the author believes they are suppressing. A `rule_id`
    that disagrees with `target`'s real, embedded rule can never match
    any real finding (`apply_suppressions` requires both to agree), so a
    copy-paste or typo error here fails safe -- reported as `STALE`
    (`controlloop.policy.suppressions.SuppressionStatus`), never as a
    silent, wrong match.

    "Suppressions cannot suppress ceiling breaches unless the ceiling
    itself is amended" is enforced the same way, structurally,
    in `apply_suppressions`: a suppression whose `rule_id` equals
    `controlloop.policy.rules.capability_ceiling.RULE_ID` is always
    reported `CEILING_PROTECTED` and never removes its target finding
    from evaluation, regardless of expiry or match -- the only real
    lever that changes a ceiling breach's outcome is amending
    `ManifestDocument.ceilings` itself.
    """

    rule_id: SafeIdentifier
    target: SuppressionTarget
    reason: SafeText
    expires_at: SuppressionExpiry

    @model_validator(mode="after")
    def validate_expires_at_is_a_real_date(self) -> Self:
        """Input validation: `SuppressionExpiry`'s regex
        only proves the `YYYY-MM-DD` *shape* -- this proves it is a real
        calendar date (rejecting, for example, `2026-13-40`), the same
        "shape, then real value" two-step every other structurally
        validated field in this codebase already follows (for example
        `controlloop.acbom.models.SemanticVersion`'s own pattern-then-
        parse precedent)."""

        try:
            date.fromisoformat(self.expires_at)
        except ValueError:
            raise ValueError(
                "expires_at must be a real calendar date in YYYY-MM-DD form"
            ) from None
        return self


class ManifestDocument(_ManifestModel):
    """Complete immutable `controlloop.yaml` manifest document."""

    schema_version: SemanticVersion
    owner: SafeIdentifier
    trust_boundaries: tuple[TrustBoundary, ...] = ()
    approvals: tuple[Approval, ...] = ()
    prohibited_capabilities: tuple[ProhibitedCapability, ...] = ()
    allowed_delegation: tuple[AllowedDelegation, ...] = ()
    data_classification: tuple[DataClassificationDeclaration, ...] = ()
    ceilings: tuple[CapabilityCeiling, ...] = ()
    logged_tools: tuple[ToolLoggingDeclaration, ...] = ()
    tool_capabilities: tuple[ToolCapabilityDeclaration, ...] = ()
    suppressions: tuple[Suppression, ...] = ()
    external_inputs: tuple[ExternalInputDeclaration, ...] = ()

    @model_validator(mode="after")
    def validate_at_most_one_ceiling_per_scope(self) -> Self:
        """An ambiguous ceiling -- two entries
        naming the same agent, or two repository-wide entries -- is
        rejected structurally, for every caller, not only the YAML
        parsing path."""

        seen: set[str | None] = set()
        for ceiling in self.ceilings:
            if ceiling.agent in seen:
                scope = f"agent {ceiling.agent!r}" if ceiling.agent else "repository"
                raise ValueError(
                    f"ambiguous capability ceiling: more than one entry "
                    f"declares the {scope} scope"
                )
            seen.add(ceiling.agent)
        return self
