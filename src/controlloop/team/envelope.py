"""The Team scan envelope.

This module answers one question, and the answer has to be defensible to a
security team reading it: **what exactly leaves the machine?**

The envelope mirrors the platform contract's `ScanEnvelopeRequest` field
for field. Rendering is a pure function of an already-computed scan:
no clock, no environment, no filesystem, no network. `serialize_envelope`
reuses `controlloop.acbom.serialization.canonical_json_bytes`, the same
canonicalization the ACBOM digest is computed over, so two runs of the
same scan produce byte-identical payloads -- which is also what
makes the ingestion endpoint's idempotency on (project, commit, digest)
work in practice rather than in principle.

## What the envelope carries, exhaustively

Repository identity (commit SHA, optional branch and pull-request
number), scanner and policy versions, the ACBOM digest, the gate verdict,
normalized findings, normalized components, and -- when repository policy
differs from the organization bundle -- the repository policy delta. That
list is the whole of it, and `docs/reference/team-envelope.md` states the
same list for users.

## Envelope 1.1.0: agent authority

A scan that holds an agent authority component (a host, hook, helper
command, permission rule, plugin, marketplace, skill, subagent, or
agent-running workflow), an MCP server, or an authority delta is sent as
**1.1.0**. Every other scan is sent as 1.0.0, byte for byte as before.

In 1.1.0, each of those components is described by
`controlloop.team.components.component_for`, the identity the gate judges
the sanctioned list by: its type, its name, the attributes the
approved-component constraints read (`package`, `version`, `digest`,
`command`) plus `host_id`, and its five flags. Every attribute value is
already redacted and bounded by the adapter that recorded it
(`controlloop.adapters.agent_authority.authority_text`). The envelope
also carries the authority delta: each entry's plain-language
statement and its location, never a file's contents.

## What it can never carry, and how that is enforced

No source code, no prompt bodies, no environment values, no secret
material, and no file contents. The enforcement is structural rather than
aspirational:

- Every field is copied from an already-sanitized value. `Finding.id`,
  `Finding.rule_id`, and the node identifiers are stable IDs derived from
  allowlisted semantic material (`controlloop.acbom.identity`), which by
  construction excludes source content, credentials, and absolute paths.
- `evidence_reference` is built from `Evidence.path` and `Evidence.line_start`
  only -- a `RelativePath` the repository walker already sanitized, plus an
  integer. `Evidence` carries no evidence *text* to leak in the first
  place.
- The models below are `extra="forbid"`, so a future field cannot be added
  to a payload without being added to this schema, reviewed, and
  documented.
- `tests/team/test_envelope.py` plants token, password, private-key,
  prompt, and environment-value canaries in a repository and asserts none
  of them appears in the serialized bytes.

## Two places the contract is narrower than the ACBOM, and what happens

**Confidence.** The ACBOM has four levels (`high`, `medium`, `low`,
`unknown`); the contract has three. `unknown` is sent as `low`. The
direction is deliberate: `low` is the weakest claim the contract can make,
so an unknown confidence is never *overstated* into something a dashboard
would rank higher than the evidence supports.

**Component type.** The contract's `ComponentType` has five members
(`agent`, `tool`, `mcp_server`, `resource`, `identity`); `NodeType` has
eight. The four with no representation -- `permission`, `data-class`,
`trigger`, and `policy-boundary` -- are **omitted from `components`**
rather than coerced into a member that would misdescribe them. They are
not lost to the verdict: they still participate in local policy evaluation
and still appear in the ACBOM. What the fleet inventory does not receive
is a component row that claims a permission is a tool.

An MCP server is a `NodeType.TOOL` whose subtype names it (`mcp-server-stdio`
or `mcp-server-http`); those map to `mcp_server`, which is the one case
where the contract is more specific than `NodeType` alone.
"""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from controlloop.acbom.models import ACBOMDocument, Confidence, Node, NodeType
from controlloop.acbom.serialization import canonical_json_bytes
from controlloop.diff.authority import AuthorityDelta, AuthorityEntry
from controlloop.findings.models import Finding
from controlloop.reporting.authority import owning_host_ids
from controlloop.reporting.terminal import Verdict
from controlloop.team.components import COMPONENT_TYPE_BY_SUBTYPE, component_for

#: `ScanEnvelopeRequest.envelope_version`. Bumped when this module's
#: rendering changes in a way a server must notice.
ENVELOPE_SCHEMA_VERSION: Final = "1.0.0"

#: The version sent when the scan holds an agent authority component, an
#: MCP server, or an authority delta.
AUTHORITY_ENVELOPE_VERSION: Final = "1.1.0"

#: `ScanEnvelopeRequest.authority_delta`: at most 200 entries.
MAX_AUTHORITY_DELTA_ENTRIES: Final = 200

#: `AuthorityDeltaEntryRequest` text limits, in characters.
_HOST_NAME_LIMIT: Final = 120
_STATEMENT_LIMIT: Final = 300
_DETAIL_LIMIT: Final = 120
_EVIDENCE_PATH_LIMIT: Final = 512
_KEY_PATH_LIMIT: Final = 256

#: `NodeType` -> the contract's `ComponentType`. Deliberately partial: a
#: node type absent from this mapping is omitted from `components`, which
#: is the documented behavior above, not an oversight. Asserted exhaustive
#: over `NodeType` by `tests/team/test_envelope.py`, so a new node type
#: forces a decision here rather than silently disappearing.
_COMPONENT_TYPE_BY_NODE_TYPE: Final[dict[NodeType, str]] = {
    NodeType.AGENT: "agent",
    NodeType.TOOL: "tool",
    NodeType.RESOURCE: "resource",
    NodeType.IDENTITY: "identity",
}

#: Node types the contract cannot represent; see the module docstring.
UNREPRESENTABLE_NODE_TYPES: Final = frozenset(
    {
        NodeType.PERMISSION,
        NodeType.DATA_CLASS,
        NodeType.TRIGGER,
        NodeType.POLICY_BOUNDARY,
    }
)

#: ACBOM `Confidence` -> the contract's three-member `Confidence`.
_CONFIDENCE: Final[dict[Confidence, str]] = {
    Confidence.HIGH: "high",
    Confidence.MEDIUM: "medium",
    Confidence.LOW: "low",
    Confidence.UNKNOWN: "low",
}

#: `Verdict` -> the contract's `Verdict`. The CLI's five-state vocabulary
#: includes `not_evaluated`, which an ingested scan cannot be: a scan that
#: evaluated no policy has no verdict to record. `render_envelope` refuses
#: it rather than mapping it to `pass`, which would record a clean result
#: for a run that checked nothing.
_VERDICT: Final[dict[Verdict, str]] = {
    Verdict.PASSED: "pass",
    Verdict.PASSED_WITH_WARNINGS: "warn",
    Verdict.REVIEW_REQUIRED: "require_review",
    Verdict.DEPLOYMENT_BLOCKED: "fail",
}

#: A 40-character lowercase hex commit, matching the contract's own
#: `commit_sha` pattern. `controlloop.bom` records the literal string
#: `"unknown"` when a repository is not a git checkout with at least one
#: commit, and that is not a commit this envelope can name.
_COMMIT_LENGTH: Final = 40


class EnvelopeRenderError(ValueError):
    """The scan cannot be represented as an envelope.

    Raised for a commit that is not a 40-character hex SHA, or a verdict
    of `not_evaluated`. Both are reported by `controlloop.cli` as an
    upload that did not happen -- never by changing the gate verdict,
    which is reserved to local policy evaluation.
    """


class _EnvelopeModel(BaseModel):
    """`extra="forbid"` for the same reason the contract states it: a
    serializer that silently drops what it does not recognize would let a
    payload smuggle content past every per-field check by putting it in a
    field the schema never declared."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class NormalizedFinding(_EnvelopeModel):
    """The platform contract\'s `NormalizedFindingRequest`."""

    fingerprint: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    severity: str
    confidence: str
    title: str = Field(min_length=1)
    capability_path: tuple[str, ...]
    evidence_reference: str = Field(min_length=1)


class ComponentFlags(_EnvelopeModel):
    """The platform contract\'s `ComponentFlagsRequest` (1.1.0).
    `None` is "the scanner could not tell", never "no"."""

    code_execution: bool | None
    bypass_mode: bool | None
    wildcard: bool | None
    pinned: bool | None
    untrusted_input: bool | None


class NormalizedComponent(_EnvelopeModel):
    """The platform contract\'s `NormalizedComponentRequest`.
    `attributes` and `flags` are 1.1.0 only, and `None` in 1.0.0."""

    stable_id: str = Field(min_length=1)
    type: str
    name: str = Field(min_length=1)
    attributes: dict[str, str] | None = None
    flags: ComponentFlags | None = None


class AuthorityDeltaEntry(_EnvelopeModel):
    """The platform contract\'s `AuthorityDeltaEntryRequest` (1.1.0)."""

    host_id: str | None
    host_name: str = Field(min_length=1, max_length=_HOST_NAME_LIMIT)
    kind: str
    grant: str
    material_class: str
    statement: str = Field(min_length=1, max_length=_STATEMENT_LIMIT)
    detail: str = Field(max_length=_DETAIL_LIMIT)
    evidence_path: str = Field(min_length=1, max_length=_EVIDENCE_PATH_LIMIT)
    key_path: str = Field(min_length=1, max_length=_KEY_PATH_LIMIT)
    approval_recorded: bool
    confidence: str
    component_stable_id: str = Field(min_length=1)


class RuleOverride(_EnvelopeModel):
    """The platform contract\'s `RuleOverrideRequest`."""

    rule_id: str = Field(min_length=1)
    enabled: bool | None = None
    severity_floor: str | None = None


class RepositoryPolicyDelta(_EnvelopeModel):
    """The platform contract\'s `RepositoryPolicyDeltaRequest`.

    Sent so the **server** computes the effective policy rather than
    trusting this client's account of what it enforced. The CLI computes
    the same merge locally (`controlloop.team.policy`) to decide its own
    verdict; the server recomputes it to record one. Those two agreeing is
    what the platform contract's `policy-merge-vectors.json` exists to
    guarantee.
    """

    rules: tuple[RuleOverride, ...] = ()
    approved_components: tuple[NormalizedComponent, ...] = ()


class ScanEnvelope(_EnvelopeModel):
    """The platform contract\'s `ScanEnvelopeRequest`.

    `project_id` is deliberately omitted. The contract calls it "optional,
    and never trusted: identity comes from the project token," and an
    optional field whose only effect is to be checked for a mismatch is a
    field with no upside for the client to send.
    """

    envelope_version: str = Field(min_length=1)
    commit_sha: str = Field(min_length=1)
    branch: str | None = None
    pull_request_number: int | None = None
    scanner_version: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    acbom_digest: str = Field(min_length=1)
    verdict: str
    findings: tuple[NormalizedFinding, ...]
    components: tuple[NormalizedComponent, ...]
    repository_policy: RepositoryPolicyDelta | None = None
    authority_delta: tuple[AuthorityDeltaEntry, ...] | None = None


def _confidence(value: Confidence) -> str:
    return _CONFIDENCE[value]


def _evidence_reference(finding: Finding) -> str:
    """Build the sanitized locator the contract asks for.

    `Evidence` is already sanitized by the repository walker: `path` is a
    repository-relative `RelativePath` and there is no evidence text on
    the model at all. The locator is `path` or `path:line`, falling back
    to the document digest for evidence that names a document rather than
    a file. Never the evidence content, because none is carried.
    """

    first = finding.evidence[0]
    if first.path is None:
        # `Evidence.validate_location_and_line_range` guarantees a digest
        # when there is no path, so this branch always has something real
        # to name.
        assert first.document_digest is not None
        return first.document_digest
    if first.line_start is None:
        return first.path
    return f"{first.path}:{first.line_start}"


def _capability_path(finding: Finding) -> tuple[str, ...]:
    """Node identifiers along the capability path, agent first.

    Empty for a repository-scoped finding, which by
    `Finding.validate_affected_agent_matches_capability_path` has no
    capability path at all -- a hardcoded secret in a shared file is not
    reached *through* an agent.
    """

    path = finding.capability_path
    if path is None:
        return ()
    return (path.agent_id, *(hop.target_id for hop in path.hops))


def normalize_finding(finding: Finding) -> NormalizedFinding:
    """One `Finding` as the contract's normalized shape."""

    return NormalizedFinding(
        fingerprint=finding.id,
        rule_id=finding.rule_id,
        rule_version=finding.rule_version,
        severity=finding.severity.value,
        confidence=_confidence(finding.confidence),
        title=finding.message,
        capability_path=_capability_path(finding),
        evidence_reference=_evidence_reference(finding),
    )


def normalize_component(node: Node) -> NormalizedComponent | None:
    """One ACBOM node as a normalized component, or `None` when the
    contract has no `ComponentType` for it (see the module docstring)."""

    if node.type in UNREPRESENTABLE_NODE_TYPES:
        return None
    if node.type is NodeType.TOOL and (node.subtype or "").startswith("mcp-server"):
        component_type = "mcp_server"
    else:
        component_type = _COMPONENT_TYPE_BY_NODE_TYPE[node.type]
    return NormalizedComponent(
        stable_id=node.id,
        type=component_type,
        name=node.name,
    )


def authority_component(node: Node, host_id: str | None) -> NormalizedComponent | None:
    """One node as a 1.1.0 component, described by `component_for` (the
    identity the gate judges by), or `None` when it is neither an agent
    authority component nor an MCP server."""

    component = component_for(node)
    if component is None:
        return None
    attributes = dict(component.attributes)
    if host_id is not None:
        attributes["host_id"] = host_id
    flags = component.flags
    return NormalizedComponent(
        stable_id=node.id,
        type=component.type,
        name=component.name,
        attributes=attributes,
        flags=ComponentFlags(
            code_execution=_flag(flags.get("code_execution")),
            bypass_mode=_flag(flags.get("bypass_mode")),
            wildcard=_flag(flags.get("wildcard")),
            pinned=_flag(flags.get("pinned")),
            untrusted_input=_flag(flags.get("untrusted_input")),
        ),
    )


def _flag(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _bounded(text: str, limit: int) -> str:
    """`text` cut to `limit` characters, ending in `…` when cut."""

    return text if len(text) <= limit else text[: limit - 1] + "…"


def _grant(entry: AuthorityEntry, node: Node | None) -> str | None:
    """The envelope's component type for `entry`: the node's own type
    where it maps (so a `mode` entry is `host` or `subagent`), else the
    CLI kind with `-` spelled `_` (`mcp-server` is `mcp_server`)."""

    if node is not None and (node.subtype or "") in COMPONENT_TYPE_BY_SUBTYPE:
        return COMPONENT_TYPE_BY_SUBTYPE[node.subtype or ""]
    grant = entry.kind.replace("-", "_")
    return grant if grant in COMPONENT_TYPE_BY_SUBTYPE.values() else None


def authority_delta_entries(
    document: ACBOMDocument, delta: AuthorityDelta | None
) -> tuple[AuthorityDeltaEntry, ...]:
    """The delta in the contract's shape: at most 200 entries, in the
    delta's own deterministic order. An entry whose grant has no
    component type is not sent; none of the scanner's kinds lacks one."""

    if delta is None:
        return ()
    by_id = {node.id: node for node in document.nodes}
    entries: list[AuthorityDeltaEntry] = []
    for entry in delta.entries:
        grant = _grant(entry, by_id.get(entry.node_id))
        if grant is None:
            continue
        entries.append(
            AuthorityDeltaEntry(
                host_id=entry.host_id,
                host_name=_bounded(entry.host_name, _HOST_NAME_LIMIT),
                kind=entry.change,
                grant=grant,
                material_class=entry.material_class.value,
                statement=_bounded(entry.statement, _STATEMENT_LIMIT),
                detail=_bounded(entry.detail, _DETAIL_LIMIT),
                evidence_path=_bounded(entry.path, _EVIDENCE_PATH_LIMIT),
                key_path=_bounded(entry.key_path or entry.path, _KEY_PATH_LIMIT),
                # The contract has no "not evaluated": with no readable
                # manifest, no approval is recorded. The statement says
                # approvals were not evaluated.
                approval_recorded=entry.approval_recorded is True,
                confidence=_confidence(entry.confidence),
                component_stable_id=entry.node_id,
            )
        )
        if len(entries) == MAX_AUTHORITY_DELTA_ENTRIES:
            break
    return tuple(entries)


def render_envelope(
    *,
    document: ACBOMDocument,
    findings: tuple[Finding, ...],
    verdict: Verdict,
    scanner_version: str,
    policy_version: str,
    branch: str | None = None,
    pull_request_number: int | None = None,
    repository_policy: RepositoryPolicyDelta | None = None,
    authority_delta: AuthorityDelta | None = None,
) -> ScanEnvelope:
    """Render one scan as an envelope, deterministically.

    Findings and components are sorted by their own stable identity here
    rather than trusting the caller's ordering, so two callers that
    assembled the same scan differently still produce byte-identical
    payloads. Raises `EnvelopeRenderError` for a scan the contract
    cannot describe; see that class.

    The envelope is 1.1.0 when the scan holds an agent authority
    component, an MCP server, or an authority delta, and
    1.0.0, exactly as before, otherwise.
    """

    commit = document.repository.commit
    if len(commit) != _COMMIT_LENGTH or any(
        character not in "0123456789abcdef" for character in commit
    ):
        raise EnvelopeRenderError(
            "the repository's commit is not a 40-character hex SHA, so this "
            "scan cannot be attributed to a commit; run the gate against a "
            "git checkout with at least one commit"
        )

    if verdict not in _VERDICT:
        raise EnvelopeRenderError(
            f"a {verdict.value!r} verdict evaluated no policy, so there is no "
            "result to record"
        )

    delta_entries = authority_delta_entries(document, authority_delta)
    authority_nodes = {
        node.id for node in document.nodes if component_for(node) is not None
    }
    version = (
        AUTHORITY_ENVELOPE_VERSION
        if authority_nodes or delta_entries
        else ENVELOPE_SCHEMA_VERSION
    )
    hosts = owning_host_ids(document) if authority_nodes else {}
    components = tuple(
        component
        for component in (
            authority_component(node, hosts.get(node.id))
            if node.id in authority_nodes
            else normalize_component(node)
            for node in document.nodes
        )
        if component is not None
    )

    return ScanEnvelope(
        envelope_version=version,
        commit_sha=commit,
        branch=branch,
        pull_request_number=pull_request_number,
        scanner_version=scanner_version,
        policy_version=policy_version,
        acbom_digest=document.digest,
        verdict=_VERDICT[verdict],
        findings=tuple(
            sorted(
                (normalize_finding(finding) for finding in findings),
                key=lambda item: item.fingerprint,
            )
        ),
        components=tuple(sorted(components, key=lambda item: item.stable_id)),
        repository_policy=repository_policy,
        authority_delta=delta_entries or None,
    )


def serialize_envelope(envelope: ScanEnvelope) -> bytes:
    """Canonical JSON bytes for one envelope.

    Reuses `canonical_json_bytes` -- the same sorted-key, tight-separator,
    non-ASCII-preserving canonicalization the ACBOM digest is computed
    over -- rather than introducing a second serialization discipline that
    could disagree with the first.

    `exclude_none=True` keeps an unset optional out of the payload
    entirely instead of sending an explicit `null`, so a repository with
    no branch configured and one with a branch of `null` are not two
    different byte sequences for the same scan. The exceptions are the
    1.1.0 fields where `null` is a value: a component's flags, and a delta
    entry's `host_id`.
    """

    payload = envelope.model_dump(mode="json", exclude_none=True)
    # Two 1.1.0 nulls carry meaning and are sent: a flag the scanner could
    # not tell, and a grant no host could be attributed to (`host_id` is
    # required, and may be null).
    for rendered, component in zip(
        payload["components"], envelope.components, strict=True
    ):
        if component.flags is not None:
            rendered["flags"] = component.flags.model_dump(mode="json")
    for rendered, entry in zip(
        payload.get("authority_delta", ()), envelope.authority_delta or (), strict=True
    ):
        rendered["host_id"] = entry.host_id
    return canonical_json_bytes(payload)
