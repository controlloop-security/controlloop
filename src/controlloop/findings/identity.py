"""Stable finding identity.

Reuses `controlloop.acbom.identity`'s exact canonicalization scheme -- a
fixed identity version, a fixed namespace, a canonical JSON payload
built only from allowlisted, nonsecret, non-mutable identity material,
SHA-256 hashed -- rather than inventing a new hashing approach, per this
codebase's "stable IDs derived only from allowlisted nonsecret semantic
identity material" rule and its own precedent for how a stable
content-addressed identifier is built.

Identity material, deliberately narrow:

- `rule_id` -- the rule that produced this finding.
- `affected_agent` -- which agent.
- `capability_path.agent_id`, `.target_id`, `.target_type`, and the
  ordered tuple of `.hops[*].edge_id` -- the specific capability chain,
  identified by its own already-stable, content-addressed edge IDs,
  never by raw evidence or line numbers.

Deliberately excluded: `evidence` (mutable provenance, the same
exclusion `controlloop.acbom.identity.NodeIdentityMaterial` already
applies), `severity`/`confidence` (would make a stable identity
impossible across a policy or analysis change), `change_state` (differs
by definition across different baseline comparisons), and
`message`/`remediation`/`documentation_url`/`rule_version` (presentation
and version text, the same "presentation" and "version" exclusion
categories `controlloop.acbom.identity` already defines).

## Repository-scoped identity

When `affected_agent is None` (a repository-scoped finding -- see
`controlloop.findings.models.Finding`'s own docstring for why this
exists), none of the agent-scoped identity material above is available
at all: there is no agent and no capability path. The only allowlisted,
non-mutable, semantically stable anchor left is the sanitized
repository-relative `path`(s) the finding's own evidence carries --
`evidence_paths` here, the same *category* of identity material
(`source_path`) `controlloop.acbom.identity.SemanticIdentity` already
treats as approved for a node, reused at this layer for the one case
that has nothing else. This is a real, narrow, disclosed exception to
"evidence is always excluded from identity" above: for a repository-
scoped finding, the path is the finding's entire semantic identity, not
incidental provenance about it.

**Disclosed limitation:** line numbers still never participate (per the
identity rule above and this module's own determinism goal -- a line
shifting elsewhere in the file must not mint a "new" finding), so two
distinct secrets of the *same* detected pattern in the *same* file
collapse to one finding identity. This is a real accuracy limitation,
not silently unhandled: it is disclosed here and in
docs/reference/finding-model.md rather than fabricated as full
per-occurrence precision this codebase's own identity constraints cannot
honestly provide.

The agent-scoped payload shape below is completely unchanged by this
addition -- `evidence_paths` only participates when `affected_agent is
None` -- so every one of the nine already-existing rules keeps its
exact original computed `id` for identical input.
"""

from __future__ import annotations

import hashlib
import json

from controlloop.capability.models import CapabilityPath
from controlloop.findings.models import AgentNodeId, FindingId

IDENTITY_VERSION = 1
_FINDING_NAMESPACE = "controlloop.finding"


def _canonical_identity_bytes(
    *,
    rule_id: str,
    affected_agent: str | None,
    capability_path: CapabilityPath | None,
    evidence_paths: tuple[str, ...],
) -> bytes:
    if affected_agent is None:
        payload: dict[str, object] = {
            "identity_version": IDENTITY_VERSION,
            "namespace": _FINDING_NAMESPACE,
            "rule_id": rule_id,
            "affected_agent": None,
            "resource_paths": sorted(set(evidence_paths)),
        }
    else:
        assert capability_path is not None
        payload = {
            "identity_version": IDENTITY_VERSION,
            "namespace": _FINDING_NAMESPACE,
            "rule_id": rule_id,
            "affected_agent": affected_agent,
            "capability_path": {
                "agent_id": capability_path.agent_id,
                "target_id": capability_path.target_id,
                "target_type": capability_path.target_type.value,
                "hop_edge_ids": [hop.edge_id for hop in capability_path.hops],
            },
        }
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def finding_id(
    *,
    rule_id: str,
    affected_agent: AgentNodeId | None,
    capability_path: CapabilityPath | None,
    evidence_paths: tuple[str, ...] = (),
) -> FindingId:
    """Return the stable identifier for a finding matching `rule_id` and
    either `affected_agent`/`capability_path` (agent-scoped) or
    `evidence_paths` (repository-scoped, `affected_agent is None` -- see
    this module's own docstring, "Repository-scoped identity"). A pure
    function: identical inputs always produce an identical `FindingId`,
    and none of `evidence` (beyond the sanitized `path`s the
    repository-scoped branch uses), `severity`, `confidence`,
    `change_state`, `message`, `remediation`, `documentation_url`, or
    `rule_version` participate, so a finding recomputed on a later scan
    with an unchanged underlying capability or location -- even with
    different line numbers, a different severity configuration, or a
    different baseline comparison -- keeps the same identity, so the
    same issue is recognizable between scans.

    `capability_path` must be supplied (non-`None`) whenever
    `affected_agent` is not `None`; `evidence_paths` is only consulted
    when `affected_agent is None` and is otherwise ignored, so every
    existing agent-scoped call site's computed ID is completely
    unaffected by this parameter's addition.
    """

    canonical_bytes = _canonical_identity_bytes(
        rule_id=rule_id,
        affected_agent=affected_agent,
        capability_path=capability_path,
        evidence_paths=evidence_paths,
    )
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return f"clp:finding:sha256:{digest}"
