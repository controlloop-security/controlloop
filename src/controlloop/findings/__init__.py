"""The finding model.

A `Finding` is what a `controlloop.policy.engine`
(`controlloop.policy.models.RuleObservation`) rule observation becomes
once the additional context a rule invocation carries is attached: rule
identifier and version, severity, confidence, the affected agent,
evidence, a capability path, change state against a baseline,
remediation text, and a documentation URL -- "everything a reviewer
needs to judge it without opening the codebase."

`controlloop.findings.models` holds the `Finding` model itself, its two
new enums (`FindingSeverity`, `FindingChangeState`), its three new
narrow value types (`AgentNodeId`, `FindingId`, `DocumentationUrl`), and
`finding_from_observation`, the `RuleObservation` -> `Finding` bridge.
`controlloop.findings.identity` holds `finding_id`, the stable identity
computation. `controlloop.findings.rendering` holds
`render_finding_text` and `finding_to_sarif_result`, the human and
SARIF-result serialization (JSON needs no dedicated function --
`Finding.model_dump_json()` already serves it).

Explicitly out of scope for this package: severity/confidence *threshold
and policy* semantics, rule-pack versioning, every concrete rule, and a
complete SARIF *log* document. `controlloop.policy.engine`,
`controlloop.policy.models`, `controlloop.capability.taxonomy`,
`controlloop.diff.models`, and `controlloop.redaction` are all reused
unmodified. See docs/reference/finding-model.md for the full design
rationale. No CLI command (`gate`, `scan`) consumes this yet.
"""

from controlloop.findings.identity import finding_id
from controlloop.findings.models import (
    CURRENT_FINDING_SCHEMA_VERSION,
    AgentNodeId,
    DocumentationUrl,
    Finding,
    FindingChangeState,
    FindingId,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.findings.rendering import finding_to_sarif_result, render_finding_text

__all__ = [
    "CURRENT_FINDING_SCHEMA_VERSION",
    "AgentNodeId",
    "DocumentationUrl",
    "Finding",
    "FindingChangeState",
    "FindingId",
    "FindingSeverity",
    "finding_from_observation",
    "finding_id",
    "finding_to_sarif_result",
    "render_finding_text",
]
