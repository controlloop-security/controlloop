"""Human and SARIF-result rendering for a `Finding`.

`Finding.model_dump_json()` / `.model_dump(mode="json")` already
serves the JSON format -- ordinary, deterministic Pydantic
serialization, the same as every other computed-report model in this
codebase (`controlloop.diff.report.DiffReport`,
`controlloop.diff.material_summary.MaterialChangeSummary`). No
dedicated JSON function is defined here.

`render_finding_text` follows `controlloop.diagnostics.render_text`'s
exact glyph-and-label convention. `finding_to_sarif_result` returns
one SARIF `result` object shape only -- **not** a complete SARIF log
document (`runs[].tool.driver.rules[]`, `originalUriBaseIds`, and the
rest of that document-level structure are built by
`controlloop.reporting.sarif`).

"Serialize identically" is read as: the same underlying data is present
and mutually consistent across all three renderings -- not
byte-identical text across three structurally different formats, which
is not a coherent requirement for a human sentence, a JSON object, and
a SARIF result to satisfy simultaneously. Every evidence entry carrying
a `path` renders as one location in all three formats via the same
`controlloop.redaction.source_reference` semantics; an evidence entry
carrying only a `document_digest` (no `path`) has no location to render
in any format and is simply omitted from the location lists both
functions below build, rather than raising.
"""

from __future__ import annotations

from controlloop.acbom.models import Evidence
from controlloop.findings.models import Finding, FindingSeverity
from controlloop.redaction import source_reference

#: Severity glyph, matching the CLI's stable symbol convention
#: (`✓ PASSED`, `! WARNING`, `✕ BLOCKED`, `• INFO`) the same way
#: `controlloop.diagnostics._SEVERITY_GLYPH` already does for
#: `DiagnosticSeverity` -- a distinct mapping here since
#: `FindingSeverity` is a different, five-member enum, not
#: `DiagnosticSeverity`.
_SEVERITY_GLYPH: dict[FindingSeverity, str] = {
    FindingSeverity.INFO: "•",
    FindingSeverity.LOW: "•",
    FindingSeverity.MEDIUM: "!",
    FindingSeverity.HIGH: "✕",
    FindingSeverity.CRITICAL: "✕",
}

#: Width of the upper-cased severity label column in the summary line,
#: derived from the enum rather than written as a literal: the longest
#: member plus one space, so the rule id always starts one column past
#: the longest label. A literal `8` was exactly the length of
#: `CRITICAL` and rendered that one severity with no separator before
#: the rule id (`✕ CRITICALpolicy.capability-ceiling`); deriving the
#: width means a future longer member cannot reintroduce the defect.
_LABEL_WIDTH: int = max(len(severity.value) for severity in FindingSeverity) + 1

#: `FindingSeverity` -> SARIF `level`. SARIF defines four levels:
#: `none`, `note`, `warning`, `error`. `none` is reserved for a
#: suppressed or non-finding result, which this function never
#: produces, since every `Finding` is, by definition, a real finding.
_SARIF_LEVEL: dict[FindingSeverity, str] = {
    FindingSeverity.INFO: "note",
    FindingSeverity.LOW: "note",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.HIGH: "error",
    FindingSeverity.CRITICAL: "error",
}


def _located_evidence(evidence: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
    return tuple(item for item in evidence if item.path is not None)


#: The glyph and closing line for a finding whose organization `action`
#: decided its effect on a Team gate verdict. Keyed by the action's wire
#: value: this module does not import `controlloop.policy`.
_ACTION_TEXT: dict[str, tuple[str, str]] = {
    "fail": ("✕", "organization action `fail`: blocks"),
    "require_review": ("!", "organization action `require_review`: needs review"),
    "warn": ("!", "organization action `warn`: reported, does not block"),
    "pass": ("•", "organization action `pass`: does not affect the verdict"),
}


def render_finding_text(
    finding: Finding,
    *,
    suppressed_until: str | None = None,
    excepted_until: str | None = None,
    organization_action: str | None = None,
) -> str:
    """Return `finding`'s brand-consistent, glyph-prefixed human text:
    one summary line, followed by one indented location line per
    evidence entry carrying a `path`, rendered through
    `controlloop.redaction.source_reference` -- the only sanctioned
    textual description of a source location, so this function
    structurally cannot print raw source content even by mistake.

    `suppressed_until` is the expiry date of an active suppression that
    covers this finding. The finding is still shown at its own severity,
    but with the neutral `•` glyph and a closing line saying it is
    suppressed, so it never reads as one that blocks.

    `excepted_until` does the same for an organization exception that
    covers this finding on a Team gate, with its expiry date.

    `organization_action` is the action the finding's organization rule
    sets (`fail`, `require_review`, `warn`, `pass`). It decided the
    finding's effect on the verdict instead of its severity, so its glyph
    follows the action, and a closing line names it. An action this
    function does not know reads as `fail`, as it is enforced."""

    closing: str | None = None
    if suppressed_until is not None:
        glyph = "•"
        closing = f"suppressed until {suppressed_until}; does not affect the verdict"
    elif excepted_until is not None:
        glyph = "•"
        closing = (
            f"organization exception until {excepted_until}; "
            "does not affect the verdict"
        )
    elif organization_action is not None:
        glyph, closing = _ACTION_TEXT.get(organization_action, _ACTION_TEXT["fail"])
    else:
        glyph = _SEVERITY_GLYPH[finding.severity]
    label = finding.severity.value.upper()
    lines = [f"{glyph} {label:<{_LABEL_WIDTH}}{finding.rule_id}: {finding.message}"]
    for evidence in _located_evidence(finding.evidence):
        assert evidence.path is not None
        location = source_reference(
            evidence.path,
            line_start=evidence.line_start,
            line_end=evidence.line_end,
        )
        lines.append(f"    at {location}")
    if closing is not None:
        lines.append(f"    {closing}")
    return "\n".join(lines)


def finding_to_sarif_result(finding: Finding) -> dict[str, object]:
    """Return one SARIF `result` object shape for `finding`.

    This is not a complete SARIF log document -- see this module's own
    docstring. Every finding field without a native slot on a bare
    SARIF `result` object (finding ID, rule version, confidence,
    affected agent, capability path, change state, remediation,
    documentation URL) is carried in a `properties.controlloop` bag,
    SARIF's own documented open extension point for tool-specific
    data.
    """

    locations = [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": evidence.path},
                **(
                    {
                        "region": {
                            key: value
                            for key, value in (
                                ("startLine", evidence.line_start),
                                ("endLine", evidence.line_end),
                            )
                            if value is not None
                        }
                    }
                    if evidence.line_start is not None
                    else {}
                ),
            }
        }
        for evidence in _located_evidence(finding.evidence)
    ]

    controlloop_properties: dict[str, object] = {
        "findingId": finding.id,
        "ruleVersion": finding.rule_version,
        "confidence": finding.confidence.value,
        "affectedAgent": finding.affected_agent,
        "changeState": finding.change_state.value,
        "remediation": finding.remediation,
        "documentationUrl": finding.documentation_url,
    }
    if finding.capability_path is not None:
        # Repository-scoped findings have no `capability_path` at all
        # -- `affectedAgent` above is already `None` in that case (the
        # model's own validator guarantees both are present or both
        # are absent), so this key is simply omitted rather than
        # rendered as a fabricated or null shape.
        controlloop_properties["capabilityPath"] = {
            "agentId": finding.capability_path.agent_id,
            "targetId": finding.capability_path.target_id,
            "targetType": finding.capability_path.target_type.value,
            "hopEdgeIds": [hop.edge_id for hop in finding.capability_path.hops],
        }

    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": locations,
        "properties": {"controlloop": controlloop_properties},
    }
