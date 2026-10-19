"""Unknown and incomplete analysis representation for canonical ACBOMs.

Dynamic or unsupported behavior is represented as an explicit unknown --
never omitted silently, since a silently dropped capability produces a
confident pass, the worst failure this product can have. This module
mirrors `controlloop.repository`'s `DIAGNOSTIC_REGISTRY`/`summarize_skips`
pattern at the canonical ACBOM layer: a closed, documented code registry,
a constructor enforcing the shape, and a deterministic summary view.

No new schema surface is introduced. `Diagnostic.incomplete` and
`Diagnostic.confidence` already exist on the canonical model; a
completeness summary is a filtered, sorted view over an
`ACBOMDocument`'s existing `diagnostics`, not new stored state.
"""

from __future__ import annotations

from collections.abc import Mapping

from controlloop.acbom.models import (
    ACBOMDocument,
    Confidence,
    Diagnostic,
    DiagnosticCode,
    DiagnosticSeverity,
    EvidenceCollection,
    SafeText,
)

_UNRESOLVED_REFERENCE_CODE = "INCOMPLETE-UNRESOLVED-REFERENCE"
_DYNAMIC_REGISTRATION_CODE = "INCOMPLETE-DYNAMIC-REGISTRATION"
_UNPARSED_REGION_CODE = "INCOMPLETE-UNPARSED-REGION"
_BOUND_EXCEEDED_CODE = "INCOMPLETE-BOUND-EXCEEDED"
_ADAPTER_FAILURE_CODE = "INCOMPLETE-ADAPTER-FAILURE"
_UNVERIFIED_DECLARATION_CODE = "INCOMPLETE-UNVERIFIED-DECLARATION"
_CYCLE_DETECTED_CODE = "INCOMPLETE-CYCLE-DETECTED"
_UNRECOGNIZED_KEY_CODE = "INCOMPLETE-UNRECOGNIZED-KEY"

INCOMPLETE_DIAGNOSTIC_REGISTRY: Mapping[str, str] = {
    _UNRESOLVED_REFERENCE_CODE: (
        "A reference to a capability, tool, or identity could not be "
        "resolved to a concrete node."
    ),
    _DYNAMIC_REGISTRATION_CODE: (
        "A tool, agent, or capability is registered at runtime and "
        "cannot be proven statically."
    ),
    _UNPARSED_REGION_CODE: (
        "A region of an otherwise-supported input could not be parsed."
    ),
    _BOUND_EXCEEDED_CODE: (
        "Analysis stopped because a configured resource or depth bound "
        "was reached before discovery completed."
    ),
    _ADAPTER_FAILURE_CODE: (
        "An adapter raised while detecting or discovering evidence, and "
        "was isolated so the rest of the scan could continue."
    ),
    _UNVERIFIED_DECLARATION_CODE: (
        "A human-authored manifest declaration names a capability that "
        "discovered evidence could not corroborate."
    ),
    _CYCLE_DETECTED_CODE: (
        "A graph traversal reached a node already present earlier on the "
        "same path and stopped there, rather than looping or reporting "
        "an arbitrarily long path through the cycle."
    ),
    _UNRECOGNIZED_KEY_CODE: (
        "A configuration file uses a key outside the documented key set "
        "the adapter is pinned to, so what that key grants is unknown."
    ),
}


def incomplete_diagnostic(
    *,
    code: DiagnosticCode,
    message: SafeText,
    evidence: EvidenceCollection,
) -> Diagnostic:
    """Return a `Diagnostic` representing an explicit unknown.

    `code` must be a member of `INCOMPLETE_DIAGNOSTIC_REGISTRY`. Always
    `incomplete=True` and `confidence=Confidence.UNKNOWN` -- an
    incompleteness diagnostic can never claim confident knowledge of the
    very thing it reports as unresolved.
    """

    if code not in INCOMPLETE_DIAGNOSTIC_REGISTRY:
        raise ValueError(f"{code!r} is not a registered incompleteness code")

    return Diagnostic(
        code=code,
        severity=DiagnosticSeverity.WARNING,
        message=message,
        confidence=Confidence.UNKNOWN,
        incomplete=True,
        evidence=evidence,
    )


def completeness_summary(document: ACBOMDocument) -> tuple[Diagnostic, ...]:
    """Return every reason `document`'s analysis was incomplete.

    A deterministic, sorted view over `document.diagnostics` filtered to
    `incomplete=True` -- independent of the input collection's order, the
    same guarantee `repository.summarize_skips` already keeps for
    repository-traversal diagnostics.
    """

    incomplete = [
        diagnostic for diagnostic in document.diagnostics if diagnostic.incomplete
    ]
    return tuple(
        sorted(
            incomplete,
            key=lambda diagnostic: (
                diagnostic.evidence[0].path or "",
                diagnostic.code,
            ),
        )
    )
