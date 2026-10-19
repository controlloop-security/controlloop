"""SARIF 2.1.0 log document assembly.

`controlloop.findings.rendering.finding_to_sarif_result` already renders
one SARIF `result` object per `Finding` -- `ruleId`, `level`, `message`,
and `locations` (an empty list, never a fabricated location, when a
finding carries no located evidence). That function's own docstring
explicitly deferred the surrounding SARIF *log* document -- `$schema`,
`version`, `runs[].tool.driver` (including per-rule help URIs) -- to
this module. `render_sarif_log` supplies exactly that: it composes an
already-computed `findings` tuple into one complete log document,
computing none of the findings themselves, the same "compose, never
compute" discipline every other `controlloop.reporting` module already
follows.
"""

from __future__ import annotations

from controlloop.acbom.models import Generator
from controlloop.findings.models import Finding
from controlloop.findings.rendering import finding_to_sarif_result
from controlloop.reporting.authority import AuthorityDelta, AuthorityEntry

#: The SARIF version this module targets, and the exact string the
#: SARIF 2.1.0 schema's own `version` property requires.
SARIF_VERSION = "2.1.0"

#: The SARIF 2.1.0 schema's own canonical `$id`
#: (`tests/fixtures/sarif/sarif-schema-2.1.0.json`, vendored from
#: `oasis-tcs/sarif-spec` for local, offline schema validation)
#: -- the conventional value a SARIF log's own `$schema` field names.
SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
    "schemas/sarif-schema-2.1.0.json"
)


def _reporting_descriptors(findings: tuple[Finding, ...]) -> list[dict[str, object]]:
    """One `ReportingDescriptor` per unique rule referenced by
    `findings`, in deterministic (`rule_id`-sorted) order, carrying
    each rule's help URI -- the one piece of rule metadata
    `finding_to_sarif_result`'s own per-result object has no native
    SARIF slot for. `Finding.documentation_url` and `.rule_version`
    are both required, defaultless fields, so every descriptor always
    has a real `helpUri` and rule-version property, never a missing or
    fabricated one."""

    representative_by_rule_id: dict[str, Finding] = {}
    for finding in findings:
        representative_by_rule_id.setdefault(finding.rule_id, finding)

    return [
        {
            "id": rule_id,
            "helpUri": representative_by_rule_id[rule_id].documentation_url,
            "properties": {
                "controlloop": {
                    "ruleVersion": representative_by_rule_id[rule_id].rule_version,
                }
            },
        }
        for rule_id in sorted(representative_by_rule_id)
    ]


def _entry_for_finding(
    finding: Finding, delta: AuthorityDelta
) -> AuthorityEntry | None:
    """The authority entry a finding is about: the one whose component is
    the finding's capability path target or, for a repository-scoped
    finding, the only entry granted in the finding's one evidence file."""

    path = finding.capability_path
    if path is not None:
        for entry in delta.entries:
            if entry.node_id == path.target_id:
                return entry
        return None
    files = {str(item.path) for item in finding.evidence if item.path is not None}
    if len(files) != 1:
        return None
    (file,) = files
    in_file = [entry for entry in delta.entries if entry.path == file]
    return in_file[0] if len(in_file) == 1 else None


def _with_authority(
    finding: Finding, delta: AuthorityDelta | None
) -> dict[str, object]:
    result = finding_to_sarif_result(finding)
    entry = _entry_for_finding(finding, delta) if delta is not None else None
    if entry is not None:
        properties = result.setdefault("properties", {})
        assert isinstance(properties, dict)
        namespace = properties.setdefault("controlloop", {})
        assert isinstance(namespace, dict)
        namespace["authorityStatement"] = entry.statement
        namespace["approvalRecorded"] = entry.approval_recorded
    return result


def render_sarif_log(
    findings: tuple[Finding, ...],
    *,
    tool: Generator,
    information_uri: str | None = None,
    blast_radius_lines: tuple[str, ...] | None = None,
    authority_delta: AuthorityDelta | None = None,
    rule_help: dict[str, str] | None = None,
) -> dict[str, object]:
    """Assemble one complete SARIF 2.1.0 log document from an
    already-computed `findings` tuple and an already-known `tool`
    identity. `tool` is a plain caller-supplied fact -- matching
    `ReportVersions.scanner`/`EvidenceVersions.scanner`'s identical
    `Generator` precedent -- never derived here. Deterministic for
    identical input: no field here is a timestamp, a random ID, or
    otherwise unstable across runs, and rule ordering is always sorted,
    never insertion order.

    `blast_radius_lines` is the exact line tuple
    `controlloop.capability.blast_radius.describe_blast_radius` already
    produces for `--format text`, embedded as
    `runs[0].properties.controlloop.blastRadius` -- reusing this
    module's own existing `properties.controlloop` extension namespace
    (see `_reporting_descriptors`) rather than inventing a second one.
    Neither `EvidenceArtifact` nor this document carried the statement
    before this parameter; a GitHub Actions step reads it straight out of
    the written SARIF file for the check summary, avoiding a second
    `gate` invocation just to recover text-rendering output. `None`
    (the default) omits the `properties` key entirely -- never an empty
    array or a `null` standing in for "no statement" -- so every
    existing caller's output is byte-identical to before this
    parameter existed.

    `authority_delta` adds
    `runs[0].properties.controlloop.authorityDelta`, every entry in
    order, and on each result about one of those grants
    `properties.controlloop.authorityStatement` and `approvalRecorded`.
    `rule_help` maps a rule ID to its `help.text`. Both default to
    `None`, which adds nothing."""

    rules = _reporting_descriptors(findings)
    if rule_help:
        for descriptor in rules:
            text = rule_help.get(str(descriptor["id"]))
            if text is not None:
                descriptor["help"] = {"text": text}
    driver: dict[str, object] = {
        "name": tool.name,
        "version": tool.version,
        "rules": rules,
    }
    if information_uri is not None:
        driver["informationUri"] = information_uri

    run: dict[str, object] = {
        "tool": {"driver": driver},
        "results": [_with_authority(finding, authority_delta) for finding in findings],
    }
    namespace: dict[str, object] = {}
    if blast_radius_lines is not None:
        namespace["blastRadius"] = list(blast_radius_lines)
    if authority_delta is not None:
        namespace["authorityDelta"] = [
            entry.model_dump(mode="json") for entry in authority_delta.entries
        ]
    if namespace:
        run["properties"] = {"controlloop": namespace}

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }
