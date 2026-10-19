"""Tests for controlloop.manifest.models."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import (  # type: ignore[import-untyped]
    ValidationError as JsonSchemaValidationError,
)
from pydantic import ValidationError
from pydantic import ValidationError as PydanticValidationError

from controlloop.acbom import EdgeType, Sensitivity
from controlloop.manifest import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    AllowedDelegation,
    Approval,
    CapabilityCeiling,
    DataClassificationDeclaration,
    ManifestDocument,
    ProhibitedCapability,
    Suppression,
    ToolLoggingDeclaration,
    TrustBoundary,
)

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _CLI_ROOT / "src/controlloop/schemas/manifest/1.0.0/manifest.schema.json"

# Regenerate by hashing the schema file after a deliberate, version-bumped
# change: `hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()`. Updated
# for the additive `logged_tools` field and the additive
# `Approval.expires_at` field together (both still within schema version
# 1.0.0: two independent new optional fields, each minor-compatible, not
# breaking, per docs/reference/schema-versioning.md) -- these two schema
# changes were developed concurrently and reconciled in one merge, so this
# single digest reflects both fields at once rather than one digest per
# field. Regenerating this file also fixed a real bug the `expires_at`
# regeneration introduced: the wrapper's own `title`/`description`
# (`"ControlLoop Security Manifest"`/the canonical one-line summary) were
# being silently overwritten by `ManifestDocument.model_json_schema()`'s own
# auto-generated top-level `title`/`description` (the class name and its
# docstring) -- caught and fixed during this reconciliation, confirmed by
# asserting `data["title"] == "ControlLoop Security Manifest"` below.
# Updated again for the additive `suppressions` field
# (`tuple[Suppression, ...] = ()`) -- a new optional field with a real
# default, minor-compatible, still within schema version 1.0.0, the
# identical precedent `logged_tools`/`Approval.expires_at` already
# established above. Updated a third time for the schemas.controlloop.dev ->
# .ai domain migration (the schema's own `$id`), reconciled with the above
# during a real merge -- both changes are present in the one committed file
# this digest covers.
_GOLDEN_SCHEMA_DIGEST_FOR_1_0_0 = (
    "c8f90fd9ac1f75f7c52a065f5311eb9f0f3cc3f55def3cf876705fcc5b501d15"
)


def _minimal_document(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
        "owner": "security-team",
    }
    payload.update(overrides)
    return payload


def test_minimal_manifest_validates() -> None:
    """The smallest valid manifest -- schema_version and owner only, every
    other field defaults to empty."""
    document = ManifestDocument.model_validate(_minimal_document())

    assert document.schema_version == CURRENT_MANIFEST_SCHEMA_VERSION
    assert document.owner == "security-team"
    assert document.trust_boundaries == ()
    assert document.approvals == ()
    assert document.prohibited_capabilities == ()
    assert document.allowed_delegation == ()
    assert document.data_classification == ()


def test_full_manifest_validates_every_declaration_type() -> None:
    """Ownership, trust boundaries, approvals, prohibited capabilities,
    allowed delegation, and data classification all validate through one
    document. Constructed from typed model instances directly (Python-mode
    strict validation requires a tuple, not a list, for these fields -- the
    parser handles a YAML list via model_validate_json, covered in
    test_parser.py)."""
    document = ManifestDocument.model_validate(
        _minimal_document(
            trust_boundaries=(TrustBoundary(name="prod", agents=("refund-agent",)),),
            approvals=(Approval(capability="send-email", approver="alice"),),
            prohibited_capabilities=(
                ProhibitedCapability(
                    agent="refund-agent",
                    edge_type=EdgeType.WRITES,
                    target="billing-db",
                ),
            ),
            allowed_delegation=(
                AllowedDelegation(
                    agent="coordinator", targets=("researcher", "writer")
                ),
            ),
            data_classification=(
                DataClassificationDeclaration(
                    resource="customer-records",
                    sensitivity=Sensitivity.CONFIDENTIAL,
                ),
            ),
            logged_tools=(
                ToolLoggingDeclaration(
                    tool="refund-tool", audit_path="audit/refund-tool.log"
                ),
            ),
        )
    )

    assert document.trust_boundaries[0] == TrustBoundary(
        name="prod", agents=("refund-agent",)
    )
    assert document.approvals[0] == Approval(capability="send-email", approver="alice")
    assert document.prohibited_capabilities[0] == ProhibitedCapability(
        agent="refund-agent", edge_type=EdgeType.WRITES, target="billing-db"
    )
    assert document.allowed_delegation[0] == AllowedDelegation(
        agent="coordinator", targets=("researcher", "writer")
    )
    assert document.data_classification[0] == DataClassificationDeclaration(
        resource="customer-records", sensitivity=Sensitivity.CONFIDENTIAL
    )
    assert document.logged_tools[0] == ToolLoggingDeclaration(
        tool="refund-tool", audit_path="audit/refund-tool.log"
    )


def test_unknown_field_is_rejected() -> None:
    """extra="forbid": an older reader cannot silently ignore a field it
    does not recognize, matching the ACBOM's own discipline."""
    with pytest.raises(ValidationError):
        ManifestDocument.model_validate(_minimal_document(raw_source="leaked"))


def test_missing_owner_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ManifestDocument.model_validate(
            {"schema_version": CURRENT_MANIFEST_SCHEMA_VERSION}
        )


def test_tool_logging_declaration_requires_both_fields() -> None:
    """A declaration names a tool and where its invocations are logged or
    audited; either omission is rejected."""
    with pytest.raises(ValidationError):
        ToolLoggingDeclaration.model_validate({"tool": "refund-tool"})
    with pytest.raises(ValidationError):
        ToolLoggingDeclaration.model_validate({"audit_path": "audit/refund-tool.log"})


def test_tool_logging_declaration_accepts_a_system_identifier_audit_path() -> None:
    """`audit_path` is free-form (`SafeIdentifier`): a repository-relative
    path and a colon-delimited external system identifier both validate,
    since this manifest only declares intent and never connects to
    anything to verify it."""
    declaration = ToolLoggingDeclaration(
        tool="refund-tool", audit_path="datadog:agent-audit-log"
    )
    assert declaration.audit_path == "datadog:agent-audit-log"


def test_tool_logging_declaration_rejects_an_empty_tool_name() -> None:
    with pytest.raises(ValidationError):
        ToolLoggingDeclaration(tool="", audit_path="audit/refund-tool.log")


def test_logged_tools_defaults_to_empty() -> None:
    document = ManifestDocument.model_validate(_minimal_document())
    assert document.logged_tools == ()


def test_suppressions_defaults_to_empty() -> None:
    """A manifest declaring no suppressions at all is a perfectly ordinary,
    valid manifest -- suppressions are opt-in, never required."""
    document = ManifestDocument.model_validate(_minimal_document())
    assert document.suppressions == ()


def test_manifest_parses_multiple_declared_suppressions() -> None:
    first = Suppression(
        rule_id="policy.undeclared-tools",
        target=f"clp:finding:sha256:{'a' * 64}",
        reason="reviewed by security team",
        expires_at="2099-01-01",
    )
    second = Suppression(
        rule_id="policy.broad-permission",
        target=f"clp:finding:sha256:{'b' * 64}",
        reason="temporary exception pending fix",
        expires_at="2026-12-31",
    )

    document = ManifestDocument.model_validate(
        _minimal_document(suppressions=(first, second))
    )

    assert document.suppressions == (first, second)


def test_suppression_missing_a_required_field_is_rejected() -> None:
    """Any missing field returns exit 2 -- structural proof at the model
    level (the manifest-parser-level exit-2 behavior is covered by
    `test_cli.py`'s `TestSuppressions`)."""
    with pytest.raises(ValidationError):
        Suppression(  # type: ignore[call-arg]
            rule_id="policy.undeclared-tools",
            target=f"clp:finding:sha256:{'a' * 64}",
            expires_at="2099-01-01",
            # reason omitted
        )


def test_capability_ceiling_validates_all_five_prohibition_categories() -> None:
    """Prohibited resources, actions, external destinations, data classes,
    and delegation targets."""
    ceiling = CapabilityCeiling(
        agent="refund-agent",
        prohibited_resources=("billing-db",),
        prohibited_actions=(EdgeType.WRITES,),
        prohibited_external_destinations=("evil.example.com",),
        prohibited_data_classes=(Sensitivity.RESTRICTED,),
        prohibited_delegation_targets=("unapproved-agent",),
    )

    document = ManifestDocument.model_validate(_minimal_document(ceilings=(ceiling,)))

    assert document.ceilings == (ceiling,)


def test_repository_wide_ceiling_has_no_agent() -> None:
    """A ceiling may be declared at repository scope."""
    ceiling = CapabilityCeiling(prohibited_resources=("billing-db",))

    document = ManifestDocument.model_validate(_minimal_document(ceilings=(ceiling,)))

    assert document.ceilings[0].agent is None


def test_two_repository_wide_ceilings_are_ambiguous_and_rejected() -> None:
    """An ambiguous ceiling is rejected, never partially applied."""
    with pytest.raises(ValidationError):
        ManifestDocument.model_validate(
            _minimal_document(
                ceilings=(
                    CapabilityCeiling(prohibited_resources=("a",)),
                    CapabilityCeiling(prohibited_resources=("b",)),
                )
            )
        )


def test_two_ceilings_for_the_same_agent_are_ambiguous_and_rejected() -> None:
    """Two ceilings for one agent are ambiguous and rejected."""
    with pytest.raises(ValidationError):
        ManifestDocument.model_validate(
            _minimal_document(
                ceilings=(
                    CapabilityCeiling(
                        agent="refund-agent", prohibited_resources=("a",)
                    ),
                    CapabilityCeiling(
                        agent="refund-agent", prohibited_resources=("b",)
                    ),
                )
            )
        )


def test_one_repository_wide_and_one_agent_ceiling_coexist() -> None:
    """Repository-wide and agent-specific scopes are distinct, not ambiguous
    with each other."""
    document = ManifestDocument.model_validate(
        _minimal_document(
            ceilings=(
                CapabilityCeiling(prohibited_resources=("a",)),
                CapabilityCeiling(agent="refund-agent", prohibited_resources=("b",)),
            )
        )
    )

    assert len(document.ceilings) == 2


def test_packaged_schema_matches_its_golden_digest() -> None:
    """A published schema. A breaking schema change without a version
    increment fails CI -- this schema file's content is tied to a committed
    digest for its declared version; any edit to the file changes the
    digest, and this test then requires a deliberate update, mirroring the
    ACBOM's own `test_packaged_schema_matches_its_golden_digest`."""
    actual_digest = hashlib.sha256(_SCHEMA_PATH.read_bytes()).hexdigest()

    assert actual_digest == _GOLDEN_SCHEMA_DIGEST_FOR_1_0_0, (
        "the packaged manifest schema file changed without updating the "
        "golden digest -- see docs/reference/schema-versioning.md before "
        "updating this constant"
    )


def test_packaged_schema_wrapper_title_and_description_are_the_hand_chosen_ones() -> (
    None
):
    """Regression test for a real bug caught reconciling the
    `Approval.expires_at` schema change against the concurrent
    `logged_tools` one: the packaged schema is generated from
    `ManifestDocument.model_json_schema()`, but that call's own top-level
    `title`/`description` (the class name and its docstring) must not
    silently overwrite this file's hand-chosen wrapper values -- a prior
    regeneration of this exact file let that happen, undetected because
    nothing asserted these two fields directly, only the whole-file
    digest."""

    schema = json.loads(_SCHEMA_PATH.read_text())

    assert schema["title"] == "ControlLoop Security Manifest"
    assert schema["description"] == (
        "Canonical controlloop.yaml security manifest for ControlLoop "
        "schema version 1.0.0."
    )


_SCHEMA_PATH_1_1_0 = (
    _CLI_ROOT / "src/controlloop/schemas/manifest/1.1.0/manifest.schema.json"
)

# Regenerate by hashing the schema file after a deliberate, version-bumped
# change: `hashlib.sha256(_SCHEMA_PATH_1_1_0.read_bytes()).hexdigest()`.
# Introduced by the change that added `tool_capabilities` and widened
# `ToolLoggingDeclaration.tool` from `SafeIdentifier` to `SafeText`. Both
# are additive or relaxing, so `1.0.0` above stays frozen and unedited -- an
# existing `1.0.0` manifest still reads fine under the one-directional
# compatibility rule in docs/reference/schema-versioning.md.
_GOLDEN_SCHEMA_DIGEST_FOR_1_1_0 = (
    "d7d7ddc04ae51e931d3a603191e827a2020f2482aa6ae7e89501b6fa00234928"
)


class TestPackagedSchema110:
    """The 1.1.0 packaged manifest schema, mirroring the 1.0.0 assertions
    immediately above rather than inventing a new style."""

    def test_published_schema_is_valid_draft_2020_12(self) -> None:
        Draft202012Validator.check_schema(
            json.loads(_SCHEMA_PATH_1_1_0.read_text(encoding="utf-8"))
        )

    def test_packaged_schema_matches_its_golden_digest(self) -> None:
        actual_digest = hashlib.sha256(_SCHEMA_PATH_1_1_0.read_bytes()).hexdigest()

        assert actual_digest == _GOLDEN_SCHEMA_DIGEST_FOR_1_1_0, (
            "the packaged manifest 1.1.0 schema file changed without "
            "updating the golden digest -- see "
            "docs/reference/schema-versioning.md before updating this "
            "constant"
        )

    def test_wrapper_title_and_description_are_the_hand_chosen_ones(self) -> None:
        """Same regression this file already guards for 1.0.0: a
        regeneration must not let `model_json_schema()`'s own top-level
        title/description overwrite the hand-chosen wrapper values."""
        schema = json.loads(_SCHEMA_PATH_1_1_0.read_text(encoding="utf-8"))

        assert schema["title"] == "ControlLoop Security Manifest"
        assert schema["description"] == (
            "Canonical controlloop.yaml security manifest for ControlLoop "
            "schema version 1.1.0."
        )

    def test_frozen_1_0_0_schema_has_no_tool_capabilities(self) -> None:
        """The frozen historical version must not have been edited in
        passing while adding the new field."""
        old = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))

        assert "tool_capabilities" not in old["properties"]
        assert old["description"].endswith("schema version 1.0.0.")

    def test_schema_and_model_agree_on_a_tool_capability_document(self) -> None:
        """Parity: the packaged schema and `ManifestDocument` accept the
        same document."""
        document = {
            "schema_version": "1.1.0",
            "owner": "support-eng",
            "tool_capabilities": [
                {
                    "tool": "Issue a refund",
                    "financial_action": True,
                    "sensitivity": "confidential",
                }
            ],
            "logged_tools": [
                {"tool": "Issue a refund", "audit_path": "logs/refund-audit.log"}
            ],
        }
        schema = json.loads(_SCHEMA_PATH_1_1_0.read_text(encoding="utf-8"))

        Draft202012Validator(schema).validate(document)
        model = ManifestDocument.model_validate_json(json.dumps(document))

        assert model.tool_capabilities[0].tool == "Issue a refund"
        assert model.tool_capabilities[0].financial_action is True
        assert model.logged_tools[0].tool == "Issue a refund"

    def test_schema_and_model_agree_on_an_unknown_field(self) -> None:
        document = {
            "schema_version": "1.1.0",
            "owner": "support-eng",
            "tool_capabilities": [{"tool": "Issue a refund", "not_a_field": True}],
        }
        schema = json.loads(_SCHEMA_PATH_1_1_0.read_text(encoding="utf-8"))

        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(schema).validate(document)
        with pytest.raises(PydanticValidationError):
            ManifestDocument.model_validate_json(json.dumps(document))


_SCHEMA_PATH_1_2_0 = (
    _CLI_ROOT / "src/controlloop/schemas/manifest/1.2.0/manifest.schema.json"
)

# Regenerate by hashing the schema file after a deliberate, version-bumped
# change: `hashlib.sha256(_SCHEMA_PATH_1_2_0.read_bytes()).hexdigest()`.
# Introduced by the change that widened the eleven fields that name a
# discovered node from `SafeIdentifier` to `SafeText`. A MINOR bump: every
# document valid under 1.1.0 is still valid, but an older reader cannot read
# a 1.2.0 document that uses the new latitude -- the same one-directional
# rule docs/reference/schema-versioning.md documents for a new optional
# field.
_GOLDEN_SCHEMA_DIGEST_FOR_1_2_0 = (
    "e87e895b4766110b35cf3fd7b92ad6e9c8ebab4a4a34a0cd5796d74edaa827b6"
)

#: A tool name discovery really produces: `a2a.py` takes a skill's node
#: name from its card `name`, so spaces are ordinary, not exotic.
_DISPLAY_NAME = "Void an invoice"


class TestPackagedSchema120:
    """The 1.2.0 packaged schema, mirroring `TestPackagedSchema110`."""

    def test_published_schema_is_valid_draft_2020_12(self) -> None:
        Draft202012Validator.check_schema(
            json.loads(_SCHEMA_PATH_1_2_0.read_text(encoding="utf-8"))
        )

    def test_packaged_schema_matches_its_golden_digest(self) -> None:
        actual_digest = hashlib.sha256(_SCHEMA_PATH_1_2_0.read_bytes()).hexdigest()

        assert actual_digest == _GOLDEN_SCHEMA_DIGEST_FOR_1_2_0, (
            "the packaged manifest 1.2.0 schema file changed without "
            "updating the golden digest -- see "
            "docs/reference/schema-versioning.md before updating this "
            "constant"
        )

    def test_wrapper_title_and_description_are_the_hand_chosen_ones(self) -> None:
        schema = json.loads(_SCHEMA_PATH_1_2_0.read_text(encoding="utf-8"))

        assert schema["title"] == "ControlLoop Security Manifest"
        assert schema["description"] == (
            "Canonical controlloop.yaml security manifest for ControlLoop "
            "schema version 1.2.0."
        )

    @pytest.mark.parametrize("frozen_version", ["1.0.0", "1.1.0"])
    def test_older_packaged_schemas_stay_frozen_and_still_reject(
        self, frozen_version: str
    ) -> None:
        """The historical versions are never edited, and must still
        reject what they always rejected -- otherwise the version bump
        was pointless."""
        path = (
            _CLI_ROOT
            / f"src/controlloop/schemas/manifest/{frozen_version}/manifest.schema.json"
        )
        schema = json.loads(path.read_text(encoding="utf-8"))
        document = {
            "schema_version": frozen_version,
            "owner": "security-team",
            "ceilings": [{"prohibited_resources": [_DISPLAY_NAME]}],
        }

        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(schema).validate(document)

    def test_1_2_0_accepts_a_display_name_the_older_versions_reject(self) -> None:
        """The whole point of the bump, asserted directly."""
        schema = json.loads(_SCHEMA_PATH_1_2_0.read_text(encoding="utf-8"))
        document = {
            "schema_version": "1.2.0",
            "owner": "security-team",
            "ceilings": [{"prohibited_resources": [_DISPLAY_NAME]}],
        }

        Draft202012Validator(schema).validate(document)
        ManifestDocument.model_validate_json(json.dumps(document))

    @pytest.mark.parametrize(
        ("section", "document"),
        [
            (
                "trust_boundaries",
                {"trust_boundaries": [{"name": "b", "agents": [_DISPLAY_NAME]}]},
            ),
            (
                "approvals",
                {"approvals": [{"capability": _DISPLAY_NAME, "approver": "a"}]},
            ),
            (
                "prohibited_capabilities",
                {
                    "prohibited_capabilities": [
                        {
                            "agent": _DISPLAY_NAME,
                            "edge_type": "writes",
                            "target": _DISPLAY_NAME,
                        }
                    ]
                },
            ),
            (
                "allowed_delegation",
                {
                    "allowed_delegation": [
                        {"agent": _DISPLAY_NAME, "targets": [_DISPLAY_NAME]}
                    ]
                },
            ),
            (
                "data_classification",
                {
                    "data_classification": [
                        {"resource": _DISPLAY_NAME, "sensitivity": "confidential"}
                    ]
                },
            ),
            (
                "ceilings",
                {
                    "ceilings": [
                        {
                            "agent": _DISPLAY_NAME,
                            "prohibited_resources": [_DISPLAY_NAME],
                            "prohibited_external_destinations": [_DISPLAY_NAME],
                            "prohibited_delegation_targets": [_DISPLAY_NAME],
                        }
                    ]
                },
            ),
        ],
    )
    def test_every_widened_section_accepts_a_display_name(
        self, section: str, document: dict[str, object]
    ) -> None:
        """All eleven widened fields, section by section, through both
        the packaged schema and the model."""
        payload = {"schema_version": "1.2.0", "owner": "security-team", **document}
        schema = json.loads(_SCHEMA_PATH_1_2_0.read_text(encoding="utf-8"))

        Draft202012Validator(schema).validate(payload)
        ManifestDocument.model_validate_json(json.dumps(payload))

    @pytest.mark.parametrize(
        "document",
        [
            {"owner": "has a space"},
            {"trust_boundaries": [{"name": "has a space", "agents": ["a"]}]},
            {"approvals": [{"capability": "c", "approver": "has a space"}]},
            {"logged_tools": [{"tool": "t", "audit_path": "has a space"}]},
        ],
    )
    def test_identifier_fields_were_not_widened(
        self, document: dict[str, object]
    ) -> None:
        """Guards against over-widening. These name a team, a label, a
        person, and a log destination -- never a discovered node -- so
        they stay `SafeIdentifier`."""
        payload = {"schema_version": "1.2.0", "owner": "security-team", **document}
        schema = json.loads(_SCHEMA_PATH_1_2_0.read_text(encoding="utf-8"))

        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(schema).validate(payload)
        with pytest.raises(PydanticValidationError):
            ManifestDocument.model_validate_json(json.dumps(payload))
