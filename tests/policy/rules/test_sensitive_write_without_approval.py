"""Tests for controlloop.policy.rules.sensitive_write_without_approval."""

from __future__ import annotations

import io
from datetime import UTC, datetime

import pytest

from controlloop import redaction
from controlloop.acbom.models import (
    ACBOMDocument,
    Confidence,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Generator,
    Node,
    NodeType,
    Repository,
    SecurityAttributes,
    Sensitivity,
)
from controlloop.findings.rendering import finding_to_sarif_result, render_finding_text
from controlloop.manifest.approvals import active_approvals
from controlloop.manifest.models import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    Approval,
    DataClassificationDeclaration,
    ManifestDocument,
)
from controlloop.policy.models import RuleContext
from controlloop.policy.rules.sensitive_write_without_approval import (
    RULE,
    evaluate,
    findings,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'b' * 64}"
_WRITE_EDGE_ID = f"clp:edge:sha256:{'1' * 64}"
_PLACEHOLDER_DIGEST = f"sha256:{'e' * 64}"
_AS_OF = datetime(2026, 8, 20, tzinfo=UTC)

_EVIDENCE = (Evidence(adapter="mcp", path="agents/refund-agent.json", line_start=3),)


def _node(
    node_id: str,
    node_type: NodeType,
    name: str,
    *,
    security_attributes: SecurityAttributes | None = None,
) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=_EVIDENCE,
    )


def _edge(edge_id: str, edge_type: EdgeType, source: str, target: str) -> Edge:
    return Edge(
        id=edge_id,
        source=source,
        target=target,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=_EVIDENCE,
    )


def _document(nodes: tuple[Node, ...], edges: tuple[Edge, ...]) -> ACBOMDocument:
    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=_PLACEHOLDER_DIGEST),
        nodes=nodes,
        edges=edges,
        diagnostics=(),
        digest=_PLACEHOLDER_DIGEST,
    )


def _manifest(
    *,
    approvals: tuple[Approval, ...] = (),
    data_classification: tuple[DataClassificationDeclaration, ...] = (),
) -> ManifestDocument:
    return ManifestDocument(
        schema_version=CURRENT_MANIFEST_SCHEMA_VERSION,
        owner="platform-team",
        approvals=approvals,
        data_classification=data_classification,
    )


def _sensitive_write_document(
    *, resource_name: str = "customer-records"
) -> ACBOMDocument:
    agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
    resource = _node(
        _RESOURCE_ID,
        NodeType.RESOURCE,
        resource_name,
        security_attributes=SecurityAttributes(sensitivity=Sensitivity.RESTRICTED),
    )
    edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
    return _document((agent, resource), (edge,))


class TestDataClassSources:
    """Data classes are read from the manifest and from adapter-supplied
    classification."""

    def test_adapter_supplied_sensitivity_alone_fires(self) -> None:
        context = RuleContext(
            acbom=_sensitive_write_document(), policy_version="1", manifest=None
        )

        assert len(evaluate(context)) == 1

    def test_manifest_declared_sensitivity_alone_fires(self) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(_RESOURCE_ID, NodeType.RESOURCE, "customer-records")
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        manifest = _manifest(
            data_classification=(
                DataClassificationDeclaration(
                    resource="customer-records", sensitivity=Sensitivity.CONFIDENTIAL
                ),
            )
        )
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            manifest=manifest,
        )

        assert len(evaluate(context)) == 1

    def test_both_sources_agreeing_still_produces_one_finding(self) -> None:
        manifest = _manifest(
            data_classification=(
                DataClassificationDeclaration(
                    resource="customer-records", sensitivity=Sensitivity.RESTRICTED
                ),
            )
        )
        context = RuleContext(
            acbom=_sensitive_write_document(), policy_version="1", manifest=manifest
        )

        assert len(evaluate(context)) == 1

    def test_non_sensitive_manifest_level_does_not_fire(self) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(_RESOURCE_ID, NodeType.RESOURCE, "customer-records")
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        manifest = _manifest(
            data_classification=(
                DataClassificationDeclaration(
                    resource="customer-records", sensitivity=Sensitivity.PUBLIC
                ),
            )
        )
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            manifest=manifest,
        )

        assert evaluate(context) == ()


class TestDeclaredApprovalSuppresses:
    """A sensitive write with a matching declared approval produces no
    finding."""

    def test_matching_approval_suppresses(self) -> None:
        manifest = _manifest(
            approvals=(Approval(capability="customer-records", approver="alice"),)
        )
        context = RuleContext(
            acbom=_sensitive_write_document(), policy_version="1", manifest=manifest
        )

        assert evaluate(context) == ()
        assert findings(context) == ()

    def test_non_matching_approval_still_fires(self) -> None:
        manifest = _manifest(
            approvals=(Approval(capability="unrelated-resource", approver="alice"),)
        )
        context = RuleContext(
            acbom=_sensitive_write_document(), policy_version="1", manifest=manifest
        )

        assert len(evaluate(context)) == 1


class TestExpiredApprovalDoesNotSuppress:
    """An approval that has expired does not suppress the finding. Expiry is
    decided entirely outside this rule -- see the module's own docstring --
    so this test filters with
    controlloop.manifest.approvals.active_approvals *before* building the
    RuleContext, exactly as a real future caller is expected to."""

    def test_expired_approval_is_filtered_before_reaching_the_rule(self) -> None:
        expired = Approval(
            capability="customer-records",
            approver="alice",
            expires_at="2026-01-01T00:00:00Z",
        )
        raw_manifest = _manifest(approvals=(expired,))
        prepared_manifest = raw_manifest.model_copy(
            update={"approvals": active_approvals(raw_manifest, as_of=_AS_OF)}
        )

        context = RuleContext(
            acbom=_sensitive_write_document(),
            policy_version="1",
            manifest=prepared_manifest,
        )

        assert len(evaluate(context)) == 1

    def test_still_active_approval_suppresses(self) -> None:
        active = Approval(
            capability="customer-records",
            approver="alice",
            expires_at="2026-12-31T00:00:00Z",
        )
        raw_manifest = _manifest(approvals=(active,))
        prepared_manifest = raw_manifest.model_copy(
            update={"approvals": active_approvals(raw_manifest, as_of=_AS_OF)}
        )

        context = RuleContext(
            acbom=_sensitive_write_document(),
            policy_version="1",
            manifest=prepared_manifest,
        )

        assert evaluate(context) == ()

    def test_a_rule_given_an_unfiltered_expired_approval_still_honors_it(self) -> None:
        """Documents the rule's own actual, disclosed behavior: it never
        checks expiry itself, so a caller that skips filtering gets a
        (potentially stale) suppression -- "an expired approval does not
        suppress" is a property of the pipeline, not of this one function
        in isolation."""

        expired = Approval(
            capability="customer-records",
            approver="alice",
            expires_at="2026-01-01T00:00:00Z",
        )
        manifest = _manifest(approvals=(expired,))
        context = RuleContext(
            acbom=_sensitive_write_document(), policy_version="1", manifest=manifest
        )

        assert evaluate(context) == ()


class TestBoundaryAndMalformed:
    def test_no_manifest_and_non_sensitive_resource_produces_nothing(self) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(_RESOURCE_ID, NodeType.RESOURCE, "public-catalog")
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)),
            policy_version="1",
            manifest=None,
        )

        assert evaluate(context) == ()

    def test_write_edge_between_two_non_agent_non_resource_nodes_is_ignored(
        self,
    ) -> None:
        """A write-typed edge whose endpoints are not (agent -> resource)
        cannot be a 'sensitive write' this rule is scoped to -- must not
        crash or misreport."""

        tool = _node(_AGENT_ID, NodeType.TOOL, "some-tool")
        identity = _node(_RESOURCE_ID, NodeType.IDENTITY, "some-identity")
        edge = _edge(_WRITE_EDGE_ID, EdgeType.WRITES, _AGENT_ID, _RESOURCE_ID)
        context = RuleContext(
            acbom=_document((tool, identity), (edge,)), policy_version="1"
        )

        assert evaluate(context) == ()

    def test_read_not_write_does_not_fire(self) -> None:
        agent = _node(_AGENT_ID, NodeType.AGENT, "refund-agent")
        resource = _node(
            _RESOURCE_ID,
            NodeType.RESOURCE,
            "customer-records",
            security_attributes=SecurityAttributes(sensitivity=Sensitivity.RESTRICTED),
        )
        edge = _edge(_WRITE_EDGE_ID, EdgeType.READS, _AGENT_ID, _RESOURCE_ID)
        context = RuleContext(
            acbom=_document((agent, resource), (edge,)), policy_version="1"
        )

        assert evaluate(context) == ()

    def test_no_manifest_at_all_still_detects_via_adapter_classification(
        self,
    ) -> None:
        context = RuleContext(
            acbom=_sensitive_write_document(), policy_version="1", manifest=None
        )

        assert len(evaluate(context)) == 1
        assert len(findings(context)) == 1

    def test_finding_carries_the_real_direct_path(self) -> None:
        context = RuleContext(acbom=_sensitive_write_document(), policy_version="1")

        (finding,) = findings(context)

        assert finding.affected_agent == _AGENT_ID
        assert finding.capability_path is not None
        assert finding.capability_path.target_id == _RESOURCE_ID
        assert len(finding.capability_path.hops) == 1
        assert finding.capability_path.hops[0].edge_id == _WRITE_EDGE_ID


class TestDeterminism:
    def test_repeated_evaluation_is_byte_identical(self) -> None:
        context = RuleContext(acbom=_sensitive_write_document(), policy_version="1")

        assert evaluate(context) == evaluate(context)
        assert findings(context) == findings(context)

    def test_rule_is_registered_under_a_stable_id(self) -> None:
        assert RULE.id == "policy.sensitive-write-without-approval"
        assert RULE.evaluate is evaluate


class TestOffline:
    def test_offline_harness_is_active_for_this_module(self) -> None:
        import socket

        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()


class TestPrivacyCanary:
    def test_secret_shaped_resource_name_never_survives_rendering(self) -> None:
        planted_secret = "ghp_" + "d" * 36
        context = RuleContext(
            acbom=_sensitive_write_document(resource_name=planted_secret),
            policy_version="1",
        )

        (finding,) = findings(context)
        stdout_buffer = io.StringIO()
        with redaction.redirected_streams(target_stdout=stdout_buffer):
            print(render_finding_text(finding))
            print(finding.model_dump_json())
            print(finding_to_sarif_result(finding))

        output = stdout_buffer.getvalue()
        assert planted_secret not in output
        assert "controlloop:redacted:sha256:" in output
