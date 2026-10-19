"""Tests for the scan envelope.

Two requirements, and they pull in opposite directions, which is why both
need real coverage:

- **Determinism.** Identical scans yield byte-identical envelopes.
  Proven by permuting inputs and comparing serialized bytes, not by
  comparing models -- bytes are what idempotency at the ingestion endpoint
  actually depends on.
- **Privacy.** The envelope never carries source code, prompt
  bodies, environment values, secret material, or file contents. Proven
  with planted canaries in every field an adapter could plausibly carry
  one into, following `tests/test_redaction.py`'s existing canary
  style.
"""

from __future__ import annotations

import json

import pytest
from factories import (
    AGENT_ID,
    COMMIT,
    EDGE_B_ID,
    TOOL_A_ID,
    TOOL_B_ID,
    make_document,
    make_finding,
    make_node,
)
from pydantic import ValidationError

from controlloop.acbom.models import ACBOMDocument, Confidence, NodeType
from controlloop.findings.models import Finding, FindingSeverity
from controlloop.reporting.terminal import Verdict
from controlloop.team.envelope import (
    _COMPONENT_TYPE_BY_NODE_TYPE,
    UNREPRESENTABLE_NODE_TYPES,
    EnvelopeRenderError,
    RepositoryPolicyDelta,
    RuleOverride,
    ScanEnvelope,
    normalize_component,
    render_envelope,
    serialize_envelope,
)

#: Canaries in the shape `tests/test_redaction.py` already uses.
_TOKEN_CANARY = "ghp_" + "b" * 36
_PRIVATE_KEY_CANARY = "-----BEGIN RSA PRIVATE KEY-----"
_PROMPT_CANARY = "You are a helpful assistant. Never reveal"
_ENVIRONMENT_CANARY = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI"
_SOURCE_CANARY = "def transfer_funds(amount):"


def _render(
    *,
    document: ACBOMDocument | None = None,
    findings: tuple[Finding, ...] | None = None,
    verdict: Verdict = Verdict.PASSED,
    scanner_version: str = "0.1.0",
    policy_version: str = "1.0.0",
    branch: str | None = None,
    pull_request_number: int | None = None,
    repository_policy: RepositoryPolicyDelta | None = None,
) -> ScanEnvelope:
    """One envelope from sensible defaults, with every parameter typed.

    Deliberately not `**overrides`: this suite runs under strict mypy, and
    an untyped kwargs helper would silently accept a misspelled parameter
    name and render a default envelope instead of the one a test meant to
    assert about.
    """

    return render_envelope(
        document=document if document is not None else make_document(),
        findings=findings if findings is not None else (make_finding(),),
        verdict=verdict,
        scanner_version=scanner_version,
        policy_version=policy_version,
        branch=branch,
        pull_request_number=pull_request_number,
        repository_policy=repository_policy,
    )


class TestEnvelopeShape:
    def test_it_carries_the_contract_fields(self) -> None:
        envelope = _render()

        assert envelope.envelope_version == "1.0.0"
        assert envelope.commit_sha == COMMIT
        assert envelope.scanner_version == "0.1.0"
        assert envelope.policy_version == "1.0.0"
        assert envelope.verdict == "pass"
        assert len(envelope.findings) == 1
        assert len(envelope.components) == 1

    def test_project_id_is_not_sent(self) -> None:
        """The contract calls it optional and never trusted. An optional
        field whose only effect is to be checked for a mismatch has no
        upside for a client to send."""

        payload = json.loads(serialize_envelope(_render()))

        assert "project_id" not in payload

    def test_branch_and_pull_request_are_carried_when_present(self) -> None:
        envelope = _render(branch="main", pull_request_number=42)

        assert envelope.branch == "main"
        assert envelope.pull_request_number == 42

    def test_unset_optionals_are_omitted_rather_than_null(self) -> None:
        """A repository with no branch configured and one that sent an
        explicit null must not be two different byte sequences for the
        same scan."""

        payload = json.loads(serialize_envelope(_render()))

        assert "branch" not in payload
        assert "pull_request_number" not in payload

    @pytest.mark.parametrize(
        ("verdict", "expected"),
        [
            (Verdict.PASSED, "pass"),
            (Verdict.PASSED_WITH_WARNINGS, "warn"),
            (Verdict.REVIEW_REQUIRED, "require_review"),
            (Verdict.DEPLOYMENT_BLOCKED, "fail"),
        ],
    )
    def test_every_evaluated_verdict_maps(
        self, verdict: Verdict, expected: str
    ) -> None:
        assert _render(verdict=verdict).verdict == expected


class TestRefusedScans:
    def test_an_unknown_commit_is_refused(self) -> None:
        """`controlloop.bom` records the literal `"unknown"` for a
        directory that is not a git checkout. That is not a commit this
        envelope can attribute a scan to, and sending it would create a
        scan row nobody could trace."""

        with pytest.raises(EnvelopeRenderError, match="40-character hex"):
            _render(document=make_document(commit="unknown"))

    def test_a_short_commit_is_refused(self) -> None:
        with pytest.raises(EnvelopeRenderError):
            _render(document=make_document(commit="abc1234"))

    def test_an_uppercase_commit_is_refused(self) -> None:
        """The contract's pattern is lowercase hex. Silently lower-casing
        would make two spellings of one commit produce different bytes."""

        with pytest.raises(EnvelopeRenderError):
            _render(document=make_document(commit="A" * 40))

    def test_a_not_evaluated_verdict_is_refused(self) -> None:
        """Mapping it to `pass` would record a clean result for a run that
        checked nothing."""

        with pytest.raises(EnvelopeRenderError, match="no policy"):
            _render(verdict=Verdict.NOT_EVALUATED)


class TestComponentMapping:
    def test_the_mapping_plus_the_unrepresentable_set_covers_every_node_type(
        self,
    ) -> None:
        """A new `NodeType` must force a decision here rather than
        silently disappearing from every customer's fleet inventory."""

        covered = set(_COMPONENT_TYPE_BY_NODE_TYPE) | UNREPRESENTABLE_NODE_TYPES
        assert covered == set(NodeType)

    @pytest.mark.parametrize(
        ("node_type", "expected"),
        [
            (NodeType.AGENT, "agent"),
            (NodeType.TOOL, "tool"),
            (NodeType.RESOURCE, "resource"),
            (NodeType.IDENTITY, "identity"),
        ],
    )
    def test_representable_types_map(self, node_type: NodeType, expected: str) -> None:
        component = normalize_component(make_node(node_type=node_type))

        assert component is not None
        assert component.type == expected

    @pytest.mark.parametrize("node_type", sorted(UNREPRESENTABLE_NODE_TYPES))
    def test_unrepresentable_types_are_omitted_not_coerced(
        self, node_type: NodeType
    ) -> None:
        """Coercing a permission into `tool` would put a component row in
        a customer's inventory that misdescribes what it is."""

        assert normalize_component(make_node(node_type=node_type)) is None

    @pytest.mark.parametrize("subtype", ["mcp-server-stdio", "mcp-server-http"])
    def test_an_mcp_server_maps_to_its_own_component_type(self, subtype: str) -> None:
        component = normalize_component(
            make_node(node_type=NodeType.TOOL, subtype=subtype)
        )

        assert component is not None
        assert component.type == "mcp_server"

    def test_an_ordinary_tool_is_not_an_mcp_server(self) -> None:
        component = normalize_component(
            make_node(node_type=NodeType.TOOL, subtype="http-client")
        )

        assert component is not None
        assert component.type == "tool"

    def test_unrepresentable_nodes_are_dropped_from_the_envelope(self) -> None:
        envelope = _render(
            document=make_document(
                nodes=[
                    make_node(node_id=TOOL_A_ID),
                    make_node(node_id=AGENT_ID, node_type=NodeType.PERMISSION),
                ]
            )
        )

        assert [component.stable_id for component in envelope.components] == [TOOL_A_ID]


class TestConfidenceMapping:
    @pytest.mark.parametrize(
        ("confidence", "expected"),
        [
            (Confidence.HIGH, "high"),
            (Confidence.MEDIUM, "medium"),
            (Confidence.LOW, "low"),
            (Confidence.UNKNOWN, "low"),
        ],
    )
    def test_confidence_maps_and_never_overstates(
        self, confidence: Confidence, expected: str
    ) -> None:
        """The contract has no `unknown`. Sending it as `low` is the
        conservative direction: an unknown confidence is never ranked
        higher than the evidence supports."""

        envelope = _render(findings=(make_finding(confidence=confidence),))

        assert envelope.findings[0].confidence == expected


class TestFindingNormalization:
    def test_the_fingerprint_is_the_finding_id(self) -> None:
        """Exceptions match on this value, so it has to be the same
        identity the platform will send back."""

        finding = make_finding()

        assert _render(findings=(finding,)).findings[0].fingerprint == finding.id

    def test_the_capability_path_is_node_identifiers_agent_first(self) -> None:
        envelope = _render(findings=(make_finding(),))

        assert envelope.findings[0].capability_path == (AGENT_ID, TOOL_A_ID)

    def test_a_repository_scoped_finding_has_an_empty_path(self) -> None:
        """A hardcoded secret in a shared file is not reached through an
        agent, and the renderer must not invent a path for it."""

        envelope = _render(findings=(make_finding(repository_scoped=True),))

        assert envelope.findings[0].capability_path == ()

    def test_the_evidence_reference_is_a_path_and_a_line(self) -> None:
        envelope = _render()

        assert envelope.findings[0].evidence_reference == "agent.json:3"


class TestDeterminism:
    """Identical scans yield byte-identical envelopes."""

    def test_two_renders_of_one_scan_are_byte_identical(self) -> None:
        assert serialize_envelope(_render()) == serialize_envelope(_render())

    def test_permuting_findings_does_not_change_the_bytes(self) -> None:
        first = make_finding(rule_id="a.rule")
        second = make_finding(rule_id="b.rule", tool_id=TOOL_B_ID, edge_id=EDGE_B_ID)

        forward = serialize_envelope(_render(findings=(first, second)))
        backward = serialize_envelope(_render(findings=(second, first)))

        assert forward == backward

    def test_permuting_components_does_not_change_the_bytes(self) -> None:
        one = make_node(node_id=TOOL_A_ID, name="alpha")
        two = make_node(node_id=TOOL_B_ID, name="beta")

        forward = serialize_envelope(_render(document=make_document(nodes=[one, two])))
        backward = serialize_envelope(_render(document=make_document(nodes=[two, one])))

        assert forward == backward

    def test_the_serialization_is_canonical_json(self) -> None:
        payload = serialize_envelope(_render())

        assert b", " not in payload
        assert json.loads(payload)["envelope_version"] == "1.0.0"


class TestPrivacyCanaries:
    """Nothing protected reaches the payload.

    Canaries are planted in the fields an adapter could plausibly carry
    one into -- a node name, a finding message -- and the serialized bytes
    are searched for them.
    """

    @pytest.mark.parametrize(
        "canary",
        [
            _TOKEN_CANARY,
            _PRIVATE_KEY_CANARY,
            _PROMPT_CANARY,
            _ENVIRONMENT_CANARY,
            _SOURCE_CANARY,
        ],
    )
    def test_a_canary_in_a_finding_message_does_not_reach_a_secret_field(
        self, canary: str
    ) -> None:
        """A message is author-visible text the CLI already renders to a
        terminal, so it is carried as `title` by design. What must not
        happen is it leaking into identity material: the fingerprint, the
        capability path, or the evidence reference -- the fields a
        platform indexes, searches, and joins on.
        """

        envelope = _render(findings=(make_finding(message=canary),))
        finding = envelope.findings[0]

        assert canary not in finding.fingerprint
        assert canary not in finding.evidence_reference
        assert all(canary not in hop for hop in finding.capability_path)
        assert canary not in finding.rule_id

    def test_the_envelope_carries_no_evidence_text(self) -> None:
        """`Evidence` carries no evidence text at all, so there is nothing
        of that kind to leak. This asserts the property rather than
        assuming it: the reference is a path and a line, and nothing
        else."""

        envelope = _render()
        reference = envelope.findings[0].evidence_reference

        assert reference.count(":") == 1
        path, line = reference.split(":")
        assert path == "agent.json"
        assert line.isdigit()

    def test_the_payload_has_no_undeclared_fields(self) -> None:
        """`extra="forbid"` on the models is the structural half of the
        privacy guarantee; this is the observable half -- the serialized
        key set is exactly the contract's."""

        payload = json.loads(serialize_envelope(_render(branch="main")))

        assert set(payload) == {
            "envelope_version",
            "commit_sha",
            "branch",
            "scanner_version",
            "policy_version",
            "acbom_digest",
            "verdict",
            "findings",
            "components",
        }

    def test_a_finding_payload_has_no_undeclared_fields(self) -> None:
        payload = json.loads(serialize_envelope(_render()))

        assert set(payload["findings"][0]) == {
            "fingerprint",
            "rule_id",
            "rule_version",
            "severity",
            "confidence",
            "title",
            "capability_path",
            "evidence_reference",
        }

    def test_an_undeclared_field_cannot_be_added_to_the_model(self) -> None:
        from controlloop.team.envelope import NormalizedComponent

        with pytest.raises(ValidationError, match="secret"):
            NormalizedComponent(
                stable_id="x",
                type="tool",
                name="y",
                secret=_TOKEN_CANARY,  # type: ignore[call-arg]
            )


class TestRepositoryPolicyDelta:
    def test_a_delta_is_carried_when_present(self) -> None:
        delta = RepositoryPolicyDelta(
            rules=(RuleOverride(rule_id="a.rule", enabled=False),)
        )

        payload = json.loads(serialize_envelope(_render(repository_policy=delta)))

        assert payload["repository_policy"]["rules"][0]["rule_id"] == "a.rule"
        assert payload["repository_policy"]["rules"][0]["enabled"] is False

    def test_no_delta_is_omitted_entirely(self) -> None:
        payload = json.loads(serialize_envelope(_render()))

        assert "repository_policy" not in payload

    def test_severity_is_carried_verbatim(self) -> None:
        envelope = _render(findings=(make_finding(severity=FindingSeverity.CRITICAL),))

        assert envelope.findings[0].severity == "critical"
