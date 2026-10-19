"""Shared fixtures for the Team test suite.

Mirrors the `_capability_path`/`_finding` helper pattern
`tests/policy/test_suppressions.py` and
`tests/policy/test_policy_thresholds.py` already established, lifted
into a module because five Team test files need the same material.

Two properties are load-bearing:

- **`Finding.id` is always computed for real**, via
  `controlloop.findings.identity.finding_id`, never hand-typed. Exception
  matching and envelope fingerprints are both identity-sensitive, so a
  stand-in digest would let those tests pass against a scheme production
  does not use.
- **`fake_transport` is a value, not a socket.** `tests/conftest.py`
  denies socket construction for the whole suite, and nothing here asks
  for an exemption; every network-shaped test drives `FakeTransport`
  instead.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from controlloop.acbom.models import (
    ACBOMDocument,
    Confidence,
    EdgeType,
    Evidence,
    Generator,
    Node,
    NodeType,
    Repository,
    SecurityAttributes,
)
from controlloop.acbom.serialization import with_digest
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.config import ResolvedConfig, load_config
from controlloop.findings.identity import finding_id
from controlloop.findings.models import (
    CURRENT_FINDING_SCHEMA_VERSION,
    Finding,
    FindingChangeState,
    FindingSeverity,
)
from controlloop.repository import RepositoryRoot
from controlloop.team.config import TeamConfig, TeamFailMode, resolve_team_config
from controlloop.team.transport import HttpResponse, TransportError

AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
TOOL_A_ID = f"clp:tool:sha256:{'b' * 64}"
TOOL_B_ID = f"clp:tool:sha256:{'c' * 64}"
EDGE_A_ID = f"clp:edge:sha256:{'d' * 64}"
EDGE_B_ID = f"clp:edge:sha256:{'e' * 64}"

EVIDENCE = (Evidence(adapter="mcp", path="agent.json", line_start=3, line_end=4),)

#: A real 40-hex commit, the shape `ScanEnvelopeRequest.commit_sha`
#: requires. Deliberately not the literal `"unknown"` that
#: `controlloop.bom` records for a non-git directory -- that case has its
#: own dedicated test.
COMMIT = "0" * 39 + "1"

ORGANIZATION_ID = "11111111-1111-4111-8111-111111111111"
PROJECT_ID = "22222222-2222-4222-8222-222222222222"
ENDPOINT = "https://platform.example"
TOKEN = "clp_" + "t" * 32

NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=UTC)


def capability_path(
    *, tool_id: str = TOOL_A_ID, edge_id: str = EDGE_A_ID
) -> CapabilityPath:
    return CapabilityPath(
        schema_version="1.0.0",
        agent_id=AGENT_ID,
        target_id=tool_id,
        target_type=NodeType.TOOL,
        hops=(
            PathHop(
                edge_id=edge_id,
                edge_type=EdgeType.INVOKES,
                source_id=AGENT_ID,
                target_id=tool_id,
                evidence=EVIDENCE,
            ),
        ),
        confidence=Confidence.HIGH,
    )


def make_finding(
    *,
    rule_id: str = "policy.undeclared-tools",
    tool_id: str = TOOL_A_ID,
    edge_id: str = EDGE_A_ID,
    severity: FindingSeverity = FindingSeverity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    message: str = "a tool is reachable",
    repository_scoped: bool = False,
) -> Finding:
    """One real `Finding`, with its identity computed the production way.

    `repository_scoped=True` produces the other valid shape -- no affected
    agent and no capability path -- which the envelope renderer has to
    handle without inventing a path.
    """

    path = (
        None if repository_scoped else capability_path(tool_id=tool_id, edge_id=edge_id)
    )
    agent = None if repository_scoped else AGENT_ID
    return Finding(
        schema_version=CURRENT_FINDING_SCHEMA_VERSION,
        id=finding_id(
            rule_id=rule_id,
            affected_agent=agent,
            capability_path=path,
        ),
        rule_id=rule_id,
        rule_version="1.0.0",
        message=message,
        severity=severity,
        confidence=confidence,
        affected_agent=agent,
        evidence=EVIDENCE,
        capability_path=path,
        change_state=FindingChangeState.ADDED,
        remediation="declare the tool in controlloop.yaml",
        documentation_url="https://docs.controlloop.dev/rules/undeclared-tools",
    )


def make_node(
    *,
    node_id: str = TOOL_A_ID,
    node_type: NodeType = NodeType.TOOL,
    name: str = "search",
    subtype: str | None = None,
) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        subtype=subtype,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=EVIDENCE,
    )


def make_document(
    *,
    nodes: Sequence[Node] | None = None,
    commit: str = COMMIT,
) -> ACBOMDocument:
    """A digested ACBOM. `with_digest` is applied so `document.digest` is a
    real digest of real content rather than a placeholder the envelope
    would happily carry."""

    document = ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit=commit, root_digest=f"sha256:{'d' * 64}"),
        nodes=tuple(nodes) if nodes is not None else (make_node(),),
        edges=(),
        diagnostics=(),
        digest=f"sha256:{'0' * 64}",
    )
    return with_digest(document)


def make_team_config(
    *,
    fail_mode: TeamFailMode = TeamFailMode.CLOSED,
    branch: str | None = None,
    pull_request: int | None = None,
    policy_cache_seconds: int = 300,
) -> TeamConfig:
    """A `TeamConfig` built through the real resolver, not by hand.

    Going through `resolve_team_config` means these tests exercise the
    same validation production does; a hand-built `TeamConfig` could hold
    a combination the resolver would have refused.
    """

    from controlloop.config import ConfigSource, ConfigValue

    values = {
        "team_enabled": ConfigValue(True, ConfigSource.REPOSITORY_FILE),
        "team_fail_mode": ConfigValue(fail_mode.value, ConfigSource.REPOSITORY_FILE),
        "team_endpoint": ConfigValue(ENDPOINT, ConfigSource.REPOSITORY_FILE),
        "team_organization_id": ConfigValue(
            ORGANIZATION_ID, ConfigSource.REPOSITORY_FILE
        ),
        "team_project_id": ConfigValue(PROJECT_ID, ConfigSource.REPOSITORY_FILE),
        "team_branch": ConfigValue(branch or "", ConfigSource.REPOSITORY_FILE),
        "team_pull_request": ConfigValue(
            str(pull_request) if pull_request else "", ConfigSource.REPOSITORY_FILE
        ),
        "team_policy_cache_seconds": ConfigValue(
            policy_cache_seconds, ConfigSource.REPOSITORY_FILE
        ),
    }
    resolved = ResolvedConfig(values=values)
    config = resolve_team_config(resolved, environ={"CONTROLLOOP_TEAM_TOKEN": TOKEN})
    assert config is not None
    return config


def resolved_config_with(root: Path, mapping: dict[str, Any]) -> ResolvedConfig:
    """Load a real `ResolvedConfig` from a real `controlloop.toml`."""

    lines = []
    for key, value in mapping.items():
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        else:
            lines.append(f'{key} = "{value}"')
    (root / "controlloop.toml").write_text("\n".join(lines) + "\n")
    return load_config(RepositoryRoot(path=root), environ={}, flags={})


@dataclass
class FakeTransport:
    """A scripted `HttpTransport`.

    `responses` is consumed in order; an entry may be an `HttpResponse` to
    return or a `TransportError` to raise, which is how a test drives the
    retry window without waiting for one. `calls` records what was sent so
    a test can assert on headers and URLs -- including asserting that a
    token never appeared where it should not.
    """

    #: Accepts any sequence and copies it, rather than taking a `list`
    #: directly. `list` is invariant, so a caller building
    #: `[TransportError(...), ...]` would otherwise have to annotate the
    #: literal to satisfy strict mypy -- noise in every test that scripts
    #: a single failure mode. Copying also means a scripted list is not
    #: consumed out from under the test that owns it.
    responses: Sequence[HttpResponse | TransportError] = field(default_factory=tuple)
    calls: list[dict[str, Any]] = field(default_factory=list)
    _remaining: list[HttpResponse | TransportError] = field(
        init=False, default_factory=list
    )

    def __post_init__(self) -> None:
        self._remaining = list(self.responses)

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout_seconds: float,
    ) -> HttpResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_seconds": timeout_seconds,
            }
        )
        if not self._remaining:
            raise AssertionError(f"unscripted request: {method} {url}")
        nxt = self._remaining.pop(0)
        if isinstance(nxt, TransportError):
            raise nxt
        return nxt


def json_response(
    payload: Any, *, status: int = 200, headers: dict[str, str] | None = None
) -> HttpResponse:
    """One scripted JSON response.

    Header names are lower-cased here because `UrllibTransport._read`
    lower-cases them in production. A fake that skipped that step would
    let a test pass against a response shape the real transport never
    produces -- which is exactly the class of bug a fake is supposed not
    to introduce.
    """

    return HttpResponse(
        status=status,
        body=json.dumps(payload).encode("utf-8"),
        headers={name.lower(): value for name, value in (headers or {}).items()},
    )


def recording_sleeper() -> tuple[Callable[[float], None], list[float]]:
    """An injected `sleep` that records instead of waiting.

    Nothing in this suite sleeps: a test that proved the retry schedule by
    actually waiting 2.5 seconds would be a test nobody runs.
    """

    recorded: list[float] = []

    def sleep(seconds: float) -> None:
        recorded.append(seconds)

    return sleep, recorded
