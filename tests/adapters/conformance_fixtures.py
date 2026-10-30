"""The per-adapter conformance fixture registry.

Each `ConformanceFixture` supplies exactly what
`test_adapter_conformance.py` needs to run the same six checks (positive,
similar negative, malformed, version drift, boundary size, determinism)
against a given adapter, without that shared test file needing to know
any adapter's format. Each writer is shaped per adapter, because
location-claimed vs. content-sniffed detection changes what "similar
negative" and "malformed" can mean.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from controlloop.adapters import (
    A2aAgentCardAdapter,
    AgentWorkflowAdapter,
    ClaudeCodeComponentsAdapter,
    ClaudeCodeSettingsAdapter,
    CodexConfigAdapter,
    CrewAiAdapter,
    CursorConfigAdapter,
    DiscoveryAdapter,
    DiscoveryResult,
    GeminiSettingsAdapter,
    IamPolicyAdapter,
    KiroConfigAdapter,
    LangGraphAdapter,
    McpServerAdapter,
    OasfAdapter,
    OpenAiAgentsAdapter,
    OpenApiAdapter,
    RooModesAdapter,
    ScanContext,
    run_adapters,
)

_BOUNDARY_ENTRY_COUNT = 200


def _default_run(adapter: DiscoveryAdapter, context: ScanContext) -> DiscoveryResult:
    return run_adapters([adapter], context)


def _write_json(tmp_path: Path, relative_path: str, payload: object) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload))


def _write_text(tmp_path: Path, relative_path: str, content: str) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


@dataclass(frozen=True)
class ConformanceFixture:
    adapter_name: str
    make_adapter: Callable[[], DiscoveryAdapter]
    write_positive: Callable[[Path], None]
    assert_positive: Callable[[DiscoveryResult], None]
    write_similar_negative: Callable[[Path], None]
    write_malformed: Callable[[Path], None]
    write_boundary: Callable[[Path], None]
    assert_boundary: Callable[[DiscoveryResult], None]
    write_version_drift: Callable[[Path], None] | None = None
    version_drift_unsupported_reason: str | None = None
    write_older_version_drift: Callable[[Path], None] | None = None
    older_version_drift_unsupported_reason: str | None = None
    #: Which file the fuzz sweep should mutate, repository-relative.
    #: Only needed when `write_positive` creates more than one file --
    #: an adapter whose discovery depends on a second, supporting
    #: document (CrewAI reads the framework version from
    #: `pyproject.toml`). Left `None`, the sweep keeps its original
    #: strict behavior: exactly one created file, or fail loudly.
    fuzz_seed_relative_path: str | None = None
    run: Callable[[DiscoveryAdapter, ScanContext], DiscoveryResult] = _default_run
    #: Plants credential-shaped values, environment and header values, and
    #: prompt bodies, and returns every planted value. None may appear in
    #: the adapter's result. Required for the agent-authority adapters (see
    #: `PRIVACY_REQUIRED_ADAPTERS`).
    write_privacy: Callable[[Path], tuple[str, ...]] | None = None

    def __post_init__(self) -> None:
        has_writer = self.write_version_drift is not None
        has_reason = self.version_drift_unsupported_reason is not None
        if has_writer == has_reason:
            raise ValueError(
                f"{self.adapter_name}: exactly one of write_version_drift or "
                "version_drift_unsupported_reason must be set -- version drift "
                "is either exercised or explicitly, visibly disclosed as N/A, "
                "never silently skipped"
            )
        has_older_writer = self.write_older_version_drift is not None
        has_older_reason = self.older_version_drift_unsupported_reason is not None
        if has_older_writer == has_older_reason:
            raise ValueError(
                f"{self.adapter_name}: exactly one of write_older_version_drift "
                "or older_version_drift_unsupported_reason must be set -- an "
                "older-than-supported version is either "
                "exercised or explicitly, visibly disclosed as N/A, never "
                "silently skipped, mirroring write_version_drift's own "
                "already-established contract for the newer direction"
            )


# --- Privacy cases -----------------------------------------------------------
# Every value below is fictional. The credential-shaped ones match a shape
# the redaction primitive knows; the rest are markers no adapter may record
# at all (an environment value, a header value, a prompt body).

_CREDENTIAL = "ghp_" + "P" * 36
_ENV_VALUE = "planted-environment-value-5d1c"
_HEADER_VALUE = "planted-header-value-82b0"
_PROMPT_BODY = "planted-prompt-body-0e4a"
_BEARER_COMMAND = f"curl -H 'Authorization: Bearer {_CREDENTIAL}' https://x.example"


def _claude_code_write_privacy(tmp_path: Path) -> tuple[str, ...]:
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {
            "env": {"DEPLOY_TOKEN": _ENV_VALUE},
            "apiKeyHelper": f"./key.sh --token={_CREDENTIAL}",
            "hooks": {
                "SessionStart": [
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": _BEARER_COMMAND,
                            },
                            {
                                "type": "http",
                                "url": "https://hooks.example/start",
                                "headers": {"X-Api-Key": _HEADER_VALUE},
                            },
                            {"type": "prompt", "prompt": _PROMPT_BODY},
                        ]
                    }
                ]
            },
        },
    )
    return (_CREDENTIAL, _ENV_VALUE, _HEADER_VALUE, _PROMPT_BODY)


def _components_write_privacy(tmp_path: Path) -> tuple[str, ...]:
    _write_text(
        tmp_path,
        ".claude/skills/deploy/SKILL.md",
        f"---\nname: deploy\nallowed-tools: Bash(kubectl *)\n---\n{_PROMPT_BODY}\n",
    )
    _write_text(
        tmp_path,
        ".claude/agents/fixer.md",
        f"---\nname: fixer\ntools: Read\n---\n{_PROMPT_BODY} {_CREDENTIAL}\n",
    )
    return (_CREDENTIAL, _PROMPT_BODY)


def _workflows_write_privacy(tmp_path: Path) -> tuple[str, ...]:
    _write_text(
        tmp_path,
        ".github/workflows/agent.yml",
        "on: push\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        f"      ANTHROPIC_BASE_URL: {_ENV_VALUE}\n"
        "    steps:\n"
        "      - uses: anthropics/claude-code-action@v1\n"
        "        with:\n"
        f"          prompt: {_PROMPT_BODY}\n"
        f"          claude_args: --token={_CREDENTIAL}\n",
    )
    return (_CREDENTIAL, _ENV_VALUE, _PROMPT_BODY)


def _mcp_server_with_secrets() -> dict[str, object]:
    return {
        "command": "npx",
        "args": ["-y", "@example/server", f"--api-key={_CREDENTIAL}"],
        "env": {"SERVICE_TOKEN": _ENV_VALUE},
    }


def _mcp_write_privacy(tmp_path: Path) -> tuple[str, ...]:
    _write_json(
        tmp_path,
        ".mcp.json",
        {
            "mcpServers": {
                "local": _mcp_server_with_secrets(),
                "remote": {
                    "type": "http",
                    "url": "https://mcp.example/v1",
                    "headers": {"Authorization": _HEADER_VALUE},
                },
            }
        },
    )
    return (_CREDENTIAL, _ENV_VALUE, _HEADER_VALUE)


def _codex_write_privacy(tmp_path: Path) -> tuple[str, ...]:
    _write_text(
        tmp_path,
        ".codex/config.toml",
        'approval_policy = "on-request"\n'
        "[shell_environment_policy.set]\n"
        f'DEPLOY_TOKEN = "{_ENV_VALUE}"\n'
        "[[hooks.Stop]]\n[[hooks.Stop.hooks]]\n"
        f'type = "command"\ncommand = "notify --token={_CREDENTIAL}"\n',
    )
    return (_CREDENTIAL, _ENV_VALUE)


def _gemini_write_privacy(tmp_path: Path) -> tuple[str, ...]:
    _write_json(
        tmp_path,
        ".gemini/settings.json",
        {
            "hooks": {
                "BeforeTool": [
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": f"audit --token={_CREDENTIAL}",
                            }
                        ]
                    }
                ]
            },
            "mcpServers": {"local": _mcp_server_with_secrets()},
        },
    )
    return (_CREDENTIAL, _ENV_VALUE)


def _roo_write_privacy(tmp_path: Path) -> tuple[str, ...]:
    _write_json(
        tmp_path,
        ".roomodes",
        {
            "customModes": [
                {
                    "slug": "reviewer",
                    "roleDefinition": _PROMPT_BODY,
                    "customInstructions": _PROMPT_BODY,
                    "whenToUse": _PROMPT_BODY,
                    "description": _PROMPT_BODY,
                    "groups": ["read", "command"],
                }
            ]
        },
    )
    return (_PROMPT_BODY,)


def _cursor_write_privacy(tmp_path: Path) -> tuple[str, ...]:
    _write_json(
        tmp_path,
        ".cursor/hooks.json",
        {
            "version": 1,
            "hooks": {"stop": [{"command": f"notify --password {_CREDENTIAL}"}]},
        },
    )
    return (_CREDENTIAL,)


def _kiro_write_privacy(tmp_path: Path) -> tuple[str, ...]:
    _write_json(
        tmp_path,
        ".kiro/hooks/review.json",
        {
            "version": "v1",
            "hooks": [
                {
                    "trigger": "PostFileSave",
                    "action": {"type": "askAgent", "prompt": _PROMPT_BODY},
                },
                {
                    "trigger": "Stop",
                    "action": {
                        "type": "command",
                        "command": f"x --token={_CREDENTIAL}",
                    },
                },
            ],
        },
    )
    return (_CREDENTIAL, _PROMPT_BODY)


#: The agent-authority adapters. Each must define `write_privacy`.
PRIVACY_REQUIRED_ADAPTERS = frozenset(
    {
        "mcp",
        "claude-code",
        "claude-code-components",
        "agent-workflows",
        "codex",
        "gemini-cli",
        "cursor",
        "kiro",
        "roo-code",
    }
)


# --- MCP -----------------------------------------------------------------
# Claimed by fixed location only (`.mcp.json` etc.), never by content, so
# "similar negative" is a near-miss path; "malformed" can be raw syntax
# garbage since detect() never inspects content. No in-document version
# field exists in the real MCP client-config format, hence the disclosed
# version-drift gap instead of a fixture.


def _mcp_write_positive(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        ".mcp.json",
        {"mcpServers": {"files": {"command": "npx", "args": ["mcp-server-files"]}}},
    )


def _mcp_assert_positive(result: DiscoveryResult) -> None:
    assert len(result.nodes) == 1
    assert result.nodes[0].subtype == "mcp-server-stdio"


def _mcp_write_similar_negative(tmp_path: Path) -> None:
    _write_json(tmp_path, ".mcp.json.bak", {"mcpServers": {"files": {"command": "x"}}})


def _mcp_write_malformed(tmp_path: Path) -> None:
    _write_text(tmp_path, ".mcp.json", "{ not valid json at all !!! ")


def _mcp_write_boundary(tmp_path: Path) -> None:
    servers = {
        f"server-{i}": {"command": "npx", "args": [f"mcp-server-{i}"]}
        for i in range(_BOUNDARY_ENTRY_COUNT)
    }
    _write_json(tmp_path, ".mcp.json", {"mcpServers": servers})


def _mcp_assert_boundary(result: DiscoveryResult) -> None:
    assert len(result.nodes) == _BOUNDARY_ENTRY_COUNT
    assert result.diagnostics == ()


MCP_FIXTURE = ConformanceFixture(
    adapter_name="mcp",
    make_adapter=McpServerAdapter,
    write_positive=_mcp_write_positive,
    assert_positive=_mcp_assert_positive,
    write_similar_negative=_mcp_write_similar_negative,
    write_malformed=_mcp_write_malformed,
    write_boundary=_mcp_write_boundary,
    assert_boundary=_mcp_assert_boundary,
    version_drift_unsupported_reason=(
        "real .mcp.json client configs carry no schema-version field; "
        "supported_versions documents the MCP protocol version this "
        "adapter was verified against, not a per-document marker"
    ),
    older_version_drift_unsupported_reason=(
        "identical reason as the newer direction: "
        "no in-document version marker exists to make older, either"
    ),
    write_privacy=_mcp_write_privacy,
)


# --- OpenAPI ---------------------------------------------------------------
# Claimed by content-sniffing an `openapi`/`swagger` key, so "similar
# negative" must be syntactically valid JSON lacking that marker;
# "malformed" must pass the sniff (has `openapi`) but break deeper
# (an unresolvable local $ref), since raw syntax garbage never reaches
# detect()'s claim at all.


def _openapi_write_positive(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        "openapi.json",
        {
            "openapi": "3.0.0",
            "paths": {"/widgets": {"get": {"operationId": "listWidgets"}}},
        },
    )


def _openapi_assert_positive(result: DiscoveryResult) -> None:
    assert len(result.nodes) == 2
    assert len(result.edges) == 1


def _openapi_write_similar_negative(tmp_path: Path) -> None:
    _write_json(tmp_path, "package.json", {"name": "not-an-api-spec", "version": "1.0"})


def _openapi_write_malformed(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        "openapi.json",
        {"openapi": "3.0.0", "paths": {"/x": {"$ref": "#/components/nonexistent"}}},
    )


def _openapi_write_version_drift(tmp_path: Path) -> None:
    _write_json(tmp_path, "openapi.json", {"openapi": "4.2.0", "paths": {}})


def _openapi_write_boundary(tmp_path: Path) -> None:
    paths = {
        f"/widgets/{i}": {"get": {"operationId": f"getWidget{i}"}}
        for i in range(_BOUNDARY_ENTRY_COUNT)
    }
    _write_json(tmp_path, "openapi.json", {"openapi": "3.0.0", "paths": paths})


def _openapi_assert_boundary(result: DiscoveryResult) -> None:
    assert len(result.nodes) == _BOUNDARY_ENTRY_COUNT * 2
    assert len(result.edges) == _BOUNDARY_ENTRY_COUNT
    assert result.diagnostics == ()


def _openapi_write_older_version_drift(tmp_path: Path) -> None:
    """Real Swagger 2.0 -- genuinely older than `_SUPPORTED_VERSIONS =
    ("3.0", "3.1")`, and (unlike the fabricated "4.2.0" newer-drift
    fixture above) a document real repositories actually still contain.
    `OpenApiAdapter` claims it (detects the `swagger` key) and explicitly
    rejects it -- verified directly to produce the
    identical nodes-empty/diagnostic-present shape `write_version_drift`
    already does."""

    _write_json(tmp_path, "openapi.json", {"swagger": "2.0", "paths": {}})


OPENAPI_FIXTURE = ConformanceFixture(
    adapter_name="openapi",
    make_adapter=OpenApiAdapter,
    write_positive=_openapi_write_positive,
    assert_positive=_openapi_assert_positive,
    write_similar_negative=_openapi_write_similar_negative,
    write_malformed=_openapi_write_malformed,
    write_version_drift=_openapi_write_version_drift,
    write_older_version_drift=_openapi_write_older_version_drift,
    write_boundary=_openapi_write_boundary,
    assert_boundary=_openapi_assert_boundary,
)


# --- A2A ---------------------------------------------------------------
# Claimed by fixed location only, mirroring MCP's precision concern; A2A
# does have a real protocolVersion field, so version drift is a normal
# fixture here (unlike MCP).


def _a2a_write_positive(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        ".well-known/agent.json",
        {
            "protocolVersion": "0.2",
            "name": "Refund agent",
            "skills": [{"id": "refund", "name": "Issue refund"}],
        },
    )


def _a2a_assert_positive(result: DiscoveryResult) -> None:
    assert len(result.nodes) == 2
    assert len(result.edges) == 1


def _a2a_write_similar_negative(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        ".well-known/agent-cards.json",
        {"protocolVersion": "0.2", "name": "x"},
    )


def _a2a_write_malformed(tmp_path: Path) -> None:
    _write_text(tmp_path, ".well-known/agent.json", "{ not valid json at all !!! ")


def _a2a_write_version_drift(tmp_path: Path) -> None:
    _write_json(
        tmp_path, ".well-known/agent.json", {"protocolVersion": "9.9", "name": "x"}
    )


def _a2a_write_boundary(tmp_path: Path) -> None:
    skills = [
        {"id": f"skill-{i}", "name": f"Skill {i}"} for i in range(_BOUNDARY_ENTRY_COUNT)
    ]
    _write_json(
        tmp_path,
        ".well-known/agent.json",
        {"protocolVersion": "0.2", "name": "Bulk agent", "skills": skills},
    )


def _a2a_assert_boundary(result: DiscoveryResult) -> None:
    assert len(result.nodes) == _BOUNDARY_ENTRY_COUNT + 1
    assert len(result.edges) == _BOUNDARY_ENTRY_COUNT
    assert result.diagnostics == ()


def _a2a_write_older_version_drift(tmp_path: Path) -> None:
    """`protocolVersion "0.0"` -- genuinely older than
    `_SUPPORTED_VERSIONS = ("0.1", "0.2", "0.3")`, distinct from the
    fabricated future `"9.9"` newer-drift fixture above. Verified directly
    to produce the identical nodes-empty/diagnostic-present shape."""

    _write_json(
        tmp_path, ".well-known/agent.json", {"protocolVersion": "0.0", "name": "x"}
    )


A2A_FIXTURE = ConformanceFixture(
    adapter_name="a2a",
    make_adapter=A2aAgentCardAdapter,
    write_positive=_a2a_write_positive,
    assert_positive=_a2a_assert_positive,
    write_similar_negative=_a2a_write_similar_negative,
    write_malformed=_a2a_write_malformed,
    write_version_drift=_a2a_write_version_drift,
    write_older_version_drift=_a2a_write_older_version_drift,
    write_boundary=_a2a_write_boundary,
    assert_boundary=_a2a_assert_boundary,
)


# --- OASF ---------------------------------------------------------------
# SUPPORTED_OASF_VERSIONS is empty by design (a disclosed low confidence in
# the OASF format). Version drift is OASF's *default*, unpatched behavior;
# positive and boundary both need a locally patched supported version to
# exercise the adapter's normalization path at all, proving it is real
# without claiming a version is verified -- the same technique
# tests/adapters/test_oasf.py already uses.

_OASF_PATCHED_VERSION = "1.0"


def _oasf_run(adapter: DiscoveryAdapter, context: ScanContext) -> DiscoveryResult:
    with patch(
        "controlloop.adapters.oasf.SUPPORTED_OASF_VERSIONS", (_OASF_PATCHED_VERSION,)
    ):
        return run_adapters([adapter], context)


def _oasf_write_positive(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        "agent.oasf.json",
        {"oasf_version": _OASF_PATCHED_VERSION, "name": "test-agent"},
    )


def _oasf_assert_positive(result: DiscoveryResult) -> None:
    assert len(result.nodes) == 1


def _oasf_write_similar_negative(tmp_path: Path) -> None:
    _write_json(tmp_path, "package.json", {"name": "not-oasf"})


def _oasf_write_malformed(tmp_path: Path) -> None:
    _write_json(tmp_path, "agent.oasf.json", {"oasf_version": _OASF_PATCHED_VERSION})


def _oasf_write_version_drift(tmp_path: Path) -> None:
    _write_json(tmp_path, "agent.oasf.json", {"oasf_version": "0.0.1", "name": "x"})


def _oasf_write_boundary(tmp_path: Path) -> None:
    payload: dict[str, object] = {
        "oasf_version": _OASF_PATCHED_VERSION,
        "name": "test-agent",
    }
    payload.update({f"future_field_{i}": i for i in range(_BOUNDARY_ENTRY_COUNT)})
    _write_json(tmp_path, "agent.oasf.json", payload)


def _oasf_assert_boundary(result: DiscoveryResult) -> None:
    assert len(result.nodes) == 1
    assert len(result.diagnostics) == 1
    assert str(_BOUNDARY_ENTRY_COUNT) in result.diagnostics[0].message


OASF_FIXTURE = ConformanceFixture(
    adapter_name="oasf",
    make_adapter=OasfAdapter,
    write_positive=_oasf_write_positive,
    assert_positive=_oasf_assert_positive,
    write_similar_negative=_oasf_write_similar_negative,
    write_malformed=_oasf_write_malformed,
    write_version_drift=_oasf_write_version_drift,
    write_boundary=_oasf_write_boundary,
    assert_boundary=_oasf_assert_boundary,
    run=_oasf_run,
    older_version_drift_unsupported_reason=(
        "SUPPORTED_OASF_VERSIONS is empty by design (a disclosed low "
        "confidence in the format), so every version -- "
        "older or newer -- already takes the identical 'unsupported' "
        "path write_version_drift above already exercises; a second, "
        "'older' fixture would run the same code, not a distinct case"
    ),
)


# --- IAM ---------------------------------------------------------------
# The native AWS IAM JSON path is content-sniffed (recognizable
# Version/Statement shape, or a GCP/Azure shape it explicitly rejects).
# The GCP-shaped rejection already in this codebase is reused as IAM's
# similar-negative fixture: it is the most on-brand "looks like a
# policy, isn't mine" case for this adapter specifically.


def _iam_write_positive(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        "policy.json",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        },
    )


def _iam_assert_positive(result: DiscoveryResult) -> None:
    assert len(result.nodes) == 1


def _iam_write_similar_negative(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        "gcp-policy.json",
        {"bindings": [{"role": "roles/owner", "members": ["user:x@example.com"]}]},
    )


def _iam_write_malformed(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        "policy.json",
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]},
    )


def _iam_write_version_drift(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        "policy.json",
        {
            "Version": "2099-01-01",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        },
    )


def _iam_write_boundary(tmp_path: Path) -> None:
    statements = [
        {"Effect": "Allow", "Action": f"s3:Action{i}", "Resource": f"arn:{i}"}
        for i in range(_BOUNDARY_ENTRY_COUNT)
    ]
    _write_json(
        tmp_path, "policy.json", {"Version": "2012-10-17", "Statement": statements}
    )


def _iam_assert_boundary(result: DiscoveryResult) -> None:
    assert len(result.nodes) == _BOUNDARY_ENTRY_COUNT
    assert result.diagnostics == ()


def _iam_write_older_version_drift(tmp_path: Path) -> None:
    """The real, still-AWS-valid historical `"Version": "2008-10-17"`
    -- genuinely older than `_SUPPORTED_VERSIONS = ("2012-10-17",)`, and
    (unlike the fabricated future
    `"2099-01-01"` newer-drift fixture above) a version some real
    policies still declare today. Verified directly to produce the
    identical nodes-empty/diagnostic-present shape."""

    _write_json(
        tmp_path,
        "policy.json",
        {
            "Version": "2008-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        },
    )


IAM_FIXTURE = ConformanceFixture(
    adapter_name="iam",
    make_adapter=IamPolicyAdapter,
    write_positive=_iam_write_positive,
    assert_positive=_iam_assert_positive,
    write_similar_negative=_iam_write_similar_negative,
    write_malformed=_iam_write_malformed,
    write_version_drift=_iam_write_version_drift,
    write_older_version_drift=_iam_write_older_version_drift,
    write_boundary=_iam_write_boundary,
    assert_boundary=_iam_assert_boundary,
)


# --- CrewAI -----------------------------------------------------------------
# Claimed by the fixed `config/agents.yaml` location, and only when that
# file exists -- a stray `crew.py` in a non-CrewAI repository must not be
# claimed, which is what "similar negative" checks here. Unlike every
# other adapter, version drift is real rather than exempt: the project's
# own `pyproject.toml` declares the framework version, and
# `framework_versions` refuses one outside the verified range.

_CREWAI_PYPROJECT = """
[project]
name = "conformance-crew"
version = "0.1.0"
dependencies = ["crewai>=0.86.0"]
"""


def _crewai_write_project(tmp_path: Path, agents: str, dependency: str) -> None:
    _write_text(
        tmp_path,
        "pyproject.toml",
        _CREWAI_PYPROJECT.replace("crewai>=0.86.0", dependency),
    )
    _write_text(tmp_path, "config/agents.yaml", agents)


def _crewai_write_positive(tmp_path: Path) -> None:
    _crewai_write_project(
        tmp_path,
        "researcher:\n  role: Senior Research Analyst\n",
        "crewai>=0.86.0",
    )


def _crewai_assert_positive(result: DiscoveryResult) -> None:
    assert len(result.nodes) == 1
    assert result.nodes[0].subtype == "crewai-agent"
    assert result.nodes[0].name == "Senior Research Analyst"


def _crewai_write_similar_negative(tmp_path: Path) -> None:
    """A CrewAI-shaped file outside the claimed location, plus a bare
    `crew.py`. Neither may cause a claim."""

    _write_text(tmp_path, "pyproject.toml", _CREWAI_PYPROJECT)
    _write_text(tmp_path, "agents.yaml", "researcher:\n  role: Analyst\n")
    _write_text(tmp_path, "crew.py", "x = 1\n")


def _crewai_write_malformed(tmp_path: Path) -> None:
    _crewai_write_project(tmp_path, "{ not: valid: yaml: [", "crewai>=0.86.0")


def _crewai_write_boundary(tmp_path: Path) -> None:
    agents = "".join(
        f"agent_{i}:\n  role: Agent {i}\n" for i in range(_BOUNDARY_ENTRY_COUNT)
    )
    _crewai_write_project(tmp_path, agents, "crewai>=0.86.0")


def _crewai_assert_boundary(result: DiscoveryResult) -> None:
    assert len(result.nodes) == _BOUNDARY_ENTRY_COUNT
    assert result.diagnostics == ()


def _crewai_write_version_drift(tmp_path: Path) -> None:
    _crewai_write_project(tmp_path, "researcher:\n  role: Analyst\n", "crewai>=99.0.0")


def _crewai_write_older_version_drift(tmp_path: Path) -> None:
    _crewai_write_project(tmp_path, "researcher:\n  role: Analyst\n", "crewai>=0.1.0")


CREWAI_FIXTURE = ConformanceFixture(
    adapter_name="crewai",
    make_adapter=CrewAiAdapter,
    write_positive=_crewai_write_positive,
    assert_positive=_crewai_assert_positive,
    write_similar_negative=_crewai_write_similar_negative,
    write_malformed=_crewai_write_malformed,
    write_boundary=_crewai_write_boundary,
    assert_boundary=_crewai_assert_boundary,
    write_version_drift=_crewai_write_version_drift,
    write_older_version_drift=_crewai_write_older_version_drift,
    # `write_positive` writes both `pyproject.toml` (the framework
    # version) and `config/agents.yaml` (the agents). The agents file
    # is the adapter's real input, so that is what gets mutated.
    fuzz_seed_relative_path="config/agents.yaml",
)


# --- LangGraph ---------------------------------------------------------------
# Claimed by the fixed `langgraph.json` location. Like CrewAI, the
# framework version lives in a second file, so this fixture names its
# fuzz seed explicitly. Version drift is real rather than exempt.

_LANGGRAPH_PYPROJECT = """
[project]
name = "conformance-graph"
version = "0.1.0"
dependencies = ["langgraph>=0.4.0"]
"""

_LANGGRAPH_MODULE = """
from langgraph.graph import StateGraph
builder = StateGraph(dict)
builder.add_node("plan", plan_step)
graph = builder.compile()
"""


def _langgraph_write_project(tmp_path: Path, config: object, dependency: str) -> None:
    _write_text(
        tmp_path,
        "pyproject.toml",
        _LANGGRAPH_PYPROJECT.replace("langgraph>=0.4.0", dependency),
    )
    _write_text(tmp_path, "agent.py", _LANGGRAPH_MODULE)
    _write_json(tmp_path, "langgraph.json", config)


def _langgraph_write_positive(tmp_path: Path) -> None:
    _langgraph_write_project(
        tmp_path, {"graphs": {"agent": "./agent.py:graph"}}, "langgraph>=0.4.0"
    )


def _langgraph_assert_positive(result: DiscoveryResult) -> None:
    graphs = [n for n in result.nodes if n.subtype == "langgraph-graph"]
    assert len(graphs) == 1
    assert graphs[0].name == "agent"


def _langgraph_write_similar_negative(tmp_path: Path) -> None:
    """A LangGraph-shaped module and config outside the claimed name."""

    _write_text(tmp_path, "pyproject.toml", _LANGGRAPH_PYPROJECT)
    _write_text(tmp_path, "agent.py", _LANGGRAPH_MODULE)
    _write_json(
        tmp_path, "langgraph.json.bak", {"graphs": {"agent": "./agent.py:graph"}}
    )


def _langgraph_write_malformed(tmp_path: Path) -> None:
    _write_text(tmp_path, "pyproject.toml", _LANGGRAPH_PYPROJECT)
    _write_text(tmp_path, "langgraph.json", "{ not valid json at all !!! ")


def _langgraph_write_boundary(tmp_path: Path) -> None:
    graphs = {f"graph_{i}": "./agent.py:graph" for i in range(_BOUNDARY_ENTRY_COUNT)}
    _langgraph_write_project(tmp_path, {"graphs": graphs}, "langgraph>=0.4.0")


def _langgraph_assert_boundary(result: DiscoveryResult) -> None:
    graphs = [n for n in result.nodes if n.subtype == "langgraph-graph"]
    assert len(graphs) == _BOUNDARY_ENTRY_COUNT
    assert result.diagnostics == ()


def _langgraph_write_version_drift(tmp_path: Path) -> None:
    _langgraph_write_project(
        tmp_path, {"graphs": {"agent": "./agent.py:graph"}}, "langgraph>=99.0.0"
    )


def _langgraph_write_older_version_drift(tmp_path: Path) -> None:
    _langgraph_write_project(
        tmp_path, {"graphs": {"agent": "./agent.py:graph"}}, "langgraph>=0.1.0"
    )


LANGGRAPH_FIXTURE = ConformanceFixture(
    adapter_name="langgraph",
    make_adapter=LangGraphAdapter,
    write_positive=_langgraph_write_positive,
    assert_positive=_langgraph_assert_positive,
    write_similar_negative=_langgraph_write_similar_negative,
    write_malformed=_langgraph_write_malformed,
    write_boundary=_langgraph_write_boundary,
    assert_boundary=_langgraph_assert_boundary,
    write_version_drift=_langgraph_write_version_drift,
    write_older_version_drift=_langgraph_write_older_version_drift,
    fuzz_seed_relative_path="langgraph.json",
)


# --- OpenAI Agents SDK ------------------------------------------------------
# The only adapter with no configuration file to claim: detection is by
# the SDK's own import, content-sniffed like OpenAPI. "Similar negative"
# is therefore a module that mentions `agents` without importing it, and
# "malformed" must pass the import sniff but break deeper.

_OPENAI_PYPROJECT = """
[project]
name = "conformance-desk"
version = "0.1.0"
dependencies = ["openai-agents>=0.2.0"]
"""


def _openai_write_project(tmp_path: Path, module: str, dependency: str) -> None:
    _write_text(
        tmp_path,
        "pyproject.toml",
        _OPENAI_PYPROJECT.replace("openai-agents>=0.2.0", dependency),
    )
    _write_text(tmp_path, "desk.py", module)


def _openai_write_positive(tmp_path: Path) -> None:
    _openai_write_project(
        tmp_path,
        'from agents import Agent\nsupport = Agent(name="Support")\n',
        "openai-agents>=0.2.0",
    )


def _openai_assert_positive(result: DiscoveryResult) -> None:
    agents = [n for n in result.nodes if n.subtype == "openai-agents-agent"]
    assert len(agents) == 1
    assert agents[0].name == "Support"


def _openai_write_similar_negative(tmp_path: Path) -> None:
    """Mentions `agents` as data, never imports the SDK."""

    _write_text(tmp_path, "pyproject.toml", _OPENAI_PYPROJECT)
    _write_text(
        tmp_path,
        "desk.py",
        'agents = ["not", "the", "sdk"]\nAgent = object\n',
    )


def _openai_write_malformed(tmp_path: Path) -> None:
    """Imports the SDK, then constructs an agent with a computed name --
    claimed, but nothing can be identified from it."""

    _openai_write_project(
        tmp_path,
        "from agents import Agent\nagent = Agent(name=build_name())\n",
        "openai-agents>=0.2.0",
    )


def _openai_write_boundary(tmp_path: Path) -> None:
    lines = ["from agents import Agent"]
    lines += [f'a{i} = Agent(name="Agent {i}")' for i in range(_BOUNDARY_ENTRY_COUNT)]
    _openai_write_project(tmp_path, "\n".join(lines) + "\n", "openai-agents>=0.2.0")


def _openai_assert_boundary(result: DiscoveryResult) -> None:
    agents = [n for n in result.nodes if n.subtype == "openai-agents-agent"]
    assert len(agents) == _BOUNDARY_ENTRY_COUNT
    assert result.diagnostics == ()


def _openai_write_version_drift(tmp_path: Path) -> None:
    _openai_write_project(
        tmp_path,
        'from agents import Agent\nsupport = Agent(name="Support")\n',
        "openai-agents>=99.0.0",
    )


def _openai_write_older_version_drift(tmp_path: Path) -> None:
    _openai_write_project(
        tmp_path,
        'from agents import Agent\nsupport = Agent(name="Support")\n',
        "openai-agents==0.0.1",
    )


OPENAI_AGENTS_FIXTURE = ConformanceFixture(
    adapter_name="openai-agents",
    make_adapter=OpenAiAgentsAdapter,
    write_positive=_openai_write_positive,
    assert_positive=_openai_assert_positive,
    write_similar_negative=_openai_write_similar_negative,
    write_malformed=_openai_write_malformed,
    write_boundary=_openai_write_boundary,
    assert_boundary=_openai_assert_boundary,
    write_version_drift=_openai_write_version_drift,
    write_older_version_drift=_openai_write_older_version_drift,
    fuzz_seed_relative_path="desk.py",
)


# --- Claude Code settings ----------------------------------------------------
# Claimed by fixed location (`.claude/settings.json`), never by content.
# Settings files carry no version field; the key set is pinned to a
# documentation snapshot date instead, which `--version` reports.


def _claude_code_write_positive(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        ".claude/settings.json",
        {
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "Edit",
                        "hooks": [{"type": "command", "command": "prettier --write"}],
                    }
                ]
            },
            "permissions": {"allow": ["Bash(npm test)"]},
        },
    )


def _claude_code_assert_positive(result: DiscoveryResult) -> None:
    subtypes = sorted(node.subtype or "" for node in result.nodes)
    assert subtypes == ["hook", "host", "permission-rule"]
    assert result.diagnostics == ()


def _claude_code_write_similar_negative(tmp_path: Path) -> None:
    _write_json(tmp_path, ".claude/settings.json.bak", {"hooks": {}})


def _claude_code_write_malformed(tmp_path: Path) -> None:
    _write_text(tmp_path, ".claude/settings.json", "{ not valid json at all !!! ")


def _claude_code_write_boundary(tmp_path: Path) -> None:
    rules = [f"Bash(task-{i})" for i in range(_BOUNDARY_ENTRY_COUNT)]
    _write_json(tmp_path, ".claude/settings.json", {"permissions": {"allow": rules}})


def _claude_code_assert_boundary(result: DiscoveryResult) -> None:
    rules = [node for node in result.nodes if node.subtype == "permission-rule"]
    assert len(rules) == _BOUNDARY_ENTRY_COUNT
    assert result.diagnostics == ()


CLAUDE_CODE_FIXTURE = ConformanceFixture(
    adapter_name="claude-code",
    make_adapter=ClaudeCodeSettingsAdapter,
    write_positive=_claude_code_write_positive,
    assert_positive=_claude_code_assert_positive,
    write_similar_negative=_claude_code_write_similar_negative,
    write_malformed=_claude_code_write_malformed,
    write_boundary=_claude_code_write_boundary,
    assert_boundary=_claude_code_assert_boundary,
    version_drift_unsupported_reason=(
        "Claude Code settings files carry no schema-version field; the "
        "recognized key set is pinned to a documentation snapshot date, and "
        "keys outside it produce INCOMPLETE-UNRECOGNIZED-KEY"
    ),
    older_version_drift_unsupported_reason=(
        "identical reason as the newer direction: no in-document version "
        "marker exists to make older"
    ),
    write_privacy=_claude_code_write_privacy,
)


# --- Agent-running workflows -------------------------------------------------
# Claimed by location (`.github/workflows/*.yml`); a workflow with no
# agent step is the similar negative. Workflow files carry no version.

_AGENT_JOB = (
    "on: push\n"
    "jobs:\n"
    "  {job}:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: anthropics/claude-code-action@v1\n"
)


def _workflows_write_positive(tmp_path: Path) -> None:
    _write_text(
        tmp_path, ".github/workflows/agent.yml", _AGENT_JOB.format(job="review")
    )


def _workflows_assert_positive(result: DiscoveryResult) -> None:
    subtypes = sorted(node.subtype or "" for node in result.nodes)
    assert subtypes == ["host", "workflow-runtime"]
    assert result.diagnostics == ()


def _workflows_write_similar_negative(tmp_path: Path) -> None:
    _write_text(
        tmp_path,
        ".github/workflows/build.yml",
        "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
    )


def _workflows_write_malformed(tmp_path: Path) -> None:
    _write_text(tmp_path, ".github/workflows/agent.yml", "jobs: [unclosed\n")


def _workflows_write_boundary(tmp_path: Path) -> None:
    jobs = "".join(
        f"  job-{i}:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: anthropics/claude-code-action@v1\n"
        for i in range(_BOUNDARY_ENTRY_COUNT)
    )
    _write_text(tmp_path, ".github/workflows/agent.yml", "on: push\njobs:\n" + jobs)


def _workflows_assert_boundary(result: DiscoveryResult) -> None:
    runtimes = [node for node in result.nodes if node.subtype == "workflow-runtime"]
    assert len(runtimes) == _BOUNDARY_ENTRY_COUNT
    assert result.diagnostics == ()


AGENT_WORKFLOWS_FIXTURE = ConformanceFixture(
    adapter_name="agent-workflows",
    make_adapter=AgentWorkflowAdapter,
    write_positive=_workflows_write_positive,
    assert_positive=_workflows_assert_positive,
    write_similar_negative=_workflows_write_similar_negative,
    write_malformed=_workflows_write_malformed,
    write_boundary=_workflows_write_boundary,
    assert_boundary=_workflows_assert_boundary,
    version_drift_unsupported_reason=(
        "GitHub workflow files carry no schema-version field"
    ),
    older_version_drift_unsupported_reason=(
        "identical reason as the newer direction: no in-document version "
        "marker exists to make older"
    ),
    write_privacy=_workflows_write_privacy,
)


# --- Claude Code skills, subagents, plugins ---------------------------------
# Claimed by location. Skill files carry no version field.


def _components_write_positive(tmp_path: Path) -> None:
    _write_text(
        tmp_path,
        ".claude/skills/deploy/SKILL.md",
        "---\nname: deploy\nallowed-tools: Bash(kubectl *)\n---\nInstructions.\n",
    )


def _components_assert_positive(result: DiscoveryResult) -> None:
    subtypes = sorted(node.subtype or "" for node in result.nodes)
    assert subtypes == ["host", "permission-rule", "skill"]
    assert result.diagnostics == ()


def _components_write_similar_negative(tmp_path: Path) -> None:
    _write_text(tmp_path, ".claude/skills/deploy/README.md", "not a skill\n")


def _components_write_malformed(tmp_path: Path) -> None:
    _write_text(tmp_path, ".claude-plugin/plugin.json", "{ not valid json at all !!! ")


def _components_write_boundary(tmp_path: Path) -> None:
    for i in range(_BOUNDARY_ENTRY_COUNT):
        _write_text(tmp_path, f".claude/commands/c{i}.md", "Do the thing.\n")


def _components_assert_boundary(result: DiscoveryResult) -> None:
    skills = [node for node in result.nodes if node.subtype == "skill"]
    assert len(skills) == _BOUNDARY_ENTRY_COUNT
    assert result.diagnostics == ()


CLAUDE_CODE_COMPONENTS_FIXTURE = ConformanceFixture(
    adapter_name="claude-code-components",
    make_adapter=ClaudeCodeComponentsAdapter,
    write_positive=_components_write_positive,
    assert_positive=_components_assert_positive,
    write_similar_negative=_components_write_similar_negative,
    write_malformed=_components_write_malformed,
    write_boundary=_components_write_boundary,
    assert_boundary=_components_assert_boundary,
    version_drift_unsupported_reason=(
        "skill, subagent, and plugin files carry no schema-version field; "
        "the recognized fields are pinned to a documentation snapshot date"
    ),
    older_version_drift_unsupported_reason=(
        "identical reason as the newer direction: no in-document version "
        "marker exists to make older"
    ),
    write_privacy=_components_write_privacy,
)


# --- Codex, Gemini CLI, Cursor, Kiro -----------------------------------------
# Claimed by location; none of these files carries a version field.


def _host_fixture(
    *,
    name: str,
    adapter: Callable[[], DiscoveryAdapter],
    path: str,
    positive: str,
    near_miss: str,
    malformed: str,
    boundary: Callable[[int], str],
    boundary_subtype: str,
    positive_subtypes: list[str],
    write_privacy: Callable[[Path], tuple[str, ...]],
) -> ConformanceFixture:
    def write_positive(tmp_path: Path) -> None:
        _write_text(tmp_path, path, positive)

    def assert_positive(result: DiscoveryResult) -> None:
        assert sorted(node.subtype or "" for node in result.nodes) == positive_subtypes
        assert result.diagnostics == ()

    def write_similar_negative(tmp_path: Path) -> None:
        _write_text(tmp_path, near_miss, positive)

    def write_malformed(tmp_path: Path) -> None:
        _write_text(tmp_path, path, malformed)

    def write_boundary(tmp_path: Path) -> None:
        _write_text(tmp_path, path, boundary(_BOUNDARY_ENTRY_COUNT))

    def assert_boundary(result: DiscoveryResult) -> None:
        found = [node for node in result.nodes if node.subtype == boundary_subtype]
        assert len(found) == _BOUNDARY_ENTRY_COUNT
        assert result.diagnostics == ()

    reason = f"{name} configuration files carry no schema-version field"
    return ConformanceFixture(
        adapter_name=name,
        make_adapter=adapter,
        write_positive=write_positive,
        assert_positive=assert_positive,
        write_similar_negative=write_similar_negative,
        write_malformed=write_malformed,
        write_boundary=write_boundary,
        assert_boundary=assert_boundary,
        version_drift_unsupported_reason=reason,
        older_version_drift_unsupported_reason=reason,
        write_privacy=write_privacy,
    )


def _hook_list(count: int, event: str) -> str:
    groups = [
        {"hooks": [{"type": "command", "command": f"task-{i}"}]} for i in range(count)
    ]
    return json.dumps({"hooks": {event: groups}})


CODEX_FIXTURE = _host_fixture(
    name="codex",
    adapter=CodexConfigAdapter,
    path=".codex/config.toml",
    positive='approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n',
    near_miss=".codex/config.toml.bak",
    malformed="[not valid toml\n",
    boundary=lambda count: "".join(
        f'[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = "command"\ncommand = "t{i}"\n'
        for i in range(count)
    ),
    boundary_subtype="hook",
    positive_subtypes=["host"],
    write_privacy=_codex_write_privacy,
)
GEMINI_FIXTURE = _host_fixture(
    name="gemini-cli",
    adapter=GeminiSettingsAdapter,
    path=".gemini/settings.json",
    positive=json.dumps({"tools": {"allowed": ["read_file"]}}),
    near_miss=".gemini/settings.json.bak",
    malformed="{ not valid json at all !!! ",
    boundary=lambda count: _hook_list(count, "BeforeTool"),
    boundary_subtype="hook",
    positive_subtypes=["host", "permission-rule"],
    write_privacy=_gemini_write_privacy,
)
CURSOR_FIXTURE = _host_fixture(
    name="cursor",
    adapter=CursorConfigAdapter,
    path=".cursor/hooks.json",
    positive=json.dumps({"version": 1, "hooks": {"stop": [{"command": "say done"}]}}),
    near_miss=".cursor/hooks.json.bak",
    malformed="{ not valid json at all !!! ",
    boundary=lambda count: json.dumps(
        {"version": 1, "hooks": {"stop": [{"command": f"t{i}"} for i in range(count)]}}
    ),
    boundary_subtype="hook",
    positive_subtypes=["hook", "host"],
    write_privacy=_cursor_write_privacy,
)
KIRO_FIXTURE = _host_fixture(
    name="kiro",
    adapter=KiroConfigAdapter,
    path=".kiro/hooks/format.json",
    positive=json.dumps(
        {
            "version": "v1",
            "hooks": [
                {
                    "trigger": "PostFileSave",
                    "action": {"type": "command", "command": "fmt"},
                }
            ],
        }
    ),
    near_miss=".kiro/hooks-old/format.json",
    malformed="{ not valid json at all !!! ",
    boundary=lambda count: json.dumps(
        {
            "version": "v1",
            "hooks": [
                {"trigger": "Stop", "action": {"type": "command", "command": f"t{i}"}}
                for i in range(count)
            ],
        }
    ),
    boundary_subtype="hook",
    positive_subtypes=["hook", "host"],
    write_privacy=_kiro_write_privacy,
)
ROO_FIXTURE = _host_fixture(
    name="roo-code",
    adapter=RooModesAdapter,
    path=".roomodes",
    positive=json.dumps({"customModes": [{"slug": "reviewer", "groups": ["read"]}]}),
    near_miss=".roomodes.bak",
    malformed="{ not valid json at all !!! ",
    boundary=lambda count: json.dumps(
        {"customModes": [{"slug": f"mode-{i}", "groups": []} for i in range(count)]}
    ),
    boundary_subtype="subagent",
    positive_subtypes=["host", "permission-rule", "subagent"],
    write_privacy=_roo_write_privacy,
)

ALL_FIXTURES: tuple[ConformanceFixture, ...] = (
    MCP_FIXTURE,
    OPENAPI_FIXTURE,
    A2A_FIXTURE,
    OASF_FIXTURE,
    IAM_FIXTURE,
    CREWAI_FIXTURE,
    LANGGRAPH_FIXTURE,
    OPENAI_AGENTS_FIXTURE,
    CLAUDE_CODE_FIXTURE,
    AGENT_WORKFLOWS_FIXTURE,
    CLAUDE_CODE_COMPONENTS_FIXTURE,
    CODEX_FIXTURE,
    GEMINI_FIXTURE,
    CURSOR_FIXTURE,
    KIRO_FIXTURE,
    ROO_FIXTURE,
)
