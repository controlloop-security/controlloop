"""Tests for AgentWorkflowAdapter."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from controlloop.acbom import EdgeType, Node, NodeType, host_node_id
from controlloop.adapters import (
    AgentWorkflowAdapter,
    ClaudeCodeSettingsAdapter,
    DiscoveryResult,
    ScanContext,
    run_adapters,
)
from controlloop.repository import resolve_repository_root

_SECRET = "planted-workflow-secret-4d4d"


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _workflow(tmp_path: Path, body: str, name: str = "agent.yml") -> None:
    target = tmp_path / ".github/workflows" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(body))


def _run(tmp_path: Path, *extra: object) -> DiscoveryResult:
    return run_adapters([AgentWorkflowAdapter(), *extra], _context(tmp_path))  # type: ignore[list-item]


def _runtimes(result: DiscoveryResult) -> list[Node]:
    return [node for node in result.nodes if node.subtype == "workflow-runtime"]


def _codes(result: DiscoveryResult) -> list[str]:
    return [d.code for d in result.diagnostics]


_CLAUDE_JOB = """
    on: pull_request
    jobs:
      review:
        runs-on: ubuntu-latest
        {permissions}
        steps:
          - uses: actions/checkout@v4
          - uses: anthropics/claude-code-action@v1
            with:
              prompt: review this
"""


# --- Agent steps and runtimes ---------------------------------------------


@pytest.mark.parametrize(
    ("action", "host"),
    [
        ("anthropics/claude-code-action@v1", "claude-code"),
        ("anthropics/claude-code-base-action@beta", "claude-code"),
        ("openai/codex-action@v1", "codex"),
        ("google-github-actions/run-gemini-cli@v0", "gemini-cli"),
        ("Anthropics/Claude-Code-Action@" + "a" * 40, "claude-code"),
    ],
)
def test_agent_actions_become_runtimes_that_invoke_their_host(
    tmp_path: Path, action: str, host: str
) -> None:
    _workflow(
        tmp_path,
        f"""
        on: push
        jobs:
          agent:
            runs-on: ubuntu-latest
            steps:
              - uses: {action}
        """,
    )

    result = _run(tmp_path)
    (runtime,) = _runtimes(result)

    assert runtime.type is NodeType.TRIGGER
    assert runtime.name == "agent / agent"
    assert runtime.attributes["host"] == host
    hosts = [node for node in result.nodes if node.subtype == "host"]
    assert [node.id for node in hosts] == [host_node_id(host)]
    assert any(
        edge.source == runtime.id
        and edge.target == host_node_id(host)
        and edge.type is EdgeType.INVOKES
        for edge in result.edges
    )


def test_a_gh_aw_lock_file_job_that_runs_an_agent_cli_is_a_runtime(
    tmp_path: Path,
) -> None:
    _workflow(
        tmp_path,
        """
        on: issues
        jobs:
          agent:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  set -e
                  codex exec --full-auto "$PROMPT"
        """,
        name="triage.lock.yml",
    )

    (runtime,) = _runtimes(_run(tmp_path))

    assert runtime.attributes["host"] == "codex"
    assert runtime.attributes["action"] == "gh-aw"
    assert runtime.name == "triage / agent"


@pytest.mark.parametrize(
    "steps",
    [
        "- uses: actions/checkout@v4",
        "- run: claude --version",  # an ordinary workflow, not a lock file
        "- uses: anthropics/claude-code-actions-helper@v1",
    ],
)
def test_jobs_that_run_no_agent_are_ignored(tmp_path: Path, steps: str) -> None:
    _workflow(
        tmp_path,
        f"""
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              {steps}
        """,
    )

    result = _run(tmp_path)

    assert result.nodes == ()
    assert result.diagnostics == ()


def test_the_runtime_host_folds_into_the_owning_adapters_host(tmp_path: Path) -> None:
    _workflow(tmp_path, _CLAUDE_JOB.format(permissions=""))
    settings = tmp_path / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"permissions": {"defaultMode": "plan"}}')

    result = _run(tmp_path, ClaudeCodeSettingsAdapter())
    hosts = [node for node in result.nodes if node.subtype == "host"]

    assert len(hosts) == 1
    assert hosts[0].attributes["default_mode"] == "plan"
    assert {e.path for e in hosts[0].evidence} == {
        ".claude/settings.json",
        ".github/workflows/agent.yml",
    }


# --- Effective permissions ------------------------------------------------


@pytest.mark.parametrize(
    ("workflow_permissions", "job_permissions", "expected"),
    [
        (None, None, "unknown"),
        ("permissions:\n  contents: read", None, "contents:read"),
        (
            "permissions:\n  contents: read",
            "permissions:\n          contents: write",
            "contents:write",
        ),
        ("permissions: write-all", None, "*:write"),
        (None, "permissions: {}", "none"),
    ],
)
def test_effective_permissions_follow_job_over_workflow(
    tmp_path: Path,
    workflow_permissions: str | None,
    job_permissions: str | None,
    expected: str,
) -> None:
    body = _CLAUDE_JOB.format(permissions=job_permissions or "")
    if workflow_permissions:
        body = body.replace(
            "    on: pull_request\n",
            "    on: pull_request\n    "
            + workflow_permissions.replace("\n", "\n    ")
            + "\n",
            1,
        )
    _workflow(tmp_path, body)

    (runtime,) = _runtimes(_run(tmp_path))

    assert runtime.attributes["job_permissions"] == expected


def test_write_scopes_are_runtime_attributes_and_permission_nodes(
    tmp_path: Path,
) -> None:
    _workflow(
        tmp_path,
        _CLAUDE_JOB.format(
            permissions=(
                "permissions:\n"
                "          contents: write\n"
                "          id-token: write\n"
                "          pull-requests: read"
            )
        ),
    )

    result = _run(tmp_path)
    (runtime,) = _runtimes(result)
    grants = sorted(
        node.attributes["pattern"]
        for node in result.nodes
        if node.subtype == "permission-rule" and node.attributes["effect"] == "grant"
    )

    assert runtime.attributes["contents_write"] == "true"
    assert runtime.attributes["id_token_write"] == "true"
    assert runtime.attributes["pull_requests_write"] == "false"
    assert grants == ["contents:write", "id-token:write", "pull-requests:read"]


def test_an_absent_permissions_block_is_unknown_never_the_default(
    tmp_path: Path,
) -> None:
    _workflow(tmp_path, _CLAUDE_JOB.format(permissions=""))

    result = _run(tmp_path)
    (runtime,) = _runtimes(result)

    for scope in ("contents_write", "pull_requests_write", "id_token_write"):
        assert runtime.attributes[scope] == "unknown"
    assert not [n for n in result.nodes if n.attributes.get("effect") == "grant"]


# --- Skip-permission flags, allowed tools, secrets ------------------------


@pytest.mark.parametrize(
    "with_block",
    [
        'claude_args: "--dangerously-skip-permissions"',
        'claude_args: "--permission-mode bypassPermissions"',
        'codex-args: "--yolo"',
        "safety-strategy: unsafe",
        "sandbox: danger-full-access",
        'settings: "--approval-mode yolo"',
    ],
)
def test_skip_permission_flags_set_bypass(tmp_path: Path, with_block: str) -> None:
    _workflow(
        tmp_path,
        f"""
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: openai/codex-action@v1
                with:
                  {with_block}
        """,
    )

    (runtime,) = _runtimes(_run(tmp_path))

    assert runtime.attributes["skip_permissions"] == "true"
    assert runtime.security_attributes.bypass_mode is True


def test_no_skip_flag_is_recorded_as_false(tmp_path: Path) -> None:
    _workflow(tmp_path, _CLAUDE_JOB.format(permissions=""))

    (runtime,) = _runtimes(_run(tmp_path))

    assert runtime.attributes["skip_permissions"] == "false"
    assert runtime.security_attributes.bypass_mode is False


def test_allowed_tools_become_permission_rules(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        """
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  allowed_tools: "Bash(npm test),Edit"
                  claude_args: --allowedTools "Bash(*)" --max-turns 5
        """,
    )

    result = _run(tmp_path)
    rules = {
        node.attributes["pattern"]: node
        for node in result.nodes
        if node.subtype == "permission-rule" and node.attributes["effect"] == "allow"
    }

    assert sorted(rules) == ["Bash(*)", "Bash(npm test)", "Edit"]
    assert rules["Bash(*)"].security_attributes.wildcard is True
    assert rules["Bash(npm test)"].security_attributes.wildcard is False


def test_secrets_are_recorded_by_name_only_and_inputs_by_shape(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        f"""
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            env:
              EXTRA: ${{{{ secrets.EXTRA_TOKEN }}}}
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  anthropic_api_key: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
                  settings: |
                    {{"env": {{"K": "{_SECRET}"}}}}
                  mcp_config: .github/mcp.json
        """,
    )

    result = _run(tmp_path)
    (runtime,) = _runtimes(result)

    assert runtime.attributes["secret_names"] == "ANTHROPIC_API_KEY,EXTRA_TOKEN"
    assert runtime.attributes["settings_input"].startswith("inline:sha256:")
    assert runtime.attributes["mcp_config_input"] == ".github/mcp.json"
    assert _SECRET not in result.model_dump_json()


# --- Untrusted triggers and input -----------------------------------------


@pytest.mark.parametrize(
    "trigger",
    [
        "pull_request_target",
        "issue_comment",
        "workflow_run",
        "issues",
        "pull_request_review_comment",
    ],
)
def test_untrusted_triggers_produce_an_untrusted_event(
    tmp_path: Path, trigger: str
) -> None:
    _workflow(
        tmp_path,
        _CLAUDE_JOB.format(permissions="").replace(
            "on: pull_request", f"on: [{trigger}]"
        ),
    )

    result = _run(tmp_path)
    (runtime,) = _runtimes(result)
    events = [node for node in result.nodes if node.subtype == "workflow-event"]

    assert runtime.security_attributes.untrusted_input is True
    assert [node.attributes["event"] for node in events] == [trigger]
    assert events[0].security_attributes.untrusted_input is True
    sources = {edge.source for edge in result.edges if edge.target == events[0].id}
    assert sources == {runtime.id, host_node_id("claude-code")}
    assert all(
        edge.type is EdgeType.RECEIVES_FROM
        for edge in result.edges
        if edge.target == events[0].id
    )


def test_checking_out_the_pull_request_head_is_untrusted_input(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        """
        on: pull_request
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - uses: anthropics/claude-code-action@v1
        """,
    )

    result = _run(tmp_path)

    assert _runtimes(result)[0].security_attributes.untrusted_input is True
    assert [
        n.attributes["event"] for n in result.nodes if n.subtype == "workflow-event"
    ] == ["checkout-of-pull-request-head"]


def test_a_trusted_trigger_has_no_untrusted_event(tmp_path: Path) -> None:
    _workflow(tmp_path, _CLAUDE_JOB.format(permissions=""))

    result = _run(tmp_path)

    assert _runtimes(result)[0].security_attributes.untrusted_input is False
    assert not [n for n in result.nodes if n.subtype == "workflow-event"]


# --- Unknowns, malformed input, determinism -------------------------------


def test_a_reusable_workflow_job_is_an_unknown_naming_the_job(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        """
        on: push
        jobs:
          delegated:
            uses: acme/shared/.github/workflows/claude.yml@main
        """,
    )

    result = _run(tmp_path)

    assert _codes(result) == ["INCOMPLETE-UNRESOLVED-REFERENCE"]
    assert "delegated" in result.diagnostics[0].message


def test_matrices_and_expressions_are_unknowns(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        """
        on: push
        permissions: ${{ inputs.perms }}
        jobs:
          a:
            runs-on: ubuntu-latest
            strategy:
              matrix:
                mode: [plan, auto]
            steps:
              - uses: anthropics/claude-code-action@v1
                with:
                  claude_args: --permission-mode ${{ matrix.mode }}
        """,
    )

    result = _run(tmp_path)

    assert _codes(result).count("INCOMPLETE-UNRESOLVED-REFERENCE") == 3
    assert _runtimes(result)[0].attributes["job_permissions"] == "unknown"


def test_yaml_anchors_resolve(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        """
        on: push
        x-agent: &agent
          uses: anthropics/claude-code-action@v1
          with:
            claude_args: --dangerously-skip-permissions
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - *agent
        """,
    )

    (runtime,) = _runtimes(_run(tmp_path))

    assert runtime.attributes["skip_permissions"] == "true"


@pytest.mark.parametrize("content", ["jobs: [unclosed", "{a: b: c}", "\t- tab"])
def test_malformed_yaml_is_a_diagnostic(tmp_path: Path, content: str) -> None:
    target = tmp_path / ".github/workflows/bad.yml"
    target.parent.mkdir(parents=True)
    target.write_text(content)

    result = _run(tmp_path)

    assert result.nodes == ()
    assert _codes(result) == ["INCOMPLETE-UNPARSED-REGION"]


def test_workflows_outside_the_workflow_directory_are_ignored(tmp_path: Path) -> None:
    for relative in (
        ".github/workflow/a.yml",
        ".github/workflows/nested/a.yml",
        "ci/a.yml",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            "on: push\njobs:\n  a:\n    steps:\n"
            "      - uses: anthropics/claude-code-action@v1\n"
        )

    assert AgentWorkflowAdapter().detect(_context(tmp_path)).claimed_paths == ()


def test_output_is_deterministic(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        _CLAUDE_JOB.format(permissions="permissions:\n          contents: write"),
    )

    assert _run(tmp_path) == _run(tmp_path)
