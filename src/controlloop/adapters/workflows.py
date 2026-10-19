"""Agent-running GitHub workflows.

A workflow file is the one place where a repository file, not a
developer's machine, decides what a coding agent can do unattended. This
adapter records each job that runs an agent as a workflow runtime: which
agent host it runs, the token permissions the job holds, the flags it
passes, the secrets it references by name, and whether its trigger hands
it untrusted input.

Workflow files are parsed with `yaml.safe_load` and never executed;
nothing here starts a process or makes a request. A value the scanner
cannot resolve statically -- a reusable workflow, a matrix, an
expression in an agent input or in `permissions` -- is reported as an
unknown naming the workflow and job, never guessed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

import yaml

from controlloop.acbom import (
    Diagnostic,
    Edge,
    EdgeType,
    Evidence,
    KnownBoolean,
    Node,
    NodeType,
    SecurityAttributes,
    host_node_id,
)
from controlloop.adapters import agent_authority as aa
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.bounded_recursion import bounded_recursion

_NAME = "agent-workflows"
_SUPPORTED_VERSIONS: tuple[str, ...] = ("github-actions",)
_WORKFLOW_DIRECTORY = ".github/workflows/"

_RUNTIME_NAMESPACE = "agent-workflows.runtime"
_PERMISSION_NAMESPACE = "agent-workflows.token-permission"
_TOOL_NAMESPACE = "agent-workflows.allowed-tool"
_EVENT_NAMESPACE = "agent-workflows.event"


@dataclass(frozen=True, slots=True)
class _Host:
    key: str
    display_name: str


_CLAUDE_CODE = _Host("claude-code", "Claude Code")
_CODEX = _Host("codex", "Codex")
_GEMINI = _Host("gemini-cli", "Gemini CLI")
_COPILOT = _Host("copilot", "GitHub Copilot")

#: Actions that run an agent, matched on `owner/repo` before `@ref`.
_AGENT_ACTIONS: dict[str, _Host] = {
    "anthropics/claude-code-action": _CLAUDE_CODE,
    "anthropics/claude-code-base-action": _CLAUDE_CODE,
    "openai/codex-action": _CODEX,
    "google-github-actions/run-gemini-cli": _GEMINI,
}
#: A gh-aw lock file's run step that starts one of these CLIs.
_LOCK_FILE_CLIS: dict[str, _Host] = {
    "claude": _CLAUDE_CODE,
    "codex": _CODEX,
    "copilot": _COPILOT,
    "gemini": _GEMINI,
}

#: Events whose payload an outside contributor controls, or that run
#: with the base repository's secrets on outside code.
_UNTRUSTED_EVENTS = frozenset(
    {
        "pull_request_target",
        "issue_comment",
        "workflow_run",
        "issues",
        "pull_request_review_comment",
        "discussion_comment",
    }
)
_HEAD_REF_PATTERN = re.compile(
    r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/"
)

_SKIP_FLAGS = (
    "--dangerously-skip-permissions",
    "--dangerously-bypass-approvals-and-sandbox",
    "--yolo",
    "--allow-all-tools",
    "--approval-mode yolo",
    "--approval-mode=yolo",
    "--permission-mode bypassPermissions",
    "--permission-mode=bypassPermissions",
)
_SKIP_INPUT_VALUES = {
    "safety-strategy": frozenset({"unsafe"}),
    "sandbox": frozenset({"danger-full-access"}),
}
_ALLOWED_TOOL_INPUTS = ("allowed_tools", "allowedTools", "allowed-tools")
_CONFIG_INPUTS = ("settings", "mcp_config", "mcp-config")
_SECRET_PATTERN = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_EXPRESSION_PATTERN = re.compile(r"\$\{\{(?!\s*secrets\.)")
_ALLOWED_TOOLS_FLAG = re.compile(
    r"--allowed-?[Tt]ools[= ]+(['\"]?)([^'\"]+?)\1(?:\s+--|$)"
)
_WRITE_SCOPES = ("contents", "pull-requests", "id-token")


def _claimed_paths(context: ScanContext) -> tuple[str, ...]:
    found: set[str] = set()
    for file in context.repository_files():
        relative = file.relative
        if (
            relative.startswith(_WORKFLOW_DIRECTORY)
            and "/" not in relative[len(_WORKFLOW_DIRECTORY) :]
            and relative.endswith((".yml", ".yaml"))
        ):
            found.add(relative)
    return tuple(sorted(found))


def _workflow_label(relative_path: str) -> str:
    name = relative_path[len(_WORKFLOW_DIRECTORY) :]
    for suffix in (".lock.yml", ".yml", ".yaml"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _events(payload: dict[Any, Any]) -> list[str]:
    # YAML 1.1 reads a bare `on:` key as the boolean True.
    trigger = payload.get("on", payload.get(True))
    if isinstance(trigger, str):
        return [trigger]
    if isinstance(trigger, list):
        return [str(item) for item in trigger]
    if isinstance(trigger, dict):
        return [str(key) for key in trigger]
    return []


def _permissions(value: object) -> tuple[dict[str, str] | None, bool]:
    """Return `(scopes, unresolved)`. `None` scopes means no block."""

    if value is None:
        return None, False
    if isinstance(value, str):
        if _EXPRESSION_PATTERN.search(value):
            return None, True
        if value in {"read-all", "write-all"}:
            return {"*": value.split("-", 1)[0]}, False
        return None, True
    if isinstance(value, dict):
        if not value:
            return {}, False
        return {str(scope): str(level) for scope, level in value.items()}, False
    return None, True


def _uses(step: dict[str, Any]) -> str | None:
    uses = step.get("uses")
    return uses.split("@", 1)[0].strip().lower() if isinstance(uses, str) else None


def _step_text(step: dict[str, Any]) -> str:
    """Every string a step passes to an agent, for flag detection."""

    parts: list[str] = []
    run = step.get("run")
    if isinstance(run, str):
        parts.append(run)
    inputs = step.get("with")
    if isinstance(inputs, dict):
        parts.extend(
            str(value) for value in inputs.values() if isinstance(value, (str, int))
        )
    return "\n".join(parts)


def _secret_names(value: object) -> set[str]:
    names: set[str] = set()
    if isinstance(value, str):
        names.update(_SECRET_PATTERN.findall(value))
    elif isinstance(value, dict):
        for item in value.values():
            names |= _secret_names(item)
    elif isinstance(value, list):
        for item in value:
            names |= _secret_names(item)
    return names


def _lock_file_host(step: dict[str, Any]) -> _Host | None:
    run = step.get("run")
    if not isinstance(run, str):
        return None
    for line in run.splitlines():
        command = line.strip().split(" ", 1)[0].rsplit("/", 1)[-1]
        if command in _LOCK_FILE_CLIS:
            return _LOCK_FILE_CLIS[command]
    return None


class _WorkflowDiscovery:
    def __init__(self, relative_path: str) -> None:
        self.path = relative_path
        self.label = _workflow_label(relative_path)
        self.evidence = aa.evidence_for(_NAME, relative_path)
        self.nodes: list[Node] = []
        self.edges: list[Edge] = []
        self.diagnostics: list[Diagnostic] = []

    def unresolved(self, job: str, what: str) -> None:
        self.diagnostics.append(
            aa.unresolved_reference_diagnostic(
                adapter=_NAME,
                path=self.path,
                what=f"In workflow '{self.label}', job '{job}': {what}, so it",
            )
        )

    def link(
        self,
        source: str,
        target: str,
        relationship: EdgeType,
        discriminator: str,
        security_attributes: SecurityAttributes | None = None,
    ) -> None:
        self.edges.append(
            aa.edge(
                source=source,
                target=target,
                relationship=relationship,
                discriminator=f"{self.path}#{discriminator}",
                evidence=self.evidence,
                security_attributes=security_attributes,
            )
        )


def _discover_job(
    found: _WorkflowDiscovery,
    *,
    job_id: str,
    job: dict[str, Any],
    workflow_permissions: object,
    untrusted_events: list[str],
    lock_file: bool,
) -> None:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return
    agent_steps: list[tuple[dict[str, Any], _Host, str]] = []
    checks_out_head = False
    for step in steps[: aa.MAX_ENTRIES]:
        if not isinstance(step, dict):
            continue
        uses = _uses(step)
        if uses == "actions/checkout":
            ref = (
                (step.get("with") or {}).get("ref")
                if isinstance(step.get("with"), dict)
                else None
            )
            if isinstance(ref, str) and _HEAD_REF_PATTERN.search(ref):
                checks_out_head = True
        if uses in _AGENT_ACTIONS:
            agent_steps.append((step, _AGENT_ACTIONS[uses], uses))
        elif lock_file:
            host = _lock_file_host(step)
            if host is not None:
                agent_steps.append((step, host, "gh-aw"))
    if not agent_steps:
        return

    if isinstance(job.get("strategy"), dict) and "matrix" in job["strategy"]:
        found.unresolved(job_id, "a matrix varies the job's agent configuration")

    job_scopes, job_unresolved = _permissions(job.get("permissions"))
    workflow_scopes, workflow_unresolved = _permissions(workflow_permissions)
    unresolved = job_unresolved or (
        job.get("permissions") is None and workflow_unresolved
    )
    scopes = job_scopes if job.get("permissions") is not None else workflow_scopes
    if unresolved:
        found.unresolved(job_id, "the token permissions are an expression")

    for index, (step, host, action) in enumerate(agent_steps):
        component_key = (
            aa.key_path("jobs", job_id, "steps", index)
            if len(agent_steps) > 1
            else aa.key_path("jobs", job_id)
        )
        text = _step_text(step)
        with_value = step.get("with")
        inputs: dict[str, Any] = with_value if isinstance(with_value, dict) else {}
        skip = any(flag in text for flag in _SKIP_FLAGS) or any(
            str(inputs.get(name, "")).strip() in values
            for name, values in _SKIP_INPUT_VALUES.items()
        )
        for name, value in inputs.items():
            if isinstance(value, str) and _EXPRESSION_PATTERN.search(value):
                found.unresolved(
                    job_id,
                    f"the agent input '{aa.authority_text(name)}' is an expression",
                )
                break

        def scope_level(scope: str) -> str:
            if scopes is None:
                return "unknown"
            if "*" in scopes:
                return scopes["*"]
            return scopes.get(scope, "none")

        attributes: dict[str, str] = {
            "workflow": aa.authority_text(found.label),
            "job": aa.authority_text(job_id),
            "action": aa.authority_text(action),
            "host": host.key,
            "job_permissions": (
                "unknown"
                if scopes is None
                else aa.authority_text(
                    ",".join(f"{k}:{v}" for k, v in sorted(scopes.items())) or "none"
                )
            ),
            "skip_permissions": "true" if skip else "false",
        }
        for scope in _WRITE_SCOPES:
            level = scope_level(scope)
            attributes[f"{scope.replace('-', '_')}_write"] = (
                "unknown"
                if level == "unknown"
                else ("true" if level == "write" else "false")
            )
        if untrusted_events:
            attributes["untrusted_events"] = aa.authority_text(
                ",".join(sorted(untrusted_events))
            )
        secrets = sorted(_secret_names(step) | _secret_names(job.get("env")))
        if secrets:
            attributes["secret_names"] = aa.authority_text(",".join(secrets))
        for name in _CONFIG_INPUTS:
            value = inputs.get(name)
            if isinstance(value, str) and value.strip():
                key = name.replace("-", "_") + "_input"
                if value.strip().startswith("{") or "\n" in value:
                    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
                    attributes[key] = f"inline:sha256:{digest}"
                else:
                    attributes[key] = aa.repository_path_text(value.strip())

        untrusted: KnownBoolean = bool(untrusted_events or checks_out_head)
        runtime = aa.component_node(
            node_type=NodeType.TRIGGER,
            subtype="workflow-runtime",
            namespace=_RUNTIME_NAMESPACE,
            declaring_path=found.path,
            component_key=component_key,
            name=f"{found.label} / {job_id}",
            attributes=attributes,
            security_attributes=SecurityAttributes(
                untrusted_input=untrusted,
                bypass_mode=skip,
            ),
            evidence=found.evidence,
        )
        found.nodes.append(runtime)
        host_id = host_node_id(host.key)
        found.nodes.append(
            aa.host_reference_node(
                host=host.key, display_name=host.display_name, evidence=found.evidence
            )
        )
        found.link(runtime.id, host_id, EdgeType.INVOKES, component_key)

        if scopes is not None:
            for scope, level in sorted(scopes.items()):
                pattern = f"{scope}:{level}"
                permission = aa.component_node(
                    node_type=NodeType.PERMISSION,
                    subtype="permission-rule",
                    namespace=_PERMISSION_NAMESPACE,
                    declaring_path=found.path,
                    component_key=f"{component_key}:{pattern}",
                    name=f"token {pattern}",
                    attributes={
                        "effect": "grant",
                        "pattern": aa.authority_text(pattern),
                    },
                    security_attributes=SecurityAttributes(
                        wildcard=scope == "*",
                        read_only=level != "write",
                    ),
                    evidence=found.evidence,
                )
                found.nodes.append(permission)
                found.link(
                    runtime.id,
                    permission.id,
                    EdgeType.PERMITTED_BY,
                    f"{component_key}:{pattern}",
                )

        tools: list[str] = []
        for name in _ALLOWED_TOOL_INPUTS:
            value = inputs.get(name)
            if isinstance(value, str):
                tools.extend(
                    part.strip() for part in re.split(r"[,\n]", value) if part.strip()
                )
        for match in _ALLOWED_TOOLS_FLAG.finditer(text):
            tools.extend(
                part.strip()
                for part in re.split(r"[, ]+(?![^(]*\))", match.group(2))
                if part.strip()
            )
        for tool in sorted(set(tools))[: aa.MAX_ENTRIES]:
            rule_tool, wildcard = aa.classify_permission_rule(tool)
            rule = aa.component_node(
                node_type=NodeType.PERMISSION,
                subtype="permission-rule",
                namespace=_TOOL_NAMESPACE,
                declaring_path=found.path,
                component_key=f"{component_key}:{tool}",
                name=f"allow {tool}",
                attributes={
                    "effect": "allow",
                    "pattern": aa.authority_text(tool),
                    "tool": aa.authority_text(rule_tool),
                },
                security_attributes=SecurityAttributes(wildcard=wildcard),
                evidence=found.evidence,
            )
            found.nodes.append(rule)
            found.link(
                runtime.id, rule.id, EdgeType.PERMITTED_BY, f"{component_key}:{tool}"
            )

        events = sorted(untrusted_events) + (
            ["checkout-of-pull-request-head"] if checks_out_head else []
        )
        for event in events:
            event_node = aa.component_node(
                node_type=NodeType.TRIGGER,
                subtype="workflow-event",
                namespace=_EVENT_NAMESPACE,
                declaring_path=found.path,
                component_key=f"{component_key}:{event}",
                name=f"{found.label} / {job_id} on {event}",
                attributes={"event": aa.authority_text(event)},
                security_attributes=SecurityAttributes(
                    untrusted_input=True, trusted=False
                ),
                evidence=found.evidence,
            )
            found.nodes.append(event_node)
            found.link(
                runtime.id,
                event_node.id,
                EdgeType.RECEIVES_FROM,
                f"{component_key}:{event}",
            )
            found.link(
                host_id,
                event_node.id,
                EdgeType.RECEIVES_FROM,
                f"{component_key}:{event}",
            )


def _discover_workflow(context: ScanContext, relative_path: str) -> _WorkflowDiscovery:
    found = _WorkflowDiscovery(relative_path)
    path = context.root.path / relative_path
    try:
        if path.stat().st_size > aa.MAX_CONFIG_BYTES:
            raise ValueError("too large")
        with bounded_recursion(margin=500):
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError, yaml.YAMLError):
        found.diagnostics.append(
            aa.unparsed_diagnostic(
                adapter=_NAME,
                path=relative_path,
                reason="the workflow is not valid YAML",
            )
        )
        return found
    if not isinstance(payload, dict):
        return found
    jobs = payload.get("jobs")
    if not isinstance(jobs, dict):
        return found
    events = [event for event in _events(payload) if event in _UNTRUSTED_EVENTS]
    lock_file = relative_path.endswith(".lock.yml")
    for job_id, job in list(jobs.items())[: aa.MAX_ENTRIES]:
        if not isinstance(job, dict):
            continue
        uses = job.get("uses")
        if isinstance(uses, str):
            if (
                any(action in uses.lower() for action in _AGENT_ACTIONS)
                or "workflows/" in uses
            ):
                found.unresolved(str(job_id), "a reusable workflow decides what runs")
            continue
        _discover_job(
            found,
            job_id=str(job_id),
            job=job,
            workflow_permissions=payload.get("permissions"),
            untrusted_events=events,
            lock_file=lock_file,
        )
    return found


class AgentWorkflowAdapter:
    """Discovers GitHub workflow jobs that run a coding agent."""

    name = _NAME
    supported_versions: tuple[str, ...] = _SUPPORTED_VERSIONS

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=_claimed_paths(context))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        nodes: list[Node] = []
        edges: list[Edge] = []
        diagnostics: list[Diagnostic] = []
        for relative_path in _claimed_paths(context):
            found = _discover_workflow(context, relative_path)
            nodes.extend(found.nodes)
            edges.extend(found.edges)
            diagnostics.extend(found.diagnostics)
        # One reference per host per run; the runner folds them.
        unique: dict[str, Node] = {}
        references: dict[str, list[Evidence]] = {}
        for node in nodes:
            if aa.is_host_reference(node):
                references.setdefault(node.id, []).extend(node.evidence)
                unique.setdefault(node.id, node)
            else:
                unique[node.id] = node
        for node_id, evidence in references.items():
            reference = unique[node_id]
            unique[node_id] = aa.host_reference_node(
                host=reference.attributes["host"],
                display_name=reference.name,
                evidence=evidence,
            )
        return DiscoveryResult(
            nodes=tuple(unique.values()),
            edges=tuple(edges),
            diagnostics=tuple(diagnostics),
        )
