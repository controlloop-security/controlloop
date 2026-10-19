"""Codex, Gemini CLI, Cursor, and Kiro host configuration.

The same conventions as the Claude Code adapters, applied to the other
major coding agents: one host node per repository, hook and helper
commands as code execution, approval and sandbox modes as host
attributes with `bypass_mode` set by the loosest documented value, and
permission grants as rules. Nothing is executed.

Each host's recognized keys are pinned to its vendor documentation as
read on `DOCUMENTATION_SNAPSHOT`; an unrecognized top-level key is
reported as `INCOMPLETE-UNRECOGNIZED-KEY`. Instruction files --
`AGENTS.md`, `.cursor/rules`, `.roomodes`, Cline rules -- are not
read. Roo Code and Cline grant authority through their MCP
auto-approve lists, which `controlloop.adapters.mcp` already records.

In the ordered scales below, a move to the right loosens. They are data here
so the rule that compares them reads the same order this adapter documents.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

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
from controlloop.adapters.claude_code import (
    ComponentDiscovery,
    discover_hooks,
    helper_command_node,
    hook_node,
)
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.bounded_recursion import bounded_recursion
from controlloop.repository import walk_repository

DOCUMENTATION_SNAPSHOT = "2026-10-17"

#: Codex `approval_policy`, strictest first. `untrusted` is retired and
#: `on-failure` deprecated in the current documentation; both keep their
#: place for older files.
CODEX_APPROVAL_SCALE = ("untrusted", "on-request", "on-failure", "never")
#: Codex `sandbox_mode`, strictest first.
CODEX_SANDBOX_SCALE = ("read-only", "workspace-write", "danger-full-access")
#: Codex `default_permissions` profiles, strictest first.
CODEX_PERMISSIONS_SCALE = (":read-only", ":workspace", ":danger-full-access")
#: Gemini CLI `general.defaultApprovalMode`, strictest first. `yolo` is
#: CLI-only in the documentation; a file that sets it is recorded at
#: the loose end.
GEMINI_MODE_SCALE = ("plan", "default", "auto_edit", "yolo")
#: Cursor cloud-agent `egressMode`, strictest first (read from the
#: environment schema's descriptions; the documentation states no order).
CURSOR_EGRESS_SCALE = (
    "network_settings_only",
    "default_with_network_settings",
    "parent_plus_network_settings",
    "allow_all",
)


def _paths(context: ScanContext) -> list[str]:
    return sorted(
        item.relative_to(context.root.path).as_posix()
        for item in walk_repository(context.root)
        if isinstance(item, Path)
    )


def _load_toml(path: Path) -> dict[str, Any]:
    if path.stat().st_size > aa.MAX_CONFIG_BYTES:
        raise aa.ConfigLoadError("the file is larger than the configuration bound")
    try:
        with bounded_recursion(margin=500):
            return tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, RecursionError, OSError):
        raise aa.ConfigLoadError("the file is not valid TOML") from None


def _env_names(path: Path) -> list[str]:
    """Variable names from a dotenv file; values are never kept."""

    names: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return names
    for line in text.splitlines()[: aa.MAX_ENTRIES]:
        match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if match:
            names.append(match.group(1))
    return sorted(set(names))


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _on_scale(value: object, scale: tuple[str, ...]) -> tuple[str, bool]:
    text = str(value)
    return (text if text in scale else aa.authority_text(text)), text in scale


class _Host:
    """One host's accumulated discovery across its files."""

    def __init__(self, key: str, display_name: str, adapter: str) -> None:
        self.key = key
        self.display_name = display_name
        self.adapter = adapter
        self.host_id = host_node_id(key)
        self.nodes: list[Node] = []
        self.edges: list[Edge] = []
        self.diagnostics: list[Diagnostic] = []
        self.evidence: list[Evidence] = []
        self.attributes: dict[str, str] = {"docs_snapshot": DOCUMENTATION_SNAPSHOT}
        self.bypass: KnownBoolean | None = None

    def file(self, relative_path: str) -> ComponentDiscovery:
        return ComponentDiscovery(relative_path, self.host_id, adapter=self.adapter)

    def take(self, found: ComponentDiscovery, *, loaded: bool = True) -> None:
        self.nodes.extend(found.nodes)
        self.edges.extend(found.edges)
        self.diagnostics.extend(found.diagnostics)
        if loaded:
            self.evidence.extend(found.evidence)
        if found.unknown_keys:
            self.diagnostics.append(
                aa.unrecognized_key_diagnostic(
                    host_label=self.display_name,
                    path=found.path,
                    adapter=self.adapter,
                    key_paths=found.unknown_keys,
                )
            )

    def loosen(self, bypass: KnownBoolean) -> None:
        if bypass is True or self.bypass is True:
            self.bypass = True
        elif bypass == "unknown" or self.bypass == "unknown":
            self.bypass = "unknown"
        else:
            self.bypass = False

    def result(self) -> DiscoveryResult:
        if not self.evidence:
            return DiscoveryResult(diagnostics=tuple(self.diagnostics))
        host = aa.host_node(
            host=self.key,
            display_name=self.display_name,
            evidence=self.evidence,
            attributes=self.attributes,
            bypass_mode=self.bypass,
        )
        return DiscoveryResult(
            nodes=(*self.nodes, host),
            edges=tuple(self.edges),
            diagnostics=tuple(self.diagnostics),
        )


def _rule(
    found: ComponentDiscovery,
    *,
    namespace: str,
    effect: str,
    pattern: str,
    component_key: str,
    wildcard: bool | None = None,
) -> None:
    tool, classified = aa.classify_permission_rule(pattern)
    node = aa.component_node(
        node_type=NodeType.PERMISSION,
        subtype="permission-rule",
        namespace=namespace,
        declaring_path=found.path,
        component_key=component_key,
        name=f"{effect} {pattern}",
        attributes={
            "effect": effect,
            "pattern": aa.authority_text(pattern),
            "tool": aa.authority_text(tool),
        },
        security_attributes=SecurityAttributes(
            wildcard=classified if wildcard is None else wildcard,
            code_execution=True if aa.is_shell_tool(tool) else None,
        ),
        evidence=found.evidence,
    )
    found.nodes.append(node)
    found.link(
        node.id,
        EdgeType.PERMITTED_BY if effect == "allow" else EdgeType.CONSTRAINED_BY,
        component_key,
    )


# --- Codex ---------------------------------------------------------------------

_CODEX_KEYS = frozenset(
    {
        "agents", "allow_login_shell", "analytics", "approval_policy",
        "approvals_reviewer", "apps", "apps_mcp_product_sku", "auto_review",
        "background_terminal_max_timeout", "browser_use", "chatgpt_base_url",
        "check_for_update_on_startup", "cli_auth_credentials_store",
        "compact_prompt", "computer_use", "default_permissions", "desktop",
        "developer_instructions", "disable_paste_burst",
        "experimental_compact_prompt_file", "experimental_realtime_ws_base_url",
        "experimental_use_unified_exec_tool", "features", "feedback",
        "file_opener", "forced_chatgpt_workspace_id", "forced_login_method",
        "hide_agent_reasoning", "history", "hooks", "instructions", "log_dir",
        "marketplaces", "mcp_oauth_callback_port", "mcp_oauth_callback_url",
        "mcp_oauth_credentials_store", "mcp_optional_startup_grace_ms",
        "mcp_servers", "memories", "model", "model_auto_compact_token_limit",
        "model_auto_compact_token_limit_scope", "model_catalog_json",
        "model_context_window", "model_instructions_file", "model_provider",
        "model_providers", "model_reasoning_effort", "model_reasoning_summary",
        "model_supports_reasoning_summaries", "model_verbosity", "notice",
        "notify", "openai_base_url", "oss_provider", "otel", "permissions",
        "personality", "plan_mode_reasoning_effort", "plugins", "profile",
        "profiles", "project_doc_fallback_filenames", "project_doc_max_bytes",
        "project_root_markers", "projects", "review_model", "sandbox_mode",
        "sandbox_workspace_write", "service_tier", "shell_environment_policy",
        "skills", "sqlite_home", "suppress_unstable_features_warning",
        "tool_output_token_limit", "tool_suggest", "tools", "tui", "web_search",
        "windows", "windows_wsl_setup_acknowledged",
    }
)  # fmt: skip
_CODEX_HOOK_EVENTS = frozenset(
    {
        "PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact",
        "PostCompact", "SessionStart", "SessionEnd", "SubagentStart",
        "SubagentStop", "UserPromptSubmit", "Stop", "Interrupt",
    }
)  # fmt: skip
_CODEX_CONFIG = ".codex/config.toml"
_CODEX_HOOKS = ".codex/hooks.json"


class CodexConfigAdapter:
    """Codex project configuration: `.codex/config.toml` and
    `.codex/hooks.json`."""

    name = "codex"
    supported_versions: tuple[str, ...] = (f"docs-{DOCUMENTATION_SNAPSHOT}",)

    def detect(self, context: ScanContext) -> DetectionResult:
        claimed = [p for p in _paths(context) if p in (_CODEX_CONFIG, _CODEX_HOOKS)]
        return DetectionResult(adapter=self.name, claimed_paths=tuple(claimed))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        paths = set(_paths(context))
        host = _Host("codex", "Codex", self.name)
        if _CODEX_CONFIG in paths:
            found = host.file(_CODEX_CONFIG)
            try:
                payload = _load_toml(context.root.path / _CODEX_CONFIG)
            except aa.ConfigLoadError as error:
                found.unparsed(str(error))
                host.take(found, loaded=False)
            else:
                self._config(host, found, payload)
                host.take(found)
        if _CODEX_HOOKS in paths:
            found = host.file(_CODEX_HOOKS)
            try:
                payload = aa.load_json_object(context.root.path / _CODEX_HOOKS)
            except aa.ConfigLoadError as error:
                found.unparsed(str(error))
                host.take(found, loaded=False)
            else:
                discover_hooks(
                    found,
                    payload.get("hooks", {}),
                    root_key=("hooks",),
                    known_events=_CODEX_HOOK_EVENTS,
                    namespace="codex.hook",
                )
                host.take(found)
        return host.result()

    def _config(
        self, host: _Host, found: ComponentDiscovery, payload: dict[str, Any]
    ) -> None:
        for key in payload:
            if key not in _CODEX_KEYS:
                found.unknown_keys.append(str(key))
        for key in (
            "notify",
            "profile",
            "profiles",
            "model_provider",
            "model_providers",
        ):
            if key in payload:
                # Ignored in project config, as the documentation says;
                # recorded so a reader knows it was present.
                host.attributes[f"ignored_{key}"] = "true"
        policy = payload.get("approval_policy")
        if isinstance(policy, str):
            text, known = _on_scale(policy, CODEX_APPROVAL_SCALE)
            host.attributes["approval_policy"] = text
            host.loosen(True if policy == "never" else (False if known else "unknown"))
        elif isinstance(policy, dict):
            host.attributes["approval_policy"] = "granular"
            host.loosen(False)
        sandbox = payload.get("sandbox_mode")
        if isinstance(sandbox, str):
            text, known = _on_scale(sandbox, CODEX_SANDBOX_SCALE)
            host.attributes["sandbox_mode"] = text
            host.loosen(
                True
                if sandbox == "danger-full-access"
                else (False if known else "unknown")
            )
        permissions = payload.get("default_permissions")
        if isinstance(permissions, str):
            text, known = _on_scale(permissions, CODEX_PERMISSIONS_SCALE)
            host.attributes["default_permissions"] = text
            host.loosen(
                True
                if permissions == ":danger-full-access"
                else (False if known else "unknown")
            )
        workspace = payload.get("sandbox_workspace_write")
        if isinstance(workspace, dict) and "network_access" in workspace:
            host.attributes["sandbox_network_access"] = aa.authority_text(
                workspace["network_access"]
            )
        projects = payload.get("projects")
        if isinstance(projects, dict):
            levels = sorted(
                {
                    str(entry.get("trust_level"))
                    for entry in projects.values()
                    if isinstance(entry, dict)
                }
            )
            if levels:
                host.attributes["project_trust_levels"] = aa.authority_text(
                    ",".join(levels)
                )
        hooks = payload.get("hooks")
        if hooks is not None:
            discover_hooks(
                found,
                hooks,
                root_key=("hooks",),
                known_events=_CODEX_HOOK_EVENTS,
                namespace="codex.hook",
            )
        servers = payload.get("mcp_servers")
        if isinstance(servers, dict):
            for name, entry in list(servers.items())[: aa.MAX_ENTRIES]:
                helper = (
                    entry.get("http_headers_helper")
                    if isinstance(entry, dict)
                    else None
                )
                if isinstance(helper, str) and helper.strip():
                    helper_command_node(
                        found,
                        setting="http_headers_helper",
                        command=aa.command_text(helper),
                        component_key=aa.key_path(
                            "mcp_servers", str(name), "http_headers_helper"
                        ),
                    )
        providers = payload.get("model_providers")
        if isinstance(providers, dict):
            for name, entry in list(providers.items())[: aa.MAX_ENTRIES]:
                auth = _mapping(_mapping(entry).get("auth"))
                command = auth.get("command")
                if isinstance(command, (str, list)) and command:
                    helper_command_node(
                        found,
                        setting="model_providers.auth.command",
                        command=aa.command_text(command, auth.get("args")),
                        component_key=aa.key_path(
                            "model_providers", str(name), "auth", "command"
                        ),
                    )


# --- Gemini CLI ----------------------------------------------------------------

_GEMINI_KEYS = frozenset(
    {
        "policyPaths", "adminPolicyPaths", "general", "output", "ui", "ide",
        "privacy", "billing", "model", "modelConfigs", "agents", "context",
        "tools", "mcp", "mcpServers", "useWriteTodos", "security", "advanced",
        "experimental", "skills", "hooksConfig", "hooks", "contextManagement",
        "admin", "telemetry", "$schema",
    }
)  # fmt: skip
_GEMINI_HOOK_EVENTS = frozenset(
    {
        "SessionStart", "SessionEnd", "BeforeAgent", "AfterAgent", "BeforeModel",
        "AfterModel", "BeforeToolSelection", "BeforeTool", "AfterTool",
        "PreCompress", "Notification",
    }
)  # fmt: skip
_GEMINI_SETTINGS = ".gemini/settings.json"
_GEMINI_ENV = ".gemini/.env"
_GEMINI_SECURITY_FLAGS = (
    "disableYoloMode",
    "disableAlwaysAllow",
    "enablePermanentToolApproval",
    "autoAddToPolicyByDefault",
)


class GeminiSettingsAdapter:
    """Gemini CLI project settings: `.gemini/settings.json` and the
    variable names in `.gemini/.env`."""

    name = "gemini-cli"
    supported_versions: tuple[str, ...] = (f"docs-{DOCUMENTATION_SNAPSHOT}",)

    def detect(self, context: ScanContext) -> DetectionResult:
        claimed = [p for p in _paths(context) if p in (_GEMINI_SETTINGS, _GEMINI_ENV)]
        return DetectionResult(adapter=self.name, claimed_paths=tuple(claimed))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        paths = set(_paths(context))
        host = _Host("gemini-cli", "Gemini CLI", self.name)
        if _GEMINI_SETTINGS in paths:
            found = host.file(_GEMINI_SETTINGS)
            try:
                payload = aa.load_json_object(context.root.path / _GEMINI_SETTINGS)
            except aa.ConfigLoadError as error:
                found.unparsed(str(error))
                host.take(found, loaded=False)
            else:
                self._settings(host, found, payload)
                host.take(found)
        if _GEMINI_ENV in paths:
            names = _env_names(context.root.path / _GEMINI_ENV)
            if names:
                host.attributes["env_names"] = aa.authority_text(",".join(names))
            host.evidence.extend(aa.evidence_for(self.name, _GEMINI_ENV))
        return host.result()

    def _settings(
        self, host: _Host, found: ComponentDiscovery, payload: dict[str, Any]
    ) -> None:
        for key in payload:
            if key not in _GEMINI_KEYS:
                found.unknown_keys.append(str(key))
        general = _mapping(payload.get("general"))
        mode = general.get("defaultApprovalMode")
        if isinstance(mode, str):
            text, known = _on_scale(mode, GEMINI_MODE_SCALE)
            host.attributes["default_approval_mode"] = text
            host.loosen(True if mode == "yolo" else (False if known else "unknown"))
        security = _mapping(payload.get("security"))
        for flag in _GEMINI_SECURITY_FLAGS:
            if flag in security:
                host.attributes[re.sub(r"(?<!^)(?=[A-Z])", "_", flag).lower()] = (
                    aa.authority_text(security[flag])
                )
        folder_trust = security.get("folderTrust")
        if isinstance(folder_trust, dict) and "enabled" in folder_trust:
            host.attributes["folder_trust_enabled"] = aa.authority_text(
                folder_trust["enabled"]
            )
        tools = _mapping(payload.get("tools"))
        for key, attribute in (
            ("sandbox", "sandbox"),
            ("sandboxNetworkAccess", "sandbox_network_access"),
        ):
            if key in tools:
                host.attributes[attribute] = aa.authority_text(tools[key])
        for effect, key in (("allow", "allowed"), ("deny", "exclude")):
            entries = tools.get(key)
            if isinstance(entries, list):
                for index, pattern in enumerate(
                    found.bounded(entries, f"tools.{key} entries")
                ):
                    if not isinstance(pattern, str) or not pattern.strip():
                        continue
                    # `run_shell_command(git)` allows every `git` command.
                    shell_prefix = pattern.startswith("run_shell_command")
                    _rule(
                        found,
                        namespace="gemini-cli.tool-rule",
                        effect=effect,
                        pattern=pattern,
                        component_key=aa.key_path("tools", key, index),
                        wildcard=True if shell_prefix and effect == "allow" else None,
                    )
        for key_path, value in (
            (("tools", "discoveryCommand"), tools.get("discoveryCommand")),
            (("tools", "callCommand"), tools.get("callCommand")),
            (
                ("mcp", "serverCommand"),
                (payload.get("mcp") or {}).get("serverCommand")
                if isinstance(payload.get("mcp"), dict)
                else None,
            ),
        ):
            if isinstance(value, str) and value.strip():
                helper_command_node(
                    found,
                    setting=".".join(key_path),
                    command=aa.command_text(value),
                    component_key=aa.key_path(*key_path),
                )
        if "hooks" in payload:
            discover_hooks(
                found,
                payload.get("hooks"),
                root_key=("hooks",),
                known_events=_GEMINI_HOOK_EVENTS,
                namespace="gemini-cli.hook",
            )
        hooks_config = payload.get("hooksConfig")
        if isinstance(hooks_config, dict) and "enabled" in hooks_config:
            host.attributes["hooks_enabled"] = aa.authority_text(
                hooks_config["enabled"]
            )


# --- Cursor --------------------------------------------------------------------

_CURSOR_HOOKS = ".cursor/hooks.json"
_CURSOR_ENVIRONMENT = ".cursor/environment.json"
_CURSOR_CLI = ".cursor/cli.json"
_CURSOR_HOOK_EVENTS = frozenset(
    {
        "sessionStart", "sessionEnd", "preToolUse", "postToolUse",
        "postToolUseFailure", "subagentStart", "subagentStop",
        "beforeShellExecution", "afterShellExecution", "beforeMCPExecution",
        "afterMCPExecution", "beforeReadFile", "afterFileEdit",
        "beforeSubmitPrompt", "preCompact", "stop", "afterAgentResponse",
        "afterAgentThought", "beforeTabFileRead", "afterTabFileEdit",
        "workspaceOpen",
    }
)  # fmt: skip
_CURSOR_ENVIRONMENT_KEYS = frozenset(
    {
        "$schema", "name", "user", "install", "start", "repositoryDependencies",
        "disableAllMcpServers", "mcpServerAllowlist", "egressAllowlist",
        "egressMode", "chromeExecutablePath", "enable_testing", "ports",
        "terminals", "build", "image", "snapshot", "agentCanUpdateSnapshot",
    }
)  # fmt: skip


class CursorConfigAdapter:
    """Cursor project configuration: `.cursor/hooks.json`,
    `.cursor/environment.json`, and `.cursor/cli.json`."""

    name = "cursor"
    supported_versions: tuple[str, ...] = (f"docs-{DOCUMENTATION_SNAPSHOT}",)

    def detect(self, context: ScanContext) -> DetectionResult:
        claimed = [
            p
            for p in _paths(context)
            if p in (_CURSOR_HOOKS, _CURSOR_ENVIRONMENT, _CURSOR_CLI)
        ]
        return DetectionResult(adapter=self.name, claimed_paths=tuple(claimed))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        paths = set(_paths(context))
        host = _Host("cursor", "Cursor", self.name)
        for relative, handler in (
            (_CURSOR_HOOKS, self._hooks),
            (_CURSOR_ENVIRONMENT, self._environment),
            (_CURSOR_CLI, self._cli),
        ):
            if relative not in paths:
                continue
            found = host.file(relative)
            try:
                payload = aa.load_json_object(context.root.path / relative)
            except aa.ConfigLoadError as error:
                found.unparsed(str(error))
                host.take(found, loaded=False)
                continue
            handler(host, found, payload)
            host.take(found)
        return host.result()

    def _hooks(
        self, host: _Host, found: ComponentDiscovery, payload: dict[str, Any]
    ) -> None:
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            found.unparsed("hooks is not an object")
            return
        for event, entries in hooks.items():
            if str(event) not in _CURSOR_HOOK_EVENTS:
                found.unknown_keys.append(aa.key_path("hooks", str(event)))
            if not isinstance(entries, list):
                found.unparsed("a hook event is not a list")
                continue
            for index, entry in enumerate(found.bounded(entries, "hook entries")):
                if not isinstance(entry, dict):
                    continue
                handler = {"type": entry.get("type", "command"), **entry}
                component_key = aa.key_path("hooks", str(event), index)
                matcher = entry.get("matcher")
                try:
                    node = hook_node(
                        found,
                        event=str(event),
                        matcher=matcher
                        if isinstance(matcher, str) and matcher
                        else None,
                        handler=handler,
                        component_key=component_key,
                        namespace="cursor.hook",
                    )
                except ValueError:
                    found.unparsed("a hook entry could not be represented")
                    continue
                found.nodes.append(node)
                found.link(node.id, EdgeType.INVOKES, component_key)

    def _environment(
        self, host: _Host, found: ComponentDiscovery, payload: dict[str, Any]
    ) -> None:
        for key in payload:
            if key not in _CURSOR_ENVIRONMENT_KEYS:
                found.unknown_keys.append(str(key))
        for key in ("install", "start"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                helper_command_node(
                    found,
                    setting=key,
                    command=aa.command_text(value),
                    component_key=key,
                )
        terminals = payload.get("terminals")
        entries = (
            terminals
            if isinstance(terminals, list)
            else [terminals]
            if isinstance(terminals, dict)
            else []
        )
        for index, terminal in enumerate(entries[: aa.MAX_ENTRIES]):
            command = terminal.get("command") if isinstance(terminal, dict) else None
            if isinstance(command, str) and command.strip():
                helper_command_node(
                    found,
                    setting="terminals",
                    command=aa.command_text(command),
                    component_key=aa.key_path("terminals", index, "command"),
                )
        build = payload.get("build")
        if isinstance(build, dict):
            for key in ("dockerfile", "dockerfileContents"):
                value = build.get(key)
                if isinstance(value, str) and value.strip():
                    helper_command_node(
                        found,
                        setting=f"build.{key}",
                        command=aa.repository_path_text(value)
                        if key == "dockerfile"
                        else "inline Dockerfile",
                        component_key=aa.key_path("build", key),
                    )
        egress = payload.get("egressMode")
        if isinstance(egress, str):
            text, _known = _on_scale(egress, CURSOR_EGRESS_SCALE)
            host.attributes["egress_mode"] = text
        if payload.get("agentCanUpdateSnapshot") is True:
            host.attributes["agent_can_update_snapshot"] = "true"

    def _cli(
        self, host: _Host, found: ComponentDiscovery, payload: dict[str, Any]
    ) -> None:
        permissions = payload.get("permissions")
        if not isinstance(permissions, dict):
            return
        for effect in ("allow", "deny"):
            entries = permissions.get(effect)
            if not isinstance(entries, list):
                continue
            for index, pattern in enumerate(
                found.bounded(entries, f"permissions.{effect}")
            ):
                if isinstance(pattern, str) and pattern.strip():
                    _rule(
                        found,
                        namespace="cursor.cli-rule",
                        effect=effect,
                        pattern=pattern,
                        component_key=aa.key_path("permissions", effect, index),
                    )


# --- Kiro ----------------------------------------------------------------------

_KIRO_HOOK_DIRECTORY = ".kiro/hooks/"
_KIRO_AGENT_DIRECTORY = ".kiro/agents/"
_KIRO_TRIGGERS = frozenset(
    {
        "SessionStart", "SessionEnd", "Stop", "UserPromptSubmit", "PreToolUse",
        "PostToolUse", "PostFileCreate", "PostFileSave", "PostFileDelete",
        "PreTaskExec", "PostTaskExec", "agentSpawn",
        # Legacy `.kiro.hook` `when.type` values.
        "agentStop", "promptSubmit", "preToolUse", "postToolUse", "fileCreated",
        "fileEdited", "fileDeleted", "preTaskExecution", "postTaskExecution",
        "userTriggered",
    }
)  # fmt: skip


class KiroConfigAdapter:
    """Kiro hooks (`.kiro/hooks/`) and custom agents (`.kiro/agents/`).
    Kiro's MCP auto-approve lists come from the MCP adapter."""

    name = "kiro"
    supported_versions: tuple[str, ...] = (f"docs-{DOCUMENTATION_SNAPSHOT}",)

    def _claimed(self, context: ScanContext) -> list[str]:
        return [
            p
            for p in _paths(context)
            if (
                p.startswith(_KIRO_HOOK_DIRECTORY)
                and p.endswith((".json", ".kiro.hook"))
            )
            or (p.startswith(_KIRO_AGENT_DIRECTORY) and p.endswith(".json"))
        ]

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(
            adapter=self.name, claimed_paths=tuple(self._claimed(context))
        )

    def discover(self, context: ScanContext) -> DiscoveryResult:
        host = _Host("kiro", "Kiro", self.name)
        for relative in self._claimed(context):
            found = host.file(relative)
            try:
                payload = aa.load_json_object(context.root.path / relative)
            except aa.ConfigLoadError as error:
                found.unparsed(str(error))
                host.take(found, loaded=False)
                continue
            if relative.startswith(_KIRO_AGENT_DIRECTORY):
                self._agent(found, payload)
            elif relative.endswith(".kiro.hook"):
                self._legacy_hook(found, payload)
            else:
                entries = payload.get("hooks")
                if isinstance(entries, list):
                    for index, entry in enumerate(found.bounded(entries, "hooks")):
                        if isinstance(entry, dict):
                            self._hook(found, entry, aa.key_path("hooks", index))
                else:
                    found.unparsed("hooks is not a list")
            host.take(found)
        return host.result()

    def _hook(
        self, found: ComponentDiscovery, entry: dict[str, Any], component_key: str
    ) -> None:
        trigger = entry.get("trigger")
        event = str(trigger) if isinstance(trigger, str) else "unknown"
        if event not in _KIRO_TRIGGERS:
            found.unknown_keys.append(f"{component_key}.trigger")
        action = _mapping(entry.get("action"))
        action_type = action.get("type")
        handler: dict[str, Any] = {
            "type": "command" if action_type == "command" else "agent"
        }
        if action_type == "command":
            handler["command"] = action.get("command")
        matcher = entry.get("matcher")
        node = hook_node(
            found,
            event=event,
            matcher=matcher if isinstance(matcher, str) and matcher else None,
            handler=handler,
            component_key=component_key,
            namespace="kiro.hook",
        )
        found.nodes.append(node)
        found.link(node.id, EdgeType.INVOKES, component_key)
        confirm = entry.get("confirm")
        if isinstance(confirm, dict):
            commands = [confirm.get("confirmCommand")]
            options = confirm.get("options")
            if isinstance(options, list):
                commands.extend(
                    option.get("run") for option in options if isinstance(option, dict)
                )
            for index, command in enumerate(
                command
                for command in commands
                if isinstance(command, str) and command.strip()
            ):
                helper_command_node(
                    found,
                    setting="confirm",
                    command=aa.command_text(command),
                    component_key=f"{component_key}.confirm[{index}]",
                )

    def _legacy_hook(self, found: ComponentDiscovery, payload: dict[str, Any]) -> None:
        when = _mapping(payload.get("when"))
        then = _mapping(payload.get("then"))
        then_type = then.get("type")
        entry = {
            "trigger": when.get("type"),
            "action": {
                "type": "command" if then_type == "runCommand" else "agent",
                "command": then.get("command"),
            },
        }
        self._hook(found, entry, "hook")
        if then_type not in ("runCommand", "askAgent"):
            found.unknown_keys.append("then.type")

    def _agent(self, found: ComponentDiscovery, payload: dict[str, Any]) -> None:
        for index, pattern in enumerate(
            found.bounded(list(payload.get("allowedTools") or []), "allowedTools")
        ):
            if isinstance(pattern, str) and pattern.strip():
                _rule(
                    found,
                    namespace="kiro.agent-rule",
                    effect="allow",
                    pattern=pattern,
                    component_key=aa.key_path("allowedTools", index),
                )
        permissions = payload.get("permissions")
        rules = permissions.get("rules") if isinstance(permissions, dict) else None
        if isinstance(rules, list):
            for index, rule in enumerate(found.bounded(rules, "permission rules")):
                if not isinstance(rule, dict):
                    continue
                effect = str(rule.get("effect", "unknown"))
                capability = str(rule.get("capability", "unknown"))
                match = rule.get("match")
                pattern = (
                    f"{capability}({match})"
                    if isinstance(match, str) and match
                    else capability
                )
                _rule(
                    found,
                    namespace="kiro.agent-rule",
                    effect="allow"
                    if effect == "allow"
                    else ("ask" if effect == "ask" else "deny"),
                    pattern=pattern,
                    component_key=aa.key_path("permissions", "rules", index),
                    wildcard=capability in ("all", "builtin", "filesystem")
                    or match in (None, "*", "**"),
                )
        settings = payload.get("toolsSettings")
        shell = settings.get("shell") if isinstance(settings, dict) else None
        allowed = shell.get("allowedCommands") if isinstance(shell, dict) else None
        if isinstance(allowed, list):
            for index, command in enumerate(found.bounded(allowed, "allowed commands")):
                if isinstance(command, str) and command.strip():
                    _rule(
                        found,
                        namespace="kiro.agent-rule",
                        effect="allow",
                        pattern=f"shell({command})",
                        component_key=aa.key_path(
                            "toolsSettings", "shell", "allowedCommands", index
                        ),
                        wildcard="*" in command,
                    )


#: The hosts these adapters own; the MCP adapter emits references to them.
OWNED_HOSTS = frozenset({"codex", "gemini-cli", "cursor", "kiro"})
