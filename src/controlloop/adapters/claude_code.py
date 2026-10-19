"""Claude Code settings discovery.

Reads the committed Claude Code project settings files and records what
they grant: the host itself, every hook handler, every command a
setting runs, permission rules, mode and bypass flags, additional
directories, plugin and marketplace sources, and which project MCP
servers are approved. Nothing in a settings file is executed, fetched,
or connected to; this module never imports `subprocess` or `socket`
and runs inside `adapter_sandbox`.

What a file grants is recorded whether or not a given Claude Code
version honors it from a project file (for example `defaultMode:
bypassPermissions`, ignored from project files since v2.1.257). Which
versions honor what is documentation, not something the scanner guesses.

The recognized key set is pinned to the Claude Code settings reference
as read on `DOCUMENTATION_SNAPSHOT`. A key outside it produces one
`INCOMPLETE-UNRECOGNIZED-KEY` diagnostic per file, never a silent drop.

`CLAUDE.md` is instructions, not authority, and is deliberately not
read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.adapters.mcp import discover_mcp_config
from controlloop.repository import walk_repository

_NAME = "claude-code"
HOST = "claude-code"
_DISPLAY_NAME = "Claude Code"

#: The date the recognized key set below was read from the vendor's
#: settings and hooks references (code.claude.com/docs/en/).
DOCUMENTATION_SNAPSHOT = "2026-10-17"

_SUPPORTED_VERSIONS: tuple[str, ...] = (f"docs-{DOCUMENTATION_SNAPSHOT}",)

_SHARED_SETTINGS = ".claude/settings.json"
_LOCAL_SETTINGS = ".claude/settings.local.json"
#: Later files take precedence for single-valued settings, matching the
#: documented order: project local over shared project.
_SETTINGS_PATHS = (_SHARED_SETTINGS, _LOCAL_SETTINGS)
_PROJECT_MCP_CONFIG = ".mcp.json"

# Every top-level key the settings reference documents under its own
# heading on DOCUMENTATION_SNAPSHOT, plus `$schema`.
_TOP_LEVEL_KEYS = frozenset(
    {
        "$schema", "advisorModel", "agent", "agentPushNotifEnabled",
        "allowAllClaudeAiMcps", "allowClaudeInChromeWithManagedMcp",
        "allowManagedHooksOnly", "allowManagedMcpServersOnly",
        "allowManagedPermissionRulesOnly", "allowedChannelPlugins",
        "allowedHttpHookUrls", "allowedMcpServers", "allowedProviders",
        "alwaysThinkingEnabled", "apiKeyHelper", "appendPlugins",
        "askUserQuestionTimeout", "attribution", "autoCompactEnabled",
        "autoCompactWindow", "autoConnectIde", "autoContinueAtUsageLimit",
        "autoInstallIdeExtension", "autoMemoryDirectory", "autoMemoryEnabled",
        "autoMode", "autoScrollEnabled", "autoUpdatesChannel", "availableModels",
        "availableModelsMatch", "awaySummaryEnabled", "awsAuthRefresh",
        "awsCredentialExport", "axScreenReader", "bashEditDiffEnabled",
        "bashOutputMaxChars", "blockedMarketplaces", "browserExternalPageTools",
        "channelsEnabled", "claudeInChromeDefaultEnabled", "claudeMd",
        "claudeMdExcludes", "cleanupPeriodDays", "companyAnnouncements",
        "copyFullResponse", "copyOnSelect", "crossSessionInbound", "defaultShell",
        "defaultToAgentsView", "deniedMcpServers", "deniedModels",
        "desktopSessionCleanupPeriodDays", "dialogExpiry", "diffTool",
        "disableAgentView", "disableAllHooks", "disableArtifact", "disableAutoMode",
        "disableBrowserExternalNavigation", "disableBundledSkills",
        "disableClaudeAiConnectors", "disableCommandPluginSources",
        "disableDeepLinkRegistration", "disableDesktopLocalSessions",
        "disableMobileSimulatorTools", "disableRemoteControl",
        "disableSideloadFlags", "disableSkillShellExecution", "disableWorkflows",
        "disabledMcpjsonServers", "editorMode", "effortLevel",
        "emojiCompletionEnabled", "enableAllProjectMcpServers", "enableArtifact",
        "enableWorkflows", "enabledMcpjsonServers", "enabledPlugins",
        "enforceAvailableModels", "env", "externalEditorContext",
        "extraKnownMarketplaces", "fallbackModel", "fastMode",
        "fastModePerSessionOptIn", "feedbackDrafts", "feedbackSurveyRate",
        "fileCheckpointingEnabled", "fileSuggestion", "footerLinksRegexes",
        "forceLoginGatewayUrl", "forceLoginMethod", "forceLoginOrgUUID",
        "forceRemoteSettingsRefresh", "gatewayInternalNetworks", "gcpAuthRefresh",
        "hooks", "httpHookAllowedEnvVars", "idleCompaction", "includeCoAuthoredBy",
        "includeGitInstructions", "inputNeededNotifEnabled", "isolatePeerMachines",
        "keybindingFlavor", "language", "leftArrowOpensAgents", "managedMcpServers",
        "managedSourcesBehavior", "maxEffortLevel", "maxProseWidth",
        "minimumVersion", "model", "modelOverrides", "modelPicker", "modelPricing",
        "modelSettings", "otelHeadersHelper", "outputStyle",
        "parentSettingsBehavior", "permissionExplainerEnabled", "permissions",
        "plansDirectory", "pluginConfigs", "pluginSuggestionMarketplaces",
        "pluginTrustMessage", "policyHelper", "prStatusFooterEnabled",
        "prUrlTemplate", "preferredNotifChannel", "prefersReducedMotion",
        "prependPlugins", "processWrapper", "promptCacheTtl",
        "promptSuggestionEnabled", "remote", "remoteControlAtStartup",
        "requiredMaximumVersion", "requiredMinimumVersion", "respectGitignore",
        "respondToBashCommands", "sandbox", "showClearContextOnPlanAccept",
        "showThinkingSummaries", "showTurnDuration", "skillListingBudgetFraction",
        "skillListingMaxDescChars", "skillOverrides", "skipAutoPermissionPrompt",
        "skipDangerousModePermissionPrompt", "skipWebFetchPreflight", "spellcheck",
        "spinnerTipsEnabled", "spinnerTipsOverride", "spinnerVerbs", "sshConfigs",
        "sshHostAllowlist", "statusLine", "strictKnownMarketplaces",
        "strictPluginOnlyCustomization", "subagentPromptCacheTtl",
        "subagentStatusLine", "switchModelsOnFlag", "syncClaudeAiPlugins",
        "syncClaudeAiSkills", "syntaxHighlightingDisabled", "taskOutputMaxChars",
        "teammateDefaultModel", "teammateMode", "terminalProgressBarEnabled",
        "terminalTitleFromRename", "theme", "timeFormat", "timeZone", "tui",
        "ultracode", "useAutoModeDuringPlan", "verbose", "viewMode",
        "vimInsertModeRemaps", "voice", "voiceEnabled",
        "wheelScrollAccelerationEnabled", "workflowKeywordTriggerEnabled",
        "workflowSizeGuideline", "worktree", "wslInheritsWindowsSettings",
    }
)  # fmt: skip

#: Documented children of the objects whose keys this adapter checks.
_NESTED_KEYS: dict[str, frozenset[str]] = {
    "permissions": frozenset(
        {
            "additionalDirectories", "allow", "ask",
            "blockReadsOutsideWorkingDirectories", "defaultMode", "deny",
            "disableBypassPermissionsMode",
        }
    ),
    "sandbox": frozenset(
        {
            "allowAppleEvents", "allowUnsandboxedCommands",
            "autoAllowBashIfSandboxed", "bwrapPath", "credentials", "enabled",
            "enableWeakerNestedSandbox", "enableWeakerNetworkIsolation",
            "excludedCommands", "failIfUnavailable", "filesystem",
            "ignoreViolations", "network", "ripgrep", "socatPath",
        }
    ),
    "sandbox.filesystem": frozenset(
        {
            "allowManagedReadPathsOnly", "allowRead", "allowWrite", "denyRead",
            "denyWrite", "disabled",
        }
    ),
    "sandbox.network": frozenset(
        {
            "allowAllUnixSockets", "allowLocalBinding", "allowMachLookup",
            "allowManagedDomainsOnly", "allowUnixSockets", "allowedDomains",
            "deniedDomains", "httpProxyPort", "socksProxyPort", "strictAllowlist",
            "tlsTerminate",
        }
    ),
    "sandbox.credentials": frozenset(
        {"allowPlaintextInject", "awsPairs", "envVars", "files", "sigv4"}
    ),
}  # fmt: skip

#: The hook events the hooks reference documents on DOCUMENTATION_SNAPSHOT.
HOOK_EVENTS = frozenset(
    {
        "SessionStart", "Setup", "InstructionsLoaded", "UserPromptSubmit",
        "UserPromptExpansion", "MessageDisplay", "PreToolUse",
        "PermissionRequest", "PostToolUse", "PostToolUseFailure",
        "PostToolBatch", "PermissionDenied", "Notification", "SubagentStart",
        "SubagentStop", "TaskCreated", "TaskCompleted", "Stop", "StopFailure",
        "TeammateIdle", "ConfigChange", "CwdChanged", "DirectoryAdded",
        "FileChanged", "WorktreeCreate", "WorktreeRemove", "PreCompact",
        "PostCompact", "PreModelSwitch", "PostModelSwitch", "SessionEnd",
        "Elicitation", "ElicitationResult",
    }
)  # fmt: skip

_HOOK_TYPES = frozenset({"command", "http", "mcp_tool", "prompt", "agent"})

#: Settings that hold a shell command line as a string.
_STRING_HELPERS = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "otelHeadersHelper",
    "processWrapper",
)
#: Settings that hold `{"type": "command", "command": ...}`.
_OBJECT_HELPERS = ("statusLine", "subagentStatusLine", "fileSuggestion")

#: Documented `permissions.defaultMode` values. `manual` is an alias for
#: `default`.
_DEFAULT_MODES = frozenset(
    {"default", "manual", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions"}
)

_HOOK_NAMESPACE = "claude-code.hook"
_HELPER_NAMESPACE = "claude-code.helper-command"
_RULE_NAMESPACE = "claude-code.permission-rule"
_DIRECTORY_NAMESPACE = "claude-code.additional-directory"
_PLUGIN_NAMESPACE = "claude-code.plugin"
_MARKETPLACE_NAMESPACE = "claude-code.marketplace"
_MCP_POLICY_NAMESPACE = "claude-code.mcp-server-policy"


def _claimed_paths(context: ScanContext) -> tuple[str, ...]:
    found: set[str] = set()
    for item in walk_repository(context.root):
        if isinstance(item, Path):
            relative = item.relative_to(context.root.path).as_posix()
            if relative in _SETTINGS_PATHS or relative == _PROJECT_MCP_CONFIG:
                found.add(relative)
    return tuple(sorted(found))


class ComponentDiscovery:
    """Accumulates one settings file's nodes, edges, and diagnostics."""

    def __init__(self, relative_path: str, host_id: str, adapter: str = _NAME) -> None:
        self.path = relative_path
        self.host_id = host_id
        self.adapter = adapter
        self.evidence = aa.evidence_for(adapter, relative_path)
        self.nodes: list[Node] = []
        self.edges: list[Edge] = []
        self.diagnostics: list[Diagnostic] = []
        self.unknown_keys: list[str] = []

    def link(
        self,
        target: str,
        relationship: EdgeType,
        discriminator: str,
        security_attributes: SecurityAttributes | None = None,
        source: str | None = None,
    ) -> None:
        self.edges.append(
            aa.edge(
                source=source or self.host_id,
                target=target,
                relationship=relationship,
                discriminator=f"{self.path}#{discriminator}",
                evidence=self.evidence,
                security_attributes=security_attributes,
            )
        )

    def unparsed(self, reason: str) -> None:
        self.diagnostics.append(
            aa.unparsed_diagnostic(adapter=self.adapter, path=self.path, reason=reason)
        )

    def bounded(self, items: list[Any], what: str) -> list[Any]:
        if len(items) > aa.MAX_ENTRIES:
            self.diagnostics.append(
                aa.bound_exceeded_diagnostic(
                    adapter=self.adapter, path=self.path, what=what
                )
            )
            return items[: aa.MAX_ENTRIES]
        return items


def _check_keys(found: ComponentDiscovery, payload: dict[str, Any]) -> None:
    for key in payload:
        if key not in _TOP_LEVEL_KEYS:
            found.unknown_keys.append(str(key))
    for parent, children in _NESTED_KEYS.items():
        value: Any = payload
        for segment in parent.split("."):
            value = value.get(segment) if isinstance(value, dict) else None
        if isinstance(value, dict):
            for key in value:
                if key not in children:
                    found.unknown_keys.append(f"{parent}.{key}")


def hook_node(
    found: ComponentDiscovery,
    *,
    event: str,
    matcher: str | None,
    handler: dict[str, Any],
    component_key: str,
    namespace: str | None = None,
) -> Node:
    hook_type = handler.get("type")
    type_text = hook_type if isinstance(hook_type, str) else "unknown"
    attributes: dict[str, str] = {
        "event": aa.authority_text(event),
        "hook_type": aa.authority_text(type_text) if type_text else "unknown",
    }
    if matcher:
        attributes["matcher"] = aa.authority_text(matcher)
    condition = handler.get("if")
    if isinstance(condition, str) and condition:
        attributes["condition"] = aa.authority_text(condition)

    code_execution: KnownBoolean = "unknown"
    external_communication: KnownBoolean | None = None
    if type_text == "command":
        code_execution = True
        attributes["command"] = aa.command_text(
            handler.get("command") or handler.get("commandWindows"),
            handler.get("args"),
        )
        if handler.get("async") is True or handler.get("asyncRewake") is True:
            attributes["async"] = "true"
    elif type_text == "http":
        code_execution = False
        external_communication = True
        url = handler.get("url")
        attributes["url_host"] = aa.url_host(url) if isinstance(url, str) else "unknown"
        headers = handler.get("headers")
        if isinstance(headers, dict) and headers:
            attributes["header_names"] = aa.authority_text(
                ",".join(sorted(str(name) for name in headers))
            )
    elif type_text == "mcp_tool":
        for field, attribute in (("server", "mcp_server"), ("tool", "mcp_tool")):
            value = handler.get(field)
            attributes[attribute] = (
                aa.authority_text(value) if isinstance(value, str) else "unknown"
            )
    elif type_text == "prompt":
        # The prompt text is protected content and is never recorded.
        code_execution = False
    if type_text not in _HOOK_TYPES:
        found.unknown_keys.append(f"{component_key}.type")

    label = f"{event} {attributes['hook_type']} hook" + (
        f" ({matcher})" if matcher else ""
    )
    return aa.component_node(
        node_type=NodeType.TOOL,
        subtype="hook",
        namespace=namespace or _HOOK_NAMESPACE,
        declaring_path=found.path,
        component_key=component_key,
        name=label,
        attributes=attributes,
        security_attributes=SecurityAttributes(
            code_execution=code_execution,
            external_communication=external_communication,
        ),
        evidence=found.evidence,
    )


def discover_hooks(
    found: ComponentDiscovery,
    hooks: object,
    *,
    root_key: tuple[str | int, ...],
    known_events: frozenset[str] | None = None,
    namespace: str | None = None,
) -> list[Node]:
    """Turn a `hooks` object (settings file, plugin `hooks.json`, or
    skill and subagent frontmatter) into hook nodes, each invoked by
    `found.host_id`. Returns the nodes so callers can attach them to a
    component as well."""

    created: list[Node] = []
    if hooks is None:
        return created
    if not isinstance(hooks, dict):
        found.unparsed("a hooks setting is not an object")
        return created
    for event, groups in hooks.items():
        event_name = str(event)
        if event_name not in (HOOK_EVENTS if known_events is None else known_events):
            found.unknown_keys.append(aa.key_path(*root_key, event_name))
        if not isinstance(groups, list):
            found.unparsed("a hook event is not a list of matcher groups")
            continue
        for group_index, group in enumerate(
            found.bounded(groups, "hook matcher groups")
        ):
            if not isinstance(group, dict):
                found.unparsed("a hook matcher group is not an object")
                continue
            matcher = group.get("matcher")
            matcher_text = matcher if isinstance(matcher, str) and matcher else None
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                found.unparsed("a hook matcher group has no list of handlers")
                continue
            for handler_index, handler in enumerate(
                found.bounded(handlers, "hook handlers")
            ):
                if not isinstance(handler, dict):
                    found.unparsed("a hook handler is not an object")
                    continue
                component_key = aa.key_path(
                    *root_key, event_name, group_index, "hooks", handler_index
                )
                try:
                    node = hook_node(
                        found,
                        event=event_name,
                        matcher=matcher_text,
                        handler=handler,
                        component_key=component_key,
                        namespace=namespace,
                    )
                except ValueError:
                    found.unparsed("a hook handler could not be represented")
                    continue
                found.nodes.append(node)
                found.link(node.id, EdgeType.INVOKES, component_key)
                created.append(node)
    return created


def helper_command_node(
    found: ComponentDiscovery, *, setting: str, command: str, component_key: str
) -> None:
    node = aa.component_node(
        node_type=NodeType.TOOL,
        subtype="helper-command",
        namespace=_HELPER_NAMESPACE,
        declaring_path=found.path,
        component_key=component_key,
        name=f"{setting} command",
        attributes={"setting": aa.authority_text(setting), "command": command},
        security_attributes=SecurityAttributes(code_execution=True),
        evidence=found.evidence,
    )
    found.nodes.append(node)
    found.link(node.id, EdgeType.INVOKES, component_key)


def _discover_helpers(found: ComponentDiscovery, payload: dict[str, Any]) -> None:
    for setting in _STRING_HELPERS:
        value = payload.get(setting)
        if value is None:
            continue
        if isinstance(value, str) and value.strip():
            helper_command_node(
                found,
                setting=setting,
                command=aa.command_text(value),
                component_key=setting,
            )
        else:
            found.unparsed(f"the {setting} setting is not a command string")
    for setting in _OBJECT_HELPERS:
        value = payload.get(setting)
        if value is None:
            continue
        command = value.get("command") if isinstance(value, dict) else None
        if isinstance(command, str) and command.strip():
            helper_command_node(
                found,
                setting=setting,
                command=aa.command_text(command),
                component_key=aa.key_path(setting, "command"),
            )
        else:
            found.unparsed(f"the {setting} setting has no command")
    policy_helper = payload.get("policyHelper")
    if policy_helper is not None:
        path = policy_helper.get("path") if isinstance(policy_helper, dict) else None
        if isinstance(path, str) and path.strip():
            helper_command_node(
                found,
                setting="policyHelper",
                command=aa.command_text(path),
                component_key=aa.key_path("policyHelper", "path"),
            )
        else:
            found.unparsed("the policyHelper setting has no path")


def permission_rule_node(
    found: ComponentDiscovery,
    *,
    effect: str,
    rule: str,
    component_key: str,
    namespace: str = _RULE_NAMESPACE,
) -> Node:
    tool, wildcard = aa.classify_permission_rule(rule)
    return aa.component_node(
        node_type=NodeType.PERMISSION,
        subtype="permission-rule",
        namespace=namespace,
        declaring_path=found.path,
        component_key=component_key,
        name=f"{effect} {rule}",
        attributes={
            "effect": effect,
            "pattern": aa.authority_text(rule),
            "tool": aa.authority_text(tool),
        },
        security_attributes=SecurityAttributes(
            wildcard=wildcard,
            code_execution=True if aa.is_shell_tool(tool) else None,
        ),
        evidence=found.evidence,
    )


def _discover_permissions(
    found: ComponentDiscovery, permissions: object
) -> dict[str, str]:
    """Rules, directories, and the mode keys; returns host attributes."""

    host_attributes: dict[str, str] = {}
    if permissions is None:
        return host_attributes
    if not isinstance(permissions, dict):
        found.unparsed("the permissions setting is not an object")
        return host_attributes

    for effect, relationship in (
        ("allow", EdgeType.PERMITTED_BY),
        ("ask", EdgeType.CONSTRAINED_BY),
        ("deny", EdgeType.CONSTRAINED_BY),
    ):
        rules = permissions.get(effect)
        if rules is None:
            continue
        if not isinstance(rules, list):
            found.unparsed(f"permissions.{effect} is not a list")
            continue
        for index, rule in enumerate(found.bounded(rules, f"{effect} rules")):
            component_key = aa.key_path("permissions", effect, index)
            if not isinstance(rule, str) or not rule.strip():
                found.unparsed(f"a permissions.{effect} entry is not a rule string")
                continue
            try:
                node = permission_rule_node(
                    found, effect=effect, rule=rule, component_key=component_key
                )
            except ValueError:
                found.unparsed("a permission rule could not be represented")
                continue
            found.nodes.append(node)
            found.link(node.id, relationship, component_key)

    directories = permissions.get("additionalDirectories")
    if isinstance(directories, list):
        for index, directory in enumerate(
            found.bounded(directories, "additional directories")
        ):
            if not isinstance(directory, str) or not directory.strip():
                found.unparsed("an additional directory is not a path string")
                continue
            component_key = aa.key_path("permissions", "additionalDirectories", index)
            node = aa.component_node(
                node_type=NodeType.RESOURCE,
                subtype="additional-directory",
                namespace=_DIRECTORY_NAMESPACE,
                declaring_path=found.path,
                component_key=component_key,
                name=f"additional directory {aa.repository_path_text(directory)}",
                attributes={"path": aa.repository_path_text(directory)},
                security_attributes=SecurityAttributes(),
                evidence=found.evidence,
            )
            found.nodes.append(node)
            found.link(node.id, EdgeType.READS, component_key)
            found.link(node.id, EdgeType.WRITES, component_key)
    elif directories is not None:
        found.unparsed("permissions.additionalDirectories is not a list")

    mode = permissions.get("defaultMode")
    if isinstance(mode, str):
        host_attributes["default_mode"] = (
            mode if mode in _DEFAULT_MODES else aa.authority_text(mode)
        )
        if mode not in _DEFAULT_MODES:
            found.unknown_keys.append("permissions.defaultMode")
    elif mode is not None:
        found.unparsed("permissions.defaultMode is not a string")
    disable_bypass = permissions.get("disableBypassPermissionsMode")
    if disable_bypass is not None:
        host_attributes["disable_bypass_permissions_mode"] = aa.authority_text(
            disable_bypass
        )
    block_reads = permissions.get("blockReadsOutsideWorkingDirectories")
    if block_reads is not None:
        host_attributes["block_reads_outside_working_directories"] = aa.authority_text(
            block_reads
        )
    return host_attributes


def _host_flag_attributes(
    found: ComponentDiscovery, payload: dict[str, Any]
) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for setting, attribute in (
        ("disableAllHooks", "disable_all_hooks"),
        ("disableSkillShellExecution", "disable_skill_shell_execution"),
        ("allowManagedHooksOnly", "allow_managed_hooks_only"),
        ("enableAllProjectMcpServers", "enable_all_project_mcp_servers"),
    ):
        value = payload.get(setting)
        if value is not None:
            attributes[attribute] = aa.authority_text(value)
    sandbox = payload.get("sandbox")
    if isinstance(sandbox, dict):
        for setting, attribute in (
            ("enabled", "sandbox_enabled"),
            ("allowUnsandboxedCommands", "sandbox_allow_unsandboxed_commands"),
            ("autoAllowBashIfSandboxed", "sandbox_auto_allow_bash"),
        ):
            value = sandbox.get(setting)
            if value is not None:
                attributes[attribute] = aa.authority_text(value)
    elif sandbox is not None:
        found.unparsed("the sandbox setting is not an object")
    env = payload.get("env")
    if isinstance(env, dict):
        # Variable names only. The values are never read into anything.
        names = sorted(str(name) for name in env)
        if names:
            attributes["env_names"] = aa.authority_text(",".join(names))
    elif env is not None:
        found.unparsed("the env setting is not an object")
    return attributes


def source_pin(source: dict[str, Any]) -> tuple[str, KnownBoolean]:
    """Return `(source_type, pinned)` for a plugin or marketplace source."""

    source_type = source.get("source")
    type_text = source_type if isinstance(source_type, str) else "unknown"
    if any(
        aa.is_pinned_ref(source.get(field))
        for field in ("sha", "sha256", "ref", "commit")
    ):
        return type_text, True
    if type_text in {"directory", "file"}:
        path = source.get("path")
        if (
            isinstance(path, str)
            and aa.repository_path_text(path) != aa.OUTSIDE_REPOSITORY_PATH
        ):
            # Content inside the repository is pinned by the commit itself.
            return type_text, True
        return type_text, "unknown"
    if type_text == "settings":
        return type_text, True
    return type_text, False


def _discover_marketplaces(
    found: ComponentDiscovery, marketplaces: object
) -> dict[str, str]:
    """Marketplace nodes; returns `{name: node id}` for plugin edges."""

    ids: dict[str, str] = {}
    if marketplaces is None:
        return ids
    if not isinstance(marketplaces, dict):
        found.unparsed("extraKnownMarketplaces is not an object")
        return ids
    for name, entry in list(marketplaces.items())[: aa.MAX_ENTRIES]:
        component_key = aa.key_path("extraKnownMarketplaces", str(name))
        source = entry.get("source") if isinstance(entry, dict) else None
        if not isinstance(source, dict):
            found.unparsed("a marketplace entry has no source object")
            continue
        source_type, pinned = source_pin(source)
        attributes = {"source_type": aa.authority_text(source_type)}
        for location_key in ("repo", "url", "path"):
            value = source.get(location_key)
            if isinstance(value, str) and value:
                attributes["location"] = (
                    aa.repository_path_text(value)
                    if location_key == "path"
                    else aa.authority_text(value)
                )
                break
        ref = source.get("ref")
        if isinstance(ref, str) and ref:
            attributes["ref"] = aa.authority_text(ref)
        headers = source.get("headers")
        if isinstance(headers, dict) and headers:
            attributes["header_names"] = aa.authority_text(
                ",".join(sorted(str(header) for header in headers))
            )
        node = aa.component_node(
            node_type=NodeType.TOOL,
            subtype="marketplace",
            namespace=_MARKETPLACE_NAMESPACE,
            declaring_path=found.path,
            component_key=component_key,
            name=f"marketplace {name}",
            attributes=attributes,
            security_attributes=SecurityAttributes(pinned=pinned),
            evidence=found.evidence,
        )
        found.nodes.append(node)
        found.link(node.id, EdgeType.RECEIVES_FROM, component_key)
        ids[str(name)] = node.id
        helper = source.get("headersHelper")
        if isinstance(helper, str) and helper.strip():
            helper_command_node(
                found,
                setting="headersHelper",
                command=aa.command_text(helper),
                component_key=aa.key_path(
                    "extraKnownMarketplaces", str(name), "source", "headersHelper"
                ),
            )
        inline_plugins = source.get("plugins") if source_type == "settings" else None
        if isinstance(inline_plugins, list):
            for index, plugin in enumerate(
                found.bounded(inline_plugins, "inline plugins")
            ):
                if not isinstance(plugin, dict):
                    continue
                plugin_source = plugin.get("source")
                plugin_name = plugin.get("name")
                if not isinstance(plugin_source, dict) or not isinstance(
                    plugin_name, str
                ):
                    found.unparsed("an inline marketplace plugin has no name or source")
                    continue
                _plugin_node(
                    found,
                    name=f"{plugin_name}@{name}",
                    source=plugin_source,
                    component_key=aa.key_path(
                        "extraKnownMarketplaces", str(name), "source", "plugins", index
                    ),
                    enabled=None,
                    marketplace_id=node.id,
                )
    return ids


def _plugin_node(
    found: ComponentDiscovery,
    *,
    name: str,
    source: dict[str, Any] | None,
    component_key: str,
    enabled: bool | None,
    marketplace_id: str | None,
) -> None:
    if source is not None:
        source_type, pinned = source_pin(source)
    else:
        # `enabledPlugins` names a plugin; its source and pin live in the
        # marketplace that serves it, which may not be in this repository.
        source_type, pinned = "marketplace", "unknown"
    attributes = {"source_type": aa.authority_text(source_type)}
    if enabled is not None:
        attributes["enabled"] = "true" if enabled else "false"
    code_execution: KnownBoolean | None = (
        True if source_type == "command" else "unknown"
    )
    node = aa.component_node(
        node_type=NodeType.TOOL,
        subtype="plugin",
        namespace=_PLUGIN_NAMESPACE,
        declaring_path=found.path,
        component_key=component_key,
        name=f"plugin {name}",
        attributes=attributes,
        security_attributes=SecurityAttributes(
            pinned=pinned, code_execution=code_execution
        ),
        evidence=found.evidence,
    )
    found.nodes.append(node)
    if enabled is not False:
        found.link(node.id, EdgeType.INVOKES, component_key)
    if marketplace_id is not None:
        found.link(
            marketplace_id, EdgeType.RECEIVES_FROM, component_key, source=node.id
        )


def _discover_plugins(
    found: ComponentDiscovery, plugins: object, marketplace_ids: dict[str, str]
) -> None:
    if plugins is None:
        return
    if not isinstance(plugins, dict):
        found.unparsed("enabledPlugins is not an object")
        return
    for key, enabled in list(plugins.items())[: aa.MAX_ENTRIES]:
        name = str(key)
        if not isinstance(enabled, bool):
            found.unparsed("an enabledPlugins value is not true or false")
            continue
        marketplace = name.rsplit("@", 1)[1] if "@" in name else None
        _plugin_node(
            found,
            name=name,
            source=None,
            component_key=aa.key_path("enabledPlugins", name),
            enabled=enabled,
            marketplace_id=marketplace_ids.get(marketplace) if marketplace else None,
        )


def _server_policy_names(
    found: ComponentDiscovery, setting: str, value: object
) -> list[tuple[int, str]]:
    """Names from a list of strings, or of `{"serverName": ...}` objects.
    Other entry forms (`serverCommand`, `serverUrl`) become rule nodes."""

    names: list[tuple[int, str]] = []
    if value is None:
        return names
    if not isinstance(value, list):
        found.unparsed(f"{setting} is not a list")
        return names
    for index, entry in enumerate(found.bounded(value, f"{setting} entries")):
        if isinstance(entry, str):
            names.append((index, entry))
        elif isinstance(entry, dict) and isinstance(entry.get("serverName"), str):
            names.append((index, entry["serverName"]))
        elif isinstance(entry, dict) and len(entry) == 1:
            ((form, pattern),) = entry.items()
            effect = "allow" if setting == "allowedMcpServers" else "deny"
            rule = f"{form}:{aa.authority_text(pattern)}"
            component_key = aa.key_path(setting, index)
            node = aa.component_node(
                node_type=NodeType.PERMISSION,
                subtype="permission-rule",
                namespace=_MCP_POLICY_NAMESPACE,
                declaring_path=found.path,
                component_key=component_key,
                name=f"{effect} MCP server {rule}",
                attributes={"effect": effect, "pattern": aa.authority_text(rule)},
                security_attributes=SecurityAttributes(wildcard="*" in rule),
                evidence=found.evidence,
            )
            found.nodes.append(node)
            found.link(
                node.id,
                EdgeType.PERMITTED_BY if effect == "allow" else EdgeType.CONSTRAINED_BY,
                component_key,
            )
        else:
            found.unparsed(f"a {setting} entry has an unrecognized form")
    return names


@dataclass(slots=True)
class _ServerApproval:
    """What the settings files say about one `.mcp.json` server."""

    approved: bool = False
    approved_by_name: bool = False
    denied: bool = False
    evidence: set[Evidence] = field(default_factory=set)


def _discover_mcp_approvals(
    found: ComponentDiscovery,
    payload: dict[str, Any],
    servers: dict[str, Node],
    approvals: dict[str, _ServerApproval],
) -> None:
    """Record which project MCP servers this file approves or rejects.
    The edges are drawn once every file has been read."""

    def record(name: str, setting: str, *, approve: bool, by_name: bool) -> None:
        if name not in servers:
            found.diagnostics.append(
                aa.unresolved_reference_diagnostic(
                    adapter=_NAME,
                    path=found.path,
                    what=(
                        f"The MCP server named in {setting} is not declared in "
                        f"{_PROJECT_MCP_CONFIG}, so it"
                    ),
                )
            )
            return
        state = approvals.setdefault(name, _ServerApproval())
        state.evidence.update(found.evidence)
        if approve:
            state.approved = True
            state.approved_by_name = state.approved_by_name or by_name
        else:
            state.denied = True

    if payload.get("enableAllProjectMcpServers") is True:
        for name in sorted(servers):
            record(name, "enableAllProjectMcpServers", approve=True, by_name=False)
    for setting, approve in (
        ("enabledMcpjsonServers", True),
        ("allowedMcpServers", True),
        ("disabledMcpjsonServers", False),
        ("deniedMcpServers", False),
    ):
        for _index, name in _server_policy_names(found, setting, payload.get(setting)):
            record(name, setting, approve=approve, by_name=True)


def _server_edges(
    host_id: str,
    servers: dict[str, Node],
    approvals: dict[str, _ServerApproval],
) -> list[Edge]:
    """One edge from the host to every project server.

    A rejected server is `constrained-by`; every other server is
    `invokes`, carrying whether an approval is recorded. A server no
    file mentions still connects after the user approves it in a
    prompt, so it is reachable and marked as requiring approval.
    """

    project_evidence = aa.evidence_for(_NAME, _PROJECT_MCP_CONFIG)
    edges: list[Edge] = []
    for name in sorted(servers):
        server = servers[name]
        state = approvals.get(name, _ServerApproval())
        evidence = (
            tuple(sorted(state.evidence, key=lambda item: item.path or ""))
            or project_evidence
        )
        discriminator = f"{_PROJECT_MCP_CONFIG}#mcp-server:{name}"
        if state.denied:
            edges.append(
                aa.edge(
                    source=host_id,
                    target=server.id,
                    relationship=EdgeType.CONSTRAINED_BY,
                    discriminator=discriminator,
                    evidence=evidence,
                )
            )
            continue
        attributes = (
            SecurityAttributes(
                approval_present=True,
                requires_approval=False,
                wildcard=not state.approved_by_name,
            )
            if state.approved
            else SecurityAttributes(approval_present=False, requires_approval=True)
        )
        edges.append(
            aa.edge(
                source=host_id,
                target=server.id,
                relationship=EdgeType.INVOKES,
                discriminator=discriminator,
                evidence=evidence,
                security_attributes=attributes,
            )
        )
    return edges


def _mcp_rule_server_edges(nodes: list[Node], servers: dict[str, Node]) -> list[Edge]:
    """A `permissions.allow` rule naming `mcp__<server>__<tool>` (or the
    whole server) is a per-tool approval on that server."""

    by_rule_name = {
        re.sub(r"[^A-Za-z0-9_-]", "_", name): node for name, node in servers.items()
    }
    edges: list[Edge] = []
    for node in nodes:
        if (
            node.subtype != "permission-rule"
            or node.attributes.get("effect") != "allow"
        ):
            continue
        tool = node.attributes.get("tool", "")
        if not tool.startswith("mcp__"):
            continue
        parts = tool.split("__")
        server = by_rule_name.get(parts[1]) if len(parts) >= 2 else None
        if server is None:
            continue
        edges.append(
            aa.edge(
                source=server.id,
                target=node.id,
                relationship=EdgeType.PERMITTED_BY,
                discriminator=f"mcp-rule:{node.id}",
                evidence=node.evidence,
                security_attributes=SecurityAttributes(
                    approval_present=True, requires_approval=False
                ),
            )
        )
    return edges


def _discover_settings_file(
    context: ScanContext,
    relative_path: str,
    host_id: str,
    servers: dict[str, Node],
    approvals: dict[str, _ServerApproval],
) -> tuple[ComponentDiscovery, dict[str, str] | None]:
    found = ComponentDiscovery(relative_path, host_id)
    try:
        payload = aa.load_json_object(context.root.path / relative_path)
    except aa.ConfigLoadError as error:
        found.unparsed(str(error))
        return found, None

    _check_keys(found, payload)
    discover_hooks(found, payload.get("hooks"), root_key=("hooks",))
    _discover_helpers(found, payload)
    attributes = _discover_permissions(found, payload.get("permissions"))
    attributes.update(_host_flag_attributes(found, payload))
    marketplace_ids = _discover_marketplaces(
        found, payload.get("extraKnownMarketplaces")
    )
    _discover_plugins(found, payload.get("enabledPlugins"), marketplace_ids)
    _discover_mcp_approvals(found, payload, servers, approvals)

    if found.unknown_keys:
        found.diagnostics.append(
            aa.unrecognized_key_diagnostic(
                host_label=_DISPLAY_NAME,
                path=relative_path,
                adapter=_NAME,
                key_paths=found.unknown_keys,
            )
        )
    return found, attributes


def _bypass_mode(default_mode: str | None) -> KnownBoolean | None:
    if default_mode is None:
        return None
    if default_mode == "bypassPermissions":
        return True
    return False if default_mode in _DEFAULT_MODES else "unknown"


class ClaudeCodeSettingsAdapter:
    """Discovers Claude Code project settings as an agent host and the
    authority its settings files grant."""

    name = _NAME
    supported_versions: tuple[str, ...] = _SUPPORTED_VERSIONS

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=_claimed_paths(context))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        claimed = _claimed_paths(context)
        settings_files = [path for path in _SETTINGS_PATHS if path in claimed]

        servers: dict[str, Node] = {}
        if _PROJECT_MCP_CONFIG in claimed:
            mcp_nodes, _ = discover_mcp_config(context, _PROJECT_MCP_CONFIG)
            servers = {node.name: node for node in mcp_nodes}
        if not settings_files and not servers:
            return DiscoveryResult()

        host_id = host_node_id(HOST)
        nodes: list[Node] = []
        edges: list[Edge] = []
        diagnostics: list[Diagnostic] = []
        evidence: list[Evidence] = []
        host_attributes: dict[str, str] = {"docs_snapshot": DOCUMENTATION_SNAPSHOT}
        approvals: dict[str, _ServerApproval] = {}
        loaded_any = False

        for relative_path in settings_files:
            found, attributes = _discover_settings_file(
                context, relative_path, host_id, servers, approvals
            )
            nodes.extend(found.nodes)
            edges.extend(found.edges)
            diagnostics.extend(found.diagnostics)
            if attributes is not None:
                loaded_any = True
                evidence.extend(found.evidence)
                # Later files override earlier ones, as the host does.
                host_attributes.update(attributes)

        if not loaded_any and not servers:
            # Every settings file failed to load: the diagnostics say so,
            # and no host is claimed on the strength of an unread file.
            return DiscoveryResult(diagnostics=tuple(diagnostics))

        if servers:
            # `.mcp.json` is Claude Code's project MCP file: its servers are
            # reachable by this host whether or not a settings file exists.
            evidence.extend(aa.evidence_for(_NAME, _PROJECT_MCP_CONFIG))
            nodes.extend(servers[name] for name in sorted(servers))
            edges.extend(_server_edges(host_id, servers, approvals))
            edges.extend(_mcp_rule_server_edges(nodes, servers))
        nodes.append(
            aa.host_node(
                host=HOST,
                display_name=_DISPLAY_NAME,
                evidence=evidence,
                attributes=host_attributes,
                bypass_mode=_bypass_mode(host_attributes.get("default_mode")),
            )
        )
        return DiscoveryResult(
            nodes=tuple(nodes), edges=tuple(edges), diagnostics=tuple(diagnostics)
        )
