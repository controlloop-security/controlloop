"""The adapter framework and registration contract."""

from controlloop.adapters.a2a import A2aAgentCardAdapter
from controlloop.adapters.agent_hosts import (
    DOCUMENTATION_SNAPSHOT as _AGENT_HOSTS_SNAPSHOT,
)
from controlloop.adapters.agent_hosts import (
    CodexConfigAdapter,
    CursorConfigAdapter,
    GeminiSettingsAdapter,
    KiroConfigAdapter,
)
from controlloop.adapters.claude_code import (
    DOCUMENTATION_SNAPSHOT as _CLAUDE_CODE_SNAPSHOT,
)
from controlloop.adapters.claude_code import ClaudeCodeSettingsAdapter
from controlloop.adapters.claude_code_components import ClaudeCodeComponentsAdapter
from controlloop.adapters.crewai import CrewAiAdapter
from controlloop.adapters.framework import (
    DetectionResult,
    DiscoveryAdapter,
    DiscoveryResult,
    ScanContext,
)
from controlloop.adapters.iam import IamPolicyAdapter
from controlloop.adapters.langgraph import LangGraphAdapter
from controlloop.adapters.mcp import McpServerAdapter
from controlloop.adapters.oasf import SUPPORTED_OASF_VERSIONS, OasfAdapter
from controlloop.adapters.openai_agents import OpenAiAgentsAdapter
from controlloop.adapters.openapi import OpenApiAdapter
from controlloop.adapters.runner import run_adapters
from controlloop.adapters.sandbox import AdapterSandboxViolationError, adapter_sandbox
from controlloop.adapters.workflows import AgentWorkflowAdapter

#: Every concrete, currently registered discovery adapter. This is the
#: one list the conformance suite checks fixture coverage against, so a
#: newly added adapter with no conformance fixtures fails CI instead of
#: shipping unverified.
ALL_ADAPTERS: tuple[type[DiscoveryAdapter], ...] = (
    McpServerAdapter,
    OpenApiAdapter,
    A2aAgentCardAdapter,
    OasfAdapter,
    IamPolicyAdapter,
    CrewAiAdapter,
    LangGraphAdapter,
    OpenAiAgentsAdapter,
    ClaudeCodeSettingsAdapter,
    ClaudeCodeComponentsAdapter,
    AgentWorkflowAdapter,
    CodexConfigAdapter,
    GeminiSettingsAdapter,
    CursorConfigAdapter,
    KiroConfigAdapter,
)

#: The vendor documentation date each agent host adapter's recognized
#: key set is pinned to, reported by `controlloop --version`.
AGENT_HOST_DOCUMENTATION_SNAPSHOTS: dict[str, str] = {
    "claude-code": _CLAUDE_CODE_SNAPSHOT,
    "codex": _AGENT_HOSTS_SNAPSHOT,
    "cursor": _AGENT_HOSTS_SNAPSHOT,
    "gemini-cli": _AGENT_HOSTS_SNAPSHOT,
    "kiro": _AGENT_HOSTS_SNAPSHOT,
}

__all__ = [
    "AGENT_HOST_DOCUMENTATION_SNAPSHOTS",
    "ALL_ADAPTERS",
    "SUPPORTED_OASF_VERSIONS",
    "A2aAgentCardAdapter",
    "AdapterSandboxViolationError",
    "AgentWorkflowAdapter",
    "ClaudeCodeComponentsAdapter",
    "ClaudeCodeSettingsAdapter",
    "CodexConfigAdapter",
    "CrewAiAdapter",
    "CursorConfigAdapter",
    "DetectionResult",
    "DiscoveryAdapter",
    "DiscoveryResult",
    "GeminiSettingsAdapter",
    "IamPolicyAdapter",
    "KiroConfigAdapter",
    "LangGraphAdapter",
    "McpServerAdapter",
    "OasfAdapter",
    "OpenAiAgentsAdapter",
    "OpenApiAdapter",
    "ScanContext",
    "adapter_sandbox",
    "run_adapters",
]
