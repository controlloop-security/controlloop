---
type: reference
title: Adapter status
tags:
  - adapters
  - standards
  - status
created: 2026-08-14
---

# Adapter status

Adapters are intended to discover agent-related evidence from standards and
configuration, then normalize it into the canonical ACBOM. They must not start
an agent, invoke a tool, contact a declared endpoint, or make policy decisions.

> **`controlloop bom` wires every adapter below except live MCP
> normalization and framework-specific source discovery.** `bom`
> runs `McpServerAdapter`, `OpenApiAdapter`, `A2aAgentCardAdapter`,
> `OasfAdapter`, and `IamPolicyAdapter` -- see [`bom`](../reference/cli.md#bom).
> The status below prevents an adapter
> from being mistaken for more support than it actually has, since `bom`
> running an adapter is not the same as that adapter supporting every
> version, transport, or provider of its format.

## Framework status

The adapter framework itself -- the one interface every future adapter
implements -- is implemented foundation, not a shipped format:

- `ScanContext` wraps a `RepositoryRoot` (the already-bounded, contained
  path primitive), never a raw filesystem or network handle. An adapter
  lists files with `context.repository_files()`, which walks the
  repository once per scan with default bounds and gives every adapter
  the same immutable list of paths and their repository-relative forms.
  An adapter never calls the walker itself;
  `tests/adapters/test_shared_walk.py` fails if one does.
- `DiscoveryAdapter` (`detect`/`discover`) is the one interface every
  adapter implements; `DetectionResult` and `DiscoveryResult` are its typed
  input/output shapes.
- `run_adapters` isolates any adapter that raises -- the scan continues,
  and the failure becomes an `INCOMPLETE-ADAPTER-FAILURE` diagnostic --
  and aggregates every adapter's output into one deterministic result
  independent of execution order.
- `adapter_sandbox` denies a file write, a subprocess, or a socket for
  the duration of an adapter's `detect`/`discover` call.

`controlloop bom`, `scan`, and `gate`
all wire this framework into real CLI commands today. A shared conformance
suite (`tests/adapters/test_adapter_conformance.py`) exercises positive
parsing, a similar negative case, malformed input, version drift in both
the newer- and older-than-supported directions,
boundary size, and determinism against every adapter listed in
`controlloop.adapters.ALL_ADAPTERS`, and fails CI if a newly registered
adapter has no matching conformance fixture. See the
[fixture corpus inventory](../reference/fixture-corpus.md) for the
full per-adapter breakdown of exactly which test covers each of those
categories.

## Format and source status

| Source | Status | Approved boundary |
| --- | --- | --- |
| A2A Agent Card | Implemented foundation | `A2aAgentCardAdapter` discovers cards committed at `.well-known/agent.json`, `.well-known/agent-card.json`, or `agent-card.json`, mapping the card to an agent node, declared `skills` to tool nodes connected by `invokes` edges, and declared `securitySchemes` to identity nodes. A card is never fetched live over the network -- only committed files are read. An unsupported `protocolVersion` produces a diagnostic naming it rather than a wrong parse; card-supplied text is only ever stored through canonical fields that already reject control characters and oversized text. A declared delegation target (a repository-committed, controlloop-owned `x-controlloop-delegates-to` extension field -- the real A2A specification does not currently standardize inter-agent delegation, which is a runtime concept, not a card field) produces a `delegates-to` edge: a repository-local target is read directly and linked to its own agent node, an external URL becomes a bounded, never-fetched external node, and an unresolvable target produces a diagnostic rather than a missing edge. Resolution is direct and non-recursive, so a mutual or self-delegation cycle cannot hang this adapter. A card's `url` becomes a `trigger` node (`inbound requests to <host>`, the host only) the agent `receives-from`, marked `untrusted_input: "unknown"` at low confidence: an inference that the agent accepts requests, never a claim about who sends them; `external_inputs` in `controlloop.yaml` confirms or rules it out. Wired into `controlloop bom`. |
| MCP server discovery | Implemented foundation | `McpServerAdapter` discovers server declarations committed in the MCP configuration of eleven agent hosts: `.mcp.json` (Claude Code), `.vscode/mcp.json` (VS Code, its `servers` key and `inputs`), `.cursor/mcp.json`, `.gemini/settings.json`, `.kiro/settings/mcp.json`, `.roo/mcp.json`, any `cline_mcp_settings.json`, `.continue/config.json` and `.continue/config.yaml`, `.windsurf/mcp.json`, `opencode.json`, and `.codex/config.toml` `[mcp_servers]`. Each server is a tool node classified by transport (`mcp-server-stdio` or `mcp-server-http`) whose identity is its file and name, and which records what makes a same-name swap visible: the command, redacted arguments, the npm, PyPI, or container package and version its launcher names, the remote host, environment-variable and header **names**, a digest of the whole redacted declaration, and a digest of tool names and descriptions from a committed `manifest.json`, `server.json`, or `tools.json` beside a local server (`unknown` when none is committed). A server that keeps its name while any of these change shows in `diff` as changed. Kiro `autoApprove`, Roo and Cline `alwaysAllow`, and Gemini CLI `trust` become per-tool permission rules. Each declaring host other than Claude Code becomes an agent host node here; Claude Code's comes from `ClaudeCodeSettingsAdapter`. It never starts a server, invokes a tool, or reads an env or header value; a malformed entry produces a diagnostic, never a dropped server or a crash. Wired into `controlloop bom`. |
| MCP live tool and resource normalization | Implemented foundation, disclosed risk escalation | `normalize_live_mcp_server` (`controlloop.adapters.mcp_live`) is a separate, standalone function -- not part of `McpServerAdapter`, never invoked by `run_adapters`, and never run inside the shared `adapter_sandbox`. Unlike every other adapter in this codebase, it **does** start a process: it is the one way to obtain a live server's actual tool list, input schemas, resources, and declared-credential identity/permission nodes, which only exist by asking the running server. It launches only the exact declared `command`/`args` (`shell=False`), exchanges `initialize`/`tools/list`/`resources/list` over stdio JSON-RPC, and is bounded on its own terms: a wall-clock timeout, a total-bytes cap on the subprocess's output, and guaranteed termination on every path -- success, timeout, malformed response, or crash. Stdio transport only; an HTTP/SSE-transport server is a genuine network call, a materially different risk, and is out of scope. Tool names and resource names flow through the same `DisplayName`-constrained fields as every other adapter; tool descriptions have no free-text home in the canonical model and are never stored verbatim. No CLI command calls this function yet, including `bom` -- wiring one in, and whether it should ever run without an explicit opt-in flag, is a separate, future decision. |
| `controlloop.yaml` | Product requirement | Intended future local, human-owned security extension. The current CLI does not consume this file. |
| OpenAPI | Implemented foundation | `OpenApiAdapter` discovers OpenAPI 3.x documents by content (JSON or YAML, no fixed filename convention), mapping each operation to a tool node and the path it addresses to a resource node connected by a method-appropriate `reads`/`writes` edge, and declared `securitySchemes` to identity/permission nodes. No network request is ever made: a remote `$ref` produces an explicit unknown rather than being fetched, and a local `$ref` cycle is detected and stopped rather than followed forever. Swagger 2.0 is recognized and explicitly rejected, never misparsed as OpenAPI 3.x. Wired into `controlloop bom`. |
| OASF | Implemented foundation, zero versions supported | `OasfAdapter` and `SUPPORTED_OASF_VERSIONS` (reported by `controlloop --version`) implement the version-governance mechanism, but the supported-version set starts **empty**: unlike MCP, OpenAPI, and A2A, the project does not yet have verified, current confidence in OASF's exact wire format, and fabricating field names for a real spec under genuine uncertainty risks a silently wrong parse. Every real OASF record currently produces an "unsupported version" diagnostic. Populating a real, verified version requires an authoritative OASF schema reference -- none is available yet. Wired into `controlloop bom`, though it claims nothing until a version is supported. |
| IAM and deployment metadata | Implemented foundation, AWS only | `IamPolicyAdapter` discovers native AWS IAM policy JSON and Terraform HCL IAM resources (`aws_iam_policy`/`aws_iam_role_policy`/`aws_iam_user_policy` via `jsonencode`, and `aws_iam_policy_document` data sources), mapping each statement to a permission node. Wildcards in action or resource are preserved (encoded as `WILDCARD`, since the canonical `permission_scopes` field's identifier pattern does not otherwise allow a literal `*`), never expanded into a false enumeration; a `Condition` block is recorded as a `condition:present` marker rather than evaluated; a Terraform variable or interpolation that cannot be resolved statically produces an unknown rather than a fabricated literal value. GCP and Azure policy documents are recognized by their distinctive shape and explicitly rejected, never misparsed as AWS. Scope is deliberately in-repo only: no live cloud API reads, no condition-key evaluation. Wired into `controlloop bom`. |
| CrewAI | Implemented | `CrewAiAdapter` discovers agents from `config/agents.yaml` at CrewAI's scaffolded path, naming each by its `role`, and turns `allow_delegation: true` into `delegates-to` edges to every other agent in the crew -- CrewAI does not let an agent name specific targets, so understating reach would be the more dangerous error. Tool wiring is read from `crew.py` by **parsing** it with `ast.parse`; the module is never imported, executed, or evaluated, asserted structurally. Gap: only a literal list of constructor calls resolves. A comprehension, conditional, bare name, splat, or call produces an `INCOMPLETE-UNRESOLVED-REFERENCE` **and** a node whose security attributes are literally `"unknown"`, which classifies as `UNCLASSIFIED` and ranks worst -- so an unreadable tool becomes the worst reachable capability rather than a silent omission. A crew overriding `agents_config`, or using the hierarchical process, is disclosed rather than silently mis-scoped. Wired into `controlloop bom`. |
| LangGraph | Implemented | `LangGraphAdapter` discovers graphs declared in `langgraph.json` -- a fixed path naming each graph and the `module.py:attribute` it lives at -- then reads topology from that module by parsing it. `add_node` becomes nodes, `add_edge` becomes edges, and **`add_conditional_edges` emits an edge to every target in its mapping**: the router decides at runtime, and a graph that modelled one branch would understate reach while looking precise. `START`/`END` are recognized as sentinels rather than mistaken for computed values. Gap: a router whose targets cannot be enumerated, a dynamically constructed graph, and a non-literal `bind_tools`/`ToolNode` argument each produce a diagnostic and an `"unknown"`-attributed node. Privacy: `langgraph.json`'s `env` is usually a **path** to a `.env` file holding real values, and that file is never opened -- only an inline mapping contributes `env:NAME` keys. Wired into `controlloop bom`. |
| OpenAI Agents SDK | Implemented | `OpenAiAgentsAdapter` is the only adapter with no configuration file to claim: detection is by the SDK's own import, gated on a byte-level marker before any parsing. `Agent(name=...)` becomes an agent, `handoffs=[...]` becomes `delegates-to`, and `Agent.as_tool()` becomes `invokes` -- deliberately distinct, since a handoff transfers the conversation while `as_tool` calls in and returns. **A `@function_tool` function is discovered at its definition site**, so a tool referenced by no agent is still found and reported as reachable by nothing. Resolution takes exactly one step beyond a literal -- a variable assigned from `Agent(...)` in the same module -- with no import following and no cross-module resolution. Gap: a computed agent name is reported rather than synthesized, since a made-up identity is worse than a missing one; a non-literal `tools` or `handoffs` list produces a diagnostic and an `"unknown"`-attributed node. Function tools contribute parameter **names** only. Wired into `controlloop bom`. |
| Claude Code project settings | Implemented | `ClaudeCodeSettingsAdapter` reads `.claude/settings.json`, and `.claude/settings.local.json` unless `.gitignore` excludes it, and records Claude Code as one agent host with what those files grant: every hook handler (a `command` hook is code execution, an `http` hook is external communication), every setting that runs a command (`apiKeyHelper`, `statusLine`, and eight more), `permissions.allow`/`ask`/`deny` rules with wildcards marked rather than expanded, the permission mode and sandbox flags, additional directories, plugins and marketplaces with their pin status, and which project MCP servers are approved. Nothing is executed. The recognized key set is pinned to the Claude Code documentation as read on 2026-10-17 (reported by `controlloop --version`); any other key is reported as `INCOMPLETE-UNRECOGNIZED-KEY`. `CLAUDE.md` is instructions, not authority, and is not read. See [Claude Code](claude-code.md). Wired into `controlloop bom`. |
| Claude Code skills, subagents, and plugins | Implemented | `ClaudeCodeComponentsAdapter` reads skills (`SKILL.md` under `.claude/skills/`, `.agents/skills/`, `.github/skills/`, and `.claude/commands/*.md`), subagents (`.claude/agents/*.md`), plugins (any directory with `.claude-plugin/plugin.json`, with its hooks, MCP servers, skills, subagents, commands, LSP and monitor commands, and `bin/` directory), and `.claude-plugin/marketplace.json`. A skill's `allowed-tools` and `disallowed-tools` become rules, its frontmatter hooks become hooks, and every `` !`cmd` `` line or ` ```! ` block becomes a code-execution command; a subagent's tools, `permissionMode` (bypass flagged), servers, hooks, and preloaded skills are recorded; each marketplace plugin records its source and pin status. Only frontmatter and shell-injection lines are read: no prompt text enters the record. See [Claude Code](claude-code.md). Wired into `controlloop bom`. |
| Agent-running GitHub workflows | Implemented | `AgentWorkflowAdapter` reads `.github/workflows/*.yml` and records each job that runs `anthropics/claude-code-action`, `anthropics/claude-code-base-action`, `openai/codex-action`, or `google-github-actions/run-gemini-cli` (and each gh-aw `*.lock.yml` job that starts the `claude`, `codex`, `copilot`, or `gemini` CLI) as a workflow runtime that invokes its agent host: the job's token permissions (job over workflow, `unknown` when absent), whether it skips permission prompts, the tools it allows, the secrets it references by name, and whether its trigger (`pull_request_target`, `issue_comment`, `workflow_run`, and others) or a checkout of the pull request's head hands it untrusted input. Nothing is executed. See [Agent-running workflows](agent-workflows.md). Wired into `controlloop bom`. |
| Codex | Implemented | `CodexConfigAdapter` reads `.codex/config.toml` and `.codex/hooks.json`: `approval_policy`, `sandbox_mode`, and `default_permissions` as host attributes (`never`, `danger-full-access`, and `:danger-full-access` set the bypass flag), hooks as code execution, and the MCP header helper and provider auth commands as helper commands. Keys Codex ignores in project files, such as `notify`, are recorded as present. See [Codex](codex.md). Wired into `controlloop bom`. |
| Gemini CLI | Implemented | `GeminiSettingsAdapter` reads `.gemini/settings.json` (hooks, `tools.allowed` and `tools.exclude` rules, `general.defaultApprovalMode`, the `security` flags, discovery and call commands) and the variable names in `.gemini/.env`. See [Gemini CLI](gemini-cli.md). Wired into `controlloop bom`. |
| Cursor | Implemented | `CursorConfigAdapter` reads `.cursor/hooks.json` (every hook entry), `.cursor/environment.json` (`install`, `start`, terminal, and build commands, `egressMode`), and `.cursor/cli.json` permission rules. See [Cursor](cursor.md). Wired into `controlloop bom`. |
| Kiro | Implemented | `KiroConfigAdapter` reads `.kiro/hooks/` (current and legacy hook files) and `.kiro/agents/` (`allowedTools`, `permissions.rules`, shell allow lists). Kiro's MCP `autoApprove` lists come from the MCP adapter. See [Kiro](kiro.md). Wired into `controlloop bom`. |
| Python, TypeScript, or framework-specific source discovery | Product direction | No framework is currently supported. |

## What agent host adapters cannot see

The agent host pages above list the files and keys each host's adapter
reads, which keys become unknown, and which files are deliberately not
read. What none of them can see -- user-scope settings, components a
plugin brings at runtime, live tool descriptions, prompt injection -- is
on [what a passing gate does not guarantee](../reference/agent-authority-limits.md).

## Why adapters are constrained

Repositories and imported documents can be attacker controlled. The accepted
adapter design therefore gives a bounded repository walker ownership of file
access. Adapters receive immutable, bounded artifacts rather than arbitrary
filesystem or network clients.

The approved boundary includes:

- repository-root containment and symlink-escape prevention;
- file-count, byte, depth, parsing, graph, diagnostic, and time limits;
- non-executing JSON, YAML, and HCL parsing (via `pyyaml`'s `safe_load`
  and `python-hcl2`, both structured-data parsers, never evaluating
  expressions or executing code);
- isolated malformed-input diagnostics;
- no source snippets or raw parser errors in output; and
- explicit incomplete-analysis results when a bound or unsupported behavior is
  encountered.

These controls remain internal engineering and architecture requirements. They
must pass implementation tests before this page marks any adapter available.

## MCP annotations are not policy authority

An MCP annotation such as `destructiveHint: true` is an untrusted hint. Any
future blocking rule must require human-owned local policy to corroborate the
classification and must have complete evidence. Missing, contradictory,
dynamic, or untrusted evidence remains a diagnostic or unknown, not a
confident blocking claim.

## What future adapter pages must include

Before a source is listed as available, its page must identify:

- supported versions and exact input location or selection rules;
- prerequisites and a verified example;
- which nodes, edges, evidence, and diagnostics it can produce;
- failure, malformed-input, unsupported-version, and dynamic behavior;
- filesystem, network, privacy, and resource bounds;
- known coverage gaps; and
- the next workflow that consumes its output.

Follow the structure of the existing adapter pages when adding that
guide.
