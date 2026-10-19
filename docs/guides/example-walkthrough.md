---
type: guide
title: Example walkthrough
tags:
  - guide
  - getting-started
created: 2026-08-27
---

# Example walkthrough

Ten minutes, one made-up agent, six steps. By the end you will know
what ControlLoop looks at, the one mistake almost everyone makes first,
why the capability ceiling is the part that matters, and what a change
to a coding agent's configuration gives that agent.

`controlloop example` prints the short version of this page in your
terminal.

Everything below is real recorded output. Nothing is illustrative.

## Build a tiny agent

Any directory will do. Create `agent-card.json`:

```json
{
  "protocolVersion": "0.2",
  "name": "invoice-agent",
  "description": "Reads invoices and emails customers about them.",
  "skills": [
    {"id": "read-invoice", "name": "read-invoice", "description": "Look up an invoice."},
    {"id": "email-customer", "name": "email-customer", "description": "Send an invoice email."}
  ]
}
```

### Where an agent card comes from in a real project

You will almost never write one of these by hand. This walkthrough does
because it needs a repository that provably contains an agent, in a
directory you can create in ten seconds — but that is a teaching
fixture, not step one of adoption.

In a real project the card is already there, because something else put
it there:

| File | Written by | Why it exists |
| --- | --- | --- |
| `.well-known/agent-card.json` | your A2A server | The protocol requires it, so other agents can discover you |
| `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json` | your editor or MCP client | Written when you added an MCP server |
| an OpenAPI document | your API tooling | Your service contract, already committed |
| AWS IAM JSON, Terraform `.tf` | your infrastructure code | Your existing least-privilege setup |
| a CrewAI crew, a LangGraph graph, an OpenAI Agents SDK module | **you, as ordinary application code** | ControlLoop reads the framework itself |

ControlLoop reads all of them. For most teams the realistic first scan
is `controlloop init` in a repository that already has `.mcp.json` and a
Terraform directory — no new file authored at all.

**And if you build on a framework, you may need no card at all.**
ControlLoop reads [CrewAI](../reference/crewai-support.md),
[LangGraph](../reference/langgraph-support.md), and the
[OpenAI Agents SDK](../reference/openai-agents-support.md) directly —
agents, delegation, and tool wiring, from the code you already wrote.
That is the most common answer to "where does my agent card come from":
you don't have one, and you don't need one.

The worked example of that is the [reference
agent](../reference/reference-agent.md): a running agent whose every
capability declaration is backed by code, with its own scan walkthrough.

## 1. See what discovery found

```bash
controlloop bom ./demo-agent -o acbom.json
```

Three nodes, two edges: the agent, its two skills, and an `invokes` edge
to each. That is the **ACBOM** — the capability graph.

Nothing was executed to produce it. ControlLoop never runs your code,
never starts an MCP server, and never contacts a declared endpoint. It
reads files.

## 2. Scan it, and read the result carefully

```bash
controlloop scan ./demo-agent
```

```
• no material capability is reachable

✓ PASSED
```

**This is the moment to slow down.** That looks like a clean bill of
health. It is not. It means *ControlLoop could not classify anything* —
not that there is nothing to worry about.

Discovery can read a card and see a skill called `email-customer`. It
cannot know that emailing a customer sends data outside your trust
boundary. Nothing in a repository says so, and ControlLoop
[deliberately does not guess from names](../reference/material-capability-taxonomy.md).

## 3. Tell it what your tools actually do

Create `controlloop.yaml`:

```yaml
schema_version: "1.1.0"
owner: billing-eng

tool_capabilities:
  - tool: read-invoice
    read_only: true
    sensitivity: confidential
  - tool: email-customer
    external_communication: true
    read_only: false

logged_tools:
  - tool: read-invoice
    audit_path: logs/invoice-read.log
  - tool: email-customer
    audit_path: logs/customer-email.log
```

Scan again:

```bash
controlloop scan ./demo-agent
```

```
! WORST REACHABLE  external-communication: invoice-agent can invoke
  email-customer
```

That first line is the **blast-radius statement**: the single worst
thing this agent can do, stated before any list of findings. It is the
line you forward to your manager.

`tool` matches the **discovered node name**, not the skill id. Run
`controlloop bom` and read the names if you are unsure. See the
[manifest schema](../reference/manifest-schema.md#declaring-what-a-tool-does-tool_capabilities).

> `logged_tools` entries are here because declaring a tool privileged
> makes `policy.missing-action-logging` require an audit path for it.

## 4. Expand the agent's authority

Now add a third skill — `void-invoice`, which reverses charges — and
declare it `destructive` and `financial_action`. Then run the CI form:

```bash
controlloop gate ./demo-agent --evidence-path evidence.json
```

```
! WORST REACHABLE  destructive-action: invoice-agent can invoke void-invoice

✓ PASSED
```

Exit `0`.

**Read that twice.** The agent just gained the ability to reverse
charges. The blast radius correctly got worse —
`external-communication` became `destructive-action`. And it still
passed.

That is not a bug. You never said what this agent is *not allowed* to
do. Pattern rules catch what somebody anticipated; nobody anticipated
your invoice agent.

> `policy.destructive-or-financial-action` would have caught this as a
> *newly gained* capability, but it is diff-aware and needs a baseline —
> a committed `.controlloop/baseline.json` or real git history. This
> throwaway directory has neither. In a real repository in CI, you get
> that check for free.

## 5. Declare a ceiling

Append to `controlloop.yaml`:

```yaml
ceilings:
  - agent: invoice-agent
    prohibited_resources:
      - void-invoice
```

```bash
controlloop gate ./demo-agent --evidence-path evidence.json
```

```
! WORST REACHABLE  destructive-action: invoice-agent can invoke void-invoice

✕ DEPLOYMENT BLOCKED
```

Exit `1`.

No rule matched a pattern here. The ceiling blocked it because you
declared a boundary and the agent crossed it. That is the whole product
in one command — see the
[capability ceiling guide](capability-ceiling-guide.md).

A ceiling breach also **cannot be suppressed**, which is enforced
structurally rather than by convention.

> Name the tool exactly as discovery found it. A
> ceiling can name a tool whose discovered name contains spaces, such as
> `Void an invoice` — this walkthrough uses `void-invoice` because that
> is what its agent card declares.

## 6. Give a coding agent new power

The steps above are about an agent you build. Most repositories now also
configure the coding agents that work *on* them -- Claude Code, Codex,
Cursor, and others -- and those files grant authority too. This step uses
the committed examples in
[`examples/agent-config/`](../../examples/agent-config/README.md).

Start from the careful version, commit it, then make the change a pull
request would: a `SessionStart` hook, `Bash(*)`, two new MCP servers, a
skill and a subagent that grant themselves more, Codex set to never ask,
and a review workflow with a write token. Two of those -- an audit hook
and the team's own `tickets` server -- were reviewed and are approved in
`controlloop.yaml`. From the root of a checkout of this repository:

```bash
mkdir my-agent && cd my-agent && git init -b main
cp -R ../examples/agent-config/baseline/. .
git add -A && git commit -m "baseline"
git switch -c widen
find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -R ../examples/agent-config/head/. .
git add -A && git commit -m "widen"
cd .. && controlloop gate ./my-agent --default-branch main
```

The git history is the baseline: `gate` compares the branch with its
merge base. Real output, recorded on 2026-10-17:

```text
! WORST REACHABLE  code-execution: Claude Code can reach allow Bash(git push:*)
  via permitted-by (2-hop chain); without asking, since Codex, subagent reviewer
  are in a bypass mode; also from over-privileged workflow agent-review
    1. invokes ->
      clp:tool:sha256:e84ca4572bdcd2535ef996779f6df40ff7b3697378ea87fa98e2ec79eb83f76d
    2. permitted-by ->
      clp:permission:sha256:b5168b4facc1539c558cccf2b001998d60d10ccb00a084aa5b43cd37e7d40dc6

✕ DEPLOYMENT BLOCKED

Authority:
  • This change gives Claude Code the power to use `Edit` without asking (a
    wildcard) through subagent `reviewer` (`.claude/agents/reviewer.md`, rule
    `Edit`). No approval is recorded.
  • This change gives Claude Code the power to run subagent `reviewer` with
    fewer confirmations: permissionMode moved to 'bypassPermissions'
    (`.claude/agents/reviewer.md`, subagent `reviewer`). No approval is
    recorded.
  • This change gives Claude Code the power to run `./scripts/audit-command.sh`
    before every `Bash` tool call (`.claude/settings.json`, hook `PreToolUse`).
    Approval recorded.
  • This change gives Claude Code the power to run `node .github/setup.js` on
    every session start (`.claude/settings.json`, hook `SessionStart`). No
    approval is recorded.
  • This change gives Claude Code the power to use `Bash(*)` without asking (a
    wildcard) (`.claude/settings.json`, rule `Bash(*)`). No approval is
    recorded.
  • This change gives Claude Code the power to use `Bash(git push:*)` without
    asking (a wildcard) through skill `release-notes`
    (`.claude/skills/release-notes/SKILL.md`, rule `Bash(git push:*)`). No
    approval is recorded.
  • This change gives Claude Code the power to load skill `release-notes`, which
    may use `Read,Grep,Bash(git push:*)` without asking
    (`.claude/skills/release-notes/SKILL.md`, skill `release-notes`). No
    approval is recorded.
  • This change gives Claude Code the power to run in GitHub Actions workflow
    `agent-review` with write access to contents, pull-requests, skipping every
    permission prompt (`.github/workflows/agent-review.yml`, job `review`). No
    approval is recorded.
  • This change gives Claude Code the power to start MCP server `browser` by
    running `npx -y @example/browser-mcp@latest` (`.mcp.json`, server
    `browser`). No approval is recorded.
  • This change gives Claude Code the power to connect to MCP server `tickets`
    at `mcp.tickets.example` (`.mcp.json`, server `tickets`). Approval recorded.
  • This change gives Codex the power to act with fewer confirmations:
    'approval_policy' moved from 'on-request' to 'never' (`.codex/config.toml`,
    setting `approval_policy`). No approval is recorded.

• GAINED  code-execution: Claude Code reaches allow Bash(git push:*) via
  permitted-by (2-hop chain)
• GAINED  external-communication: Claude Code invokes tickets
• GAINED  code-execution: Claude Code invokes browser
• GAINED  code-execution: Claude Code invokes SessionStart command hook
• GAINED  code-execution: Claude Code invokes PreToolUse command hook (Bash)

✕ HIGH     policy.agent-hook-command-change: Added: Hook on event 'SessionStart'
  for host 'Claude Code' runs `node .github/setup.js`.
    at .claude/settings.json

! MEDIUM   policy.mcp-server-identity-change: Server 'browser' is new; it
  launches @example/browser-mcp@latest.
    at .mcp.json

✕ HIGH     policy.widened-permission-rule: Allow rule for 'Claude Code' widened
  from 'Bash(npm test)' to 'Bash(*)'.
    at .claude/settings.json

✕ HIGH     policy.component-self-grant: Subagent reviewer runs in
  bypassPermissions mode, which the host does not.
    at .claude/agents/reviewer.md

• INFO     policy.agent-hook-command-change: Added: Hook on event 'PreToolUse'
  for host 'Claude Code' runs `./scripts/audit-command.sh`. Approval recorded by
  platform-team.
    at .claude/settings.json

! MEDIUM   policy.component-self-grant: Subagent reviewer allows 'Edit', which
  the host's allow set does not grant.
    at .claude/agents/reviewer.md

✕ HIGH     policy.overprivileged-agent-workflow: Job 'agent-review / review'
  holds contents: write, pull-requests: write and skips permission prompts.
    at .github/workflows/agent-review.yml

• INFO     policy.mcp-server-identity-change: Server 'tickets' is new; it
  launches a remote endpoint. Approval recorded by platform-team.
    at .mcp.json

✕ HIGH     policy.permission-bypass-from-project: Codex: 'approval_policy' moved
  from 'on-request' to 'never'.
    at .codex/config.toml

Suppressions: none declared

Completeness enforcement: warn (default)
Evidence: evidence.json
```

Exit `1`.

**Read the `Authority:` section first.** Each line is one new power, the
agent that gets it, and the file and key that granted it. The audit hook
and the `tickets` server end "Approval recorded." and their findings are
kept at `INFO` with the approver's name, so they do not block. The
unapproved `SessionStart` hook is the shape the Miasma worm and Mini
Shai-Hulud used: a command that runs on every machine that opens the
repository. A change that grants nothing prints no `Authority:` section
at all.

See [the authority statement](../reference/authority-statement.md) for
every kind of grant it describes, and
[what a passing gate does not guarantee](../reference/agent-authority-limits.md).

## Reading the output

| Line | Means |
| --- | --- |
| `! WORST REACHABLE …` | The worst capability reachable right now |
| `• no material capability is reachable` | Nothing was **classified** — usually a missing `tool_capabilities` |
| `✓ PASSED` | Nothing blocking |
| `! PASSED WITH WARNINGS` | Findings below the blocking threshold |
| `! REVIEW REQUIRED` | Analysis incomplete, enforcement set to fail (exit `3`) |
| `✕ DEPLOYMENT BLOCKED` | A blocking finding (exit `1`) |
| `• material change: not evaluated` | No baseline comparison was possible — not "nothing changed" |
| `Authority:` | What this change gives a coding agent, one sentence per grant; absent when it grants nothing |

Exit codes: `0` pass · `1` blocking finding · `2` invalid input ·
`3` incomplete analysis · `5` internal error. Full detail in the
[CLI reference](../reference/cli.md) and the
[terminal report format](../reference/terminal-report-format.md).

## What to do next

- `controlloop rules` — every rule in the pack and what it looks for.
- `controlloop init` — draft a `controlloop.yaml` for a real repository.
- [`examples/agent-config/`](../../examples/agent-config/README.md) — the
  configurations from step 6, with the rule each difference trips.
- The [reference agent](../reference/reference-agent.md) — a realistic,
  deliberately imperfect agent with scenarios you can run.
- The [GitHub Action](../reference/github-action.md) — put `gate` in CI.

## The two things worth remembering

1. **`no material capability is reachable` is not a pass.** It means
   nothing was classified. Declare `tool_capabilities`.
2. **Pattern rules catch anticipated risk; the ceiling catches the
   rest.** Step 4 passed and step 5 blocked, on identical code.
