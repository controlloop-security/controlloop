# Example agent configurations

Two versions of one small project's coding-agent configuration, for
reproducing an authority diff on your own machine. `baseline/` is what a
careful team starts with. `head/` is the same project after a pull
request that hands its agents a lot of new power, two pieces of which the
team has reviewed and approved in `controlloop.yaml`.

Nothing here runs. ControlLoop reads these files and never executes them,
and no script a hook names exists in this directory.

## Try it

From the root of a checkout of this repository:

```bash
mkdir my-agent && cd my-agent && git init -b main
cp -R ../examples/agent-config/baseline/. .
git add -A && git commit -m "baseline"
git switch -c widen
find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -R ../examples/agent-config/head/. .
git add -A && git commit -m "widen"
cd .. && controlloop gate ./my-agent --default-branch main
rm -rf my-agent evidence.json
```

The git history is the baseline: `gate` compares the branch with its
merge base on `main`. (A committed `.controlloop/baseline.json` compares
effective authority only and produces no authority statement.)

`gate` exits `1`, **Deployment blocked**. The full recorded output is in
the [example walkthrough](../../docs/guides/example-walkthrough.md#6-give-a-coding-agent-new-power),
and `expected.json` records the verdict, every finding, and every
authority statement; `tests/test_agent_config_examples.py` checks
they still hold.

## What each difference trips

| File | `baseline/` | `head/` | Rule | Severity |
| --- | --- | --- | --- | --- |
| `.claude/settings.json` | a Prettier hook after edits | adds a `SessionStart` hook running `node .github/setup.js` | `policy.agent-hook-command-change` | high |
| `.claude/settings.json` | | adds a `PreToolUse` audit hook, **approved** | `policy.agent-hook-command-change` | info (approved) |
| `.claude/settings.json` | `Bash(npm test)` | `Bash(*)` | `policy.widened-permission-rule` | high |
| `.mcp.json` | `docs`, pinned to `2026.1.14` | adds `browser`, on `@latest` | `policy.mcp-server-identity-change` | medium |
| `.mcp.json` | | adds `tickets`, a remote server, **approved** | `policy.mcp-server-identity-change` | info (approved) |
| `.claude/skills/release-notes/SKILL.md` | `Read, Grep` | adds `Bash(git push:*)` | authority statement only | — |
| `.claude/agents/reviewer.md` | `Read, Grep, Glob` | adds `Edit` and `permissionMode: bypassPermissions` | `policy.component-self-grant` | high (bypass), medium (`Edit`) |
| `.codex/config.toml` | `approval_policy = "on-request"` | `"never"` | `policy.permission-bypass-from-project` | high |
| `.github/workflows/agent-review.yml` | a read-only token | `contents: write`, `pull-requests: write`, and `--dangerously-skip-permissions` | `policy.overprivileged-agent-workflow` | high |

Each change also gets one sentence in the authority statement, for
example:

```text
This change gives Claude Code the power to run `node .github/setup.js` on
every session start (`.claude/settings.json`, hook `SessionStart`). No
approval is recorded.
```

The two approved changes end "Approval recorded." instead, and their
findings are kept at `info` with the approver's name, so they do not
block. Everything else does.

These are examples, not tests of the rules: the rules' own tests, the
adapter conformance fixtures, and the benign corpus live under
`tests/`.
