---
type: guide
title: Your first Team gate
tags:
  - guide
  - platform
created: 2026-09-02
---

# Your first Team gate

Community ControlLoop gates a repository against policy that repository
carries. Team adds one thing: policy your **organization** carries, applied
the same deterministic way, with approvals your organization has recorded.

This guide turns it on for one repository.

> **Want Team for your organization?** Team is set up directly with each
> organization; [get in touch](https://controlloop.ai/#get-started) and you will receive the endpoint and token used
> below. Nothing here changes Community behavior: with `team_enabled` at its
> default of `false`, the CLI makes no network request and needs no account.

## What changes when Team is on

| | Community | Team |
| --- | --- | --- |
| Policy | Your repository's | Your organization's, merged with your repository's |
| Approvals | `controlloop.yaml` suppressions | Those, plus organization exceptions |
| Entitlement | None | Checked before the gate reports a paid verdict |
| After the verdict | Evidence written locally | Evidence written locally, plus a sanitized envelope uploaded |
| Network | Never | Four requests, all to your configured endpoint |

Local scanning is never degraded. An unreachable platform cannot stop a
Community gate, because a Community gate never asks it anything.

## 1. Enable Team in the repository

`controlloop.toml`, committed:

```toml
team_enabled = true
team_organization_id = "11111111-1111-4111-8111-111111111111"
team_project_id = "22222222-2222-4222-8222-222222222222"
```

Enablement lives in the repository, not the environment, on purpose. A
token inherited from another job in the same CI runner must not be able to
silently switch what your gate enforces — so ControlLoop never infers
"Team is on" from the presence of a credential.

## 2. Supply the endpoint and token from CI

These are environment variables, not file keys. The token is a credential;
the endpoint belongs to your deployment.

```bash
export CONTROLLOOP_TEAM_ENDPOINT="https://controlloop.your-company.example"
export CONTROLLOOP_TEAM_TOKEN="<project token>"
```

In GitHub Actions:

```yaml
env:
  CONTROLLOOP_TEAM_ENDPOINT: https://controlloop.your-company.example
  CONTROLLOOP_TEAM_TOKEN: ${{ secrets.CONTROLLOOP_TEAM_TOKEN }}
```

The token is **never** written to a configuration file, never printed by
`controlloop --show-config`, and never appears in an error message or in
the evidence artifact. `https` is required; plain `http` is accepted only
for a loopback host, so you can run against a local stack in development.

## 3. Run the gate

```bash
uv run controlloop gate
```

Nothing about the command changes. What changes is what happens around it:

1. **Entitlement is verified** before any paid behavior runs.
2. **Your organization's policy bundle is fetched** and merged with your
   repository's policy, strengthen-only — see
   [How organization and repository policy combine](../reference/policy-merge-semantics.md).
3. **Active exceptions are fetched** and honored by exact finding
   fingerprint, if they have not expired.
4. **The gate evaluates** and writes evidence, exactly as before, with the
   organization's contribution recorded in it.
5. **A sanitized envelope is uploaded** — see
   [What a Team gate sends](../reference/team-envelope.md).

## 4. Read what it tells you

Team adds diagnostic lines on standard error. Standard output — the report
and the exit code your CI reads — keeps the same contract it always had.

```text
ℹ Team entitlement confirmed.
! Repository policy disables `capability.new-tool`, which organization policy
  version 7 marks mandatory. Repository policy may tighten a mandatory rule but
  never disable it.
! organization exception for clp:finding:sha256:… expired on 2026-08-30; the
  finding it covered is blocking again
ℹ Team upload accepted as scan 9f2c….
```

Each of those is worth understanding:

- **A rejected policy change** means your `controlloop.toml` asked for
  something your organization forbids. The gate is enforcing the
  *stronger* policy, so the run is correct — your configuration is what
  needs fixing.
- **An expired exception** is the one most likely to surprise you: a build
  that passed yesterday fails today with no code change, because an
  approval lapsed. ControlLoop says so, with the date, on the run that
  breaks.

## 5. Approve agent components

> **Availability:** Implemented in the CLI, and proven on a real repository
> by the reference scenarios. An approved list is a Team capability: a
> Community gate never loads the rule, never reads a list, and scans exactly
> as before.

Your organization's policy bundle can list the agent components it has
approved: MCP servers, hooks, plugins, marketplaces, skills, subagents,
permission rules, and the rest of the agent authority kinds. The gate
judges every grant a pull request **adds or changes** against that list,
exactly as the platform flags components. A grant already in the
repository is not re-judged on every pull request.

### An example bundle

This is a bundle as an admin creates it, using every constraint an entry
can carry. It is committed as
[`examples/approved-components-bundle.json`](examples/approved-components-bundle.json),
and a test checks it against the platform contract and the gate's parser.

```json
{
  "rules": [
    {
      "rule_id": "policy.unsanctioned-agent-component",
      "enabled": true,
      "severity_floor": "medium",
      "mandatory": true
    }
  ],
  "approved_components": [
    {
      "type": "mcp_server",
      "name_pattern": "catalog-docs",
      "package": "@widgetworks-example/catalog-docs-mcp",
      "version_range": "1.4.x",
      "note": "Product docs search; patch releases only."
    },
    {
      "type": "mcp_server",
      "name_pattern": "catalog-search",
      "package": "@widgetworks-example/catalog-search-mcp",
      "version_range": ">=2.1.0 <2.2.0",
      "digest": "sha256:5143fff499ec",
      "note": "Pinned to the declaration the security team reviewed."
    },
    {
      "type": "mcp_server",
      "name_pattern": "web-fetch",
      "package": "@widgetworks-example/web-fetch-mcp",
      "version_range": "1.x"
    },
    {
      "type": "hook",
      "name_pattern": "PostToolUse",
      "command_pattern": "npx prettier *"
    },
    {
      "type": "marketplace",
      "name_pattern": "widgetworks-*",
      "pin_required": true
    }
  ],
  "publish": false
}
```

| Constraint | Holds when |
| --- | --- |
| `package` | The component is installed from exactly that package |
| `version_range` | Its version is inside the range: exact (`1.4.2`), wildcard (`1.4.x`, `1.x`), or bounded (`>=2.1.0 <2.2.0`) |
| `digest` | Its declaration digest starts with this `sha256:` prefix |
| `command_pattern` | A hook's command matches, exactly or by the prefix before a trailing `*` |
| `pin_required` | It is pinned to an exact version or commit |

A constraint the gate cannot show is met is not met. A missing version is
inside no range, and an unknown pin is not a pin.

### The three outcomes

These are real runs of `controlloop gate` on the reference repository's
storefront (`controlloop-security/controlloop-reference-agent`), judged by the
bundle above as published version `12`. On `main`, the storefront already
runs `catalog-docs`, a Prettier hook, and a pinned marketplace. Each pull
request adds MCP servers. The excerpts start at the verdict.

**A sanctioned grant passes.** `scenario/team-sanctioned-grant` adds
`catalog-search`. Its package, version, and declaration digest meet the
entry, so there is no sanction finding, and the verdict is unchanged.
Exit `0`.

```text
✓ PASSED

Authority:
  • This change gives Claude Code the power to start MCP server `catalog-search`
    by running `npx -y @widgetworks-example/catalog-search-mcp@2.1.0`
    (`.mcp.json`, server `catalog-search`). No approval is recorded.

• GAINED  code-execution: Claude Code invokes catalog-search

! MEDIUM   policy.mcp-server-identity-change: Server 'catalog-search' is new; it
  launches @widgetworks-example/catalog-search-mcp@2.1.0.
    at .mcp.json
```

**An unsanctioned grant requires review.**
`scenario/team-unsanctioned-grant` also adds `web-fetch`, which runs
`@webfetch-tools/web-fetch-mcp`: a different package under a name the
bundle approves only for `@widgetworks-example/web-fetch-mcp`. Exit `3`,
which fails the check until someone reviews it:

```text
! REVIEW REQUIRED

Authority:
  • This change gives Claude Code the power to start MCP server `catalog-search`
    by running `npx -y @widgetworks-example/catalog-search-mcp@2.1.0`
    (`.mcp.json`, server `catalog-search`). No approval is recorded.
  • This change gives Claude Code the power to start MCP server `web-fetch` by
    running `npx -y @webfetch-tools/web-fetch-mcp@0.3.1` (`.mcp.json`, server
    `web-fetch`). No approval is recorded.

• GAINED  code-execution: Claude Code invokes catalog-search
• GAINED  code-execution: Claude Code invokes web-fetch

! MEDIUM   policy.unsanctioned-agent-component: The mcp_server `web-fetch` is
  not approved by organization policy version 12: its package is not the
  approved package (constraint `package`).
    at .mcp.json
```

The evidence artifact records the list it applied, its digest, and how
each grant was judged, with the version that judged it:

```json
{
  "organization_bundle_version": "12",
  "approved_components_digest": "sha256:27804315d199a565188678133ce4812bfdf74ca46d7dfcbb3a48390f4a77e3ae",
  "sanction_note": null,
  "sanction_judgments": [
    {
      "component_stable_id": "clp:tool:sha256:210314ce044e6a2c8a8694af8a084821694dafe38702f3dbae2065bada36a60b",
      "component_type": "mcp_server",
      "component_name": "catalog-search",
      "state": "sanctioned",
      "failed_constraint": null,
      "judged_by_policy_version": "12"
    },
    {
      "component_stable_id": "clp:tool:sha256:72960cf7ffe4853bba2b05b282cfe181028675324f5aa18975780771b69a1a57",
      "component_type": "mcp_server",
      "component_name": "web-fetch",
      "state": "unsanctioned",
      "failed_constraint": "package",
      "judged_by_policy_version": "12"
    }
  ]
}
```

Review required is the default. An organization that wants
an unsanctioned grant to block outright raises the rule's
`severity_floor` to `high` in its bundle, and the verdict becomes
**Deployment blocked** (exit `1`). An organization exception clears one
finding by its fingerprint. A repository's own `controlloop.yaml` approval
does not.

**No published bundle judges nothing.**
`scenario/team-no-published-bundle` makes the same change for an
organization that has never published a bundle. There is no sanction
finding and the verdict passes, exit `0`. The evidence does not imply an
approval:

```json
{
  "organization_bundle_version": "",
  "sanction_note": "unevaluated: no published organization policy bundle governs this project, so no agent-authority grant was judged against an approved list. This is not an approval.",
  "sanction_judgments": [
    {
      "component_stable_id": "clp:tool:sha256:210314ce044e6a2c8a8694af8a084821694dafe38702f3dbae2065bada36a60b",
      "component_type": "mcp_server",
      "component_name": "catalog-search",
      "state": "unevaluated",
      "failed_constraint": null,
      "judged_by_policy_version": ""
    },
    {
      "component_stable_id": "clp:tool:sha256:72960cf7ffe4853bba2b05b282cfe181028675324f5aa18975780771b69a1a57",
      "component_type": "mcp_server",
      "component_name": "web-fetch",
      "state": "unevaluated",
      "failed_constraint": null,
      "judged_by_policy_version": ""
    }
  ]
}
```

### How the reference scenarios run without a platform

The scenarios are public and run with no platform behind them, so each
scenario branch commits the bundle in the
gate's own policy cache, `.controlloop/team-cache/policy.json`. Its
`controlloop.toml` points at a loopback port nothing listens on, with
`team_fail_mode = "open"`. The gate says so on standard error, before the
report:

```text
• TEAM STATUS  The entitlement service could not be reached after the bounded retry window. team_fail_mode is 'open', so the gate continued without a verified entitlement.
• TEAM STATUS  The organization policy bundle could not be refreshed; using the cached copy stored at 2026-10-18T00:00:00+00:00.
• TEAM UPLOAD  Team upload failed: the platform endpoint could not be reached after the bounded retry window. The gate verdict is unaffected.
```

Its evidence records `policy_source: stale_cache` and
`entitlement_state: unreachable`. ControlLoop's scheduled
reference-scenario workflow runs all three branches through the published
Action and asserts every value shown here. Your own repository keeps a
reachable endpoint, and usually the default `closed` fail mode, described
next.

## What happens when the platform is down

This is a decision you make, in advance, in your repository:

```toml
team_fail_mode = "closed"   # the default
```

`closed` stops the gate rather than reporting a verdict it could not
verify. `open` continues and says on standard error that it did so.

The default is `closed`, and it is the uncomfortable choice on purpose: a
control that stops being enforced whenever the service enforcing it is
unreachable is a control an attacker removes by making it unreachable.
Choosing `open` is legitimate — many teams would rather ship during an
outage — but it should be a decision in your commit history, not a default
someone inherited.

Between those, ControlLoop softens the outage where it safely can: the
organization policy bundle is cached (`team_policy_cache_seconds`,
default 300), and a short outage is usually served from cache with no
change in behavior at all. A cached bundle used *past* its lifetime is
recorded in evidence as `stale_cache`, so a verdict decided against
day-old policy is distinguishable later from one decided against current
policy.

## Exit codes

Team adds one reachable exit code, and one more way to reach `3`:

| Code | Meaning |
| --- | --- |
| `3` | Review required: the pull request adds an agent-authority grant your organization has not approved, and its bundle leaves the rule at the default require-review |
| `4` | Not entitled, token rejected, or platform unreachable under `team_fail_mode = "closed"` |

Every other exit code keeps its Community meaning. A Community gate never
returns `4` — see [CLI reference](../reference/cli.md#exit-codes).

## Turning it off

```toml
team_enabled = false
```

The next run makes no network request, checks no entitlement, and produces
byte-identical output to a build of ControlLoop that had never heard of the
paid tier.

## Next step

[What a Team gate sends](../reference/team-envelope.md) enumerates the
upload field by field. [Configuration](../reference/configuration.md)
documents every key and its precedence.
