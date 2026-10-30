---
type: guide
title: What a Team gate sends, and what it never sends
tags:
  - reference
  - platform
  - privacy
created: 2026-09-02
---

# Exactly what leaves your machine

ControlLoop is a local-first scanner. Turning on Team adds one thing:
after a gate reaches a verdict, it sends a **scan envelope** to your
organization's ControlLoop platform.

This page enumerates that envelope, field by field. It is the honest
answer to the question a security team asks before approving a tool that
reads their source code: *what does it upload?*

> **Availability:** Implemented in the CLI. Community scanning sends
> nothing and needs no network — with `team_enabled` at its default of
> `false`, the CLI makes no request at all.

## The short answer

Findings and component metadata that ControlLoop itself derived, plus the
commit they describe. **No source code. No prompt text. No environment
values. No secrets. No file contents.**

## The envelope, field by field

| Field | What it holds | Where it comes from |
| --- | --- | --- |
| `envelope_version` | The envelope schema version | A constant in the CLI |
| `commit_sha` | The 40-character commit being gated | `git rev-parse HEAD` |
| `branch` | Branch name, when one is known | `team_branch`, else the CI or git — see [Where the branch comes from](#where-the-branch-comes-from) |
| `pull_request_number` | PR number, if you configured one | `team_pull_request` |
| `scanner_version` | Which ControlLoop produced this | The installed version |
| `policy_version` | Which rule pack was applied | The rule pack |
| `acbom_digest` | Digest of the capability graph | Computed locally |
| `verdict` | `pass`, `warn`, `require_review`, or `fail` | The gate |
| `findings` | Normalized findings — see below | Policy evaluation |
| `components` | Normalized agents, tools, MCP servers, resources, identities, and (1.1.0) agent authority components | The ACBOM |
| `repository_policy` | Your repository's own policy, as a delta | `disabled_rules` |
| `authority_delta` | 1.1.0 only: what the change lets an agent do — see [Envelope 1.1.0](#envelope-110-agent-authority) | The authority statement |

### Where the branch comes from

The first of these that names a branch is sent:

1. `team_branch` (or `CONTROLLOOP_TEAM_BRANCH`), when set. It always wins.
2. The CI's branch variable, in this order:
   - `GITHUB_HEAD_REF`, the source branch of a GitHub pull request.
   - `GITHUB_REF_NAME`, unless `GITHUB_REF_TYPE` is `tag`.
   - `CI_COMMIT_REF_NAME` on GitLab, unless `CI_COMMIT_TAG` is set.
   - `BITBUCKET_BRANCH`.
   - On Azure DevOps, `SYSTEM_PULLREQUEST_SOURCEBRANCH`, then
     `BUILD_SOURCEBRANCH`, when either is a `refs/heads/` ref. The CLI
     doesn't use `BUILD_SOURCEBRANCHNAME` because it keeps only the last
     path segment, so `feature/login` would arrive as `login`.
3. The branch checked out in git (`git symbolic-ref --short HEAD`).

A detached `HEAD` with none of these sends no `branch` at all, never a
guess. A detected name longer than 255 characters, the most the platform
stores, is also dropped. The branch name is the only value the envelope
takes from these variables.

### Inside one finding

| Field | What it holds |
| --- | --- |
| `fingerprint` | The finding's stable ID — a digest over semantic identity |
| `rule_id`, `rule_version` | Which rule fired, and its version |
| `severity`, `confidence` | The rule's assessment |
| `title` | The finding's own message, the same line the terminal prints |
| `capability_path` | Node IDs along the path from agent to target |
| `evidence_reference` | A repository-relative path and line number, e.g. `agent.json:14` |

`evidence_reference` is the field people ask about, so to be explicit: it
is a **path and a line number**, never the text at that line. The CLI's
internal evidence model has no field for evidence text in the first place,
so there is nothing of that kind for the envelope to carry.

### Inside one component

`stable_id`, `type` (one of `agent`, `tool`, `mcp_server`, `resource`,
`identity`), and a normalized `name`. In 1.1.0, agent authority
components and MCP servers also carry `attributes` and `flags`; see
[Envelope 1.1.0](#envelope-110-agent-authority).

## What is never sent

- **Source code**, in any field.
- **Prompt bodies** — system prompts, instructions, templates.
- **Environment values** — nothing read from the environment except the
  configuration keys documented in
  [Configuration](configuration.md#team-keys), and the project token,
  which is sent as an `Authorization` header and never as payload.
- **Secret values.** ControlLoop's `hardcoded-secrets` rule reports *that*
  a secret-shaped value exists at a path and line. The value itself never
  enters a finding, and so never enters an envelope.
- **File contents**, including the files a finding points at.
- **Your organization or project identifiers in the evidence artifact.**
  They are in the request URL, because that is how the request is
  addressed, but the retainable evidence file on disk records the policy
  *version*, not your tenant's identifiers.

This is enforced by construction, not by review: every field above is
copied from an already-sanitized value, the envelope models refuse fields
they do not declare, and `tests/team/test_envelope.py` plants token,
private-key, prompt, environment-value, and source-code canaries in a
scan and asserts none of them reaches a fingerprint, a capability path, or
an evidence reference.

## Two places the envelope is narrower than the ACBOM

**Confidence.** ControlLoop tracks four levels (`high`, `medium`, `low`,
`unknown`); the platform contract has three. `unknown` is sent as `low` —
the weakest claim available, so an unknown confidence is never *overstated*
into something a dashboard ranks higher than the evidence supports.

**Component types.** The contract has five component types. ControlLoop's
graph has eight node types. The four with no equivalent — `permission`,
`data-class`, `trigger`, and `policy-boundary` — are **omitted** from
`components` rather than relabelled as something they are not. They still
participate fully in local policy evaluation and still appear in your
ACBOM; what your fleet inventory does not receive is a row claiming a
permission is a tool.

## Envelope 1.1.0: agent authority

> **Availability:** The platform accepts envelope 1.1.0, and the Team gate
> sends it.

**When 1.1.0 is sent.** The gate sends 1.1.0 when the scan holds an agent
authority component, an MCP server, or an authority delta. Any other scan
is sent as 1.0.0, byte for byte as before. An MCP server alone is enough,
because an approved-component entry can constrain one by its package,
version, digest, and pin, and only 1.1.0 can carry those.

Version 1.1.0 adds four things, all optional and all subject to the same
prohibited-content checks as the rest of the envelope:

- **Agent authority component types.** Nine kinds, one per subtype the
  ACBOM 1.2.0 contract defines: `host`, `subagent`, `hook`,
  `helper_command`, `plugin`, `marketplace`, `skill`, `workflow_runtime`,
  and `permission_rule`. A Claude Code hook is a `hook` component rather
  than an omitted node.
- **Component `attributes`.** The component's value-free security
  attributes, as the ACBOM records them: at most 32 keys of lowercase
  letters, digits, and underscores, values of 1 to 512 characters. A key
  that names a value category (`token`, `secret`, `password`,
  `credential`, `api_key`, `private_key`, `env_value`) is refused, whatever
  its value. Approved-component constraints read the keys `package`,
  `version`, `digest`, and `command`. The key `host_id`, the stable id of
  the agent host that holds the component, places it under that host in
  the authority view.
- **Component `flags`.** `code_execution`, `bypass_mode`, `wildcard`,
  `pinned`, and `untrusted_input`, each true, false, or null. Null means
  the scanner could not tell, never "no".
- **`authority_delta`.** One entry per new, changed, or removed grant of
  authority to an agent, against the repository's baseline, at most 200.
  Absent when nothing changed.

| Field | What it holds |
| --- | --- |
| `host_id`, `host_name` | The agent host, e.g. `Claude Code`. `host_id` is null when the scanner could not attribute the grant to a host; the platform then shows no host rather than guessing one |
| `kind` | `added`, `changed`, or `removed` |
| `grant` | The component kind that carries the grant, e.g. `hook` |
| `material_class` | The scanner's material capability class, e.g. `code-execution` |
| `statement` | The scanner's plain-language statement, at most 300 characters. Literals the scanner wraps in single backticks, such as a command, are shown as code in the dashboard and the pull request comment; nothing else in it is interpreted |
| `detail` | A short grant label, e.g. `hook SessionStart`, at most 120 characters |
| `evidence_path`, `key_path` | The repository-relative file and the key within it |
| `approval_recorded` | Whether the repository's manifest records an approval |
| `confidence` | `low`, `medium`, or `high` |
| `component_stable_id` | Optional: the component in `components` that carries the grant, so the grant is shown with that component's sanction state |

**What the CLI puts in them.**

- **Components.** Each agent authority component and MCP server is sent
  with the same type, name, attributes, and flags the gate judges the
  sanctioned list by. A hook is named by its event, such as
  `SessionStart`. The only attributes sent are `package`, `version`,
  `digest`, `command` (where recorded), and `host_id`. Every value was
  already redacted and bounded by the adapter that recorded it, so a
  token in a command arrives as `<redacted>`. A value over 512 characters
  is left out rather than cut, so it meets no constraint, locally or on
  the platform. Agents, tools, resources, and identities keep the 1.0.0
  shape.
- **The authority delta.** Each entry the gate's authority statement
  holds is sent, up to the first 200 in its own order. Removed grants are
  not in the statement, so they are not sent. `component_stable_id`
  always names the component. A bypass-mode change is a `host` grant for
  the host, or a `subagent` grant for the subagent. Text longer than a
  limit is cut to the limit and ends in `…`.
- **Approvals.** The contract's `approval_recorded` is true or false.
  When no manifest could be read, the CLI sends `false`, and the statement
  says approvals were not evaluated.

This is one hook added on a branch, as the gate sends it (the host's id
shortened):

```json
{
  "components": [
    {
      "stable_id": "clp:tool:sha256:a729851d262a8cef7a8fa28604f62876ce77cc03acf29edf8b531d4c5764f011",
      "type": "hook",
      "name": "SessionStart",
      "attributes": {
        "command": "node .github/setup.js --token=<redacted>",
        "host_id": "clp:agent:sha256:31c6551c…"
      },
      "flags": {
        "bypass_mode": null,
        "code_execution": true,
        "pinned": null,
        "untrusted_input": null,
        "wildcard": null
      }
    }
  ],
  "authority_delta": [
    {
      "approval_recorded": false,
      "component_stable_id": "clp:tool:sha256:a729851d262a8cef7a8fa28604f62876ce77cc03acf29edf8b531d4c5764f011",
      "confidence": "high",
      "detail": "hook `SessionStart`",
      "evidence_path": ".claude/settings.json",
      "grant": "hook",
      "host_id": "clp:agent:sha256:31c6551c…",
      "host_name": "Claude Code",
      "key_path": "hooks.SessionStart[0].hooks[0]",
      "kind": "added",
      "material_class": "code-execution",
      "statement": "This change gives Claude Code the power to run `node .github/setup.js --token=<redacted>` on every session start (`.claude/settings.json`, hook `SessionStart`). No approval is recorded."
    }
  ]
}
```

`tests/team/test_envelope_authority.py` checks the rendered bytes
against `ScanEnvelopeRequest` in the platform's contract and against
the attribute rules in the platform's serializer. It also plants a token
in a hook command, an MCP argument, and both `env` blocks, and a prompt
in a subagent, then asserts none of them reaches the bytes.

A field inside an entry that the schema does not declare is refused, as
at the top level. **A version describes a shape:** a 1.0.0 envelope that
carries any of these additions is refused rather than read.

**What the platform keeps.** Each component's attributes and flags are
recorded in your fleet index, so approved-component constraints can be
matched against them, including again after you publish a new policy.
Each `authority_delta` entry is stored with the scan, its commit, and its
pull request, and is listed per project through
`project_authority_changes_list`
(`GET /api/v1/organizations/{organization_id}/projects/{project_id}/authority-changes`),
filtered by `pull_request_number` or `scan_id`. Each listed grant carries
the sanction state of the component it names, or null when it names none.

**On the pull request.** For a pull-request scan, the Team check run and
the single ControlLoop comment lead with a "What this pull request lets
an agent do" section: one line per grant, with the verdict
(`✓ Sanctioned`, `✕ Unsanctioned`, `• Unevaluated`, `• Sanction not
determined`, or `− Removed`) first, then the scanner's statement, the
file and key, the grant label, and whether an approval is recorded. At
most 20 grants are listed, followed by "and N more", and the section
links to the authority view. Text from the repository is escaped so it
cannot add links or mention anyone. When a scan records no authority
delta, the comment is exactly what it was before.

## What the repository policy delta contains

Only your disabled rules. ControlLoop's other policy settings —
`severity_threshold`, `low_confidence_action`, `completeness_enforcement`
— are gate-wide thresholds rather than per-rule configuration, and the
platform contract has no field for them. Rather than coerce them into a
shape that does not fit and have the server compute an effective policy
that misdescribes what you asked for, they are not sent.

The consequence is worth stating plainly: the effective policy the
platform records reflects your organization bundle and your disabled
rules, not your severity threshold. Your local verdict applies the
threshold; the recorded effective policy does not name it.

## Idempotency

Ingestion is idempotent on (project, commit, ACBOM digest). Re-running a
gate on the same commit sends byte-identical bytes and the platform
returns the original scan rather than creating a second one — the CLI
reports that as a replay rather than presenting it as a fresh scan.

## When an envelope cannot be sent

Two cases produce a reported skip rather than an upload, and **neither
changes the gate verdict**:

- **No resolvable commit.** A directory that is not a git checkout with at
  least one commit has no commit to attribute a scan to.
- **A verdict of `not_evaluated`.** A run that evaluated no policy has no
  result to record.

Upload failures — an unreachable platform, a rejected token — are
reported the same way, on standard error, leaving the exit code alone. A
gate's answer is decided by local policy evaluation; whether a report of
that answer reached a server is a separate fact.

## Next step

[Your first Team gate](../guides/first-team-gate.md) walks through
enabling this end to end. [Configuration](configuration.md) documents
every key and its precedence.
