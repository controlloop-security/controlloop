---
type: reference
title: Configuration loading and precedence
tags:
  - reference
  - configuration
  - cli
created: 2026-08-19
---

# Configuration loading and precedence

**Status: Implemented foundation.** `controlloop --show-config` is a real,
tested command-line option. The four repository-walker keys it resolves are
consumed by `bom`'s, `init`'s, `diff`'s (in its repository-plus-baseline
usage form), `scan`'s, and `gate`'s own repository walk; `scan` and `gate`
additionally resolve the policy keys below for rule evaluation -- see
"Known limitations" below for the full breakdown. This page documents what
`--show-config` does today, not a broader configuration system.

## Precedence order

Every configuration key resolves through exactly four tiers, lowest to
highest precedence:

1. **Default.** A conservative, documented built-in value.
2. **Repository file.** `controlloop.toml` at the repository root (an
   explicit path if given to the resolver, otherwise the nearest enclosing
   `.git` ancestor, otherwise the current directory -- the same resolution
   `resolve_repository_root` already uses for every other repository-relative
   concern).
3. **Environment.** A `CONTROLLOOP_<KEY>` environment variable, uppercased.
4. **Flag.** An explicit command-line option.

A higher tier overrides a lower one only for the specific key it supplies;
keys the higher tier does not mention keep resolving from whichever lower
tier last set them. `controlloop --show-config` prints, for every key, both
the winning value and which of the four tiers supplied it.

## Configuration keys

The original key set was the repository walker's already-approved resource
bounds (`TraversalBounds`, part of repository discovery). [Severity,
confidence, and thresholds](policy-thresholds.md) extended
this same loading mechanism with three policy keys, and [Incomplete-analysis
policy](policy-thresholds.md#completeness-enforcement) added a fourth. Every key resolves through the identical
four-tier precedence order above -- this table names each key's
repository-file/environment name, its CLI flag if one exists, and its
default.

**Generated.** Rendered directly from
`controlloop.config._KEY_SPECS`, the single source of truth both this
page and `tests/test_cli_reference_doc.py` read from -- see
`tests/reference/cli_doc_fixtures.py`'s `render_config_key_table`.
Regenerate with `python tests/reference/cli_doc_fixtures.py` after
adding or changing a configuration key.

<!-- BEGIN GENERATED: configuration-keys -->
| Key | Repository file / environment name | Flag | Default |
| --- | --- | --- | ---: |
| `max_file_size_bytes` | `max_file_size_bytes` / `CONTROLLOOP_MAX_FILE_SIZE_BYTES` | `--max-file-size-bytes` | `10000000` |
| `max_total_bytes` | `max_total_bytes` / `CONTROLLOOP_MAX_TOTAL_BYTES` | `--max-total-bytes` | `500000000` |
| `max_file_count` | `max_file_count` / `CONTROLLOOP_MAX_FILE_COUNT` | `--max-file-count` | `50000` |
| `max_depth` | `max_depth` / `CONTROLLOOP_MAX_DEPTH` | `--max-depth` | `100` |
| `severity_threshold` | `severity_threshold` / `CONTROLLOOP_SEVERITY_THRESHOLD` | none yet | `high` |
| `low_confidence_action` | `low_confidence_action` / `CONTROLLOOP_LOW_CONFIDENCE_ACTION` | none yet | `block` |
| `disabled_rules` | `disabled_rules` / `CONTROLLOOP_DISABLED_RULES` | none yet | (empty) |
| `completeness_enforcement` | `completeness_enforcement` / `CONTROLLOOP_COMPLETENESS_ENFORCEMENT` | none yet | `warn` |
| `team_enabled` | `team_enabled` / `CONTROLLOOP_TEAM_ENABLED` | none yet | `false` |
| `team_fail_mode` | `team_fail_mode` / `CONTROLLOOP_TEAM_FAIL_MODE` | none yet | `closed` |
| `team_endpoint` | `team_endpoint` / `CONTROLLOOP_TEAM_ENDPOINT` | none yet | (none) |
| `team_organization_id` | `team_organization_id` / `CONTROLLOOP_TEAM_ORGANIZATION_ID` | none yet | (none) |
| `team_project_id` | `team_project_id` / `CONTROLLOOP_TEAM_PROJECT_ID` | none yet | (none) |
| `team_branch` | `team_branch` / `CONTROLLOOP_TEAM_BRANCH` | none yet | (none) |
| `team_pull_request` | `team_pull_request` / `CONTROLLOOP_TEAM_PULL_REQUEST` | none yet | (none) |
| `team_policy_cache_seconds` | `team_policy_cache_seconds` / `CONTROLLOOP_TEAM_POLICY_CACHE_SECONDS` | none yet | `300` |
<!-- END GENERATED: configuration-keys -->

Every integer key's value must be an integer of at least `1`; a boolean is
not accepted even though TOML and Python both treat `true`/`false` as
integer-like. `severity_threshold` must be one of `info`, `low`, `medium`,
`high`, `critical`; `low_confidence_action` must be one of `block`, `warn`;
`disabled_rules` is an array of rule-ID strings in `controlloop.toml`
(`disabled_rules = ["policy.rule-a", "policy.rule-b"]`) or a comma-separated
list in its environment variable; `completeness_enforcement` must be one of
`warn`, `enforce`. No CLI flag exists for any of the four policy keys yet --
`gate` consumes `completeness_enforcement`; `severity_threshold`,
`low_confidence_action`, and `disabled_rules` are consumed by both `scan`
and `gate` (see "Known limitations" below).

`severity_threshold` defaulting to `high` and `low_confidence_action`
defaulting to `block` are disclosed, overridable engineering starting
points, not an approved business SLA or pricing-adjacent threshold -- see
[Severity, confidence, and thresholds](policy-thresholds.md) for the full
rationale. `completeness_enforcement` defaults to `warn` for the identical
reason: a first run must never be a wall.

## Team keys

Eight keys configure the paid Team tier.
Every one of them defaults to Team being off, so a repository that never
configures them resolves exactly as it did before these keys existed, and
`gate` makes no network request at all.

> **Want Team for your organization?** [get in touch](https://controlloop.ai/#get-started) and you will
> receive the values these keys take. See
> [Your first Team gate](../guides/first-team-gate.md).

| Key | What it does |
| --- | --- |
| `team_enabled` | Turns Team behavior on. `false` by default. |
| `team_endpoint` | Your platform's base URL. Required when Team is on; no default, because ControlLoop does not pick a domain for you. |
| `team_organization_id` | Your organization's UUID. |
| `team_project_id` | This repository's project UUID. |
| `team_fail_mode` | `closed` (default) or `open` — what a gate does when the platform is unreachable. |
| `team_policy_cache_seconds` | How long a fetched organization policy bundle stays fresh. `300` by default. |
| `team_branch` | Branch name recorded on the uploaded scan. Optional: when unset, the CLI reads the CI's branch variable, then the branch checked out in git. See [Where the branch comes from](team-envelope.md#where-the-branch-comes-from). |
| `team_pull_request` | Pull-request number recorded on the uploaded scan. Optional. |

### The project token is not a configuration key

`CONTROLLOOP_TEAM_TOKEN` is read directly from the environment and is
deliberately **not** part of the key registry above. Every registered key
is printed verbatim by `controlloop --show-config`, so a credential in the
registry would be a credential printed on demand. The token is never
written to `controlloop.toml`, never rendered, never included in an error
message, and never recorded in the evidence artifact.

Set it as a CI secret:

```bash
export CONTROLLOOP_TEAM_TOKEN="<project token>"
```

### Enablement is explicit, never inferred

ControlLoop does not conclude "Team is on" from the presence of a token.
A `CONTROLLOOP_TEAM_TOKEN` inherited from another job in the same CI
runner would otherwise silently change what your gate enforces.
Enablement is a decision recorded in your repository, in your commit
history.

### Endpoint rules

`team_endpoint` must use `https`. Plain `http` is accepted only for a
loopback host (`localhost`, `127.0.0.1`, `::1`), so you can run against a
local platform stack in development without terminating TLS. Any other
`http` endpoint is refused rather than downgraded silently — a project
token sent in clear text is a compromised token.

A trailing slash is normalized away, so `https://example/` and
`https://example` produce identical request URLs and therefore identical
ingestion idempotency.

### Misconfiguration is exit 2, naming the key

A missing token, a malformed endpoint, a non-UUID identifier, or a
non-numeric pull-request number each fail with exit code `2` and a message
naming the specific key or environment variable — never a stack trace, and
never the rejected value:

```bash
$ uv run controlloop gate
✕ INVALID CONFIG  team_endpoint must use https; http is permitted only for a loopback host, because a project token sent in clear text is a compromised token
$ echo $?
2
```

These checks run only when `team_enabled` is `true`. A repository that
disabled Team but left a half-finished endpoint behind still runs
normally, rather than failing a build over a setting nothing reads.

## `controlloop.toml`

An optional TOML file at the repository root. Only the keys above are
recognized; every key is optional; an absent file is equivalent to
supplying none of them (see "No configuration is required" below).

```toml
# controlloop.toml
max_depth = 50
max_file_count = 20000
```

## Using `--show-config`

```bash
uv run controlloop --show-config
```

```text
completeness_enforcement = warn  (default)
disabled_rules =   (default)
low_confidence_action = block  (default)
max_depth = 100  (default)
max_file_count = 50000  (default)
max_file_size_bytes = 10000000  (default)
max_total_bytes = 500000000  (default)
severity_threshold = high  (default)
team_branch =   (default)
team_enabled = false  (default)
team_endpoint =   (default)
team_fail_mode = closed  (default)
team_organization_id =   (default)
team_policy_cache_seconds = 300  (default)
team_project_id =   (default)
team_pull_request =   (default)
```

Note what is absent from that output: `CONTROLLOOP_TEAM_TOKEN`. It is not
a registered key, so `--show-config` cannot print it. That is the reason
it is not one.

A nonempty `disabled_rules` value renders as a comma-joined list, for
example `disabled_rules = policy.rule-a,policy.rule-b  (repository file)`.

Lines are sorted by key name and always follow the form
`<key> = <value>  (<source>)`, where `<source>` is one of `default`,
`repository file`, `environment`, or `flag`. The four override flags
(`--max-file-size-bytes`, `--max-total-bytes`, `--max-file-count`,
`--max-depth`) can be combined with `--show-config` to preview what a flag
override would resolve to without needing a real scan to pass it to.

## No configuration is required

`controlloop --show-config` succeeds with no `controlloop.toml`, no
`CONTROLLOOP_*` environment variables, and no override flags -- every key
resolves from its documented default. A first run never needs a
configuration file.

## Hard errors

Two conditions are hard errors, exit `2`, never a silently ignored or
partially applied value:

- **An unknown key in `controlloop.toml`.** The error names both the
  offending key and the file path. For example, a file containing
  `retry_limit = 3` (not a key ControlLoop implements) fails with a message
  naming `retry_limit` and the file -- it is never silently dropped.
- **A `controlloop.toml` that fails to parse.** The error reports a parse
  location (line and column, from the TOML parser's own structural error)
  and the file path. It never reproduces the surrounding file content, so a
  parse error cannot leak anything else the file happens to contain.

A non-integer value (from the file or the environment) and a value that
fails the `>= 1` bound are also rejected, each naming only the offending
key or environment variable, never the raw value supplied.

```bash
$ echo 'not_a_real_key = 1' > controlloop.toml
$ uv run controlloop --show-config
✕ INVALID CONFIG  unknown configuration key 'not_a_real_key' in /path/to/controlloop.toml
$ echo $?
2
```

## Known limitations

- `bom`, `init`, `diff` (repository-plus-baseline usage form), `scan`, and
  `gate` all consume the resolved configuration for their own repository
  walk. `scan` and `gate` additionally resolve `severity_threshold`,
  `low_confidence_action`, and `disabled_rules` for policy evaluation (see
  [Severity, confidence, and thresholds](policy-thresholds.md)); `gate`
  alone additionally resolves `completeness_enforcement`
  -- `scan` deliberately keeps its own separate, prior, unconditional
  incomplete-analysis behavior, a disclosed asymmetry, not an oversight
  (see [Severity, confidence, and
  thresholds](policy-thresholds.md#completeness-enforcement)).
- No CLI flag exists yet for any of the four policy keys
  (`severity_threshold`, `low_confidence_action`, `disabled_rules`,
  `completeness_enforcement`) -- only `controlloop.toml` and their
  environment variables resolve them today. The same is true of the eight
  Team keys, deliberately: they configure a repository's relationship with
  its organization, which belongs in a commit rather than in one
  invocation's argument list.
- Only `gate` reads the Team keys. `scan`, `diff`, `bom`, and `init` are
  Community commands and remain so with Team enabled.
- There is no `--config`/`--config-file` override to point at a repository
  file outside the resolved repository root.

## Next step

Review [CLI reference](cli.md) for the complete current option surface,
[Severity, confidence, and thresholds](policy-thresholds.md) for what the
three new policy keys actually do once resolved, or [Privacy, security, and
limitations](privacy-security.md) for what `--show-config` does and does
not read or transmit.
