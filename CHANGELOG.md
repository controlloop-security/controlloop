# Changelog

All notable changes to the ControlLoop CLI are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **The Action's description fits GitHub Marketplace.** `action.yml`'s
  `description` was about 630 characters, and Marketplace refuses one of
  125 or more. It now reads "Block pull requests that widen what an AI
  agent can do, from agent configs, MCP servers and framework code." The
  `fetch-depth: 0` and pinning notes move to a comment in `action.yml`;
  [The ControlLoop GitHub Action](docs/reference/github-action.md) already
  documents both.

## [0.6.0] - 2026-10-30

Team uploads name their branch, and CrewAI agents built in code are
discovered. The rule pack is unchanged at `0.9.0`.

### Changed

- **Team uploads name their branch without `team_branch`.** When
  `team_branch` is unset, the envelope's `branch` comes from the CI's
  branch variable. The variables are `GITHUB_HEAD_REF`, `GITHUB_REF_NAME`,
  `CI_COMMIT_REF_NAME`, `BITBUCKET_BRANCH`, and Azure DevOps'
  `SYSTEM_PULLREQUEST_SOURCEBRANCH` and `BUILD_SOURCEBRANCH`. If none of
  them is set, the branch checked out in git is used. Tag builds and a
  detached `HEAD` send no branch. `team_branch` still wins when it is set.

### Added

- **CrewAI agents built in code.** A crew with no `config/agents.yaml`
  is now discovered: any module that imports `crewai` is parsed, and each
  `Agent(...)` with no `config=` becomes an agent named by its `role`.
  Its identity is its `@agent` method, then its variable, then its role.
  Its tools resolve as a YAML agent's do. A list built at runtime is an
  `INCOMPLETE-DYNAMIC-REGISTRATION`, so
  `policy.unresolved-dynamic-registration` now fires for these agents as
  it does for the OpenAI Agents SDK. `allow_delegation=True` reaches the
  module's other agents. The rule pack is unchanged.

## [0.5.0] - 2026-10-30

Rule pack `0.9.0`: the adapter work behind three gaps the limits page
named, and one new rule.

### Added

- **`policy.hook-script-changed`, 24 rules in total.** A hook, helper
  command, skill shell line, or plugin `bin/` directory whose command
  names a script committed in the repository now records `script_path`
  and `script_digest` (SHA-256 of the file, never its content), from the
  Claude Code, Codex, Gemini CLI, Cursor, and Kiro adapters. The new rule
  reports the script changing while the command does not: `high`, or
  `medium` when a readable script becomes `unknown`. A change to the
  command too is left to `policy.agent-hook-command-change`, so one change
  gives one finding; a first scan is silent. Not mandatory. A script
  outside the repository records `unknown` and an informational
  `SCRIPT-OUTSIDE-REPOSITORY` diagnostic, which does not mark the analysis
  incomplete.
- **Roo Code custom modes.** `RooModesAdapter` reads `.roomodes` (YAML or
  JSON) at the repository root: each mode is a subagent under the Roo Code
  host, and each tool group (`read`, `edit` with its `fileRegex`,
  `browser`, `command`, `mcp`) an allow rule, so
  `policy.widened-permission-rule` reports a mode that gains `command` or
  an `edit` group that loses its `fileRegex`. Prompt text is never read.
  `controlloop --version` lists `roo-code 2026-10-29`.

### Changed

- **Codex writable roots are covered by `policy.workspace-scope-expansion`
  (1.1.0).** The Codex adapter now records each
  `sandbox_workspace_write.writable_roots` entry as a directory the host
  may write, an outside path only as `<outside-repository>`, so a root
  outside the repository added `high`, one inside `low`, and an outside one
  on a first scan `low`, as for Claude Code's `additionalDirectories`.
- **Tool lists built at runtime are reported as findings.** The CrewAI,
  LangGraph, and OpenAI Agents SDK adapters emit
  `INCOMPLETE-DYNAMIC-REGISTRATION` for a comprehension, call, splat,
  conditional, a list the module builds with a loop or appends to, and
  `agent.tools.append`/`extend` after construction, and link it to the
  unknown tool node by line. `policy.unresolved-dynamic-registration` now
  reports a `medium` finding naming the file and the agent where it
  previously could only fire on hand-built input. A bare name the adapter
  did not follow is still `INCOMPLETE-UNRESOLVED-REFERENCE`.
- Reports and gate results show `controlloop-community` `0.9.0` with a new
  fingerprint. The ACBOM schema stays `1.2.0`: the new attributes use the
  existing `attributes` map.

## [0.4.0] - 2026-10-29

Rule pack `0.8.0`: five rules for coding-agent configuration the
adapters already record.

### Added

- **Rule pack `0.8.0`: five coding-agent rules, 23 in total.** Each
  reads attributes the adapters already record; no adapter changed.
  - `policy.agent-sandbox-weakened`: a change that turns off a coding
    agent's sandbox, lets commands run outside it, auto-approves commands
    because of it, or opens its network egress (Claude Code `sandbox`
    settings, Codex and Gemini CLI network access, Gemini CLI
    `tools.sandbox`, Cursor `egressMode`). Loosened `high`; a setting
    already at the loose end on a first scan `low`.
  - `policy.secret-exposed-to-untrusted-agent-run`: a workflow job that
    runs a coding agent on untrusted input and is given a repository
    secret, named but never read. Added or newly exposed `high`; first
    scan `medium`.
  - `policy.credentialed-remote-mcp-server`: an HTTP or SSE MCP server
    whose declaration sends a credential-named header or variable to its
    host. Host changed `high`; added, or a credential name added,
    `medium`; first scan `low`.
  - `policy.workspace-scope-expansion`: a Claude Code
    `additionalDirectories` entry outside the repository. Added `high`;
    an inside directory added, or an outside one on a first scan, `low`.
  - `policy.component-shell-execution`: a skill shell line or a plugin
    `bin/` directory added or changed. `high`; removed `info`; first
    scan `low`, once per skill or plugin.

  The new rules are not mandatory. Reports and gate results show
  `controlloop-community` `0.8.0` with a new fingerprint.

### Changed

- **Two findings move to the new rules.** Claude Code's
  `sandbox.enabled` turned off was reported by
  `policy.permission-bypass-from-project`; it is now
  `policy.agent-sandbox-weakened` (`permission-bypass-from-project`
  1.1.0). A skill shell line or plugin `bin/` directory was reported by
  `policy.agent-hook-command-change` as a "Setting 'skill-shell'" or
  "Setting 'plugin-bin'" finding; it is now
  `policy.component-shell-execution` (`agent-hook-command-change`
  1.1.0). Severities are unchanged. A suppression of one of those older
  findings reports `stale`; suppress the new finding's `id` instead.

## [0.3.0] - 2026-10-29

A Team gate now does what each rule's organization action says.

### Added

- **The Team gate honors each rule's organization `action`.** On a Team
  gate, a finding's effect on the verdict comes from its rule's `action`
  in the organization's policy, whatever the finding's severity or
  confidence:
  - `fail` blocks (`deployment_blocked`, exit `1`).
  - `require_review` gives `review_required` (exit `3`) unless something
    else blocks.
  - `warn` reports without blocking.
  - `pass` reports and never affects the verdict.

  A rule with no `action` keeps the severity-against-`severity_threshold`
  behavior, so bundles without actions gate as before. An action this CLI
  does not recognize is enforced as `fail`. Organization exceptions and
  repository suppressions still apply first. Community gates are
  unchanged.
- **A finding an organization action decided says so.** In `gate` text
  output it takes the action's glyph and a closing line such as
  ``organization action `warn`: reported, does not block``.
- **Evidence records each finding's action** (evidence schema `1.6.0`).
  Each `team.effective_policy` rule records its `action` when it has one.
  `team.finding_actions` records, for every finding, the action the gate
  took and what decided it: the organization's rule (`organization`) or
  the severity threshold (`severity_threshold`). Both fields are left out
  when empty.

### Changed

- **Merge semantics `1.2.0`: a rule's `action` merges strengthen-only.**
  Actions are ordered `pass` < `warn` < `require_review` < `fail`. A
  repository may raise a rule's action but never lower it. A lowering is
  refused and reported like a lowered severity floor. An organization
  rule with no action counts as `fail`. The platform contract's
  `policy-merge-vectors.json` gains six `action` cases.

### Fixed

- **An excepted finding looked like a blocking one.** In `gate` text
  output, a finding covered by an applied organization exception keeps
  its severity but takes the neutral `•` glyph and a closing line,
  `organization exception until YYYY-MM-DD; does not affect the verdict`,
  instead of printing as `✕ HIGH`.
- **The Homebrew formula passes `brew audit --strict`.** It no longer
  repeats the version Homebrew already reads from the release URL.

## [0.2.0] - 2026-10-23

A container image on GHCR and a Homebrew formula are published from this
release on, alongside PyPI and the standalone binaries.

### Added

- **Declare where an agent's input comes from.** `controlloop.yaml`
  (manifest schema `1.3.0`) gains `external_inputs`: each entry names a
  discovered agent and an external source it accepts input from. It
  becomes a `trigger` node and a `receives-from` edge in the ACBOM,
  marked untrusted, which is the untrusted-input leg the
  exfiltration-triangle rule reads. The declaration is authoritative.
  `1.2.0` manifests still load unchanged.
- **An A2A card's `url` is read as an inferred input.** The agent
  `receives-from` a `trigger` node named for the host, marked
  `untrusted_input: "unknown"` at low confidence: the card says the
  agent accepts requests, not who sends them.

### Changed

- **Rule pack `0.7.0`: `policy.exfiltration-triangle` is `1.1.0`.** A
  declared input confirms the leg; an inferred one leaves it unknown,
  and with the other two legs present that is reported at `medium`
  (below the default gate threshold) naming what was inferred and how to
  confirm or rule it out, instead of silence. A confirmed edge always
  outranks an inferred one. The pack has the same 18 rules; reports and
  gate results now show `controlloop-community` `0.7.0` with a new
  fingerprint.

- **A container image.** The release pipeline publishes
  `ghcr.io/controlloop-security/controlloop:<version>` for linux/amd64 and
  linux/arm64, built from the repository's `Dockerfile`: non-root, no
  build toolchain, pinned base image, no network request when it runs.
  Before pushing, the image is smoke-tested with networking disabled and
  scanned for known vulnerabilities; a critical finding blocks
  publication. Images are tagged by exact version only and attested with
  GitHub build provenance. See `docs/reference/container-image.md`.
- **A Homebrew formula.** The release pipeline writes
  `Formula/controlloop.rb` to the `controlloop-security/controlloop` tap
  from the release's own checksums (`release-scripts/homebrew_formula.py`),
  installing the published standalone binary on macOS (Apple Silicon) and
  Linux. See `docs/reference/homebrew.md`.
- **Getting-started documentation for a released CLI.** `Installation`
  now covers every install path (PyPI with uv or pipx, the shell
  installer, a standalone binary by hand, Homebrew, the container image,
  from source) with the command that installs it and the command that
  verifies it. `Quickstart: your first scan` scans the public reference
  agent and reads the result line by line, and a new `Quickstart: your
  first CI gate` adds the gate to a repository and shows it blocking a
  real change. The release pages no longer say that no release has been
  published: v0.1.1 was, on 2026-10-20.
- **The Team gate names each organization exception it applies.** A gate
  that passes only because an exception covers a finding now prints
  `• organization exception applied to <rule> (<fingerprint>) until
  <date>; that finding does not block` (diagnostic
  `CLI-TEAM-EXCEPTION-APPLIED`). The evidence file already recorded it.

### Changed

- **Rule pack `0.6.0`: the fingerprint covers rule logic.** It now hashes
  each rule's whole module and the shared rule helpers, not only the
  one-line `evaluate` wrapper, so a change to what a rule detects moves the
  fingerprint and needs a new pack version. The pack has the same rules
  as `0.5.0`; the only behavior change is the hardcoded-secret finding IDs
  listed under Fixed. Reports and gate results now show
  `controlloop-community` `0.6.0` with a new fingerprint.

### Fixed

- **One suppression could silence several secrets.** Two hardcoded
  secrets in the same file shared one finding ID, even an AWS key and a
  Stripe key, so a suppression of one also suppressed the other. Each
  `policy.hardcoded-secrets` finding's identity now includes its
  credential kind and its ordinal among detections of that kind in the
  file, never a line number or any part of the value. **Existing
  suppressions of `policy.hardcoded-secrets` findings report `stale`:**
  copy the new ID from `scan --format json`. No other rule's finding IDs
  change.
- **`bom --validate` accepted an edited ACBOM.** It now recomputes the
  document's `digest` and exits `2` when it does not match the content.
  `diff` applies the same check to each ACBOM file it compares.
- **`bom --validate` crashed on a schema violation.** A document the
  schema rejects (for example an unknown node `type`) ended with
  `INTERNAL ERROR` and exit `5`. It now exits `2` with one line naming
  the first error's location, such as `nodes.0.type`.
- **Suppressed findings looked like blocking ones.** In `scan` and
  `gate` text output, a finding an active suppression covers keeps its
  severity but takes the neutral `•` glyph and a closing line,
  `suppressed until YYYY-MM-DD; does not affect the verdict`.

## [0.1.1] - 2026-10-19

The first public release of the ControlLoop CLI, published to PyPI as
`controlloop`. Version `0.1.0` on PyPI only reserved the name and is not a
release.

### Fixed

- **`gate --default-branch` on a pull request.** A bare branch name such
  as `main` that does not exist locally is now also tried as
  `origin/main`. A pull-request checkout in GitHub Actions has the target
  branch only as a remote-tracking ref, so the Action's own default
  (`$GITHUB_BASE_REF`) failed with exit `2` on every pull request.

### Changed

- **One repository walk per scan.** `scan`, `bom`, `diff`, and `gate`
  walk the repository once per scan instead of once per discovery
  adapter. Every adapter now reads one cached file list from
  `ScanContext.repository_files()`, and `bom`'s own walk seeds it when it
  used the default bounds adapters have always seen. On the
  100,000-line benchmark repository a scan goes from 1.84 s to 1.35 s
  wall clock with byte-identical output. Adapters still walk with
  default bounds, as before.

### Added

- **Commands:** `scan`, `gate`, `diff`, `bom`, `init`, `rules`, and
  `example`. `scan` is the human report; `gate` is the CI form, with one
  verdict, one exit code, and an evidence artifact on every run.
- **The Agent Capability Bill of Materials (ACBOM):** one graph of an
  agent's agents, tools, resources, identities, and permissions, with
  evidence for every node and edge, a content digest, and a CycloneDX 1.6
  projection.
- **Adapters** for A2A agent cards, MCP server declarations in eleven agent
  hosts, OpenAPI 3.x, AWS IAM (JSON and Terraform), CrewAI, LangGraph, the
  OpenAI Agents SDK, Claude Code (settings, hooks, skills, subagents,
  plugins, and marketplaces), Codex, Gemini CLI, Cursor, Kiro, and GitHub
  workflows that run a coding agent. Framework code is parsed, never
  imported or executed.
- **A capability diff** against a committed baseline or the merge-base of
  the default branch, reported as capabilities rather than files.
- **The blast-radius statement:** the single worst thing an agent can
  reach, first in every report.
- **The authority statement:** a plain-language sentence for every grant a
  change adds to an agent's configuration, such as "This change gives
  Claude Code the power to run `node .github/setup.js` on every session
  start".
- **18 policy rules** (rule pack `controlloop-community 0.5.0`), a
  capability ceiling that cannot be suppressed, expiring repository
  suppressions, and JSON and SARIF 2.1.0 output.
- **A GitHub Action** that gates pull requests, uploads SARIF, writes a
  check summary, and keeps one pull-request comment with the authority
  statement current; and a **pre-commit hook**.
- **The Team client** for the ControlLoop platform: organization policy
  bundles with strengthen-only merge, exceptions, an approved-components
  list, and a sanitized scan envelope. Off by default; with
  `team_enabled = false` the CLI makes no network request.
