# Changelog

All notable changes to the ControlLoop CLI are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
