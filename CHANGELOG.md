# Changelog

All notable changes to the ControlLoop CLI are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
