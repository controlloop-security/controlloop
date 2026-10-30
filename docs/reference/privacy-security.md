---
type: guide
title: Privacy, security, and limitations
tags:
  - privacy
  - security
  - limitations
created: 2026-08-14
---

# Privacy, security, and limitations

ControlLoop is designed to help teams examine agent authority without handing
their repository to a scanning service. Privacy, deterministic decisions, and
honest uncertainty are product boundaries, not optional presentation choices.

This page distinguishes safeguards in the current foundation from behavior
that must still be implemented and verified.

## Current development preview

The current `controlloop` command supports `--help`, `--version`,
`--show-config`, `init`, `bom`, `diff`, `scan`, and `gate`.

`--help`, `--version`, and `--show-config`:

- do not traverse or read a selected repository's source, prompts, or
  credentials;
- do not contact a ControlLoop cloud service;
- do not emit telemetry; and
- do not produce an ACBOM, diagnostic, finding, or gate result.

`bom`, `init`, and `diff` are different: all three traverse the repository
using the same discovery (`diff` only in its repository-plus-baseline usage
form; its two-ACBOM-file form reads two already-generated files instead).
`bom` writes a real canonical ACBOM to standard output or `--output` -- see
[`bom`](cli.md#bom) in the CLI reference. `init` writes (or, with
`--dry-run`, prints) a draft `controlloop.yaml` manifest built from that
same discovery, with every field it could not determine marked `TODO` --
see [`init`](cli.md#init). `diff` compares two ACBOMs, or a repository
against a resolved baseline, and reports node/edge/effective-capability
changes -- see [`diff`](cli.md#diff). None of the three contacts a
ControlLoop cloud service or emits telemetry, and none evaluates policy or
produces a finding or gate result. `bom --validate` only checks an existing
ACBOM file against the published schema; it never generates or prints a
document. `init` never reads, overwrites, or modifies an existing
`controlloop.yaml`; it reports the conflict and exits `2` instead. `diff`
never writes or commits a baseline.

`--show-config` (see [Configuration loading and precedence](configuration.md)),
`bom`, `init`, and `diff` all load a ControlLoop configuration -- an
optional `controlloop.toml` at the resolved repository root, plus the
process environment and any override flags -- but only for four narrow,
already-approved repository-walker resource bounds. `bom`, `init`, and
`diff` (repository-plus-baseline form) consume the resolved configuration
for those same bounds; `scan` and `gate` also consume the resolved
configuration, additionally reading `severity_threshold`,
`low_confidence_action`, and `disabled_rules` -- and, for `gate`,
`completeness_enforcement` as well.

The canonical ACBOM code also enforces value-free, bounded fields for modeled
security attributes and sanitized repository-relative evidence paths. Its
identity boundary rejects field categories associated with source content,
credentials, passwords, secrets, tokens, private keys, and environment values.

These implemented model controls are one part of the scanner's overall
privacy posture, not the complete claim on their own.

## Redaction boundary

`controlloop.redaction` is the one module allowed to know what a secret, a
source line, or a full ACBOM document looks like well enough to keep it out
of anything the CLI writes. Every command dispatched through `main()` -- the
only entry point, covering `--help`, `--version`, `--show-config`,
`init` (generation and `--dry-run`), `bom` (generation and `--validate`),
`diff`, `scan`, `gate`, and every error Typer/Click render for an
unrecognized option or command -- runs with process stdout and stderr
wrapped by this boundary for the duration of the call. No emission API (`print`, `typer`/`click` echo, or a direct
`sys.stdout`/`sys.stderr` write) can opt out while it is installed, because
the wrapper is `sys.stdout`/`sys.stderr` itself during that call, not a
function individual call sites have to remember to use.

What it does today:

- Scans emitted text for a documented, signature-based (not entropy-based)
  baseline set of known credential shapes -- AWS access key IDs, GitHub
  tokens and fine-grained tokens, Slack tokens, Google API keys, Stripe
  secret keys, Anthropic API and Admin API keys (`sk-ant-api03-`,
  `sk-ant-admin01-`), OpenAI API keys (project, service-account, admin,
  and legacy user keys, recognized by their `sk-` prefix and OpenAI's
  `T3BlbkFJ` signature), PEM private-key blocks, and JSON Web Tokens --
  and replaces each match in full
  with a stable, non-reversible placeholder. The placeholder never retains a
  prefix, suffix, or partial fragment of the original value, and the same
  secret always produces the same placeholder so a reviewer can correlate
  occurrences without ever seeing the value.
- Provides `source_reference(path, line_start=None, line_end=None)` as the
  only sanctioned way to describe a source location in emitted text. The
  function has no parameter for the line's own content, so source text
  cannot be passed through it even by mistake.
- Provides `document_reference(digest)` and `acbom_document_reference(document)`
  as the only sanctioned way to describe an ACBOM document in emitted text.
  Both require a canonical `sha256:<hex>` digest -- never document content --
  and reject anything else, including a raw document body.
- Provides `scan_credential_shapes(text)` as the one
  sanctioned way for another module to ask "does this text contain
  something shaped like a known credential, and where" -- returning a
  shape name and character offsets only, never the matched substring.
  `controlloop.secret_scan` (a new, directly-invoked discovery pass, see
  [Concrete policy rules](policy-rules.md#hardcoded-secret-material))
  uses this to scan repository file content for hardcoded credentials
  during `bom` generation, reusing this module's pattern set rather than
  duplicating it, and reporting only a pattern/heuristic name, a
  location, and a confidence -- never the value -- on `ACBOMDocument.
  diagnostics`.

**Canary coverage today:** `tests/test_redaction.py`
has 20 canary tests, ending in a structural, CI-failing registry
(`TestCanaryCoverageRegistry`) that asserts every command the real Typer
app registers (`init`, `bom`, `diff`, `scan`, `gate`) has a real,
dedicated canary -- a new command shipped without a matching entry fails
that check, not just a stale claim on this page. `scan` and `gate` each
have their own real end-to-end canary, invoked through the real `main()`
boundary across every output format they support (`text`/`json`/`sarif`)
-- both formats now genuinely exist and are covered, not a future
promise. A comprehensive sweep (`TestComprehensiveExfiltrationSweep`)
additionally plants all four of a credential-shaped value, a
source-code-shaped line, a configuration-shaped value, and a real
environment-variable *value* (proving `McpServerAdapter` captures only
the declared variable name, per [Adapter status](../adapters/readme.md),
never the value) in one fixture, and searches every marker across
`scan`/`gate`'s every format and every `--log-level`, plus `bom`.

What it does not yet cover:

- Detection is limited to the documented baseline credential-shape set.
  Expanding it is a separate, deliberate change, the same rule that
  governs every other detection surface in this repository.
- This boundary covers the process's stdout and stderr, the CLI's only
  current output surface. `--log-level verbose`/`debug`'s optional operator
  diagnostic lines (see the
  [CLI reference](cli.md#verbosity-and-logging)) are ordinary stderr writes
  through `controlloop.output.OutputStreams`, so they pass through this same
  boundary automatically, including at `debug`, the level most likely to
  interpolate a repository-controlled value such as a path. Raising
  verbosity never changes what any command decides, only how much optional
  diagnostic detail reaches standard error.

## Offline enforcement

Every test in this repository's CLI test suite (`tests/`) runs with all
socket access denied by default, enforced by an autouse fixture in
`tests/conftest.py`. Everything implemented today -- ACBOM construction
and serialization, the redaction boundary, repository root resolution and
walking, configuration loading and precedence, `--help`/`--version`/
`--show-config` -- is core, local-first Community CLI behavior, so the whole
suite is the current scope of "core scanning never touches the network."

**Team integration does not weaken this**. The paid tier adds network calls, but they run only when a
repository sets `team_enabled = true`, and the harness was not exempted
to accommodate them. Instead the one place a value becomes a socket --
`controlloop.team.transport.UrllibTransport` -- sits behind a protocol,
is constructed only by `controlloop.cli`, and is replaced by a fake in
every test. A Team code path accidentally reached with Team disabled does
not produce a subtly different result; it raises
`NetworkAccessDeniedError` and fails the suite. See
[What a Team gate sends](team-envelope.md) for what an enabled gate
uploads, field by field.

What it does today:

- Denies socket construction and outbound connection attempts by replacing
  `socket.socket` and `socket.create_connection` for the duration of every
  test.
- Raises a dedicated `NetworkAccessDeniedError` rather than hanging,
  returning a dummy object, or silently degrading. It deliberately does not
  subclass `OSError`, so it cannot be swallowed by ordinary network- or
  file-error handling.
- Runs in this repository's CI on every pull request and every push to
  `main` (`.github/workflows/ci.yml`), because running the test suite there
  runs the autouse harness with it -- no separate offline-only job exists or
  is needed.
- Is proven directly by `tests/test_offline_harness.py`:
  `TestNetworkDenialRaisesLoudly` is the positive control proving a
  denied socket construction or connection attempt actually raises
  rather than hanging or silently degrading; `TestCoreSurfaceCompletesOffline`
  exercises every currently-implemented core path -- ACBOM construction,
  serialization, and digesting; the redaction boundary; repository root
  resolution and walking; and the CLI's `--version` path -- in one
  place, under the same autouse harness every other test in this suite
  already runs under.
- Is proven, individually and by name, for all five implemented core
  commands by `tests/test_offline_canary.py`'s
  `TestEveryCoreCommandCompletesOffline`: `init`, `bom`, `diff`, `scan`,
  and `gate` each get their own real invocation under the identical
  autouse harness. The same file's `TestDeliberateNetworkCallFailsImmediately`
  goes one step further than a positive control: it deliberately
  introduces a real network call into a real core function's own call
  graph (`controlloop.bom.build_acbom_document`'s call to
  `walk_repository`) and proves the harness catches it immediately --
  concrete evidence that "a newly introduced network call in a core
  path fails CI immediately" is not only claimed but demonstrated.

Standing rule for later work: any optional network behavior added to the
Community CLI must be opt-in through an explicit flag and off by default.
No such flag exists, because nothing in the Community CLI today has
optional network behavior to gate.

What it does not yet cover:

- The container image does not exist yet -- `docker/` has no
  Dockerfile or build asset today (`docker/README.md` states this
  directly) -- so there is no image to verify network-free
  independently of the installed package. `tests/
  test_offline_canary.py`'s `TestContainerImageOfflineVerification`
  records this gap as a real, visible skipped test naming the reason,
  rather than a silent omission.
- This is process-level socket denial for the CLI's own test run, not a
  sandboxed or containerized network-isolation boundary. Nothing in this
  repository currently needs one -- there is no database, queue, or other
  service to isolate.

## Adapter coverage

`controlloop bom` wires five registered discovery adapters
(`controlloop.adapters.ALL_ADAPTERS`) into a real command. Each is
already limited to a declared depth with an explicit, named gap; see
[Adapter status](../adapters/readme.md) for the full per-format
boundary this list summarizes:

- **`McpServerAdapter`** (MCP) -- discovers committed server
  declarations only, in eleven hosts' configuration files (see the
  adapter table). Gap: never starts a server or reads an
  environment-variable or header value, only its declared name.
  Arguments pass through redaction, and any `KEY=VALUE` argument keeps
  only `KEY=`. The declaration digest is computed over the redacted
  declaration, so it cannot be used to test a guessed value.
- **`OpenApiAdapter`** (OpenAPI) -- discovers OpenAPI 3.x documents by
  content. Gap: a remote `$ref` is never fetched; Swagger 2.0 is
  explicitly rejected, not misparsed.
- **`A2aAgentCardAdapter`** (A2A) -- discovers committed agent cards
  only. Gap: a card is never fetched live; delegation resolution is
  direct and non-recursive.
- **`OasfAdapter`** (OASF) -- implements the version-governance
  mechanism. Gap: `SUPPORTED_OASF_VERSIONS` is currently **empty** --
  every real OASF record produces an unsupported-version diagnostic.
- **`IamPolicyAdapter`** (IAM/deployment) -- discovers AWS IAM policy
  JSON and Terraform HCL only. Gap: AWS only; a GCP or Azure policy
  document is recognized by its distinctive shape and explicitly
  rejected, not misparsed.
- **`CrewAiAdapter`** (CrewAI) -- discovers agents from
  `config/agents.yaml` and tool wiring by **parsing** `crew.py` with
  `ast.parse`. It is the first adapter to read Python. Reading source is
  not executing it: the module is never imported, executed, or
  evaluated, no name is resolved to a runtime object, and
  `tests/adapters/test_crewai.py::TestNeverExecutesRepositoryCode`
  asserts structurally that `importlib`, `subprocess`, `socket`,
  `runpy`, `eval`, `exec`, and `compile` appear nowhere in the module.
  Gap: only a literal list of constructor calls resolves. Every other
  shape -- a comprehension, a conditional, a bare name, a splat, a call
  -- produces both an `INCOMPLETE-UNRESOLVED-REFERENCE` diagnostic and a
  node whose security attributes are literally `"unknown"`, so an
  unreadable tool is reported as the worst thing in the graph rather
  than silently absent.
- **`LangGraphAdapter`** (LangGraph) -- discovers graphs from
  `langgraph.json` and topology by **parsing** the module each graph
  names with `ast.parse`. Never imports, executes, or evaluates it;
  `tests/adapters/test_langgraph.py::TestNeverExecutesRepositoryCode`
  asserts structurally that `importlib`, `subprocess`, `socket`,
  `runpy`, `eval`, `exec`, and `compile` appear nowhere in the module.
  Gap: `add_conditional_edges` routes at runtime, so **every** target in
  the mapping is emitted as reachable rather than one guessed branch; a
  router whose targets cannot be enumerated, and a tool binding that is
  not a literal list, each produce an
  `INCOMPLETE-UNRESOLVED-REFERENCE` diagnostic and an
  `"unknown"`-attributed node. Privacy note: `langgraph.json`'s `env` is
  usually a **path** to a `.env` file holding real values. That file is
  **never opened** -- a path contributes only the fact that an
  environment file is declared, and only an inline mapping contributes
  `env:NAME` scopes, keys only. A redaction canary asserts a committed
  credential never reaches the ACBOM.
- **`OpenAiAgentsAdapter`** (OpenAI Agents SDK) -- the only adapter with
  no configuration file to claim: detection is by the SDK's own import,
  content-sniffed. Discovers agents, `handoffs` as `delegates-to`,
  `@function_tool` functions as tools, and `Agent.as_tool()` as
  `invokes` -- deliberately distinct from a handoff, which transfers the
  conversation. **Parses** each module with `ast.parse` and never
  imports, executes, or evaluates it;
  `tests/adapters/test_openai_agents.py::TestNeverExecutesRepositoryCode`
  asserts that structurally. It performs exactly one resolution step
  beyond reading a literal -- a variable assigned from `Agent(...)` in
  the same module -- with no import following, no cross-module
  resolution, and no value tracking through reassignment. Gap: a
  computed agent name is reported rather than synthesized, since a
  made-up identity is worse than a missing one; a non-literal `tools` or
  `handoffs` list produces an `INCOMPLETE-UNRESOLVED-REFERENCE` and an
  `"unknown"`-attributed node. Privacy note: a function tool contributes
  its parameter **names** only -- no default value, docstring body, or
  literal argument reaches identity material or evidence, asserted by a
  redaction canary.
- **`ClaudeCodeSettingsAdapter`** (Claude Code project settings) -- reads
  `.claude/settings.json`, and `.claude/settings.local.json` unless
  `.gitignore` excludes it, as data. A hook or helper command is recorded as
  a bounded command string and is never executed. Privacy: `env` contributes
  variable **names** only; an HTTP hook contributes its URL host and header
  **names** only; a `prompt` or `agent` hook's prompt text is never
  recorded; every recorded command and rule passes through
  `controlloop.redaction` and a second pass that removes `--token=`- and
  `--key`-style, `Bearer`, and `NAME_TOKEN=`-style values; a path outside
  the repository is replaced by `<outside-repository>`. Gap: user-scope and
  managed settings live outside the repository and are never read; a key
  outside the documentation snapshot (2026-10-17) is reported as
  `INCOMPLETE-UNRECOGNIZED-KEY` rather than interpreted.
- **`ClaudeCodeComponentsAdapter`** (Claude Code skills, subagents,
  plugins, and marketplaces) -- reads `SKILL.md` files,
  `.claude/commands/`, `.claude/agents/`, `.claude-plugin/plugin.json`,
  and `.claude-plugin/marketplace.json`. Privacy: from a skill or
  subagent file only the YAML frontmatter and the `` !`cmd` `` and
  ` ```! ` shell-injection lines are read into anything; the
  description, instructions, and every other line of the body are not.
  A shell line is recorded through the same redaction as a hook command.
  An inline MCP server records env and header **names** only. Gap: a
  plugin installed from outside the repository is seen only through the
  settings that enable it.
- **`CodexConfigAdapter`**, **`GeminiSettingsAdapter`**,
  **`CursorConfigAdapter`**, **`KiroConfigAdapter`** -- read
  `.codex/config.toml` and `.codex/hooks.json`, `.gemini/settings.json`
  and `.gemini/.env`, `.cursor/hooks.json`, `.cursor/environment.json`,
  and `.cursor/cli.json`, and `.kiro/hooks/` and `.kiro/agents/`, as
  data. Privacy: `.gemini/.env` contributes variable **names** only; a
  hook or helper command passes through the same redaction as Claude
  Code's; a Kiro `agent` hook's prompt is never recorded; an inline
  Dockerfile in `.cursor/environment.json` is recorded only as present.
  Gap: user-scope configuration (`~/.codex`, `~/.gemini`, `~/.cursor`,
  `~/.kiro`) and settings held in an editor's UI state are never read.
- **`RooModesAdapter`** (Roo Code custom modes) -- reads `.roomodes` at
  the repository root as YAML or JSON data. Privacy: a mode's `slug`,
  `name`, and tool groups are recorded; `roleDefinition`,
  `customInstructions`, `whenToUse`, and `description` are prompt text
  and never read into anything. An `edit` group's `fileRegex` is recorded
  as text, never evaluated. Gap: global modes (`custom_modes.yaml`) live
  outside the repository and are never read.
- **`AgentWorkflowAdapter`** (agent-running GitHub workflows) -- parses
  `.github/workflows/*.yml` with `yaml.safe_load`; a workflow is never run.
  Privacy: a secret is recorded by **name** from `${{ secrets.NAME }}`; an
  inline `settings` or `mcp_config` input is recorded only as a short
  digest, a path input as the path. Gap: a reusable workflow, a matrix, or
  an expression in an agent input or in `permissions` is reported as
  `INCOMPLETE-UNRESOLVED-REFERENCE`, never guessed; an absent `permissions`
  block is `unknown`, never the repository's default.

`normalize_live_mcp_server` (MCP live tool/resource normalization) is
not in `ALL_ADAPTERS` and is not wired into `bom`, `run_adapters`, or
the adapter sandbox: it is a standalone function, disclosed as a risk
escalation because it is the one adapter path that starts a real
process -- the declared MCP server, stdio transport only -- rather
than only reading committed files. No CLI command calls it yet.

No Python, TypeScript, or other framework-specific source adapter
exists yet. `scan` and `gate` wire in every adapter that does exist,
through the same `build_acbom_document` path `bom` uses.

## Hostile input fuzzing

A dependency-free, deterministic, seeded fuzzer (`tests/fuzz_support.py`)
exercises every place ControlLoop parses untrusted repository content,
proving the same "never crashes" contract the shared adapter conformance
suite already established for one hand-picked malformed example per
adapter, but under hundreds of adversarial byte-level mutations instead:

- every discovery adapter's `discover()` (`tests/adapters/
  test_fuzz_adapters.py`), seeded from each adapter's own realistic
  positive fixture;
- the `controlloop.yaml` manifest parser, including
  `capability_ceiling` declarations, which are fields within the
  manifest schema rather than a separately parsed document
  (`tests/test_fuzz_manifest.py`); and
- the committed baseline document loader
  (`tests/test_fuzz_baseline.py`).

Running this fuzzer for real, before it was folded into the standing
suite, found that pathologically deep nesting (a long run of `{` or
`[`) in a manifest or baseline document could take an unbounded amount
of work to reject rather than failing fast, in both PyYAML's and the
stdlib JSON decoder's own recursive-descent parsing. Both parsers are
now wrapped in a recursion-depth bound
(`controlloop.bounded_recursion.bounded_recursion`) relative to the
caller's own current stack depth, so a hostile document is rejected as
`ManifestValidationError` or `BaselineIntegrityError` within a small,
fixed number of recursive calls, never an unhandled `RecursionError` and
never unbounded work. The exact inputs that surfaced this are committed
as a standing regression corpus
(`tests/fuzz_corpus/manifest/`, `tests/fuzz_corpus/baseline/`)
and replayed unconditionally on every run, independent of the seeded
sweep.

The identical unprotected-recursion gap was found a second time, not
by the seeded sweep locally (a fast development machine did not
reproduce it) but by the fuzzer's own pull request hanging in CI: every
discovery adapter parses JSON (and, for OpenAPI, YAML) via a raw
`json.loads`/`yaml.safe_load` call with no recursion bound of its own,
identical in shape to the manifest and baseline gap. Every adapter
that parses JSON or YAML (`mcp.py`, `openapi.py`, `a2a.py`, `oasf.py`,
`iam.py`, and `agent_authority.py`, which
`claude_code.py` loads settings through) now wraps every such call site
in the same `bounded_recursion` guard. `tests/
fuzz_corpus/adapters/` remains empty -- the seeded local sweep still
finds no adapter-level crash on this development machine -- disclosed
as an environment-dependent limitation of the corpus rather than a
claim that no risk existed.

That fix alone did not resolve the CI hang: the fuzz harness's own
timeout mechanism was the real remaining gap. The first version bounded
each call with `signal.alarm`, which only fires between Python bytecode
instructions and cannot preempt a tight C-level loop, a blocked
syscall, or anything else that never yields back to the interpreter --
regardless of which input or code path triggers it. `run_bounded`
(`tests/fuzz_support.py`) now isolates every fuzz call in a forked
child process, killed at the OS level (`terminate()`, then `kill()`) if
it outlives the bound, so the guarantee no longer depends on the target
ever returning control. Verified directly: a deliberately infinite loop
passed to `run_bounded` is killed within the 2-second bound.

Even that fix did not resolve CI, because there was never a true hang:
GitHub Actions cancels a job at its own configured `timeout-minutes`
(10 for this repository's CI job), then hard-kills it after a further
grace period if it has not exited -- the ~15-minute durations reported
across three failed attempts were this 10-minute timeout plus that
grace period, not a stuck process. The real cause was volume: forking
roughly 2,100 child processes (300 fuzz iterations per target x 7
targets) under coverage-tracing overhead added up to more than 10
minutes on GitHub's shared runner, even though the same suite completed
in under two minutes locally. `FUZZ_ITERATIONS` was cut from 300 to 40,
reducing the full local suite's own runtime by roughly 3x.

With that cut in place, CI failed a fourth time -- in about a minute,
not fifteen, confirming the diagnosis above. The failure was a real
call reporting `FuzzOutcome.TIMEOUT` on an input the recursion-depth
fix already handles almost instantly: `run_bounded`'s own
fork-and-IPC overhead, not the target's work, was what pushed the call
past the original 2-second bound on GitHub's runner. `_TIMEOUT_SECONDS`
was raised to 10 to absorb that overhead with real margin.

## Performance benchmark

`tests/performance/` measures `controlloop scan` against a
deterministically generated, representative ~100,000-line repository
(`bench_repo.py`, fixed seed, never committed as literal content) --
real `.mcp.json` and `openapi.json` declarations buried in ordinary
generated source, not an adversarial stress test (that is a separate,
already-shipped concern: the decompression-bomb and pathological-depth
fixtures). Two things are asserted on every pull
request, in a genuinely separate subprocess per timed run:

- an absolute service-level target (p50 under 30 seconds, p95 under
  90 seconds); and
- a regression-margin check against a committed baseline
  (`baseline.json`, never auto-updated by CI), so a real algorithmic
  regression is caught long before the much looser absolute target
  would notice it.

The reference machine specification (CPU count, total memory,
platform) is queried live at benchmark time and printed alongside the
raw timings, rather than assumed.

## Approved local-scanning boundary

When the first scanning workflow is implemented, its acceptance evidence must
prove that:

- core scanning works with network access denied;
- repository traversal stays inside the selected root;
- symlink escapes, special files, unsupported archives, excessive depth, and
  oversized inputs fail safely;
- adapters receive bounded artifacts and cannot start tools, execute repository
  code, contact declared endpoints, or retrieve remote schemas;
- parsing, graph traversal, paths, diagnostics, findings, and total work are
  bounded;
- evidence contains sanitized locations and safe digests, not source snippets;
- outputs, logs, snapshots, errors, and artifacts exclude prompts, credentials,
  secret values, environment values, and customer data; and
- identical inputs and pinned versions produce identical material output and
  gate decisions.

Until those tests pass, treat this list as an approved implementation contract,
not available behavior.

### Where the Team tier sits relative to this boundary

Nothing above changes when Team is enabled. Scanning, traversal, adapter
isolation, bounding, evidence sanitization, and determinism are identical
on both tiers; the platform receives a rendered summary of the result and
never participates in producing it. Concretely:

- No adapter, walker, or rule gains network access.
- No platform response can add a finding. The organization bundle can
  enable a rule or raise a severity floor -- both of which make the local
  rule pack stricter -- and nothing else.
- A blocked platform makes a Community gate no different at all, and
  makes a Team gate either stop (`team_fail_mode = "closed"`) or continue
  and say so (`"open"`).
- The platform's own MCP server sits on the platform side
  of this line and moves nothing across it. It exposes what the platform
  already holds to a user who could already read it in the dashboard,
  as that user, through the same views; no scanner, adapter, or rule is
  involved, and no repository content passes through it. The free CLI
  serves no MCP and needs no network.

## Explainable enforcement

The approved policy design uses versioned deterministic rules over validated,
immutable canonical data. A blocking result must identify the rule, affected
agent, evidence, capability path, reason, and remediation. A model verdict
cannot be the sole reason a build fails.

`scan` and `gate` implement this design: both evaluate the full registered
rule set and report the rule, affected agent, evidence, capability path,
reason, and remediation for every finding.

## Threat model and vulnerability reporting

[`SECURITY.md`](../../SECURITY.md) is this repository's threat-model
baseline and disclosure process, not only a contact address:

- **Threat model.** Its "Scope priorities" section names this
  project's highest-priority attack surface directly: repository or
  symlink escape; arbitrary code execution or unsafe deserialization;
  network access during a declared offline scan; secret, source,
  prompt, or customer-data disclosure; nondeterministic or bypassable
  blocking behavior; and malicious schema, archive, graph, or parser
  denial of service.
- **Reporting process.** Its "Reporting a vulnerability" and "Response
  targets" sections describe the private disclosure channel, what a
  report should include, and response-time targets -- never a public
  issue or troubleshooting thread for an unpatched vulnerability.

## Out of scope

The project's explicit out-of-scope list applies to this entire
Community CLI, not only to a single command:

- Runtime traffic interception or action authorization.
- Sandboxing, quarantine, kill switch, and incident response.
- Managed monitoring or advisory services.
- Model-quality or hallucination evaluation.
- SSO, SCIM, self-hosting, and enterprise compliance packs.
- Windows support for the first release.
- Automatic remediation that edits customer code.

Malicious-component and threat-feed detection are excluded for a
specific reason, not only priority: either one would break local-first
scanning, and both are left to content scanners -- a different product
category this repository does not compete with, not a feature deferred
to a later release.

## Known limitations

- `scan` and `gate` scan a repository under policy and gate a build. `bom`
  generates or validates a canonical ACBOM -- see [`bom`](cli.md#bom) -- and
  `diff` compares two ACBOMs or a repository against a resolved baseline --
  see [`diff`](cli.md#diff). `scan` and `gate` build on that same
  foundation and additionally evaluate policy, producing findings and, for
  `gate`, a deterministic gate result.
- See "Adapter coverage" above for exactly which adapters `bom`, `scan`, and
  `gate` wire in and each one's declared depth and explicit gap.
- JSON, SARIF, and terminal findings output all ship today, and a GitHub
  Action provides free public-repository CI. Every Team workflow remains
  unavailable.
- The initial approved scanner slice is intentionally narrow and will not
  establish broad framework or standards coverage.
- Static analysis cannot always prove dynamically registered or runtime-created
  authority. Such behavior must be represented as unknown, not safe.
- A future passing scan will not guarantee that an agent is safe; it will report
  the result of bounded analysis under selected, versioned policy.
- The redaction boundary's credential-shape detection is signature based and
  limited to a documented baseline set; a credential format outside that set
  is not currently redacted.

See [Adapter status](../adapters/readme.md) for a capability-by-capability
view.

## Handling sensitive test material

Examples in user documentation must be synthetic. Never paste production
source, prompts, credentials, secret values, environment-variable values,
customer records, or proprietary configuration into an issue, fixture, output
example, or troubleshooting report.

Security vulnerabilities should follow the repository's
[security policy](../../SECURITY.md), not a public troubleshooting thread.

## Next step

If an implemented command behaves differently from this page, stop relying on
the disputed privacy claim and report the mismatch with sanitized reproduction
steps. Contributors should update behavior, tests, and documentation together.
