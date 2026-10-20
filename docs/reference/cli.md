---
type: reference
title: CLI reference
tags:
  - reference
  - cli
created: 2026-08-14
---

# CLI reference

This page describes the implemented command surface in the current repository,
not the broader product direction described for future work.

## Invocation

From the repository root in a source checkout:

```bash
uv run controlloop [OPTIONS]
```

## Available options

| Option | Behavior | Standard output | Exit code |
| --- | --- | --- | ---: |
| `--help` | Shows usage, product purpose, and current options. | Terminal-formatted help. | 0 |
| `--version` | Shows the installed ControlLoop version, supported OASF versions, and the bundled rule pack's own name/version/rule count, then exits. See [Rule pack versioning](rule-pack-versioning.md). | `ControlLoop <version>`, `Supported OASF versions: <list or "none yet">`, `Rule pack: <name> <version> (<n> rules)` | 0 |
| `--show-config` | Resolves and prints the effective configuration and the source (`default`, `repository file`, `environment`, or `flag`) that supplied each value, then exits. See [Configuration loading and precedence](configuration.md). | One `<key> = <value>  (<source>)` line per key, sorted by key. | 0, or 2 if the repository configuration file is unknown-key or malformed. |
| `--max-file-size-bytes`, `--max-total-bytes`, `--max-file-count`, `--max-depth` | Override one resolved configuration value at the flag tier (highest precedence). Consumed by `--show-config` and by `bom`'s, `diff`'s, and `scan`'s own repository walk. | N/A alone. | N/A alone. |
| `--log-level {quiet,default,verbose,debug}` | Set the operator diagnostic verbosity. Also selectable via `CONTROLLOOP_LOG_LEVEL`; the flag wins if both are set. Never changes findings, a gate result, or an exit code -- only how much optional diagnostic detail reaches standard error. See [Verbosity and logging](#verbosity-and-logging) below. | N/A alone. | 2 if an unrecognized value is supplied via the flag or the environment. |
| `--log-format {text,json}` | Set the format of the optional diagnostic lines `--log-level verbose`/`debug` add: `text` (default, human-oriented) or `json` (one structured object per line). Also selectable via `CONTROLLOOP_LOG_FORMAT`. | N/A alone. | 2 if an unrecognized value is supplied via the flag or the environment. |

Invoking `controlloop` without an option renders help and exits with code `2`
because no operation was selected.

## Available subcommands

`init`, `bom`, `diff`, `scan`, `gate`, `rules`, and `example` all exist and
appear in `--help` with a one-line description, and all seven are
implemented -- see [`init`](#init),
[`bom`](#bom), [`diff`](#diff), [`scan`](#scan), [`gate`](#gate),
[`rules`](#rules), and [`example`](#example) below.

One product command remains wholly absent from the CLI:

- `auth`

Planned command signatures are not current usage instructions until a
contract for them is approved and the CLI supports them.

## `init`

`controlloop init [REPOSITORY] [--dry-run]` discovers candidate agents in a
repository -- the same discovery `bom` uses (`build_acbom_document`) -- and
writes a schema-valid, human-commented draft `controlloop.yaml` security
manifest next to it, or (`--dry-run`) prints the draft to standard output
without creating anything.

| Argument or option | Behavior |
| --- | --- |
| `REPOSITORY` (optional positional) | Repository path to scan for candidate agents. Defaults to the current directory, or the nearest enclosing git repository. |
| `--dry-run` | Print the draft `controlloop.yaml` to standard output instead of creating it. Never touches the filesystem. |

Every field the published manifest schema declares is present in the
generated file, even when `init` could not determine a value: `owner` and
each trust boundary's name are always the literal placeholder value
`"TODO-owner"` / `"TODO-trust-boundary-name"`, and every other optional
field (`approvals`, `prohibited_capabilities`, `allowed_delegation`,
`data_classification`) is present as an empty list. Each is preceded by a
`# TODO:` comment explaining what to add and why `init` could not fill it
in -- these are human policy decisions (who is accountable, what has been
approved, what is prohibited), never discoverable from repository content
alone.

`ceilings` is the one field `init` pre-fills with a real
proposal rather than leaving empty: for each discovered candidate agent with
a usable name, ControlLoop proposes prohibiting every `reads`/`writes`/
`invokes` action and every delegation target this scan found *no* evidence
of, at any confidence -- so adopting the proposal unchanged cannot conflict
with what this same scan found. The section is still preceded by a
`# TODO: ceilings` comment marking it a **starting point requiring human
review, not an approved envelope**: the proposal never covers
`prohibited_resources`, `prohibited_external_destinations`, or
`prohibited_data_classes` (there is no way to enumerate "a resource never
touched" or "a domain never contacted" from static repository discovery
alone -- this is disclosed explicitly, not left to look like a considered
"nothing to prohibit" answer), and an action or delegation edge discovered
only at low or unknown confidence is never silently folded into the
proposal in either direction -- it is excluded from the prohibition and
listed separately in its own disclosed comment, for a human to review and
decide. `init` never evaluates a ceiling against a live scan or blocks on a
violation -- that is `scan`'s own job, via the
`policy.capability-ceiling` rule; see [Capability
ceiling declaration](capability-ceiling.md) and [Writing a capability
ceiling](../guides/capability-ceiling-guide.md) for worked examples.

What `init` *can* determine is pre-filled: each discovered candidate agent
(an A2A Agent Card or OASF record found in the repository) is listed by
name under `trust_boundaries[0].agents`, with a comment naming the tools
`bom`'s own discovery found it invoking. A discovered agent whose name
cannot be represented in the manifest's identifier format (letters,
digits, and `. _ : / @ + -` only -- for example a name containing a
space) is never silently renamed or hashed into a substitute identifier;
it is excluded from that list and named in a comment instead, so nothing
is misrepresented as pre-filled when it was not. A delegation-shaped
relationship observed between two discovered agents is likewise
surfaced only as a reference comment under `allowed_delegation`, never
written as an approved entry -- declaring one permitted is a policy
decision `init` does not make on a user's behalf.

`init` never reads, overwrites, or modifies an existing `controlloop.yaml`.
If one already exists at the resolved repository root, `init` (with or
without `--dry-run`) reports the conflict on standard error and exits `2`
without touching the file or performing discovery.

Generation (without `--dry-run`) exits `0` on success and writes nothing to
standard output; `--dry-run` exits `0` and writes the draft to standard
output. Both exit `2` if the repository path cannot be resolved, the
repository configuration file is invalid, an existing manifest conflicts,
or (generation only) the destination could not be written. If the scan's
diagnostics include any marked incomplete, `init` prints the same
completeness summary `bom` does to standard error, in both modes.

The generated draft parses through the same manifest schema validator
(`controlloop.manifest.load_manifest`) reconciliation and the capability
ceiling use, with no edits required, at the version `init` was built
against.

## `bom`

`controlloop bom [REPOSITORY]` generates a canonical ACBOM from a repository
and writes it to standard output. Discovery requires no policy configuration
and evaluates no rules -- it is the same repository walk and adapter
discovery `--show-config` already resolves bounds for, wrapped in the
canonical document envelope (`schema_version`, `schema_url`, `generator`,
`repository`, `nodes`, `edges`, `diagnostics`, `digest`). `schema_url`
 is the permanent, versioned URL this exact schema
version is published at -- see
[Schema versioning and compatibility policy](schema-versioning.md).

| Argument or option | Behavior |
| --- | --- |
| `REPOSITORY` (optional positional) | Repository path to scan. Defaults to the current directory, or the nearest enclosing git repository. With `--validate`, this is instead the path to the ACBOM file to validate. |
| `--output`, `-o PATH` | Write the generated ACBOM to `PATH` instead of standard output. Not valid together with `--validate`. |
| `--validate` | Validate an existing ACBOM file against the current reader's schema version and structural contract instead of generating one. |
| `--format {acbom,cyclonedx}` | Output format for generation. `acbom` (default) writes the native canonical document unchanged. `cyclonedx` writes a CycloneDX 1.6 BOM instead -- a reduced projection of the ACBOM, by a recorded design decision; see [CycloneDX export format](cyclonedx-export-format.md) for the exact field mapping. Not valid together with `--validate`. |

Generation (the default) exits `0` on success, or `2` if the repository path
cannot be resolved or the repository configuration file is invalid.
Repeated generation over unchanged input produces an identical digest.

`bom --validate PATH` exits `0` and prints `✓ VALID  PATH is a valid ACBOM`
to standard output if `PATH` parses as a structurally valid ACBOM document at
a compatible schema version and its declared `digest` matches its content;
otherwise it exits `2` and reports the reason on one line of standard error
(for example `does not match the ACBOM schema at nodes.0.type`, or `digest
does not match its content` for a document edited after it was generated).
It never generates or prints a document itself. `diff` applies the same
check to each ACBOM file it is given.

Repository identity in the generated document is deliberately minimal:
`repository.commit` is `git rev-parse HEAD` (local only; never touches the
network) if the repository is a git checkout with at least one commit, or
the literal `"unknown"` otherwise. `repository.root_digest` is a SHA-256
digest over the sorted, repository-relative paths of every file the scan
actually walked -- it names *what was scanned*, not each file's content;
two scans of the same path set with different file content produce the same
`root_digest` today.

If the scan's diagnostics include any marked incomplete (an adapter
failure, a bound exceeded, or similar), `bom` prints a one-line
completeness summary to standard error -- for example
`• COMPLETENESS  2 diagnostic(s) indicate incomplete analysis:
INCOMPLETE-ADAPTER-FAILURE`. This is a redundant, human-readable surface
over diagnostics already present in the generated document's own
`diagnostics` array; the underlying data is not new.

With `--format cyclonedx`, if any node or edge has no CycloneDX
representation (see [CycloneDX export format](cyclonedx-export-format.md)
for exactly which ones), `bom` prints a one-line lossy-export summary to
standard error -- for example `• LOSSY EXPORT  2 node(s) or edge(s) have
no CycloneDX representation and were omitted` -- so a
caller always knows content was omitted, never silently.

## `diff`

`controlloop diff` compares two ACBOMs, or a repository against a resolved
baseline, and reports every node, edge, and effective-capability change as
added, removed, changed, or unknown (`controlloop.diff.compute.compute_diff`).
It evaluates no policy and never returns any exit code other than `0` or
`2`. See [Diff output format](diff-output-format.md).

There are two mutually exclusive usage forms, distinguished structurally by
the number of positional arguments, never by sniffing file content:

```bash
uv run controlloop diff BASELINE_ACBOM CURRENT_ACBOM [--format text|json]
uv run controlloop diff [REPOSITORY] [--baseline VALUE] [--format text|json]
```

| Argument or option | Behavior |
| --- | --- |
| Two positional arguments | Two ACBOM files. The first is the baseline side, the second the current side (matching `compute_diff`'s own argument order and `git diff A B` convention). `--baseline` is not valid together with two positional arguments and exits `2`. |
| One positional argument, or none | A repository path to scan live (default: the current directory, or the nearest enclosing git repository), compared against a resolved baseline. |
| `--baseline VALUE` | Repository mode only. `VALUE` is tried first as an existing readable file path (an explicit committed-baseline-document override, reusing `resolve_baseline`'s own `explicit_path` semantics unmodified); if it does not exist as a file, it is tried as a git revision (a branch, tag, or SHA, resolved locally). A value that is neither exits `2`, naming both attempts. Omitted: resolved automatically -- see "Baseline resolution" below. |
| `--format {text,json}` | `text` (default): a human-oriented CLI-voice summary. `json`: the complete comparison report (`DiffReport`, including the wrapped `DiffResult`) for machine consumption. No SARIF renderer exists anywhere in this codebase yet. |

### Baseline resolution

With no `--baseline`, `diff` resolves a baseline automatically:

1. A baseline committed at the conventional path (`.controlloop/baseline.json`,
   `resolve_baseline`) takes precedence when present.
2. Otherwise, the merge-base of the default branch is resolved and scanned
   (`resolve_merge_base`/`build_merge_base_acbom`) through local
   git alone -- never `git fetch`, never a remote URL.
3. When neither is available -- no committed baseline **and** no usable git
   history at all (`NoGitHistoryError`: zero commits, or not a git repository)
   -- `diff` reports plainly that no comparison is possible, exit `2`,
   distinct from reporting zero changes. A repository with *some* history but
   not enough to find a merge-base (for example a shallow clone) instead
   raises `MergeBaseResolutionError`'s own actionable message (naming the
   likely cause and the remediation) at exit `2`.

A resolved committed or explicit-file baseline (`controlloop.baseline.models.BaselineDocument`)
carries `effective_authority` but no `nodes`/`edges` at all, so only an
effective-authority comparison is possible in that case -- never a fabricated
node/edge comparison against an empty graph, which would incorrectly report
every current node and edge as added. Every `diff` report names which
resolution path supplied its baseline (`baseline_origin`) and whether the
comparison covered nodes and edges or effective authority alone
(`comparison_scope`), in the same payload as the changes themselves, in both
`--format json` and `--format text` -- see [Diff output format](diff-output-format.md#cli-report-envelope).

`diff` returns `0` on a successfully computed and rendered comparison --
regardless of whether the diff itself is empty -- and `2` on every input,
resolution, or usage error: an unreadable or malformed ACBOM file, an
unresolvable repository path, an invalid repository configuration file, a
tampered or malformed baseline document, an unresolvable `--baseline` value,
two positional ACBOM files combined with `--baseline`, `MergeBaseResolutionError`,
or the "no comparison possible" case above. `diff` never returns `1`, `3`,
`4`, or `5` as a result of its own logic (`5` remains reachable only through
the generic unhandled-exception envelope every command shares) -- see the
[Exit codes](#exit-codes) table below for how this fits every other command.

### `diff`'s standard output and standard error

`diff`'s stdout carries exactly one document: the rendered `--format text`
summary or the `--format json` report, and nothing else. A completeness
summary for any ACBOM this command builds or loads (mirroring `bom`'s own
`• COMPLETENESS` line) reaches stderr only, never stdout. See [Output stream
separation](#output-stream-separation) below for the shared primitive this
reuses.

## `scan`

`controlloop scan` discovers the repository, builds its ACBOM, resolves a
baseline when one is available, evaluates policy with every registered rule
not disabled by configuration, applies any declared repo-local suppressions
(see [Expiring repo-local suppressions](suppressions.md)),
and renders the result in the requested format, returning the exit code the
result implies. See [Concrete policy
rules](policy-rules.md) for what each of the ten currently registered rules
detects, [Severity, confidence, and thresholds](policy-thresholds.md) for
how a blocking decision is reached, and [Stable JSON report
format](report-format.md) / [SARIF export format](sarif-export-format.md)
for the two machine formats.

```bash
uv run controlloop scan [REPOSITORY] [--format text|json|sarif]
```

| Argument or option | Behavior |
| --- | --- |
| `REPOSITORY` | A repository path to scan (default: the current directory, or the nearest enclosing git repository). |
| `--format {text,json,sarif}` | `text` (default): a human-oriented CLI-voice summary, followed by a `Suppressions:` section listing every declared suppression's own disposition (`Suppressions: none declared` when none are declared). `json`: the complete `ScanReport`, including its own `suppressions` field. `sarif`: a complete SARIF 2.1.0 log document, for ingestion by code-scanning tooling. |

`scan` reads rules from `controlloop.policy.rules.ALL_RULES` (all ten
currently implemented rules) for execution, not `CURRENT_RULE_PACK.rules`
-- currently identical content, but execution deliberately stays
decoupled from rule-pack identity; `scan`'s own `validate_disabled_rules`
check reads `CURRENT_RULE_PACK.metadata` directly. See [Concrete policy
rules](policy-rules.md) for the disclosed reasoning.
A `controlloop.yaml` manifest is read when present at the repository root
and passed to every rule; its absence is never an error. A baseline is
resolved the same automatic way `diff`'s own no-`--baseline` path does (a
committed baseline first, falling back to the merge-base of the default
branch) -- `scan` has no `--baseline` option of its own; use `diff` for
explicit baseline control. Unlike `diff`, whose whole purpose is
comparison, `scan` never fails when no baseline can be found at all (no
committed baseline and no usable git history) -- it proceeds with
`material_changes: null`: it works with no baseline, reporting current
state without change classification. A malformed
*committed* baseline is still a hard error, since that is a real
repository problem, not merely an absent one. A committed baseline
document carries no `nodes`/`edges`, only `effective_authority`, so
`material_changes` stays `null` even when a baseline is found that way --
only the merge-base fallback (a real baseline ACBOM on both sides) ever
produces a populated `MaterialChangeSummary`.

`scan`'s own verdict and exit code are derived, in order: any blocking
finding (a finding meeting or exceeding the configured severity threshold,
per [Severity, confidence, and thresholds](policy-thresholds.md)) means
`deployment_blocked` and exit `1`; otherwise incomplete analysis (an ACBOM
completeness diagnostic, or the policy engine's own bound-exceeded
diagnostic) means `review_required` and exit `3`; otherwise any
warning-only finding means `passed_with_warnings` and exit `0`; otherwise
`passed` and exit `0`. `scan` returns `2` for every input-resolution
failure: an unresolvable repository path, an invalid repository
configuration file, a malformed or unresolvable manifest, a malformed
committed baseline, or a `disabled_rules` entry naming a mandatory or
unrecognized rule ID.

### `scan`'s standard output and standard error

`scan`'s stdout carries exactly one document: the rendered `--format text`
summary, the `--format json` report, or the `--format sarif` log, and
nothing else. A completeness summary for a merge-base baseline ACBOM this
command builds along the way reaches stderr only, never stdout, mirroring
`diff`'s own convention; the *current* document's own completeness is
folded into the rendered report's own `diagnostics` field instead. See
[Output stream separation](#output-stream-separation) below for the shared
primitive this reuses.

## `gate`

`controlloop gate` is the noninteractive, CI-facing command: it composes
the identical discovery, baseline-resolution, and policy-evaluation
pipeline `scan` already implements, and adds a four-state
pass/warn/require-review/fail verdict and an unconditionally written,
retainable evidence artifact. See [Evidence
artifact format](evidence-artifact-format.md) for the artifact's schema and
[Severity, confidence, and thresholds](policy-thresholds.md) for how a
blocking decision is reached.

```bash
uv run controlloop gate [REPOSITORY] [--evidence-path PATH] [--format text|json|sarif] [--default-branch NAME] [--sarif-path PATH]
```

| Argument or option | Behavior |
| --- | --- |
| `REPOSITORY` | A repository path to scan (default: the current directory, or the nearest enclosing git repository). |
| `--evidence-path PATH` | Write the evidence artifact to `PATH` (default: `evidence.json` in the current directory). Written for every run that reaches a verdict, including a failing one. The parent directory must already exist; it is never created automatically. |
| `--format {text,json,sarif}` | `text` (default): a human-oriented CLI-voice summary (the same rendering `scan` uses), followed by a `Suppressions:` section listing every declared repo-local suppression's own disposition (`Suppressions: none declared` when the repository declares none), then ending with two appended lines: the resolved completeness-enforcement setting (`Completeness enforcement: VALUE (SOURCE)`) and the resolved evidence path (`Evidence: PATH`). `json`: the literal evidence artifact -- byte-identical to the file written to `--evidence-path`. `sarif`: a complete SARIF 2.1.0 log document, identical in shape to `scan --format sarif`. |
| `--sarif-path PATH` | Additionally write a complete SARIF 2.1.0 log document to `PATH`, independent of `--format` -- written unconditionally whenever given, mirroring `--evidence-path`'s own unconditional-write guarantee. Includes the blast-radius statement as `runs[0].properties.controlloop.blastRadius`. Omit to skip writing one; `--format sarif` still renders one to stdout either way. Used by the [ControlLoop GitHub Action](github-action.md) for its own code-scanning upload and check summary. |

`gate` never prompts and never reads standard input: no code path it
reaches calls this codebase's one prompt-shaped primitive
(`controlloop.output.OutputStreams.confirm_or_exit`), asserted
structurally by `tests/test_cli.py`.

`gate` reuses `scan`'s own discovery, manifest loading, baseline
resolution, and rule evaluation almost entirely unmodified -- everything
in [`scan`](#scan) above about rule selection (`ALL_RULES`, not
`CURRENT_RULE_PACK.rules`), manifest handling, and automatic baseline
resolution (a committed baseline first, falling back to the merge-base of
the default branch) applies identically to `gate`. `gate` has no full
`--baseline` option of its own, matching `scan`'s own precedent; use
`diff` for explicit-file/-revision baseline control. `--default-branch`
(above) is narrower: a single ref-name override for automatic merge-base
target selection only, not a reintroduction of `diff --baseline`'s
capability.

**One deliberate difference from `scan`:** both commands
treat a repository with genuinely no git history at all as "no baseline,"
never an error. `gate` alone additionally treats a *resolvable* git
history whose merge-base specifically cannot be computed (for example, a
CI checkout too shallow to include the target branch's shared history) as
an input error -- exit `2`, with a message naming the likely cause and
remediation -- rather than silently proceeding with no baseline
comparison. `scan` keeps its original, unchanged behavior for this case.
See [the ControlLoop GitHub Action](github-action.md) for why a CI-facing
command needs this distinction and `diff` does not.

### Verdict and exit code

`gate`'s verdict is one of four words -- pass, warn, require review, or
fail -- each mapped to a documented exit code, reusing `scan`'s own
already-published five-state exit-code table below unchanged (no new
exit code was added for `gate`): any blocking finding means **fail**
(`deployment_blocked`) and exit `1`; otherwise incomplete analysis means
**require review** (`review_required`) and exit `3`; otherwise any
warning-only finding means **warn** (`passed_with_warnings`) and exit
`0`; otherwise **pass** (`passed`) and exit `0`. Pass and warn
deliberately share exit `0` -- a warning never fails a CI build, matching
`scan`'s own identical precedent and this codebase's published exit-code
table (below), which names code `0` as "gate passed" without
distinguishing a clean pass from a pass with warnings. `gate` returns `2`
for every input-resolution failure, identical in kind to `scan`'s own
(see [`scan`](#scan) above), plus a failure to write the resolved
`--evidence-path` itself (an unwritable directory, permissions, disk
full) -- an input problem, not a policy outcome, mirroring `bom
--output`'s own `OSError` handling.

**Completeness enforcement:** whether incomplete
analysis alone blocks `gate` is a resolved `controlloop.toml`/
environment setting, `completeness_enforcement` (`"warn"` default /
`"enforce"` opt-in), through the identical four-tier precedence
mechanism [Configuration loading and precedence](configuration.md)
already documents. Under the default `"warn"`, incomplete analysis with
no blocking finding is **warn** (`passed_with_warnings`) at exit `0` --
a first run is never a wall. A repository that sets
`completeness_enforcement = "enforce"` restores **require review**
(`review_required`) at exit `3` for the identical incomplete analysis.
Either way, every reason analysis was incomplete is listed in
`evidence.json`'s `completeness` field regardless of the setting, and
the resolved setting itself is stated in the gate result: as
`completeness_enforcement`/`completeness_enforcement_source` on the
`--format json` evidence artifact, and as an appended
`Completeness enforcement: <value> (<source>)` line in `--format text`
output, immediately before the `Evidence: <path>` line. `scan`
deliberately keeps its own separate, prior, unconditional
incomplete-analysis-always-exit-3 behavior -- this toggle applies to
`gate` only; see [Severity, confidence, and
thresholds](policy-thresholds.md#completeness-enforcement).

### The evidence artifact write guarantee

`evidence.json` (or the path `--evidence-path` names) is written for
every run that reaches a real verdict -- pass, warn, require review, or
fail -- including a failing one. This is unconditional by the command's
own straight-line structure: the complete evidence artifact is built and
written immediately after the verdict is computed, before any stdout
rendering or exit. This guarantee covers every reached verdict; it does
not cover a pre-verdict input failure (an unresolvable repository path, a
malformed manifest, a malformed committed baseline, an unrecognized
`disabled_rules` entry, or similar -- exit `2`) or an uncaught internal
error (exit `5`), neither of which has a real ACBOM digest or verdict to
report, matching this codebase's evidence schema (`acbom_digest` and
`verdict` are both mandatory fields).

**Disclosed interaction:** if `--evidence-path` is written *inside* the
directory `gate` scans, a later `gate` run over that same directory will
see the previous run's own artifact as part of the repository, which can
change `repository.root_digest` (and therefore `acbom_digest`) between
runs -- the identical, already-documented interaction `bom`'s own
`root_digest` has with any file added to a scanned tree. Writing the
evidence artifact outside the scanned repository (or excluding it via
repository configuration) avoids this.

### Team behavior

With `team_enabled = true` (see [Configuration](configuration.md#team-keys)),
`gate` does four things it does not otherwise do, in this order:

1. **Verifies entitlement** before any paid behavior runs. Not entitled is
   exit `4`; a grace period proceeds.
2. **Fetches the organization policy bundle** and merges it with
   repository policy under strengthen-only semantics, so an organization
   rule cannot be switched off locally. See
   [How organization and repository policy combine](policy-merge-semantics.md).
3. **Fetches active exceptions** and honors unexpired ones by exact
   finding fingerprint. An exception that has expired re-blocks its
   finding and its expiry date is printed.
4. **Uploads a sanitized scan envelope** after the verdict is decided and
   evidence is written. See [What a Team gate sends](team-envelope.md).

None of this runs with Team disabled, which is the default: no request is
attempted and no token is read. An upload failure is reported on standard
error and **never changes the exit code** -- a gate's answer is decided by
local policy evaluation, and whether a report of that answer reached a
server is a separate fact.

When the platform cannot be reached after a bounded retry window,
`team_fail_mode` decides what happens: `closed` (the default) stops,
`open` continues and says so.

### `gate`'s standard output and standard error

`gate`'s stdout carries exactly one document: the rendered `--format
text` summary (ending with the completeness-enforcement-setting and
evidence-path lines), the `--format json` evidence artifact, or the
`--format sarif` log, and nothing else. Every Team diagnostic described
above -- entitlement status, a refused repository policy change, an
expired exception, the upload result -- is a stderr line, so enabling Team
does not change what a CI step parsing stdout receives. A
completeness summary for a merge-base baseline ACBOM this command builds
along the way reaches stderr only, never stdout, mirroring `scan`'s own
identical convention. See [Output stream separation](#output-stream-separation)
below for the shared primitive this reuses.

## `rules`

`controlloop rules [REPOSITORY] [--format text|json] [--all]` lists the rule
pack in use and what each rule looks for.

Before this command, `--version` reported a rule *count* and nothing listed
the rules themselves; `controlloop.policy.models.Rule` carries only `id` and
`evaluate`, so no description existed anywhere in the model layer. A
repository that disabled a non-mandatory rule had no way to confirm what it
had turned off.

It prints the pack's name, version, and fingerprint, then every rule with:

| Field | Meaning |
| --- | --- |
| id | The `Finding.rule_id` this rule produces |
| state | `active`, or `disabled` by this repository's own configuration |
| governance | `mandatory` (cannot be disabled) or `optional` |
| summary | One line naming what the rule actually detects |

`REPOSITORY` decides whose configuration is consulted, defaulting to the
current directory or the nearest enclosing git repository. By default only
rules that would actually run are listed; `--all` lists the whole pack
regardless of configuration.

`--format json` emits the same content for scripting, including each rule's
`documentation_url`.

The active set is resolved through the same
`resolve_policy_config`/`validate_disabled_rules` pair `scan` and `gate` use,
so "active" here means exactly what it means there.

This command evaluates no policy and scans nothing -- it reads configuration
and prints. It exits `0` on success, or `2` if the repository or its
configuration cannot be resolved.

Full detail for every rule, including detection shape, confidence, and known
limitations, is in [Concrete policy rules](policy-rules.md).

## `example`

`controlloop example` prints a five-step walkthrough of how ControlLoop works
 and links to the
[Example walkthrough](../guides/example-walkthrough.md) guide for the full
narrative with real recorded output at every step.

It is written for someone who has never used ControlLoop. Each step explains
what is happening and why: what an ACBOM is and why an agent needs one, that
discovery reads files and executes nothing, what a scan does, what the
blast-radius statement means, why discovery cannot infer what a tool does and
what `tool_capabilities` fixes, what a rule is, how `gate` differs from
`scan`, what a capability ceiling is and why it catches what rules cannot, and
what each exit code means.

The link is emitted as a URL rather than a repository-relative path, so it is
useful to someone who installed the CLI without a checkout. It currently
points at the GitHub blob URL: the canonical documentation host
`docs.controlloop.ai` does not resolve yet. When it does, that URL should
move.

The narrative deliberately lives in `docs/` rather than in CLI output, so
there is one source for the explanation and the terminal output stays short
enough to read.

It reads nothing, writes nothing, contacts nothing, and always exits `0`. It
is guidance, not a scan -- in particular it does not create the demo agent for
you; the guide shows the file to write.

It exists mostly to defuse one specific trap: a first `scan` against a
repository with no `tool_capabilities` prints `no material capability is
reachable`, which reads like a clean bill of health and actually means
nothing could be classified.

## Exit codes

**Generated.** The table below is rendered directly
from `controlloop.exit_codes.EXIT_CODE_INFO`, the single source of truth
both this page and `tests/test_cli_reference_doc.py` read from --
see `tests/reference/cli_doc_fixtures.py`'s `render_exit_code_table`.
A committed edit to this table that no longer matches a fresh call to
that function fails the test suite; regenerate it with
`python tests/reference/cli_doc_fixtures.py` after changing
`EXIT_CODE_INFO` and paste the `exit-codes` fragment back in between the
markers below, unchanged outside them.

<!-- BEGIN GENERATED: exit-codes -->
| Code | Meaning | When it occurs | Remediation |
| ---: | --- | --- | --- |
| 0 | Scan completed and gate passed | `--help`, `--version`, `init` (generation and `--dry-run`), `bom` (generation and `--validate`), `diff` (any successfully computed comparison, empty or not), `scan` (a clean pass, or a pass with only warning-level findings), `gate` (verdict `passed` or `passed_with_warnings`) | Nothing to do -- this is success. |
| 1 | Gate failed because findings exceeded policy threshold | `scan`, when at least one finding meets or exceeds the configured severity threshold; `gate`, identically (verdict `deployment_blocked`) | Review the reported findings and either remediate the capability change, adjust the declared capability ceiling if the change is intentional and approved, or raise the configured `severity_threshold` if the finding is a known, accepted risk -- see [Concrete policy rules](policy-rules.md) and [Severity, confidence, and thresholds](policy-thresholds.md). |
| 2 | Configuration or input was invalid | A bare invocation, an unknown subcommand, a malformed flag, an unresolvable repository path, an invalid `bom --validate` target, an existing `controlloop.yaml` conflicting with `init`, `init` failing to write the manifest, any `diff` input/resolution/usage error, any `scan` input-resolution error, or the identical class of `gate` input-resolution error, plus an unwritable `--evidence-path` | Read the printed diagnostic message and location; it names the exact problem (an invalid flag combination, an unreadable path, a malformed configuration file) without echoing hostile input content back -- fix the named input and re-run. |
| 3 | Analysis was incomplete and policy requires completeness | `scan` always returns this when analysis is incomplete and nothing blocks (verdict `review_required`) -- unconditional, unchanged. `gate` returns this only when incomplete analysis is combined with `completeness_enforcement = "enforce"`; under the default `"warn"`, the identical incomplete analysis is exit `0` instead. A Team `gate` also returns this (verdict `review_required`) when the change adds an agent-authority grant the organization has not approved and its bundle leaves `policy.unsanctioned-agent-component` at the default require-review. `diff` never returns this. | Review the `completeness`/diagnostics field naming what could not be fully analyzed (an adapter failure, a bound exceeded, an unresolved dynamic registration) and address it, or explicitly accept the incompleteness by leaving `completeness_enforcement` at its default `"warn"` -- see [Incomplete-analysis policy](policy-thresholds.md#completeness-enforcement). For an unsanctioned grant, have it approved in the organization's bundle, change it to match an approved entry, or record an organization exception -- see [Unsanctioned agent component](policy-rules.md#unsanctioned-agent-component). |
| 4 | Team entitlement or authentication failed | `gate`, and only when `team_enabled = true`: the project is not entitled, the project token was rejected, or the platform could not be reached after the bounded retry window while `team_fail_mode` is `closed`. Unreachable on the Community path -- a repository with Team disabled makes no entitlement check at all, asserted by test rather than only observed, in `tests/test_free_public_repository_path.py`. | Read the printed message: it names which of the three conditions occurred. For a not-entitled project, check the subscription and the project's plan in your ControlLoop organization. For a rejected token, check `CONTROLLOOP_TEAM_TOKEN` and that it belongs to this project. For an outage, either wait or set `team_fail_mode = "open"` to continue through one -- see [Your first Team gate](../guides/first-team-gate.md). Setting `team_enabled = false` runs the free Community gate, which never returns this code. |
| 5 | Internal scanner error | Any unhandled exception in any command | The printed message is deliberately generic (only the exception's class name, never its own message, which could carry unsanitized interpolated content) -- re-run with `--log-level debug` for additional non-sensitive diagnostic context, and if the problem persists, report it including the command and repository shape that triggered it (never raw repository content) per `SECURITY.md`. |
<!-- END GENERATED: exit-codes -->

An unhandled exception never prints a Python traceback. It is caught at the
entry point and reported as a fixed, generic line to standard error --
`✕ INTERNAL ERROR controlloop encountered an unexpected internal error and
stopped (<ExceptionClassName>).` -- then exits `5`. The exception's own
message is deliberately never included, since it could carry arbitrary
interpolated content the redaction boundary was never asked to scrub.

## Errors

An unknown option or subcommand exits with code `2` and writes a usage error.
For example, `uv run controlloop nosuchcommand` reports `No such command
'nosuchcommand'.` (Click's own usage-error path; it runs before any
`controlloop` code and does not go through the diagnostic model below.)

If even `--help` or `--version` fails, use [Troubleshooting](../troubleshooting.md).

### Error diagnostics

Every failure or non-fatal condition a command reports on standard error is a
`CliDiagnostic` (`controlloop.diagnostics`): a stable code
drawn from a closed registry, a severity (`error`, `warning`, or `info`), a
message, and an optional sanitized location. One shared rendering function
produces the brand-consistent line every such diagnostic prints --
`<glyph> <LABEL>  <message>`, with `(<location>)` appended when a location is
present -- so every command's error output follows the same shape regardless
of which one produced it. Constructing or rendering a diagnostic never
touches the exit code; each call site still chooses its own, exactly as
before this model existed.

| Code | Meaning |
| --- | --- |
| `CLI-INVALID-INPUT` | A command-line argument, option, or input file was invalid. |
| `CLI-INVALID-CONFIG` | The repository configuration file could not be resolved. |
| `CLI-INVALID-ACBOM` | A supplied ACBOM document failed schema-version or structural validation. |
| `CLI-NOT-IMPLEMENTED` | The requested command is not implemented yet. |
| `CLI-INTERNAL-ERROR` | An unexpected internal error stopped the command. |
| `CLI-NONINTERACTIVE-ENVIRONMENT` | An interactive confirmation was required but standard output is not a terminal. |

This registry is closed: every code above is one this codebase's own test
suite enumerates explicitly, so adding a new one without updating that test
fails the build. It is not itself a machine output format -- there is no
JSON or SARIF error stream yet -- but every `CliDiagnostic` already
serializes through its own ordinary structured form, ready for a future
machine format to reuse without re-deriving the same information from text.

## Output, privacy, and compatibility

- `--version` emits one machine-stable line and no standard-error text.
- Help formatting is terminal-oriented and can vary in spacing, color, or
  border characters.
- `--show-config` reads at most one local file (`controlloop.toml` at the
  resolved repository root) and the process environment; it never contacts a
  ControlLoop service, emits telemetry, or writes anything. See
  [Configuration loading and precedence](configuration.md).
- `init` and `bom` both traverse the repository, consume the resolved
  configuration, and use the same discovery. `bom` writes an ACBOM; `init`
  writes (or, with `--dry-run`, prints) a draft manifest. `diff`, `scan`,
  and `gate` all traverse the repository the same way in their own
  repository-plus-baseline usage forms, and additionally read local git
  plumbing only (never a remote) to resolve a merge-base or an explicit
  revision. `scan` and `gate` both additionally evaluate policy against
  every registered rule and render a full report; `gate` additionally
  writes the evidence artifact named in `--evidence-path` (see
  [`gate`](#gate) above) -- the only command in this list that writes a
  file by default rather than only on an explicit `--output`/`-o`. None
  of `init`, `bom`, `diff`, `scan`, or `gate` contacts a ControlLoop
  service or emits telemetry.
- Exit codes `0`, `1`, `2`, `3`, and `5` above are verified current
  behavior. Code `4` is defined (see `controlloop.exit_codes.ExitCode`) but
  has no reachable code path until the command that would trigger it
  (team entitlement checking) is implemented.
- **Free public-repository path.** Gating a public
  repository requires no account, no token, and no entitlement check.
  `gate` (and every other implemented command) completes with a fully
  cleared process environment and no credential-shaped flag on its own
  option list; no module the free path reaches contains any
  entitlement, licensing, subscription, or billing check; and no
  registered policy rule or configuration key gates on any of those
  terms -- all asserted structurally by
  `tests/test_free_public_repository_path.py`, not only observed.
  This is a Community-tier commercial boundary expressed in code,
  kept verifiable now so a
  future Team-tier entitlement path can be added without the free path
  silently starting to depend on it.

### Output stream separation

`--version`'s, `bom`'s, `init`'s, `diff`'s, `scan`'s, and `gate`'s stdout
writes are routed through a dedicated `controlloop.output.OutputStreams`
primitive, not through ad hoc `print`/`echo` calls. The primitive
enforces one rule: machine-readable data goes to stdout and only stdout,
and progress, warnings, or diagnostics go to stderr and only stderr.
`bom` (without `--output`) is the first command whose stdout carries more
than a fixed string: exactly one canonical ACBOM JSON document, with any
completeness summary routed to stderr instead. `init --dry-run` is the
same shape for the draft manifest; `init` without `--dry-run` writes the
draft to a file instead and leaves stdout empty on success, with any
completeness summary still routed to stderr. `diff` is the same shape
again: exactly one document (the `--format text` summary or the
`--format json` report) on stdout, with every completeness summary and
progress line on stderr instead -- see [`diff`'s own section](#diff)
above. `scan` is the same shape once more, with a third format (`--format
sarif`) added -- see [`scan`'s own section](#scan) above. `gate` is the
same shape again -- see [`gate`'s own section](#gate) above -- plus it
also writes the evidence artifact to `--evidence-path` as a second,
independent output alongside stdout, unconditionally for every verdict
it reaches.

The same primitive also implements, and is unit-tested for:

- disabling color and progress rendering automatically when stdout is not a
  terminal, and whenever the `NO_COLOR` environment variable is present
  (regardless of its value), per [no-color.org](https://no-color.org); and
- failing closed with exit code `2` instead of blocking on stdin when an
  interactive confirmation is requested but stdout is not a terminal.

Neither behavior is independently observable through the current command
surface, because no implemented command -- including `scan` and `gate`
-- currently renders color, shows progress, or prompts interactively
(`scan`'s and `gate`'s own `--format text` rendering both always pass
`color_enabled=False`; `gate` must never prompt at all, asserted
structurally in `tests/test_cli.py`). They exist as a
tested foundation for future color/progress behavior. Do not treat this
section as availability of color or progress rendering.

## Verbosity and logging

`--log-level` selects one of four levels -- `quiet`, `default`, `verbose`, or
`debug` -- also selectable via the `CONTROLLOOP_LOG_LEVEL` environment
variable (the flag wins if both are set). `--log-format` selects `text`
(default) or `json`, also selectable via `CONTROLLOOP_LOG_FORMAT`. Both are
global options: they apply to every subcommand, not only `--show-config` or
`bom`.

Raising the level only ever *adds* optional diagnostic lines to standard
error -- it never changes a command's standard output, a finding, a gate
result, or an exit code. `--show-config`, `bom`, `init`, `diff` (in its
repository-plus-baseline usage form only -- its two-ACBOM-file form resolves
no repository root or configuration at all, so it emits neither line),
`scan`, and `gate` each emit two such lines at `verbose` (the resolved
repository root) and `debug` (an additional implementation-specific
detail: the checked `controlloop.toml` path for `--show-config`, the
resolved traversal bounds for `bom`, `init`, `diff`, `scan`, and `gate`).
`quiet` and `default` are observably identical today, since none of
these commands has an existing default-level diagnostic for `quiet` to
suppress -- there is nothing to demonstrate beyond "no extra lines
appear," which is also true at `default`.

```bash
$ uv run controlloop --log-level debug --show-config
• VERBOSE  resolved repository root: /path/to/repo
• DEBUG  checking repository configuration file: /path/to/repo/controlloop.toml
max_depth = 100  (default)
max_file_count = 50000  (default)
max_file_size_bytes = 10000000  (default)
max_total_bytes = 500000000  (default)
```

With `--log-format json`, the same lines become one JSON object per line on
standard error instead:

```bash
$ uv run controlloop --log-level debug --log-format json --show-config 1>/dev/null
{"level": "verbose", "message": "resolved repository root: /path/to/repo"}
{"level": "debug", "message": "checking repository configuration file: /path/to/repo/controlloop.toml"}
```

An unrecognized `--log-level`/`--log-format` value is rejected by Typer's own
choice validation before any command runs; an unrecognized
`CONTROLLOOP_LOG_LEVEL`/`CONTROLLOOP_LOG_FORMAT` value is rejected the same
way `--show-config`'s configuration errors are, at exit `2`, naming the
environment variable and the valid choices, never the invalid value supplied.

These lines pass through the same redaction boundary as every other output
this process writes (see [Output stream separation](#output-stream-separation)
above and [Privacy, security, and limitations](privacy-security.md)) --
including at `debug`, which is the level most likely to interpolate a
repository-controlled value such as a path.

## Next step

Follow [Current CLI quickstart](../getting-started/quickstart.md) for a verified
walkthrough, review [Configuration loading and precedence](configuration.md)
for `--show-config`, or check [Adapter status](../adapters/readme.md)
before relying on a source format.
