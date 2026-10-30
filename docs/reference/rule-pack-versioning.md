---
type: reference
title: Rule pack versioning
tags:
  - reference
  - policy
created: 2026-08-20
---

# Rule pack versioning

**Status: Implemented foundation.** `RulePack`, `rule_pack_fingerprint`,
and the bundled `CURRENT_RULE_PACK` described below are implemented and
tested library code, and `controlloop --version` genuinely reports the
bundled pack's name, version, and rule count. `CURRENT_RULE_PACK`
carries every registered rule with a decided `RuleMetadata.mandatory`
flag per rule. **No CLI command evaluates
a real `RulePack` end to end for rule *execution*, by deliberate design**
-- `scan` and `gate` (see the [CLI reference](cli.md)) both read their
rules directly from `controlloop.policy.rules.ALL_RULES` for execution
rather than from `CURRENT_RULE_PACK.rules` (identical content now), while
consuming `CURRENT_RULE_PACK.metadata` for `validate_disabled_rules` and
`CURRENT_RULE_PACK`'s name/version/fingerprint for
`GateVerdict`/`EvidenceArtifact` identity.

## What this is

`controlloop.findings.models.Finding.rule_version` validates a
semantic-version *shape* only. `controlloop.policy.rulepack` is its
reserved successor: a rule pack -- a versioned, named collection of
rules -- independent of the scanner's own version, so a verdict can be
reproduced exactly against a pinned rule pack version.

## The model

```python
class RulePackError(ValueError): ...  # a malformed pack is a programming defect


class RulePack:  # a frozen dataclass
    name: str  # SafeIdentifier shape
    version: str  # SemanticVersion shape
    rules: tuple[Rule, ...]  # controlloop.policy.models.Rule (execution)
    metadata: tuple[
        RuleMetadata, ...
    ]  # controlloop.policy.thresholds.RuleMetadata (governance)


def rule_pack_fingerprint(
    pack: RulePack,
) -> str: ...  # deterministic SHA-256 hex digest


CURRENT_RULE_PACK: (
    RulePack  # name="controlloop-community", version="0.6.0", every registered rule
)

KNOWN_RULE_PACK_FINGERPRINTS: dict[
    str, str
]  # {"0.1.0": "<pinned hex>", "0.2.0": "<pinned hex>", "0.3.0": "<pinned hex>", "0.4.0": "<pinned hex>", "0.5.0": "<pinned hex>", "0.6.0": "<pinned hex>"}
```

## Why `rules`/`metadata` stay two parallel tuples, not one merged type (deliberate, disclosed)

`Rule` (execution) and `RuleMetadata` (governance -- whether a rule may
be disabled) are both already-shipped, independently-owned shapes. `RulePack.__post_init__` enforces they name
the exact same set of rule ids -- a pack cannot execute a rule it declares
no governance metadata for, or vice versa -- without merging either
already-shipped type into something new.

## The fingerprint: how a silent rule change fails CI

`rule_pack_fingerprint` hashes, for every rule in the pack, its id,
SHA-256 digests of its `evaluate` callable's own source text and of the
full source of the module that defines it, and its `mandatory` flag --
sorted by rule id so order never matters -- together with the source of
the shared rule helper modules, `controlloop.policy.rules._authority` and
`controlloop.policy.rules._shared`. All of it is read with
`inspect.getsource`, the same introspection primitive
[`controlloop.policy.engine`](rule-engine.md)'s own structural safety check
already uses. A rule's `evaluate` is a one-line wrapper over its
`findings`, so the module source is what makes a change to a rule's real
logic visible; before `0.6.0`, only `evaluate` was hashed and such a change
moved no pin. `KNOWN_RULE_PACK_FINGERPRINTS` pins one hand-computed, hardcoded
fingerprint per declared version, deliberately **not**
`{CURRENT_RULE_PACK.version: rule_pack_fingerprint(CURRENT_RULE_PACK)}`
computed at import time -- self-computing the pinned value from the same
pack it checks against would always pass by construction, catching
nothing. A future change that adds, removes, or changes a rule in
`CURRENT_RULE_PACK` without adding a *new* pinned entry for a *new* version
changes the *computed* fingerprint away from the *pinned* one, failing
`tests/policy/test_rule_pack.py`'s
`test_current_rule_pack_fingerprint_matches_pinned_registry`: adding,
removing, or changing a rule's behavior without a version increment
fails CI.

**Disclosed limitation:** the fingerprint detects a change to a rule's
module, to a shared rule helper module, or to a rule's `mandatory` flag,
and a rule being added or removed. It does not cover code outside those
modules that a rule reaches indirectly, such as the finding model or the
[material capability taxonomy](material-capability-taxonomy.md), so a
behavior change made only there still needs a deliberate version bump.
Any edit to a covered module moves the fingerprint, a comment included,
so a pin can also move with no behavior change; a needless version bump
is the safe direction to err in. A best-effort mechanism, not a general
semantic-diff tool, the same "best-effort, disclosed" framing
[`controlloop.policy.engine`](rule-engine.md)'s own structural safety check
already established for this codebase.

## `--version` reports the rule pack

```bash
$ uv run controlloop --version
ControlLoop 0.1.0
Supported OASF versions: none yet
Agent host key sets (documentation read on): claude-code 2026-10-17, codex 2026-10-17, cursor 2026-10-17, gemini-cli 2026-10-17, kiro 2026-10-17, roo-code 2026-10-29
Rule pack: controlloop-community 0.9.0 (24 rules)
```

## A gate result records both versions

[`GateVerdict`](policy-thresholds.md) gained four fields, a deliberate,
additive amendment: `scanner_version`, `rule_pack_name`,
`rule_pack_version`, `rule_pack_fingerprint`. `evaluate_gate` takes these as four required,
plain-string keyword arguments rather than a `RulePack` object --
`controlloop.policy.thresholds` never imports `controlloop.policy.rulepack`
(only the reverse), avoiding a circular import.

## Reproducibility

`controlloop.policy.engine.evaluate` already guarantees identical
output for identical `rules`/`context` -- the rule engine's own
determinism requirement. "Pinning a rule pack version reproduces a prior
verdict on unchanged input" is that same guarantee applied to a pack's
`rules`: run the same pinned `RulePack.rules` against the same
`RuleContext` twice and the result is byte-identical, proven directly by
`tests/policy/test_rule_pack.py`'s
`test_pinning_a_rule_pack_version_reproduces_prior_verdict_on_unchanged_input`.

## Versions

| Version | Rules | Change |
| --- | --- | --- |
| `0.1.0` | 0 | Empty pack, before any rule shipped. |
| `0.2.0` | 10 | The original ten rules. |
| `0.3.0` | 14 | Adds `policy.unpinned-agent-component`, `policy.mcp-server-identity-change`, `policy.overprivileged-agent-workflow`, and `policy.component-self-grant`, and extends `policy.hardcoded-secrets` to agent configuration. |
| `0.4.0` | 17 | Adds `policy.agent-hook-command-change`, `policy.widened-permission-rule`, and `policy.permission-bypass-from-project`. Before its first release, a read-only tool allow rule was set to `medium`; the change is outside `evaluate`, so the pinned fingerprint is unchanged. |
| `0.5.0` | 18 | Adds `policy.unsanctioned-agent-component`, a Team rule: it is loaded only on a Team gate with an effective organization policy, so a Community run is unchanged. |
| `0.6.0` | 18 | The same rules; `policy.hardcoded-secrets` findings get one ID per occurrence. The fingerprint now covers each rule's whole module and the shared rule helpers, so a change to a rule's logic moves it; earlier pins used `evaluate` source only and can no longer be recomputed. |
| `0.7.0` | 18 | The same rules; `policy.exfiltration-triangle` (1.1.0) reads a declared untrusted-input leg (`external_inputs` in `controlloop.yaml`) as confirmed and an inferred one (an A2A card's endpoint) as unknown, reported at `medium` with the other two legs present instead of silence. |
| `0.8.0` | 23 | Adds five coding-agent rules read from attributes the adapters already record: `policy.agent-sandbox-weakened`, `policy.secret-exposed-to-untrusted-agent-run`, `policy.credentialed-remote-mcp-server`, `policy.workspace-scope-expansion`, and `policy.component-shell-execution`. `policy.permission-bypass-from-project` (1.1.0) hands Claude Code's `sandbox.enabled` to the sandbox rule, and `policy.agent-hook-command-change` (1.1.0) hands skill shell lines and plugin `bin/` to the component rule. |
| `0.9.0` | 24 | Adds `policy.hook-script-changed`, which reads the `script_digest` the Claude Code, Codex, Gemini CLI, Cursor, and Kiro adapters now record for a hook's script. `policy.unresolved-dynamic-registration` is unchanged in behaviour; its docstring moves the fingerprint, since the CrewAI, LangGraph, and OpenAI Agents SDK adapters now emit the diagnostic it reads. |

## Known limitations

- **No CLI command evaluates a real `RulePack` end to end for rule
  execution.** `scan` and `gate` (see the [CLI reference](cli.md)) both
  read their rules directly from `ALL_RULES` for execution -- see the
  status line above -- though both now consume `CURRENT_RULE_PACK.metadata`
  for `validate_disabled_rules`.
- **`CURRENT_RULE_PACK` carries every rule** that exists in
  `controlloop.policy.rules.ALL_RULES`, each paired with a decided
  `RuleMetadata.mandatory` governance flag since version `0.2.0` (a
  disclosed, reviewable classification; see `controlloop.policy.rules`'s
  module docstring). Expiring suppressions are implemented, but are a
  suppression *mechanism*, not a rule -- they do not appear in
  `ALL_RULES` or `CURRENT_RULE_PACK`.
- The fingerprint mechanism is disclosed as narrow, not a general
  semantic-diff tool -- see above.
- `Finding.rule_version` is unchanged: still shape-validated only,
  and still deliberately excluded from finding identity. Nothing yet
  connects a `Finding`'s own `rule_version` to
  `RulePack.version`/`rule_pack_fingerprint`.

## Next steps

- Review [Severity, confidence, and thresholds](policy-thresholds.md) for
  `GateVerdict`, the type the rule pack identity extends.
- Review [Deterministic rule engine](rule-engine.md) for `Rule` and the
  structural safety check `rule_pack_fingerprint` reuses the introspection
  technique of.
- Review [Finding model](finding-model.md) for `rule_version`, the field
  `controlloop.policy.rulepack` is the reserved successor of.
- Review the [CLI reference](cli.md) for what is available today.
