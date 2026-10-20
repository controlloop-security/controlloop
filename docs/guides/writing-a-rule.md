---
type: guide
title: Writing a rule
tags:
  - guide
  - policy
  - contributing
created: 2026-10-20
---

# Writing a rule

A rule is a small, deterministic Python function that reads the Agent
Capability Bill of Materials (ACBOM) and reports findings. This guide walks
through adding one, from the data it needs to the pull request, and lists
every file a new rule touches.

Open an issue before you start: a new rule changes what can block a build,
which [CONTRIBUTING](../../CONTRIBUTING.md) asks to be agreed first.

## How a rule fits in

1. **Adapters read files.** Each adapter in `src/controlloop/adapters/`
   parses one kind of configuration (`.mcp.json`, Claude Code settings,
   Codex config, IAM policies, workflows) into ACBOM nodes and edges, with
   attributes such as `package`, `package_version`, or `command`.
2. **Rules read the ACBOM, never files.** The engine
   (`src/controlloop/policy/engine.py`) hands each rule a `RuleContext`:
   the ACBOM, the diff against the baseline on a pull request, and the
   repository's `controlloop.yaml`. A rule never opens a file, runs a
   process, or touches the network; the engine refuses to run a rule whose
   module imports `os`, `subprocess`, `socket`, `shutil`, `urllib`, `http`,
   or a known LLM SDK, or calls `open(...)`. See the [rule
   engine](../reference/rule-engine.md).
3. **Findings decide the gate.** Each finding carries a severity and a
   confidence. With the default `severity_threshold` of `high`, a `high` or
   `critical` finding blocks; see [Policy severity, confidence, and
   thresholds](../reference/policy-thresholds.md).

So the first question for any rule is whether the ACBOM already holds what
it needs. Read the adapter for the configuration you care about and check
which node attributes it records. If the data is missing, the adapter
changes first, in its own pull request, with its own tests.

## Before you write code

Decide, and write down in the issue:

- **The rule ID.** `policy.<kebab-case-name>`, for example
  `policy.mcp-server-identity-change`. It never changes once released:
  findings, suppressions, `disabled_rules`, and documentation links all
  key on it. The module is the same name in snake case.
- **What it reports, and what it stays silent on.** Name the cases that
  must not produce a finding; they become your negative tests.
- **Severity per case.** Look at the tables in the [policy
  rules](../reference/policy-rules.md) reference for comparable rules. A
  change a reviewer must see before merge is usually `high`; a risky
  state found on a first scan, with no change to review, is usually lower.
- **First scan versus pull request.** Many rules report only what a pull
  request added or changed, so a repository's first scan is not blocked
  on authority it has always had. Decide which your rule does.
- **Mandatory or not.** A mandatory rule cannot be turned off with
  `disabled_rules`. Reserve it for narrow, high-confidence detections
  central to the product.
- **Whether it reads coding-agent authority.** Rules see coding-agent host
  components (hooks, plugins, skills, permission rules, agent-running
  workflows) only when they declare `reads_agent_authority=True`.

## Write the rule

Create `src/controlloop/policy/rules/<name>.py`. Every rule has the same
shape: a module docstring that states the risk and the severities, a
`findings()` function with the logic, a thin `evaluate()` the engine calls,
and a module-level `RULE`.

```python
"""Rule: <one line on what it detects>.

<Why it matters, with a real incident if there is one. The severity for
each case, and what is silent.>
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.<name>"
_RULE_VERSION = "1.0.0"

_REMEDIATION = "<What to do about it, in one or two sentences.>"


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for node in authority.nodes_with_subtype(context, "<subtype>"):
        state = authority.component_state(context, node)
        if state is None or state is FindingChangeState.REMOVED:
            continue
        # ... decide whether this node is a finding, and how severe ...
        results.append(
            authority.build_finding(
                rule_id=RULE_ID,
                rule_version=rule_version,
                message=f"<What happened to '{node.name}'.>",
                node=node,
                context=context,
                severity=FindingSeverity.HIGH,
                confidence=Confidence.HIGH,
                change_state=state,
                remediation=_REMEDIATION,
            )
        )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = ["RULE", "RULE_ID", "evaluate", "findings"]
```

`findings()` holds all the logic and `evaluate()` only adapts it to the
engine, so the two can never disagree. Keep the output deterministic: sort
what you return, and never depend on dictionary order, time, or the
environment.

The helpers in `src/controlloop/policy/rules/_authority.py` cover most of
what a rule needs:

| Helper | Use |
| --- | --- |
| `nodes_with_subtype` | Nodes of the subtypes the rule inspects. |
| `component_state` | `added`, `changed`, `removed`, or `not-compared` (no baseline, as on a first scan); `None` when the component is unchanged and the rule should say nothing. |
| `baseline_node` | The same node as it was in the baseline, to compare fields. |
| `changed_attributes` | Which attributes differ from the baseline. |
| `edges_into`, `edges_out_of`, `owning_host` | Walk the graph around a node. |
| `build_finding` | Build the `Finding`, including the documentation link, and apply `controlloop.yaml` approvals (an approved component drops to `info`, which never blocks). |
| `observations` | Turn findings into the `RuleObservation`s `evaluate()` returns. |

Rules about agents a repository ships, rather than coding-agent hosts, use
`src/controlloop/policy/rules/_shared.py` and
`controlloop.findings.finding_from_observation`; `undeclared_tools.py` is a
short example.

Never put raw repository content into a message: name the component, the
file, and the changed field, the way existing rules do. Secrets, prompts,
and environment values must never reach the output.

## Register it

1. **`src/controlloop/policy/rules/__init__.py`:** import `RULE`, `RULE_ID`,
   and `findings` under the rule's names, add the rule to `ALL_RULES`, and
   add the names to `__all__`, following the existing entries.
2. **`src/controlloop/policy/rulepack.py`:**
   - add the rule ID to `_MANDATORY_BY_RULE_ID` with your decision;
   - add a one-line summary to `_SUMMARY_BY_RULE_ID`, written from what the
     code does; `controlloop rules` prints it;
   - bump `CURRENT_RULE_PACK.version` (a new rule is a minor bump);
   - add the new version to `KNOWN_RULE_PACK_FINGERPRINTS` with the value
     `rule_pack_fingerprint(CURRENT_RULE_PACK)` computes. Run it once and
     paste the value; never compute the pinned value at import time.

`tests/policy/test_rule_pack.py` fails until the pinned fingerprint
matches. Two tests state the expected pack version and rule count, so
update both: `test_current_rule_pack_ships_all_registered_rules` in the
same file and `test_version_reports_the_real_populated_rule_pack` in
`tests/test_cli.py`. The version
examples in the README, `docs/getting-started/quickstart.md`, and the
[rule pack versioning](../reference/rule-pack-versioning.md) reference show
the pack version and fingerprint; update them and add a row to that
reference's version table.

## Test it

Add `tests/policy/rules/test_<name>.py`. Rules about coding-agent
configuration build real repositories with the helpers in
`tests/policy/rules/_authority_rule_support.py`: `repos()` makes a base and
a head, `write()` writes a configuration file, and `context(head, base)`
builds the `RuleContext` a pull request would see.
`test_mcp_server_identity_change.py` is a compact example. Rules about
shipped agents build ACBOM nodes directly with
`tests/policy/rules/_helpers.py`.

Cover at least:

- one positive case per severity, asserting severity, change state, and
  the message;
- at least two similar cases that must stay silent, per
  [CONTRIBUTING](../../CONTRIBUTING.md);
- the first-scan behavior you chose;
- an approval in `controlloop.yaml` lowering the finding to `info`, if the
  rule honors approvals;
- `reads_agent_authority`, if the rule sets it.

`tests/policy/rules/test_all_rules_registry.py` lists every rule ID the
registry must hold, in sets named for the issue that added them. Add a set
for your issue with the new ID, and include it in
`test_the_reconciled_registry_has_every_registered_rule`. The same file
runs the whole registry through the real engine and checks that IDs are
unique and evaluation is deterministic.

## Document it

Add a section to [`docs/reference/policy-rules.md`](../reference/policy-rules.md),
with an anchor directly above the heading. The anchor is the rule ID
without `policy.`:

```markdown
<a id="<name>"></a>
## <Rule title>

**Outcome:** ...

**Why this matters:** ...

**Example:** ...

| Change | Severity |
| --- | --- |
| ... | ... |

**Remediation:** ...

**False positives:** ...
```

`tests/policy/rules/test_documentation_urls.py` fails if a registered rule
has no matching anchor, or if its section lacks any of **Why this
matters:**, **Example:**, **Remediation:**, or **False positives:**. Every
finding links to this anchor, so the section is what a developer reads
when your rule blocks their pull request.

Then:

- **Rule counts.** Pages that state the number of rules must match the
  registry; `tests/test_rule_count_documentation_drift.py` finds the ones
  to update, including the README and any `--version` example output.
- **`CHANGELOG.md`.** Add an entry under `## [Unreleased]`.

## Check the outputs

A new rule can change recorded outputs. If the golden tests fail, regenerate
them and read the diff before committing:

```bash
uv run python tests/golden_regenerate.py
git diff tests/fixtures/golden
```

Every change in that diff should be one your rule explains. See [Golden
baselines](../reference/golden-baselines.md).

Then run the full checks from [CONTRIBUTING](../../CONTRIBUTING.md):

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

## Changing a rule later

- **Bump the rule's own `_RULE_VERSION`** when what it reports changes.
- **Bump the rule pack version, and pin its new fingerprint, whenever the
  fingerprint moves.** It covers each rule's whole module and the shared
  helpers in `_authority.py` and `_shared.py`, so any edit there, even to a
  comment, fails `test_current_rule_pack_fingerprint_matches_pinned_registry`
  until you do.
- **Bump it by hand for a change outside those modules.** A rule's
  behavior can also change through code it reaches indirectly, such as the
  finding model or the material capability taxonomy. The fingerprint does
  not cover those, so no test will remind you.
- **Never rename a rule ID or its anchor.** Findings, suppressions, and
  links from older reports depend on both.
- **Changing severity changes what blocks.** Say so in the changelog.

## Checklist

- [ ] Issue agreed: rule ID, what it reports and ignores, severities,
      first-scan behavior, mandatory or not
- [ ] The ACBOM already records the data, or an adapter change landed first
- [ ] `src/controlloop/policy/rules/<name>.py` with docstring, `findings()`,
      `evaluate()`, and `RULE`
- [ ] Registered in `policy/rules/__init__.py` (`ALL_RULES`, `__all__`)
- [ ] `rulepack.py`: mandatory decision, summary, pack version bump, pinned
      fingerprint
- [ ] `tests/policy/rules/test_<name>.py`: positives, two or more similar
      negatives, first scan, approvals
- [ ] The new ID added to `tests/policy/rules/test_all_rules_registry.py`
- [ ] `docs/reference/policy-rules.md` section with its anchor and the four
      required markers
- [ ] Rule counts updated where pages state them
- [ ] `CHANGELOG.md` entry under `## [Unreleased]`
- [ ] Golden outputs regenerated and the diff explained, if they changed
- [ ] Format, lint, type checks, and tests pass
- [ ] Commits signed off (`git commit -s`)

## Next steps

- Read the [rule engine](../reference/rule-engine.md) for the contract
  every rule runs under.
- Read the [finding model](../reference/finding-model.md) for every field
  a finding carries.
- Read the [policy rules](../reference/policy-rules.md) reference for how
  existing rules are documented.
