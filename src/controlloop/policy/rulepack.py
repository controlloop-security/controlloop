"""Rule pack versioning.

`controlloop.findings.models.Finding.rule_version` validates a
semantic-version *shape* only. This module defines what actually produces a
version, whether it must increment on behavior change, and how it relates to
an independently versioned rule pack reported by `--version`.

A `RulePack` is a versioned, named collection of rules (execution,
`controlloop.policy.models.Rule`) paired with their policy-governance
metadata (`controlloop.policy.thresholds.RuleMetadata`) -- two
already-shipped, separately-owned shapes, kept as two parallel tuples
rather than merged into a new combined type.

`rule_pack_fingerprint` is the actual enforcement mechanism: a
deterministic SHA-256 digest over every declared rule's own `evaluate`
source text, the full source of the module that defines it, and its
`mandatory` flag, plus the source of the helper modules every rule calls
into (`_SHARED_RULE_MODULES`), all read with `inspect.getsource`, the same
introspection primitive `controlloop.policy.engine`'s own safety check
already uses. A rule's `evaluate` is a thin wrapper over its `findings`,
so hashing `evaluate` alone missed every change to a rule's real logic;
the module source catches it. `KNOWN_RULE_PACK_FINGERPRINTS` pins one
hand-computed, hardcoded fingerprint per declared version; a rule pack
version whose *computed* fingerprint no longer matches its *pinned*
one is exactly "a rule's behavior changed without a version
increment", enforced by `tests/policy/test_rule_pack.py`'s
`test_current_rule_pack_fingerprint_matches_pinned_registry`.

**Disclosed limitation:** the fingerprint detects a change to a rule's
module, to the rule helper modules in `_SHARED_RULE_MODULES`, or to a
rule's `mandatory` flag, and a rule being added or removed. It does not
cover code outside those modules that a rule reaches indirectly, such as
the finding model or the material capability taxonomy, so a behavior
change made only there still needs a deliberate version bump. Any edit to
a covered module changes the fingerprint, including a comment, so a pin
can also move without a behavior change; a needless version bump is the
safe direction to err in. Disclosed as a best-effort mechanism, not a
general semantic-diff tool -- the same "best-effort, disclosed" framing
`controlloop.policy.engine`'s own structural safety check already
established for this codebase.

**Disclosed scope boundary: `scan`/`gate` still execute rules from
`controlloop.policy.rules.ALL_RULES` directly, not
`CURRENT_RULE_PACK.rules`.** `CURRENT_RULE_PACK.rules`/`.metadata`
carry every rule `ALL_RULES` currently defines, paired with a reviewed
`mandatory` decision per rule (see `controlloop.policy.rules`'s own
module docstring). `controlloop.cli`'s `scan`/`gate` commands consume
`CURRENT_RULE_PACK.metadata` for `validate_disabled_rules` and
`CURRENT_RULE_PACK.name`/`.version`/`rule_pack_fingerprint(CURRENT_RULE_PACK)`
for `--version` and every `GateVerdict`/`EvidenceArtifact` identity
field, but deliberately keep reading `ALL_RULES` directly for rule
*execution* -- a decision made before `CURRENT_RULE_PACK` had real
content and kept since, because decoupling rule-pack identity from
execution wiring remains valid regardless of whether the pack is
populated.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import json
from dataclasses import dataclass

from pydantic import TypeAdapter

from controlloop.acbom.models import SafeIdentifier, SemanticVersion
from controlloop.policy.models import Rule
from controlloop.policy.rules import ALL_RULES
from controlloop.policy.thresholds import RuleMetadata

_SAFE_IDENTIFIER_ADAPTER: TypeAdapter[str] = TypeAdapter(SafeIdentifier)
_SEMANTIC_VERSION_ADAPTER: TypeAdapter[str] = TypeAdapter(SemanticVersion)


class RulePackError(ValueError):
    """A `RulePack` failed to validate: a malformed `name`/`version`
    shape, a duplicate rule or metadata id, or `rules`/`metadata` naming
    different id sets. Constructing an invalid `RulePack` is a programming
    defect in this codebase's own bundled pack (or a future caller's), not
    user-supplied input -- unlike `controlloop.config.ConfigError` or
    `controlloop.policy.thresholds.PolicyConfigError`, this carries no
    `exit_code`."""


@dataclass(frozen=True, slots=True)
class RulePack:
    """A versioned, named collection of rules paired with their
    policy-governance metadata. See this module's own docstring for
    why `rules`/`metadata` stay two parallel tuples rather than one
    merged type.

    `__post_init__` rejects, via `RulePackError`: a `name` not shaped like
    `controlloop.acbom.models.SafeIdentifier`; a `version` not shaped like
    `controlloop.acbom.models.SemanticVersion`; a duplicate id within
    `rules`; a duplicate id within `metadata`; or `rules`/`metadata` not
    naming the exact same set of rule ids -- a pack cannot execute a rule
    it declares no governance metadata for, or declare governance metadata
    for a rule it never executes.
    """

    name: str
    version: str
    rules: tuple[Rule, ...]
    metadata: tuple[RuleMetadata, ...]

    def __post_init__(self) -> None:
        _SAFE_IDENTIFIER_ADAPTER.validate_python(self.name)
        _SEMANTIC_VERSION_ADAPTER.validate_python(self.version)

        rule_ids = tuple(rule.id for rule in self.rules)
        if len(set(rule_ids)) != len(rule_ids):
            raise RulePackError(f"rule pack {self.name!r} has a duplicate rule id")

        metadata_ids = tuple(entry.id for entry in self.metadata)
        if len(set(metadata_ids)) != len(metadata_ids):
            raise RulePackError(f"rule pack {self.name!r} has a duplicate metadata id")

        if set(rule_ids) != set(metadata_ids):
            raise RulePackError(
                f"rule pack {self.name!r}: rules and metadata must name the "
                "same set of rule ids"
            )


#: Helper modules the registered rules call into for their detection
#: logic. Their source is part of every fingerprint, so editing a helper
#: moves the pin even though no rule module changed.
_SHARED_RULE_MODULES: tuple[str, ...] = (
    "controlloop.policy.rules._authority",
    "controlloop.policy.rules._shared",
)


def _source_digest(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _rule_fingerprint_entry(
    rule: Rule, metadata_by_id: dict[str, RuleMetadata]
) -> object:
    module = inspect.getmodule(rule.evaluate)
    if module is None:
        raise RulePackError(
            f"rule {rule.id!r}: its evaluate callable has no defining module "
            "to fingerprint"
        )
    return [
        rule.id,
        _source_digest(inspect.getsource(rule.evaluate)),
        _source_digest(inspect.getsource(module)),
        metadata_by_id[rule.id].mandatory,
    ]


def _shared_module_entries() -> list[list[str]]:
    return [
        [name, _source_digest(inspect.getsource(importlib.import_module(name)))]
        for name in _SHARED_RULE_MODULES
    ]


def rule_pack_fingerprint(pack: RulePack) -> str:
    """Return a deterministic SHA-256 hex digest over `pack`'s own
    content: every rule's id, SHA-256 digests of its `evaluate`
    callable's source text and of its defining module's full source, and
    its `mandatory` flag, sorted by rule id so fingerprint order never
    depends on `pack.rules`' own input order (mirroring
    `controlloop.policy.engine.evaluate`'s own canonicalization
    convention), together with a digest of each `_SHARED_RULE_MODULES`
    source. Two `RulePack`s with identical rules (in any order) and
    identical metadata always produce an identical fingerprint;
    changing, adding, or removing a rule, editing its module or a shared
    rule helper, or changing a rule's `mandatory` flag, always changes
    it."""

    metadata_by_id = {entry.id: entry for entry in pack.metadata}
    entries = sorted(
        (_rule_fingerprint_entry(rule, metadata_by_id) for rule in pack.rules),
        key=lambda entry: entry[0],  # type: ignore[index]
    )
    canonical = json.dumps(
        {"rules": entries, "shared": _shared_module_entries()},
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


#: Per-rule `mandatory` governance decision: whether a repository may
#: disable the rule via `controlloop.yaml`'s `disabled_rules`. A reviewed
#: judgment, not a mechanical derivation. Rules whose detection is
#: structural/narrow/high-confidence and whose risk category is central to
#: this product are `mandatory=True`; advisory, pattern-based, or
#: completeness-signaling rules are `mandatory=False`.
_MANDATORY_BY_RULE_ID: dict[str, bool] = {
    "policy.undeclared-tools": False,
    "policy.destructive-or-financial-action": True,
    "policy.broad-permission": False,
    "policy.sensitive-write-without-approval": True,
    "policy.missing-action-logging": False,
    "policy.unauthorized-delegation": False,
    "policy.unresolved-dynamic-registration": False,
    "policy.capability-ceiling": True,
    "policy.exfiltration-triangle": True,
    "policy.hardcoded-secrets": True,
    # Agent-authority rules: not mandatory.
    "policy.unpinned-agent-component": False,
    "policy.mcp-server-identity-change": False,
    "policy.overprivileged-agent-workflow": False,
    "policy.component-self-grant": False,
    "policy.agent-hook-command-change": False,
    "policy.widened-permission-rule": False,
    "policy.permission-bypass-from-project": False,
    # A Team rule; the organization's bundle, not this flag, decides how
    # strictly it applies.
    "policy.unsanctioned-agent-component": False,
}

#: One line per rule naming what it actually detects, surfaced by
#: `controlloop rules`. Each was written from that rule's own module
#: docstring and source, not from its id -- a summary that drifts from
#: real behavior is worse than none. Descriptive only: not a
#: fingerprint input, so editing one never implies a version bump.
_SUMMARY_BY_RULE_ID: dict[str, str] = {
    "policy.undeclared-tools": (
        "A tool an agent can reach, directly or transitively, that the "
        "repository's controlloop.yaml never declares."
    ),
    "policy.destructive-or-financial-action": (
        "A change that gives an agent a destructive or financial action "
        "it did not previously have, against the approved baseline."
    ),
    "policy.broad-permission": (
        "Wildcard or overly broad permission grants, reported with the "
        "breadth they actually confer, from IAM, MCP, or OpenAPI."
    ),
    "policy.sensitive-write-without-approval": (
        "A write to a resource carrying a sensitive data class with no "
        "corresponding, unexpired approval in the manifest."
    ),
    "policy.missing-action-logging": (
        "A tool the capability taxonomy classifies as privileged that "
        "has no declared logging or audit path in logged_tools."
    ),
    "policy.unauthorized-delegation": (
        "An agent delegating to a target outside the manifest's own "
        "allowed_delegation list for that agent."
    ),
    "policy.unresolved-dynamic-registration": (
        "Tools registered dynamically at runtime that static discovery "
        "cannot resolve, so their real authority is unknown."
    ),
    "policy.capability-ceiling": (
        "Any effective authority outside the declared capability "
        "ceiling -- including expansions no pattern rule anticipates."
    ),
    "policy.exfiltration-triangle": (
        "One agent combining sensitive-data access, untrusted input, "
        "and outbound communication, reported as a single finding."
    ),
    "policy.hardcoded-secrets": (
        "Secret material committed into scanned repository files, "
        "reported without ever echoing the secret value."
    ),
    "policy.unpinned-agent-component": (
        "An agent plugin or marketplace added or changed without a commit or "
        "digest pin, so its contents can change upstream."
    ),
    "policy.mcp-server-identity-change": (
        "An MCP server that kept its name while its package, version, "
        "command, or declaration changed."
    ),
    "policy.overprivileged-agent-workflow": (
        "A CI workflow that runs a coding agent with write tokens and "
        "skipped permission prompts, or on untrusted input with no "
        "permissions block."
    ),
    "policy.component-self-grant": (
        "A skill or subagent that grants itself a tool or a bypass mode its "
        "agent host does not allow."
    ),
    "policy.agent-hook-command-change": (
        "A hook or helper command added or changed in an agent host's "
        "committed configuration, with the command it runs."
    ),
    "policy.widened-permission-rule": (
        "An agent allow rule added or changed to a wildcard or to a "
        "superset of the baseline's rules."
    ),
    "policy.permission-bypass-from-project": (
        "A permission or approval mode loosened by a project file, or a "
        "tool auto-approved without a prompt."
    ),
    "policy.unsanctioned-agent-component": (
        "On a Team gate, an agent-authority grant the organization's "
        "approved-components list does not cover."
    ),
}

#: The rule pack this Community CLI ships today: every rule currently
#: registered in `controlloop.policy.rules.ALL_RULES`, paired with the
#: `mandatory` governance decision above. `0.2.0` is a deliberate
#: version bump from `0.1.0`'s honestly-disclosed zero-rule pack --
#: adding real rules to `CURRENT_RULE_PACK` without bumping its version
#: would silently change what `0.1.0`'s pinned fingerprint should have
#: covered (see this module's own docstring and
#: `KNOWN_RULE_PACK_FINGERPRINTS` below).
CURRENT_RULE_PACK = RulePack(
    name="controlloop-community",
    version="0.7.0",
    rules=ALL_RULES,
    metadata=tuple(
        RuleMetadata(
            id=rule.id,
            mandatory=_MANDATORY_BY_RULE_ID[rule.id],
            summary=_SUMMARY_BY_RULE_ID[rule.id],
        )
        for rule in ALL_RULES
    ),
)

#: The actual CI-enforced check (see this module's own docstring): one
#: hand-computed, hardcoded fingerprint per declared rule-pack version.
#: Deliberately **not**
#: `{CURRENT_RULE_PACK.version: rule_pack_fingerprint(CURRENT_RULE_PACK)}`
#: computed at import time -- self-computing the pinned value from the same
#: pack it checks against would always pass by construction, catching
#: nothing. `0.1.0`'s value was computed once, by hand, from a real run of
#: `rule_pack_fingerprint(CURRENT_RULE_PACK)` against that version's actual
#: empty `rules`/`metadata` tuples
#: (`sha256(json.dumps([], separators=(",", ":")).encode()).hexdigest()`)
#: and is kept here unchanged as a permanent historical record, even though
#: `CURRENT_RULE_PACK.version` has since moved on. `0.2.0`'s value was
#: likewise computed once, by hand, from a real run of
#: `rule_pack_fingerprint(CURRENT_RULE_PACK)` against the populated
#: `rules`/`metadata` above. Adding, removing, or changing a rule in
#: `CURRENT_RULE_PACK` without adding a *new* entry here for a *new*
#: version changes the fingerprint
#: `rule_pack_fingerprint(CURRENT_RULE_PACK)` computes away from this
#: pinned value, failing `tests/policy/test_rule_pack.py`'s
#: `test_current_rule_pack_fingerprint_matches_pinned_registry`.
KNOWN_RULE_PACK_FINGERPRINTS: dict[str, str] = {
    "0.1.0": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "0.2.0": "33173e07e721f199ec29939f652efe10d18c40c66dbbeb9c9016be6aaa86bfd8",
    # Four agent-authority rules, 14 in total.
    "0.3.0": "a1f740594f3992d37f79677a9ff04e279f584753f6622979afc881b278216724",
    # Three more agent-authority rules, 17 in total.
    "0.4.0": "c91150a1d8a80626bd6e3bbda6527576f62be4a00227bbfc5aba3ebed0ce06fe",
    # policy.unsanctioned-agent-component, a Team rule, 18 in total.
    "0.5.0": "fcc904c2a47d9a3353a8ddfd3607e7b26140b8476012f0e80c7629babee1edc0",
    # The same rules, with policy.hardcoded-secrets' per-occurrence
    # finding IDs, fingerprinted with each rule's whole module and the
    # shared rule helpers. Every pin above used the older evaluate-only
    # digest and can no longer be recomputed; they stay as a record.
    "0.6.0": "169a7ceb80ffac4ccdb2ab95bc7491cb296f8736ded076f666a3020d3f1a342e",
    # 0.7.0: the exfiltration-triangle rule (1.1.0) reads a declared or
    # inferred untrusted-input leg; an inferred one is reported at
    # medium severity instead of silence or a confident claim.
    "0.7.0": "06beef30e8745a1fd18898c800555aa29dab80ef4e80a446c069e4b532197cde",
}
