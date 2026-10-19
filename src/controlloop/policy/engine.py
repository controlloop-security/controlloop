"""The deterministic rule engine's own evaluation logic.

This module -- not `controlloop.policy.models`, which is pure data -- is
the one structurally checked for forbidden imports (no file writes,
subprocesses, network access, or language-model SDKs), mirroring
`controlloop.diff.compute`'s own precedent split from
`controlloop.diff.models`. Every real check lives in
`tests/policy/test_policy_engine.py`; see that file's
`test_engine_module_never_imports_forbidden_names` for the direct proof
(the same `ast.parse`/`ast.walk` technique `tests/test_diagnostics.py`
and `tests/test_redaction.py` already established) and `TestRuleSafety`
for the runtime extension this module implements below.

Design decisions recorded permanently here:

1. **Execution order is always canonicalized to `sorted(rule.id)`
   internally**, regardless of the order the caller's `rules` tuple
   arrives in, so results never depend on input order. This is what
   keeps that guarantee robust even when `EvaluationBounds.max_rules` is
   smaller than the number of supplied rules: which rules actually run
   is a deterministic function of their own IDs, never of
   caller-supplied ordering, so a shuffled and an unshuffled call to
   `evaluate()` produce byte-identical results in every case, not merely
   "the same set when nothing was truncated."

2. **A rule's exception propagates uncaught.** Unlike an adapter
   (which parses untrusted, malformed real-world repository content and
   is therefore isolated), a rule here only ever receives
   already-validated canonical models. A rule raising is a defect in
   that rule, not a data-quality problem; converting it into a silent
   diagnostic would risk masking a real bug in this product's own
   deterministic core.

3. **The structural safety check runs twice.** Once, test-only,
   against this module's own source (proving the engine's own machinery
   is clean). Once, at runtime, against every rule module `evaluate()`
   is actually given, before any rule executes (`_validate_rule_safety`
   below) -- a genuine extension beyond direct precedent-copying, since
   this engine is the foundational primitive every concrete rule builds
   on. This is a best-effort, disclosed defense-in-depth guard, not a
   sandbox: the forbidden-import list below is closed and necessarily
   incomplete (a brand-new LLM SDK name it does not yet know about would
   not be caught on day one), and source inspection alone cannot preempt
   a single rule's own unbounded in-process loop -- only stop an
   *external* file/process/network operation from ever being reachable
   through an import.

4. **The evaluation bound is a deterministic step-count proxy, not
   wall-clock**, because a wall-clock bound is flaky under CI load
   and is not itself deterministic. See
   `controlloop.policy.models.EvaluationBounds`.
"""

from __future__ import annotations

import ast
import inspect
from collections.abc import Iterable
from types import ModuleType

from controlloop.acbom.completeness import incomplete_diagnostic
from controlloop.acbom.models import Diagnostic, Evidence
from controlloop.policy.authority_scope import without_agent_authority
from controlloop.policy.models import (
    DuplicateRuleIdError,
    EvaluationBounds,
    EvaluationResult,
    Rule,
    RuleContext,
    RuleObservation,
    RuleSafetyError,
)

#: File-write/subprocess/network primitives, plus known LLM SDK names --
#: one closed, documented, disclosed-as-incomplete set (see this
#: module's own docstring, point 3). Matched against each imported
#: name's top-level component, so `import os.path` and `from os import
#: path` are both caught under `"os"`.
_FORBIDDEN_IMPORT_MODULES: frozenset[str] = frozenset(
    {
        # File writes, subprocess execution, network access.
        "subprocess",
        "socket",
        "os",
        "shutil",
        "urllib",
        "http",
        "ftplib",
        "smtplib",
        "ssl",
        "requests",
        "httpx",
        "aiohttp",
        # Today's known language-model SDK names.
        "openai",
        "anthropic",
        "google.generativeai",
        "cohere",
        "langchain",
        "langchain_openai",
        "transformers",
    }
)

#: Bracket-marker convention `controlloop.capability.compute` already
#: established for `Evidence` that describes a bound on the evaluation
#: itself, not any one file.
_NO_EVIDENCE_MARKER = "<policy-engine-evaluation>"

_BOUND_EXCEEDED_CODE = "INCOMPLETE-BOUND-EXCEEDED"
_ENGINE_ADAPTER_NAME = "policy.engine"


def _imported_top_level_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names.add(node.module.split(".")[0])
    return names


def _has_bare_open_call(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "open"
        for node in ast.walk(tree)
    )


def module_forbidden_imports(module: ModuleType) -> frozenset[str]:
    """Return every name in `_FORBIDDEN_IMPORT_MODULES` that `module`
    actually imports, plus the literal string `"open"` if `module`'s
    source contains a bare `open(...)` call -- the same two structural
    checks `test_diff_module_never_reads_raw_content` already applies to
    `controlloop.diff.compute`. An empty result means `module` is clean
    by this check."""

    tree = ast.parse(inspect.getsource(module))
    forbidden = _imported_top_level_names(tree) & _FORBIDDEN_IMPORT_MODULES
    if _has_bare_open_call(tree):
        forbidden = forbidden | {"open"}
    return frozenset(forbidden)


def _validate_rule_safety(rules: Iterable[Rule]) -> None:
    """Reject every rule whose defining module cannot be verified free
    of forbidden imports, or that has no resolvable source module at
    all, before any rule in this `evaluate()` call is invoked. Checks
    each unique module once, not once per rule sharing it."""

    checked_modules: set[str] = set()
    for rule in rules:
        module = inspect.getmodule(rule.evaluate)
        if module is None:
            raise RuleSafetyError(
                f"rule {rule.id!r} has no resolvable source module; "
                "a rule's evaluate callable must be an ordinary "
                "module-level function so its safety can be verified"
            )
        if module.__name__ in checked_modules:
            continue
        checked_modules.add(module.__name__)

        forbidden = module_forbidden_imports(module)
        if forbidden:
            raise RuleSafetyError(
                f"rule {rule.id!r} (module {module.__name__!r}) is not "
                f"safe to evaluate: forbidden import(s) {sorted(forbidden)!r}"
            )


def _validate_rule_ids(rules: tuple[Rule, ...]) -> None:
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise DuplicateRuleIdError(f"duplicate rule id: {rule.id!r}")
        seen.add(rule.id)


def _observation_sort_key(
    observation: RuleObservation,
) -> tuple[str, str, tuple[tuple[str, str, int, int], ...]]:
    """Fully deterministic regardless of rule execution order or the
    order a single rule returned its own observations in."""

    return (
        observation.rule_id,
        observation.message,
        tuple(
            (
                evidence.adapter,
                evidence.path or "",
                evidence.line_start or 0,
                evidence.line_end or 0,
            )
            for evidence in observation.evidence
        ),
    )


def _bound_diagnostic(message: str) -> Diagnostic:
    return incomplete_diagnostic(
        code=_BOUND_EXCEEDED_CODE,
        message=message,
        evidence=(Evidence(adapter=_ENGINE_ADAPTER_NAME, path=_NO_EVIDENCE_MARKER),),
    )


def evaluate(
    rules: tuple[Rule, ...],
    context: RuleContext,
    *,
    bounds: EvaluationBounds | None = None,
) -> EvaluationResult:
    """Evaluate every rule in `rules` against `context` and return one
    `EvaluationResult`.

    Execution order is always canonicalized to `sorted(rule.id)`
    internally before `bounds.max_rules` is applied, regardless of
    `rules`'s own input order (see this module's own docstring, point
    1). Every rule's module is verified free of forbidden imports before
    any rule runs (point 3). A rule's own exception propagates uncaught
    (point 2). Exceeding either bound in `bounds` adds one
    `INCOMPLETE-BOUND-EXCEEDED` diagnostic and marks
    `EvaluationResult.is_incomplete` `True`, rather than silently
    returning a partial answer. Given an identical `rules` set (any
    order) and an identical `context`, this function always returns a
    byte-identical `EvaluationResult`.
    """

    bounds = bounds or EvaluationBounds()

    _validate_rule_ids(rules)
    _validate_rule_safety(rules)

    canonical = tuple(sorted(rules, key=lambda rule: rule.id))
    executed = canonical[: bounds.max_rules]

    bound_diagnostics: list[Diagnostic] = []
    if len(canonical) > bounds.max_rules:
        skipped = len(canonical) - bounds.max_rules
        bound_diagnostics.append(
            _bound_diagnostic(
                f"evaluation stopped after the configured rule bound of "
                f"{bounds.max_rules}; {skipped} further rule(s) were not "
                "evaluated"
            )
        )

    collected: list[RuleObservation] = []
    scoped_context: RuleContext | None = None
    for rule in executed:
        if rule.reads_agent_authority:
            collected.extend(rule.evaluate(context))
            continue
        if scoped_context is None:
            scoped_context = without_agent_authority(context)
        collected.extend(rule.evaluate(scoped_context))

    ordered = tuple(sorted(collected, key=_observation_sort_key))
    if len(ordered) > bounds.max_observations:
        dropped = len(ordered) - bounds.max_observations
        ordered = ordered[: bounds.max_observations]
        bound_diagnostics.append(
            _bound_diagnostic(
                "evaluation stopped retaining observations after the "
                f"configured observation bound of {bounds.max_observations}; "
                f"{dropped} further observation(s) were dropped"
            )
        )

    return EvaluationResult(
        observations=ordered,
        diagnostics=tuple(sorted(bound_diagnostics, key=lambda d: d.code)),
    )
