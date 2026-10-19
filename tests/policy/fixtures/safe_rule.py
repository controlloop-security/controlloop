"""Test-only fixture rule module for
`tests/policy/test_policy_engine.py`. Imports nothing outside the
standard library's own safe surface and performs no file, process,
network, or model access -- a genuinely safe module, used to prove the
*positive* structural-safety case and to exercise the engine's ordering,
determinism, and bound behavior with predictable, countable output.

Never registered as a real rule anywhere outside this test package.
"""

from __future__ import annotations

from collections.abc import Callable

from controlloop.acbom.models import Evidence
from controlloop.policy.models import RuleContext, RuleObservation


def make_node_evaluate(
    rule_id: str,
) -> Callable[[RuleContext], tuple[RuleObservation, ...]]:
    """Return an `evaluate` function that reports one `RuleObservation`
    per node in `context.acbom.nodes`, tagged with `rule_id`. A factory
    (rather than one fixed function) so a single safe module can back
    several distinctly-identified `Rule`s for the shuffled-order and
    bound tests -- `inspect.getmodule` still resolves every closure it
    returns to this same real module, since `__module__` is fixed at
    the closure's textual definition site, not at call time."""

    def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
        return tuple(
            RuleObservation(
                rule_id=rule_id,
                message=f"{rule_id} observed {node.id}",
                evidence=node.evidence,
            )
            for node in context.acbom.nodes
        )

    return evaluate


def make_bulk_evaluate(
    rule_id: str, *, count: int
) -> Callable[[RuleContext], tuple[RuleObservation, ...]]:
    """Return an `evaluate` function that reports exactly `count`
    observations, independent of `context`'s own size -- used to
    exercise `EvaluationBounds.max_observations` without needing a
    correspondingly large ACBOM fixture."""

    def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
        evidence = (
            context.acbom.nodes[0].evidence
            if context.acbom.nodes
            else (Evidence(adapter="fixture", path="a.json"),)
        )
        return tuple(
            RuleObservation(
                rule_id=rule_id,
                message=f"{rule_id} bulk observation {index}",
                evidence=evidence,
            )
            for index in range(count)
        )

    return evaluate


def make_raising_evaluate(
    message: str,
) -> Callable[[RuleContext], tuple[RuleObservation, ...]]:
    """Return an `evaluate` function that always raises `RuntimeError`
    -- used to prove a rule's own exception propagates out of
    `evaluate()` uncaught rather than being silently isolated."""

    def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
        raise RuntimeError(message)

    return evaluate
