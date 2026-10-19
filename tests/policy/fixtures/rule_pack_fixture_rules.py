"""Test-only fixture rule module for
`tests/policy/test_rule_pack.py`. Imports nothing outside the
standard library's own safe surface and performs no file, process,
network, or model access -- kept in a separate file from the test module
itself (mirroring `tests/policy/fixtures/safe_rule.py`'s own
precedent) specifically so `controlloop.policy.engine`'s own structural
safety check, which walks a rule's *entire defining module* for
forbidden imports, is not tripped by an unrelated `import socket`
elsewhere in the test module (for example, inside a `TestOffline` case).

Never registered as a real rule anywhere outside this test package.
"""

from __future__ import annotations

from controlloop.policy.models import RuleContext, RuleObservation


def evaluate_a(context: RuleContext) -> tuple[RuleObservation, ...]:
    return tuple(
        RuleObservation(
            rule_id="policy.rule-a",
            message=f"rule-a observed {node.id}",
            evidence=node.evidence,
        )
        for node in context.acbom.nodes
    )


def evaluate_a_changed(context: RuleContext) -> tuple[RuleObservation, ...]:
    # Deliberately different source text (a different message string) from
    # `evaluate_a`, so `inspect.getsource` produces a different digest --
    # simulates "a rule's behavior changed" for the drift-detection tests.
    return tuple(
        RuleObservation(
            rule_id="policy.rule-a",
            message=f"rule-a NOW REPORTS {node.id} DIFFERENTLY",
            evidence=node.evidence,
        )
        for node in context.acbom.nodes
    )


def evaluate_b(context: RuleContext) -> tuple[RuleObservation, ...]:
    return tuple(
        RuleObservation(
            rule_id="policy.rule-b",
            message=f"rule-b observed {node.id}",
            evidence=node.evidence,
        )
        for node in context.acbom.nodes
    )
