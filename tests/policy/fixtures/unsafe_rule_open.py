"""Test-only fixture: a rule module containing a bare `open(...)` call,
with no suspicious import at all.

Used by `tests/policy/test_policy_engine.py` to prove
`controlloop.policy.engine.module_forbidden_imports` catches direct
file access via the bare `open(` structural check alone -- the same
check `tests/test_redaction.py`'s
`test_diff_module_never_reads_raw_content` already applies to
`controlloop.diff.compute`. This function is never actually invoked in
any test; `_validate_rule_safety` rejects the rule before any call.
Never registered as a real rule anywhere outside this test package.
"""

from __future__ import annotations

from controlloop.policy.models import RuleContext, RuleObservation


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    with open("/dev/null") as handle:
        handle.read()
    return ()
