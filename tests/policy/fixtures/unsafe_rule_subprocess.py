"""Test-only fixture: a rule module that imports `subprocess`.

Used by `tests/policy/test_policy_engine.py` to prove
`controlloop.policy.engine._validate_rule_safety` rejects a rule whose
module could perform subprocess execution, before ever calling it.
Never registered as a real rule anywhere outside this test package.
"""

from __future__ import annotations

import subprocess  # noqa: F401 -- imported only to trigger the structural check

from controlloop.policy.models import RuleContext, RuleObservation


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return ()
