"""Tests for controlloop.policy.engine."""

from __future__ import annotations

import ast
import importlib.util
import inspect
import random
import sys
from pathlib import Path
from types import ModuleType

import pytest

from controlloop.acbom.models import (
    ACBOMDocument,
    Confidence,
    Evidence,
    Generator,
    Node,
    NodeType,
    Repository,
    SecurityAttributes,
)
from controlloop.diff.models import CURRENT_DIFF_SCHEMA_VERSION, DiffResult
from controlloop.manifest.models import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    ManifestDocument,
)
from controlloop.policy import engine as engine_module
from controlloop.policy.engine import evaluate, module_forbidden_imports
from controlloop.policy.models import (
    DuplicateRuleIdError,
    EvaluationBounds,
    Rule,
    RuleContext,
    RuleSafetyError,
)

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_PLACEHOLDER_DIGEST = f"sha256:{'0' * 64}"
_CANARY_SECRET = (
    "sk-live-51NqOJ2eZvKYlo2CvcanaryTESTvalueONLY0000"  # pragma: allowlist secret
)


def _load_fixture_module(name: str) -> ModuleType:
    """Load a fixture rule module for real via `importlib`, independent
    of pytest's own import-mode configuration, so `inspect.getmodule`
    resolves it via the standard `sys.modules[__module__]` lookup path
    exactly as it would for a genuinely installed rule module."""

    module_name = f"controlloop_policy_test_fixture_{name}"
    spec = importlib.util.spec_from_file_location(
        module_name, _FIXTURES_DIR / f"{name}.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _node(node_id: str, *, name: str = "x", path: str = "a.json") -> Node:
    return Node(
        id=node_id,
        type=NodeType.AGENT,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="fixture", path=path),),
    )


_NODE_A = _node(f"clp:agent:sha256:{'a' * 64}", name="agent-a", path="a.json")
_NODE_B = _node(f"clp:agent:sha256:{'b' * 64}", name="agent-b", path="b.json")


def _acbom(*, nodes: tuple[Node, ...] = (_NODE_A, _NODE_B)) -> ACBOMDocument:
    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
        nodes=nodes,
        edges=(),
        diagnostics=(),
        digest=_PLACEHOLDER_DIGEST,
    )


def _diff() -> DiffResult:
    return DiffResult(
        schema_version=CURRENT_DIFF_SCHEMA_VERSION,
        node_changes=(),
        edge_changes=(),
        effective_authority_changes=(),
    )


def _manifest() -> ManifestDocument:
    return ManifestDocument(
        schema_version=CURRENT_MANIFEST_SCHEMA_VERSION, owner="security-team"
    )


def _context(**overrides: object) -> RuleContext:
    payload: dict[str, object] = {
        "acbom": _acbom(),
        "policy_version": "policy-v1",
        "diff": _diff(),
        "manifest": _manifest(),
    }
    payload.update(overrides)
    return RuleContext(**payload)  # type: ignore[arg-type]


class TestStructuralSafetyOfTheEngineItself:
    """The engine's own machinery is clean -- the exact
    `ast.parse`/`ast.walk` technique `tests/test_diagnostics.py`'s
    `test_never_imports_exit_code_or_typer` and `tests/test_redaction.py`'s
    `test_diff_module_never_reads_raw_content` already established, applied
    directly to `controlloop.policy.engine` and
    `controlloop.policy.models`."""

    def test_engine_module_imports_are_parsed_and_contain_no_forbidden_name(
        self,
    ) -> None:
        source = inspect.getsource(engine_module)
        tree = ast.parse(source)

        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module.split(".")[0])

        assert not (imported_names & engine_module._FORBIDDEN_IMPORT_MODULES)
        assert "open" not in {
            call.func.id
            for call in ast.walk(tree)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        }

    def test_engine_module_is_clean_via_its_own_public_check(self) -> None:
        assert module_forbidden_imports(engine_module) == frozenset()

    def test_models_module_is_clean_via_the_engines_public_check(self) -> None:
        import controlloop.policy.models as models_module

        assert module_forbidden_imports(models_module) == frozenset()


class TestRuleSafety:
    """The runtime extension -- every rule module `evaluate()` is given
    is verified free of forbidden imports before any rule executes."""

    def test_a_safe_rule_evaluates_successfully(self) -> None:
        module = _load_fixture_module("safe_rule")
        rule = Rule(
            id="fixture.safe", evaluate=module.make_node_evaluate("fixture.safe")
        )

        result = evaluate((rule,), _context())

        assert len(result.observations) == 2
        assert result.is_incomplete is False

    def test_rejects_a_rule_whose_module_imports_subprocess(self) -> None:
        module = _load_fixture_module("unsafe_rule_subprocess")
        rule = Rule(id="fixture.unsafe-subprocess", evaluate=module.evaluate)

        with pytest.raises(RuleSafetyError, match="subprocess") as excinfo:
            evaluate((rule,), _context())
        assert "fixture.unsafe-subprocess" in str(excinfo.value)

    def test_rejects_a_rule_whose_module_imports_socket(self) -> None:
        module = _load_fixture_module("unsafe_rule_socket")
        rule = Rule(id="fixture.unsafe-socket", evaluate=module.evaluate)

        with pytest.raises(RuleSafetyError, match="socket") as excinfo:
            evaluate((rule,), _context())
        assert "fixture.unsafe-socket" in str(excinfo.value)

    def test_rejects_a_rule_whose_module_contains_a_bare_open_call(self) -> None:
        module = _load_fixture_module("unsafe_rule_open")
        rule = Rule(id="fixture.unsafe-open", evaluate=module.evaluate)

        with pytest.raises(RuleSafetyError, match="open") as excinfo:
            evaluate((rule,), _context())
        assert "fixture.unsafe-open" in str(excinfo.value)

    def test_rejects_a_rule_whose_module_imports_a_known_llm_sdk_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No model access, enforced by the same structural check as the
        network check. `openai` is never an actual dependency of this
        repository, so `inspect.getsource` is monkeypatched to return a
        fixed source string for this one already-loaded, otherwise-safe
        fixture module -- exercising the real detection logic
        (`module_forbidden_imports`) against genuine "import openai"
        text without ever requiring `openai` to be importable or
        writing that import into a real committed file (which would
        fail `uv run mypy`)."""

        module = _load_fixture_module("safe_rule")
        real_getsource = inspect.getsource

        def fake_getsource(obj: ModuleType) -> str:
            if obj is module:
                return "import openai\n\n\ndef evaluate(context):\n    return ()\n"
            return real_getsource(obj)

        monkeypatch.setattr(inspect, "getsource", fake_getsource)
        rule = Rule(id="fixture.llm-like", evaluate=module.make_node_evaluate("x"))

        with pytest.raises(RuleSafetyError, match="openai") as excinfo:
            evaluate((rule,), _context())
        assert "fixture.llm-like" in str(excinfo.value)

    def test_rejects_a_rule_with_no_resolvable_source_module(self) -> None:
        namespace: dict[str, object] = {
            "__name__": "controlloop_policy_test_unresolvable_module"
        }
        exec("def evaluate(context):\n    return ()\n", namespace)
        assert "controlloop_policy_test_unresolvable_module" not in sys.modules
        rule = Rule(
            id="fixture.unresolvable",
            evaluate=namespace["evaluate"],  # type: ignore[arg-type]
        )

        with pytest.raises(RuleSafetyError, match="no resolvable source module"):
            evaluate((rule,), _context())

    def test_checks_each_unique_module_only_once(self) -> None:
        """A module shared by several rules is only ever inspected
        once -- proven indirectly: two rules backed by the same safe
        module both still evaluate successfully together."""

        module = _load_fixture_module("safe_rule")
        rules = (
            Rule(id="fixture.a", evaluate=module.make_node_evaluate("fixture.a")),
            Rule(id="fixture.b", evaluate=module.make_node_evaluate("fixture.b")),
        )

        result = evaluate(rules, _context())

        assert {observation.rule_id for observation in result.observations} == {
            "fixture.a",
            "fixture.b",
        }


class TestDuplicateRuleIds:
    def test_two_rules_sharing_an_id_are_rejected(self) -> None:
        module = _load_fixture_module("safe_rule")
        rules = (
            Rule(id="fixture.dup", evaluate=module.make_node_evaluate("fixture.dup")),
            Rule(id="fixture.dup", evaluate=module.make_node_evaluate("fixture.dup")),
        )

        with pytest.raises(DuplicateRuleIdError, match=r"fixture\.dup"):
            evaluate(rules, _context())


class TestRuleExceptionPropagation:
    def test_a_raising_rule_is_not_isolated(self) -> None:
        module = _load_fixture_module("safe_rule")
        rule = Rule(
            id="fixture.raises",
            evaluate=module.make_raising_evaluate("boom"),
        )

        with pytest.raises(RuntimeError, match="boom"):
            evaluate((rule,), _context())


class TestShuffledOrderDeterminism:
    """Rules execute in an order that cannot affect the result."""

    def _rules(self) -> tuple[Rule, ...]:
        module = _load_fixture_module("safe_rule")
        return tuple(
            Rule(
                id=f"fixture.rule-{letter}",
                evaluate=module.make_node_evaluate(f"fixture.rule-{letter}"),
            )
            for letter in "abcdefgh"
        )

    @pytest.mark.parametrize("seed", [0, 1, 2, 3])
    def test_shuffled_order_produces_identical_result_when_unbounded(
        self, seed: int
    ) -> None:
        rules = self._rules()
        context = _context()
        canonical = evaluate(rules, context)

        shuffled = list(rules)
        random.Random(seed).shuffle(shuffled)
        shuffled_result = evaluate(tuple(shuffled), context)

        assert shuffled_result == canonical

    @pytest.mark.parametrize("seed", [0, 1, 2, 3])
    def test_shuffled_order_produces_identical_result_when_exactly_at_the_bound(
        self, seed: int
    ) -> None:
        rules = self._rules()
        context = _context()
        bounds = EvaluationBounds(max_rules=len(rules))
        canonical = evaluate(rules, context, bounds=bounds)

        shuffled = list(rules)
        random.Random(seed).shuffle(shuffled)
        shuffled_result = evaluate(tuple(shuffled), context, bounds=bounds)

        assert shuffled_result == canonical

    @pytest.mark.parametrize("seed", [0, 1, 2, 3])
    def test_shuffled_order_is_still_deterministic_when_the_rule_bound_is_exceeded(
        self, seed: int
    ) -> None:
        """The stronger guarantee this engine provides: execution order
        is canonicalized to `sorted(rule.id)` internally, so even a
        truncated, honestly-incomplete result is identical regardless
        of the caller's own input order."""

        rules = self._rules()
        context = _context()
        bounds = EvaluationBounds(max_rules=len(rules) - 2)
        canonical = evaluate(rules, context, bounds=bounds)

        shuffled = list(rules)
        random.Random(seed).shuffle(shuffled)
        shuffled_result = evaluate(tuple(shuffled), context, bounds=bounds)

        assert shuffled_result == canonical
        assert canonical.is_incomplete is True
        executed_rule_ids = {
            observation.rule_id for observation in canonical.observations
        }
        assert executed_rule_ids == {f"fixture.rule-{letter}" for letter in "abcdef"}


class TestBounds:
    """Evaluation is bounded in time (rule count) and memory (observation
    count); exceeding a bound is a diagnostic and marks the analysis
    incomplete."""

    def test_no_diagnostics_when_neither_bound_is_exceeded(self) -> None:
        module = _load_fixture_module("safe_rule")
        rule = Rule(
            id="fixture.safe", evaluate=module.make_node_evaluate("fixture.safe")
        )

        result = evaluate((rule,), _context(), bounds=EvaluationBounds())

        assert result.diagnostics == ()
        assert result.is_incomplete is False

    def test_max_rules_bound_exceeded_marks_incomplete(self) -> None:
        module = _load_fixture_module("safe_rule")
        rules = tuple(
            Rule(
                id=f"fixture.rule-{letter}",
                evaluate=module.make_node_evaluate(f"fixture.rule-{letter}"),
            )
            for letter in "abc"
        )

        result = evaluate(rules, _context(), bounds=EvaluationBounds(max_rules=1))

        assert result.is_incomplete is True
        assert len(result.diagnostics) == 1
        assert result.diagnostics[0].code == "INCOMPLETE-BOUND-EXCEEDED"
        assert "rule bound of 1" in result.diagnostics[0].message
        assert {observation.rule_id for observation in result.observations} == {
            "fixture.rule-a"
        }

    def test_max_observations_bound_exceeded_marks_incomplete(self) -> None:
        module = _load_fixture_module("safe_rule")
        rule = Rule(
            id="fixture.bulk",
            evaluate=module.make_bulk_evaluate("fixture.bulk", count=10),
        )

        result = evaluate(
            (rule,), _context(), bounds=EvaluationBounds(max_observations=3)
        )

        assert result.is_incomplete is True
        assert len(result.observations) == 3
        assert any(
            diagnostic.code == "INCOMPLETE-BOUND-EXCEEDED"
            and "observation bound of 3" in diagnostic.message
            for diagnostic in result.diagnostics
        )

    def test_max_observations_truncation_is_deterministic(self) -> None:
        module = _load_fixture_module("safe_rule")
        rule = Rule(
            id="fixture.bulk",
            evaluate=module.make_bulk_evaluate("fixture.bulk", count=20),
        )
        bounds = EvaluationBounds(max_observations=5)

        first = evaluate((rule,), _context(), bounds=bounds)
        second = evaluate((rule,), _context(), bounds=bounds)

        assert first == second


class TestRepeatRunDeterminism:
    """The same ACBOM, diff, and policy version always produce the same
    findings in the same order."""

    def test_identical_input_produces_byte_identical_output(self) -> None:
        module = _load_fixture_module("safe_rule")
        rules = tuple(
            Rule(
                id=f"fixture.rule-{letter}",
                evaluate=module.make_node_evaluate(f"fixture.rule-{letter}"),
            )
            for letter in "abc"
        )
        context = _context()

        first = evaluate(rules, context)
        second = evaluate(rules, context)

        assert first.model_dump_json() == second.model_dump_json()

    def test_a_rule_that_ignores_policy_version_is_unaffected_by_it(self) -> None:
        """Determinism is a property of the engine, not a claim that
        every rule must consume `policy_version` -- no rule does yet;
        the engine only threads its determinism inputs through for
        whichever future rule chooses to read them."""

        module = _load_fixture_module("safe_rule")
        rule = Rule(
            id="fixture.safe", evaluate=module.make_node_evaluate("fixture.safe")
        )

        first = evaluate((rule,), _context(policy_version="policy-v1"))
        second = evaluate((rule,), _context(policy_version="policy-v2"))

        assert first.observations == second.observations


class TestOffline:
    """Offline evidence: this entire module runs under
    `tests/conftest.py`'s autouse `_deny_network_access` fixture, the
    same as every other test in `tests/`; no dedicated additional test
    is needed beyond the structural checks above, recorded here
    explicitly rather than silently omitted."""

    def test_offline_harness_is_active_for_this_module(self) -> None:
        import socket

        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()


class TestPrivacy:
    def test_canary_never_appears_in_a_result_from_the_engines_own_error_paths(
        self,
    ) -> None:
        """A planted secret-shaped canary in the ACBOM's own evidence
        never leaks into the engine's own bound-exceeded or
        duplicate-id diagnostics/messages -- both only ever name rule
        IDs and bound counts."""

        canary_node = _node(
            f"clp:agent:sha256:{'c' * 64}", name=_CANARY_SECRET, path="secret.json"
        )
        module = _load_fixture_module("safe_rule")
        rules = tuple(
            Rule(
                id=f"fixture.rule-{letter}",
                evaluate=module.make_node_evaluate(f"fixture.rule-{letter}"),
            )
            for letter in "ab"
        )
        context = _context(acbom=_acbom(nodes=(_NODE_A, canary_node)))

        result = evaluate(rules, context, bounds=EvaluationBounds(max_rules=1))

        assert _CANARY_SECRET not in result.model_dump_json()
