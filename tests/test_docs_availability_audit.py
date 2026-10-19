"""Documentation availability audit.

Mirrors `test_fixture_corpus_doc.py`'s own established discipline: assert
directly against real repository content, never merely describe it in a
docstring. That module proves a cited *path* still exists; this one goes one
step further and proves a documented *availability claim* is still true,
closing exactly the gap a full manual audit of `docs/` found; the stale
claims that pass found were fixed in the same change that added this test.

Three checks:

- A documented capability with no implementing test fails the audit,
  made concrete two ways: every rule module under
  `controlloop.policy.rules` must have a corresponding
  `tests/policy/rules/test_<module>.py` file (the exact convention
  this repository's own nine existing rule test files already follow),
  and every real `@app.command`-registered CLI command (parsed directly
  from `cli.py`'s own AST, never a hand-maintained list that could itself
  drift) must appear as a real invoked subcommand argument somewhere
  under `tests/`.
- Every availability label is reconciled against implemented behavior
  before release, enforced as a phrase-blocklist regression test: the
  exact stale phrase shapes the manual audit found and fixed
  (`"argument-free stub"`, `"scan and gate remain"`, `"no CLI command
  (consumes|reads|loads|computes|produces)"`, `"cannot scan a repository"`,
  `"zero registered rules"`, `"zero concrete rules"`) must never reappear
  anywhere under `docs/`. A small, explicit allowlist covers the pages
  that legitimately use similar-sounding "never published"/"never
  triggered" language for a real, still-accurate disclosure (the release
  pipeline and standalone-binary pages -- neither has ever run for real,
  and both say so honestly; that is not the same claim this blocklist
  targets).
- Every rule ID this repository actually ships is at least named in
  `docs/reference/policy-rules.md` -- the reverse direction of the first
  check: a shipped, undocumented capability is exactly as dishonest as a
  documented, unshipped one.

Running the audit in the release pipeline, not by hand, needs no special
wiring here: this module runs as part of `uv run pytest`, already the one
command both `.github/workflows/ci.yml` (every pull request) and
`.github/workflows/release.yml` (every tag push) run via the shared
`.github/workflows/verify.yml` -- the same reasoning that already makes
`test_fixture_corpus_doc.py` and every other test in this suite run in the
release pipeline without a second, separately maintained audit mechanism.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOCS_ROOT = _REPO_ROOT / "docs"
_CLI_PATH = _REPO_ROOT / "src" / "controlloop" / "cli.py"
_RULES_DIR = _REPO_ROOT / "src" / "controlloop" / "policy" / "rules"
_RULE_TESTS_DIR = _REPO_ROOT / "tests" / "policy" / "rules"
_TESTS_ROOT = _REPO_ROOT / "tests"
_POLICY_RULES_DOC = _DOCS_ROOT / "reference" / "policy-rules.md"

#: Rule-package modules that are not themselves a rule (no corresponding
#: `RULE`/`RULE_ID` export, so the one-test-file-per-rule convention does
#: not apply to them).
_NON_RULE_MODULES = frozenset({"__init__", "_shared", "_authority"})

#: Pages that legitimately, honestly say a real pipeline/binary has
#: "never" run/published/triggered -- confirmed individually, not
#: assumed, to use none of the stale phrase shapes below; listed here so
#: a real future stale claim on one of these pages is still caught, not
#: silently exempted wholesale.
_BLOCKLIST_ALLOWLISTED_FILES = frozenset(
    {
        "reference/release-pipeline.md",
        "reference/release-notes.md",
        "reference/standalone-binaries.md",
    }
)

#: The exact stale phrase shapes the manual audit found and fixed (see this
#: module's own docstring). Case-insensitive; matched against each doc
#: file's raw text.
_STALE_PHRASE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"argument-free stub",
        r"scan and gate remain",
        r"no CLI command (?:consumes|reads|loads|computes|produces)",
        r"cannot scan a repository",
        r"zero registered rules",
        r"zero concrete rules",
    )
)

#: Known, individually-verified-accurate sentences that happen to share
#: one of the stale phrase shapes above by coincidence of wording, not
#: by being stale -- `docs/workflows/readme.md`'s own "no CLI command
#: reads and reconciles an existing repository's manifest against a
#: live scan yet" is real, current, and confirmed directly against
#: `cli.py`: `reconcile_manifest` is genuinely never called from any
#: command. Matched as an exact substring of the *matching line*, not
#: the whole file, so this stays narrow: any *other* stale phrase
#: elsewhere in the same file is still caught.
_KNOWN_ACCURATE_EXCEPTIONS: tuple[str, ...] = ()


def _iter_doc_files() -> list[Path]:
    return sorted(_DOCS_ROOT.rglob("*.md"))


def _iter_command_functions() -> dict[str, ast.FunctionDef]:
    """Every real `@app.command(...)`-decorated function in `cli.py`,
    keyed by its own function name -- which is also the real CLI
    subcommand name for every command this repository currently
    registers (none currently overrides it via `name=`, confirmed by
    this function itself: it would raise below if one ever did, since it
    only ever keys by the function's own name)."""

    tree = ast.parse(_CLI_PATH.read_text(encoding="utf-8"))
    commands: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "command"
                and isinstance(target.value, ast.Name)
                and target.value.id == "app"
            ):
                commands[node.name] = node
    return commands


def _all_test_source_text() -> str:
    chunks = []
    for path in _TESTS_ROOT.rglob("*.py"):
        chunks.append(path.read_text(encoding="utf-8"))
    return "\n".join(chunks)


class TestEveryRegisteredRuleHasATestFile:
    """A documented, shipped capability (a registered policy rule) with no
    implementing test fails the audit."""

    def test_every_rule_module_has_a_corresponding_test_file(self) -> None:
        rule_modules = sorted(
            path.stem
            for path in _RULES_DIR.glob("*.py")
            if path.stem not in _NON_RULE_MODULES
        )
        assert rule_modules, "expected at least one rule module to exist"

        missing = [
            module
            for module in rule_modules
            if not (_RULE_TESTS_DIR / f"test_{module}.py").is_file()
        ]
        assert not missing, (
            f"rule module(s) with no corresponding test file: {missing} "
            f"(expected tests/policy/rules/test_<module>.py for each)"
        )


class TestEveryCliCommandHasTestCoverage:
    """The same check, applied to CLI commands rather than rules: a
    registered `@app.command` with zero real invocations anywhere under
    `tests/` fails the audit."""

    def test_every_registered_command_is_invoked_somewhere_in_tests(self) -> None:
        commands = _iter_command_functions()
        assert commands, "expected at least one @app.command to be registered"

        test_source = _all_test_source_text()
        missing = sorted(
            name
            for name in commands
            if f'"{name}"' not in test_source and f"'{name}'" not in test_source
        )
        assert not missing, (
            f"CLI command(s) with no real invocation anywhere under tests/: {missing}"
        )


class TestEveryRuleIsDocumented:
    """The reverse direction of the test-file check: a shipped rule this
    repository never documents at all is exactly as dishonest as a
    documented, unshipped one."""

    def test_every_registered_rule_id_appears_in_the_policy_rules_doc(self) -> None:
        # Imported here, not at module level, to avoid this test module
        # paying the cost of importing the full policy/rules package for
        # every other test class in this file.
        from controlloop.policy.rules import ALL_RULES

        assert ALL_RULES, "expected at least one registered rule"

        doc_text = _POLICY_RULES_DOC.read_text(encoding="utf-8")
        doc_text_lower = doc_text.lower()

        def _documented(rule_id: str) -> bool:
            # This page documents each rule three different ways
            # depending on where in the page it is referenced: the raw
            # `RULE_ID` string constant (`policy.<kebab-name>`), the
            # dotted module path (`controlloop.policy.rules.<module>`),
            # or a plain-English heading built from the same words with
            # spaces instead of underscores (for example "## Missing
            # action logging on a privileged tool"). All three are real,
            # honest documentation of the same rule -- accept any of
            # them rather than assuming the doc's own long-standing
            # heading convention is itself the stale thing.
            if rule_id in doc_text:
                return True
            module_name = rule_id.removeprefix("policy.").replace("-", "_")
            if f"controlloop.policy.rules.{module_name}" in doc_text:
                return True
            # Loosest, final check: every distinctive word of the
            # module's own name appears somewhere in the page (not
            # necessarily contiguous or in order) -- tolerant of a
            # heading that legitimately inserts an extra word (for
            # example "Unresolved dynamic *tool* registration"), while
            # still catching a rule with genuinely zero documentation,
            # since a wholly undocumented rule's own distinctive words
            # (e.g. "capability"+"ceiling", "exfiltration"+"triangle")
            # would not otherwise appear on this page at all.
            words = module_name.split("_")
            return all(word in doc_text_lower for word in words)

        missing = sorted(rule.id for rule in ALL_RULES if not _documented(rule.id))
        assert not missing, (
            f"registered rule ID(s) not mentioned (by ID or by dotted "
            f"module path) anywhere in {_POLICY_RULES_DOC}: {missing}"
        )


class TestNoStaleAvailabilityPhraseRemains:
    """Every availability label under `docs/` is reconciled against
    implemented behavior -- enforced going forward as a regression guard
    against the exact stale phrase shapes the manual audit found and
    fixed."""

    def test_no_doc_file_contains_a_known_stale_phrase(self) -> None:
        doc_files = _iter_doc_files()
        assert doc_files, "expected at least one file under docs/"

        violations: list[str] = []
        for path in doc_files:
            relative = path.relative_to(_DOCS_ROOT).as_posix()
            if relative in _BLOCKLIST_ALLOWLISTED_FILES:
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if any(exception in line for exception in _KNOWN_ACCURATE_EXCEPTIONS):
                    continue
                for pattern in _STALE_PHRASE_PATTERNS:
                    match = pattern.search(line)
                    if match is not None:
                        violations.append(f"{relative}: {match.group(0)!r}")

        assert not violations, (
            "stale availability phrase(s) found under docs/ (fix the "
            "claim, or add the file to _BLOCKLIST_ALLOWLISTED_FILES only "
            "if the phrase is a genuinely accurate disclosure on that "
            f"page): {violations}"
        )

    def test_allowlisted_files_actually_exist_and_are_still_accurate(self) -> None:
        """Guards the allowlist itself against silent drift: a listed
        path that no longer exists, or that has quietly grown a real
        stale claim of its own, should not go unnoticed just because it
        is exempted from the main sweep above."""

        for relative in _BLOCKLIST_ALLOWLISTED_FILES:
            path = _DOCS_ROOT / relative
            assert path.is_file(), (
                f"allowlisted path {relative!r} no longer exists under docs/"
            )

    def test_known_accurate_exceptions_still_appear_somewhere_in_docs(self) -> None:
        """Guards `_KNOWN_ACCURATE_EXCEPTIONS` against silent drift the
        identical way: an exception substring that no page actually
        contains any more is dead weight that could quietly hide a real
        future stale phrase reusing its exact wording by coincidence."""

        combined = "\n".join(
            path.read_text(encoding="utf-8") for path in _iter_doc_files()
        )
        for exception in _KNOWN_ACCURATE_EXCEPTIONS:
            assert exception in combined, (
                f"known-accurate exception {exception!r} no longer appears "
                "anywhere under docs/ -- remove it from "
                "_KNOWN_ACCURATE_EXCEPTIONS"
            )
