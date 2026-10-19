"""Drift guard for `docs/reference/fixture-corpus.md`, the fixture-coverage
inventory.

The inventory page cites dozens of existing test file paths as evidence
that adapter, node/edge type, and rule fixture coverage already exists.
A hand-written inventory like that can silently drift the moment a cited
file is renamed or removed -- nothing would fail, the page would simply
become wrong. This test closes that specific gap: every inline-code path
under `tests/` or `src/controlloop/` that the page cites must
actually exist on disk, checked directly against the real repository tree
that this test itself runs from, or the suite fails.

This does not, and is not meant to, prove that a cited test *function or
class name* still asserts what its name implies -- that would require
either re-generating the page from the test files (this page is a curated
narrative, not a mechanically generated one like
`docs/concepts/acbom.md`) or parsing every test file's AST. The narrower,
proportionate guarantee here is existence: a cited path that has been
deleted or renamed is caught immediately instead of silently misleading a
future reader, which is this repository's own "unknown, never omitted"
principle applied to documentation instead of scan output.
"""

from __future__ import annotations

import re
from pathlib import Path

_DOC_PATH = (
    Path(__file__).resolve().parents[1] / "docs" / "reference" / "fixture-corpus.md"
)
_REPO_ROOT = Path(__file__).resolve().parents[1]

# Matches an inline-code-formatted repository-relative path under either
# of this repository's two test/source roots this page cites from,
# ending in `.py`. Deliberately narrow (no wildcards, no directories) so
# it only ever matches an exact file citation, never accidentally
# swallows prose.
_CITED_PATH_PATTERN = re.compile(r"`((?:tests|src/controlloop)/[A-Za-z0-9_./-]+\.py)`")


def _cited_paths(doc_text: str) -> set[str]:
    return set(_CITED_PATH_PATTERN.findall(doc_text))


def test_the_inventory_page_exists() -> None:
    assert _DOC_PATH.is_file(), f"expected {_DOC_PATH} to exist"


def test_every_cited_test_or_source_path_exists_on_disk() -> None:
    doc_text = _DOC_PATH.read_text(encoding="utf-8")
    cited = _cited_paths(doc_text)

    assert cited, "expected the inventory page to cite at least one file path"

    missing = sorted(path for path in cited if not (_REPO_ROOT / path).is_file())

    assert not missing, (
        "docs/reference/fixture-corpus.md cites path(s) that no longer "
        f"exist, and is now stale: {missing}"
    )


def test_the_inventory_page_cites_every_adapter_and_every_rule_test_file() -> None:
    """A narrower, more specific check than existence alone: the page
    must actually mention each of the five adapter test files and all
    nine rule test files by name, so a whole category cannot be quietly
    dropped from the inventory while individual citations stay valid."""

    doc_text = _DOC_PATH.read_text(encoding="utf-8")
    cited = _cited_paths(doc_text)

    expected_adapter_files = {
        "tests/adapters/test_mcp.py",
        "tests/adapters/test_iam.py",
        "tests/adapters/test_a2a.py",
        "tests/adapters/test_oasf.py",
        "tests/adapters/test_openapi.py",
    }
    expected_rule_files = {
        "tests/policy/rules/test_undeclared_tools.py",
        "tests/policy/rules/test_destructive_or_financial_action.py",
        "tests/policy/rules/test_sensitive_write_without_approval.py",
        "tests/policy/rules/test_broad_permission.py",
        "tests/policy/rules/test_missing_action_logging.py",
        "tests/policy/rules/test_unauthorized_delegation.py",
        "tests/policy/rules/test_unresolved_dynamic_registration.py",
        "tests/policy/rules/test_capability_ceiling.py",
        "tests/policy/rules/test_exfiltration_triangle.py",
    }

    missing = (expected_adapter_files | expected_rule_files) - cited

    assert not missing, f"inventory page no longer cites: {sorted(missing)}"


class TestCitedPathExtraction:
    """Boundary and malformed-input coverage for the extraction helper
    itself, independent of the real doc file -- proves the pattern
    actually flags a missing path rather than passing vacuously."""

    def test_extracts_a_cited_path(self) -> None:
        text = "See `tests/adapters/test_mcp.py` for details."

        assert _cited_paths(text) == {"tests/adapters/test_mcp.py"}

    def test_ignores_prose_without_backticks(self) -> None:
        text = "See tests/adapters/test_mcp.py for details, unquoted."

        assert _cited_paths(text) == set()

    def test_ignores_a_non_python_path(self) -> None:
        text = "See `tests/fixtures/sarif/README.md` for details."

        assert _cited_paths(text) == set()

    def test_detects_a_deliberately_nonexistent_cited_path(self) -> None:
        """Proves the missing-path check itself would actually fail if a
        citation pointed at a file that does not exist -- constructed
        here rather than by mutating the real doc, so this test cannot
        itself go stale alongside the page."""

        doc_text = "See `tests/adapters/test_does_not_exist.py` for details."
        cited = _cited_paths(doc_text)

        missing = [path for path in cited if not (_REPO_ROOT / path).is_file()]

        assert missing == ["tests/adapters/test_does_not_exist.py"]
