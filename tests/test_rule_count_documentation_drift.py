"""The rule-pack rule count stated in prose matches the registry.

The rule-pack rule count was named, twice, as an unguarded repetition that
would drift, and naming a candidate does not retire it. It drifted: when
four rules were added, nine pages still said "ten". This test retires it.
Prose either states no current count, or states the real one.

A sentence that is explicitly historical ("the ten rules that predate the
agent-authority rules", "three of the original rules") is exempt by its own
wording.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from controlloop.policy.rulepack import CURRENT_RULE_PACK
from controlloop.policy.rules import ALL_RULES

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

_NUMBER_WORDS = {
    "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
    "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19, "twenty": 20,
}  # fmt: skip

#: "all ten rules", "every one of the 14 registered rules", "ten registered rules".
_CURRENT_COUNT = re.compile(
    r"\b(?:all|the)\s+(?P<count>\d+|" + "|".join(_NUMBER_WORDS) + r")\s+"
    r"(?:registered\s+)?rules\b",
    re.IGNORECASE,
)
#: "there are ten in the pack" -- the `controlloop example` sentence that
#: drifted unnoticed because the guard read only Markdown.
_IN_THE_PACK = re.compile(
    r"\b(?:are|is)\s+(?P<count>\d+|"
    + "|".join(_NUMBER_WORDS)
    + r")\s+in\s+the\s+pack\b",
    re.IGNORECASE,
)
_VERSION_LINE = re.compile(
    r"Rule pack: controlloop-community (?P<version>\S+) \((?P<count>\d+) rules\)"
)
_HISTORICAL_MARKERS = ("predate", "original", "at the time", "then-")


def _pages() -> list[Path]:
    pages = [_REPOSITORY_ROOT / "README.md"]
    pages.extend(sorted((_REPOSITORY_ROOT / "docs").rglob("*.md")))
    return [page for page in pages if page.is_file()]


def _assert_counts(text: str, label: str) -> None:
    expected = len(ALL_RULES)
    for line in text.splitlines():
        if any(marker in line.lower() for marker in _HISTORICAL_MARKERS):
            continue
        for pattern in (_CURRENT_COUNT, _IN_THE_PACK):
            for match in pattern.finditer(line):
                raw = match.group("count").lower()
                stated = _NUMBER_WORDS.get(raw) or int(raw)
                assert stated == expected, f"{label}: {line.strip()}"


@pytest.mark.parametrize(
    "page", _pages(), ids=lambda page: page.relative_to(_REPOSITORY_ROOT).as_posix()
)
def test_a_stated_rule_count_matches_the_registry(page: Path) -> None:
    _assert_counts(page.read_text(encoding="utf-8"), page.name)


def test_the_example_command_states_no_stale_count() -> None:
    """`controlloop example` is user-facing prose that lives in code, so the
    Markdown sweep above never read it."""

    from typer.testing import CliRunner

    from controlloop.cli import app

    output = CliRunner().invoke(app, ["example"]).output
    _assert_counts(" ".join(output.split()), "controlloop example")


@pytest.mark.parametrize(
    "page", _pages(), ids=lambda page: page.relative_to(_REPOSITORY_ROOT).as_posix()
)
def test_a_version_example_shows_the_current_pack(page: Path) -> None:
    for match in _VERSION_LINE.finditer(page.read_text(encoding="utf-8")):
        assert match.group("version") == CURRENT_RULE_PACK.version, page.name
        assert int(match.group("count")) == len(CURRENT_RULE_PACK.rules), page.name


def test_the_guard_binds() -> None:
    """The patterns match the sentences that drifted, so a passing run
    means the pages agree, not that nothing was checked."""

    assert _CURRENT_COUNT.search("consume all ten rules via ALL_RULES")
    assert _IN_THE_PACK.search("there are ten in the pack, run it")
    assert _CURRENT_COUNT.search("carries all 14 registered rules")
    assert _VERSION_LINE.search("Rule pack: controlloop-community 0.2.0 (10 rules)")
