"""Prose about adapters cannot silently fall behind `ALL_ADAPTERS`.

Three framework adapters shipped in three separate pull requests. Each
updated the one page a guard enforced --
`docs/reference/privacy-security.md`, whose
`test_every_registered_adapter_class_is_named` fails CI until a newly
registered adapter is named there -- and every page with no guard was left
behind: both READMEs, the adapter table, the walkthrough, and the `example`
command's own text.

The guard did its job precisely, and precisely nothing more. This file
is the missing half: the count and the framework names are enforced
everywhere a reader actually looks, not only where CI happened to look.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from controlloop.adapters import ALL_ADAPTERS

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

#: Every page a user might read to answer "will this see my agent".
_USER_FACING_PAGES = (
    "README.md",
    "docs/adapters/readme.md",
    "docs/guides/example-walkthrough.md",
    "docs/reference/privacy-security.md",
)

#: Written-out numbers this repository's prose actually uses.
_NUMBER_WORDS = {
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
}

_ADAPTER_COUNT_PATTERN = re.compile(
    r"\b(?P<count>\d+|" + "|".join(_NUMBER_WORDS) + r")\s+adapters\b",
    re.IGNORECASE,
)

#: The frameworks whose absence from a source list is the specific failure
#: this file guards against.
_FRAMEWORK_NAMES = ("CrewAI", "LangGraph", "OpenAI Agents")


def _text(relative: str) -> str:
    return (_REPOSITORY_ROOT / relative).read_text(encoding="utf-8")


class TestAdapterCountInProse:
    @pytest.mark.parametrize("relative", _USER_FACING_PAGES)
    def test_any_stated_adapter_count_matches_the_registry(self, relative: str) -> None:
        """A page may decline to state a count. If it states one, it must
        be right."""

        expected = len(ALL_ADAPTERS)
        for match in _ADAPTER_COUNT_PATTERN.finditer(_text(relative)):
            raw = match.group("count").lower()
            stated = _NUMBER_WORDS.get(raw)
            if stated is None:
                stated = int(raw)
            assert stated == expected, (
                f"{relative} says {match.group(0)!r} but "
                f"len(ALL_ADAPTERS) is {expected}"
            )

    def test_the_fuzz_support_comment_matches_the_registry(self) -> None:
        """A stale comment in test scaffolding misleads the next author
        about how much the sweep actually covers."""

        expected = len(ALL_ADAPTERS)
        for match in _ADAPTER_COUNT_PATTERN.finditer(_text("tests/fuzz_support.py")):
            raw = match.group("count").lower()
            stated = _NUMBER_WORDS.get(raw) or int(raw)
            assert stated == expected


class TestFrameworkAdaptersAreDiscoverable:
    """The specific failure this file guards against: a user on one of these
    three frameworks reads that ControlLoop cannot see their agent."""

    @pytest.mark.parametrize("framework", _FRAMEWORK_NAMES)
    def test_the_root_readme_names_every_framework(self, framework: str) -> None:
        assert framework in _text("README.md")

    @pytest.mark.parametrize("framework", _FRAMEWORK_NAMES)
    def test_the_cli_readme_names_every_framework(self, framework: str) -> None:
        assert framework in _text("README.md")

    @pytest.mark.parametrize("framework", _FRAMEWORK_NAMES)
    def test_the_adapter_table_names_every_framework(self, framework: str) -> None:
        assert framework in _text("docs/adapters/readme.md")

    @pytest.mark.parametrize("framework", _FRAMEWORK_NAMES)
    def test_the_walkthrough_names_every_framework(self, framework: str) -> None:
        """The table that answers 'where does an agent card come from'.
        For these three the answer is 'you may not need one', and that
        is exactly what a newcomer needs told."""

        assert framework in _text("docs/guides/example-walkthrough.md")

    @pytest.mark.parametrize("framework", _FRAMEWORK_NAMES)
    def test_the_example_command_names_every_framework(self, framework: str) -> None:
        """`controlloop example` is executable and self-describing. A
        reader runs it to learn what ControlLoop reads."""

        assert framework in _text("src/controlloop/cli.py")


class TestEveryRegisteredAdapterIsReachableFromTheAdapterTable:
    def test_each_adapter_class_appears(self) -> None:
        table = _text("docs/adapters/readme.md")
        for adapter in ALL_ADAPTERS:
            assert adapter.__name__ in table, (
                f"{adapter.__name__} is registered but absent from the adapter table"
            )
