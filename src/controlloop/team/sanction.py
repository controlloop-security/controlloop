"""Approved-component matching, CLI side.

The platform flags components against an organization's approved list;
the Team gate must reach the same answer for the same component before it
uploads anything. So the functions exist twice, and the shared vector
files from the platform's contract (copied into `tests/fixtures/contract/`)
keep them honest:

- `version_range_vectors.json`: accepted and refused ranges and
  containment;
- `flagging_vectors.json`: components, entries, and the state each must
  produce;
- `policy_merge_vectors.json`: the strengthen-only merge of constrained
  entries.

`tests/team/test_sanction.py` runs this module against all three.

Everything here is data comparison. A version range is parsed by a small
hand-written grammar and never evaluated; a name pattern is an exact
string or a single trailing `*`; nothing is compiled or executed. A
constraint the component cannot be shown to meet is not met: a missing
version is inside no range, and an unknown pin is not a pin.

Pure: no clock, no I/O, no ordering dependence.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

#: The constraint fields an approved entry can carry, in the order a
#: failure is reported.
CONSTRAINT_FIELDS: Final = (
    "package",
    "version_range",
    "digest",
    "command_pattern",
    "pin_required",
)

MAX_RANGE_LENGTH: Final = 64

Version = tuple[int, int, int]

_PART = r"(?:0|[1-9][0-9]{0,5})"
_VERSION = re.compile(rf"^({_PART})\.({_PART})\.({_PART})$")
_WILDCARD = re.compile(rf"^({_PART})\.(?:x|({_PART})\.x)$")
_COMPARATOR = re.compile(r"^(>=|>|<=|<)(.+)$")

#: Every message `parse_range` can raise -- fixed strings, identical to
#: the platform's, so no input is ever reflected into an error.
RANGE_MESSAGES: Final = (
    "A version range must be 1 to 64 characters.",
    "A version range has no leading, trailing, or doubled spaces.",
    "A bounded version range must not be empty.",
    "A version range is exact (1.0.15), a wildcard (1.0.x, 2.x), or bounded "
    "(>=1.0.0 <1.1.0).",
)


class SanctionState(StrEnum):
    SANCTIONED = "sanctioned"
    UNSANCTIONED = "unsanctioned"
    #: No published policy governs the project: nothing was judged.
    UNEVALUATED = "unevaluated"


@dataclass(frozen=True)
class VersionRange:
    """A parsed range: an inclusive or exclusive lower and upper bound."""

    lower: Version
    lower_inclusive: bool
    upper: Version | None
    upper_inclusive: bool

    def contains(self, version: str) -> bool:
        parsed = parse_version(version)
        if parsed is None:
            # An approval never covers something it cannot read.
            return False
        if parsed < self.lower or (parsed == self.lower and not self.lower_inclusive):
            return False
        if self.upper is None:
            return True
        return parsed < self.upper or (parsed == self.upper and self.upper_inclusive)


def parse_version(text: object) -> Version | None:
    match = _VERSION.match(text) if isinstance(text, str) else None
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _comparator(token: str) -> tuple[str, Version] | None:
    match = _COMPARATOR.match(token)
    if not match:
        return None
    version = parse_version(match.group(2))
    if version is None:
        return None
    return match.group(1), version


def parse_range(text: object) -> VersionRange:
    """Parse `text` or raise `ValueError` with a fixed message."""

    if not isinstance(text, str) or not text or len(text) > MAX_RANGE_LENGTH:
        raise ValueError(RANGE_MESSAGES[0])
    if text != text.strip() or "  " in text:
        raise ValueError(RANGE_MESSAGES[1])

    exact = parse_version(text)
    if exact is not None:
        return VersionRange(exact, True, exact, True)

    wildcard = _WILDCARD.match(text)
    if wildcard:
        major = int(wildcard.group(1))
        minor = wildcard.group(2)
        if minor is None:
            return VersionRange((major, 0, 0), True, (major + 1, 0, 0), False)
        return VersionRange(
            (major, int(minor), 0), True, (major, int(minor) + 1, 0), False
        )

    parts = text.split(" ")
    if len(parts) == 2:
        lower = _comparator(parts[0])
        upper = _comparator(parts[1])
        if lower is not None and upper is not None:
            lower_op, lower_version = lower
            upper_op, upper_version = upper
            if lower_op in {">=", ">"} and upper_op in {"<=", "<"}:
                if lower_version > upper_version or (
                    lower_version == upper_version
                    and (lower_op, upper_op) != (">=", "<=")
                ):
                    raise ValueError(RANGE_MESSAGES[2])
                return VersionRange(
                    lower_version, lower_op == ">=", upper_version, upper_op == "<="
                )

    raise ValueError(RANGE_MESSAGES[3])


def range_inside(inner: str, outer: str) -> bool:
    """Whether every version `inner` admits, `outer` admits too."""

    try:
        a = parse_range(inner)
        b = parse_range(outer)
    except ValueError:
        return False
    if a.lower < b.lower or (
        a.lower == b.lower and a.lower_inclusive and not b.lower_inclusive
    ):
        return False
    if b.upper is None:
        return True
    if a.upper is None:
        return False
    return not (
        a.upper > b.upper
        or (a.upper == b.upper and a.upper_inclusive and not b.upper_inclusive)
    )


def name_matches(pattern: str, name: str) -> bool:
    """Case-insensitive exact match, or a trailing-`*` prefix match."""

    pattern = pattern.strip().lower()
    name = name.strip().lower()
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return pattern == name


def command_matches(pattern: str, command: str) -> bool:
    if pattern.endswith("*"):
        return command.startswith(pattern[:-1])
    return command == pattern


def command_covers(outer: str, inner: str) -> bool:
    """Whether pattern `outer` admits every command pattern `inner` admits."""

    if outer.endswith("*"):
        return inner.startswith(outer[:-1])
    return inner == outer


@dataclass(frozen=True, slots=True)
class ApprovedEntry:
    """One approved-component entry, with its optional constraints."""

    type: str
    name_pattern: str
    package: str | None = None
    version_range: str | None = None
    digest: str | None = None
    command_pattern: str | None = None
    pin_required: bool | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> ApprovedEntry:
        def text(key: str) -> str | None:
            value = data.get(key)
            return str(value) if value is not None else None

        pin = data.get("pin_required")
        return cls(
            type=str(data.get("type", "")),
            name_pattern=str(data.get("name_pattern", "")),
            package=text("package"),
            version_range=text("version_range"),
            digest=text("digest"),
            command_pattern=text("command_pattern"),
            pin_required=bool(pin) if pin is not None else None,
        )

    def to_mapping(self) -> dict[str, object]:
        """The entry as the contract writes it: absent constraints left out."""

        data: dict[str, object] = {"type": self.type, "name_pattern": self.name_pattern}
        for name in CONSTRAINT_FIELDS:
            value = getattr(self, name)
            if value is not None:
                data[name] = value
        return data

    @property
    def key(self) -> tuple[str, str]:
        return (self.type, self.name_pattern)


@dataclass(frozen=True, slots=True)
class Component:
    """What a component is judged by: its type, its name, the
    value-free attributes the constraints read, and its flags."""

    type: str
    name: str
    attributes: Mapping[str, str] = field(default_factory=dict)
    flags: Mapping[str, object] = field(default_factory=dict)


def failed_constraint(entry: ApprovedEntry, component: Component) -> str | None:
    """The first constraint `component` does not meet, or `None` when it
    meets them all. The platform's `satisfies` is `failed_constraint(...)
    is None`."""

    attributes = component.attributes
    if entry.package is not None and attributes.get("package") != entry.package:
        return "package"
    if entry.version_range is not None:
        try:
            parsed = parse_range(entry.version_range)
        except ValueError:
            return "version_range"
        if not parsed.contains(str(attributes.get("version", ""))):
            return "version_range"
    if entry.digest is not None and not str(attributes.get("digest", "")).startswith(
        entry.digest
    ):
        return "digest"
    if entry.command_pattern is not None:
        recorded = attributes.get("command")
        if not isinstance(recorded, str) or not command_matches(
            entry.command_pattern, recorded
        ):
            return "command_pattern"
    if entry.pin_required and component.flags.get("pinned") is not True:
        return "pin_required"
    return None


@dataclass(frozen=True, slots=True)
class Judgment:
    """One component's sanction state. `failed` names why an
    unsanctioned component was not covered: `name` when no entry has its
    type and name, otherwise the first constraint the closest entry's
    component did not meet."""

    state: SanctionState
    failed: str | None = None
    entry: ApprovedEntry | None = None


def judge(component: Component, approved: Sequence[ApprovedEntry] | None) -> Judgment:
    """The pure core, matching the platform's `flagging.evaluate`.

    `approved=None` means no published policy governs the project:
    `unevaluated`, never a pass. An empty list is a published policy that
    approves nothing.
    """

    if approved is None:
        return Judgment(SanctionState.UNEVALUATED)
    first_failure: tuple[ApprovedEntry, str] | None = None
    for entry in approved:
        if entry.type != component.type or not name_matches(
            entry.name_pattern, component.name
        ):
            continue
        failure = failed_constraint(entry, component)
        if failure is None:
            return Judgment(SanctionState.SANCTIONED, entry=entry)
        if first_failure is None:
            first_failure = (entry, failure)
    if first_failure is not None:
        return Judgment(
            SanctionState.UNSANCTIONED, failed=first_failure[1], entry=first_failure[0]
        )
    return Judgment(SanctionState.UNSANCTIONED, failed="name")


def _narrows(name: str, mine: object, theirs: object) -> bool:
    """Whether the repository's value for constraint `name` admits no more
    than the organization's."""

    if name == "package":
        return mine == theirs
    if name == "version_range":
        return range_inside(str(mine), str(theirs))
    if name == "digest":
        return str(mine).startswith(str(theirs))
    if name == "command_pattern":
        return command_covers(str(theirs), str(mine))
    return not bool(theirs) or bool(mine)


def widened_fields(
    organization: ApprovedEntry, repository: Mapping[str, object]
) -> list[str]:
    """The constraint fields in which a repository entry admits more than
    the organization's. A field the repository leaves out inherits the
    organization's value and so never widens."""

    widened: list[str] = []
    for name in CONSTRAINT_FIELDS:
        if name not in repository:
            continue
        mine = repository[name]
        theirs = getattr(organization, name)
        if theirs is None:
            continue
        if not _narrows(name, mine, theirs):
            widened.append(name)
    return widened


def narrowed_entry(
    organization: ApprovedEntry, repository: Mapping[str, object]
) -> ApprovedEntry:
    """The organization's entry with the repository's narrowing applied.
    Call only when `widened_fields` is empty."""

    data = organization.to_mapping()
    for name in CONSTRAINT_FIELDS:
        if name in repository:
            if name == "pin_required":
                data[name] = bool(organization.pin_required) or bool(repository[name])
            else:
                data[name] = repository[name]
    return ApprovedEntry.from_mapping(data)


__all__ = [
    "CONSTRAINT_FIELDS",
    "RANGE_MESSAGES",
    "ApprovedEntry",
    "Component",
    "Judgment",
    "SanctionState",
    "VersionRange",
    "command_covers",
    "command_matches",
    "failed_constraint",
    "judge",
    "name_matches",
    "narrowed_entry",
    "parse_range",
    "parse_version",
    "range_inside",
    "widened_fields",
]
