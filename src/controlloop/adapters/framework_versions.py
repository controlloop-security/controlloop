"""Which framework versions an adapter has actually been verified against.

Framework adapters parse a moving target. An agent framework can rename
a configuration key, move a decorator, or change how tools are attached
between minor releases, and an adapter that parses the new shape with
the old rules does not fail loudly -- it finds fewer capabilities and
reports a confident pass. That is the failure this module exists to
prevent.

The design follows `controlloop.adapters.oasf` deliberately. That module
ships with `SUPPORTED_OASF_VERSIONS` empty because the wire format was
never verified, and its parsing path therefore fires on nothing rather
than guessing. The same instinct applies to a framework: **an
undeterminable version is unsupported, never optimistically the newest
supported one**. Guessing forward is how a silent misparse
happens.

This is shared rather than per-adapter because the OpenAI Agents,
LangGraph, and CrewAI adapters all depend on it. A registry copied three
times drifts three ways.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: A PEP 440-ish release prefix. Deliberately permissive on suffixes
#: (`1.2.3rc1`, `1.2.3.post1`) and strict on the release segment, since
#: only the release segment participates in support decisions.
_RELEASE_PATTERN = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")

#: Matches a pinned or bounded requirement in a dependency string, e.g.
#: `crewai>=0.80,<0.90`, `crewai==0.86.0`, `crewai ~= 0.86`.
_REQUIREMENT_PATTERN = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?P<rest>.*)$", re.DOTALL
)
_SPECIFIER_PATTERN = re.compile(r"(?P<op>[<>=!~]=?|===)\s*(?P<version>[0-9][^,\s\]]*)")


class UnsupportedFrameworkVersionError(ValueError):
    """The declared framework version is outside the verified range, or
    could not be determined at all.

    Carries a message the caller turns into a diagnostic. The message
    names the found and supported versions and nothing else -- never a
    dependency string copied from the repository, which is untrusted
    content.
    """


@dataclass(frozen=True, slots=True)
class FrameworkSupport:
    """The verified support window for one framework.

    `minimum` is inclusive, `exclusive_maximum` is exclusive, both as
    `(major, minor)`. A range rather than a version list because agent
    frameworks release constantly and enumerating every patch would be
    both wrong and unmaintainable -- but the range is only ever widened
    with a conformance fixture proving the new end still parses.
    """

    framework: str
    #: The distribution name as it appears in a dependency declaration.
    distribution: str
    minimum: tuple[int, int]
    exclusive_maximum: tuple[int, int]
    #: Fixture identifiers proving each end of the range. Empty means
    #: the range is unproven, which `validate_registry` rejects.
    verified_by: tuple[str, ...] = field(default_factory=tuple)

    def supports(self, release: tuple[int, int]) -> bool:
        return self.minimum <= release < self.exclusive_maximum

    def describe(self) -> str:
        lo = f"{self.minimum[0]}.{self.minimum[1]}"
        hi = f"{self.exclusive_maximum[0]}.{self.exclusive_maximum[1]}"
        return f">={lo},<{hi}"


#: The registry. **Empty entries are legitimate**: a framework whose
#: version cannot yet be verified belongs here with an unproven range
#: and no adapter parsing behind it, exactly as OASF does, rather than
#: absent with an adapter guessing.
SUPPORTED_FRAMEWORKS: dict[str, FrameworkSupport] = {
    "crewai": FrameworkSupport(
        framework="crewai",
        distribution="crewai",
        minimum=(0, 80),
        exclusive_maximum=(1, 0),
        verified_by=("crewai-conformance-positive", "crewai-conformance-boundary"),
    ),
    "langgraph": FrameworkSupport(
        framework="langgraph",
        distribution="langgraph",
        minimum=(0, 2),
        exclusive_maximum=(1, 0),
        verified_by=(
            "langgraph-conformance-positive",
            "langgraph-conformance-boundary",
        ),
    ),
    "openai-agents": FrameworkSupport(
        framework="openai-agents",
        distribution="openai-agents",
        minimum=(0, 1),
        exclusive_maximum=(2, 0),
        verified_by=(
            "openai-agents-conformance-positive",
            "openai-agents-conformance-boundary",
        ),
    ),
}


def validate_registry() -> tuple[str, ...]:
    """Return a tuple of problems with the registry, empty when sound.

    A version range with no fixture behind it is a problem, so a
    contributor cannot widen support by editing a constant. A test calls
    this and fails CI on any non-empty result.
    """

    problems: list[str] = []
    for key, support in sorted(SUPPORTED_FRAMEWORKS.items()):
        if key != support.framework:
            problems.append(f"{key}: registry key does not match framework name")
        if support.minimum >= support.exclusive_maximum:
            problems.append(f"{key}: minimum is not below exclusive_maximum")
        if not support.verified_by:
            problems.append(
                f"{key}: support range {support.describe()} has no conformance "
                "fixture behind it"
            )
    return tuple(problems)


def parse_release(version: str) -> tuple[int, int] | None:
    """The `(major, minor)` release segment of a version string, or
    `None` when it is not a version at all.

    Returns `None` rather than raising so a caller can treat
    undeterminable and out-of-range through the same refusal path.
    """

    match = _RELEASE_PATTERN.match(version.strip())
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)))


def declared_version(dependencies: tuple[str, ...], distribution: str) -> str | None:
    """The version a project's dependency declarations pin for
    `distribution`, or `None` if it declares none.

    Reads the lower bound of whatever specifier it finds, since that is
    the oldest version the project claims to work with and therefore the
    one an adapter must be able to parse. A dependency with no specifier
    at all yields `None` -- an unpinned framework is undeterminable, not
    "presumably current".
    """

    for raw in dependencies:
        match = _REQUIREMENT_PATTERN.match(raw)
        if match is None:
            continue
        if match.group("name").lower().replace("_", "-") != distribution.lower():
            continue
        candidates = [
            found.group("version")
            for found in _SPECIFIER_PATTERN.finditer(match.group("rest"))
            if found.group("op") in {"==", ">=", "~=", "==="}
        ]
        if candidates:
            return candidates[0]
        return None
    return None


def require_supported(framework: str, version: str | None) -> tuple[int, int]:
    """Return the release segment when supported; raise otherwise.

    An unsupported version is refused rather than parsed as if it were
    supported. `None`, an unparseable string, and an
    out-of-range version all take the same refusal path -- an
    undeterminable version is never resolved to the newest supported
    one.
    """

    support = SUPPORTED_FRAMEWORKS.get(framework)
    if support is None:
        raise UnsupportedFrameworkVersionError(
            f"{framework} is not a registered framework"
        )

    if version is None:
        raise UnsupportedFrameworkVersionError(
            f"no {framework} version is declared (supported: "
            f"{support.describe()}); an undeclared version is treated as "
            "unsupported rather than assumed current"
        )

    release = parse_release(version)
    if release is None or not support.supports(release):
        found = f"{release[0]}.{release[1]}" if release else "unparseable"
        raise UnsupportedFrameworkVersionError(
            f"{framework} version {found} is not supported "
            f"(supported: {support.describe()})"
        )
    return release
