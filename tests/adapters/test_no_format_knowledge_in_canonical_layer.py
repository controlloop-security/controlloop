"""Framework-specific parsing lives only in adapters; the canonical layer
has no format-specific branches.

A structural check, not a behavioral one: the canonical ACBOM layer
(`controlloop.acbom`) must never name a specific standard or framework in
its source. This does not prove no such logic could ever sneak in some
other way, but it catches the direct, obvious violation -- an
`if format == "mcp"`-shaped branch -- the same way this repository's
other structural tests (schema/enum sync, diagnostic registry
consistency) catch a different class of drift than behavioral tests can.
"""

from __future__ import annotations

import re
from pathlib import Path

_CLI_ROOT = Path(__file__).resolve().parents[2]
_CANONICAL_LAYER = _CLI_ROOT / "src/controlloop/acbom"

# Case-insensitive; word-boundary anchored so "map" doesn't match "mcp"
# style substrings and "oasis" doesn't match "oasf".
_FORBIDDEN_FORMAT_NAMES = (
    "mcp",
    "a2a",
    "openapi",
    "oasf",
    "agentcard",
    "agent-card",
    "cyclonedx",
)


def test_canonical_layer_source_names_no_specific_format() -> None:
    violations = []
    for path in sorted(_CANONICAL_LAYER.rglob("*.py")):
        text = path.read_text(encoding="utf-8").casefold()
        for name in _FORBIDDEN_FORMAT_NAMES:
            if re.search(rf"\b{re.escape(name)}\b", text):
                violations.append(f"{path.relative_to(_CLI_ROOT)}: {name!r}")

    assert violations == [], (
        "the canonical layer must hold no format-specific knowledge; "
        f"found: {violations}"
    )


_FRAMEWORK_MODULES = ("framework.py", "runner.py", "sandbox.py")


def test_adapter_framework_itself_names_no_specific_format() -> None:
    """The generic contract (Protocol, context, runner, sandbox) must not
    name a specific format either -- unlike a concrete adapter module
    (for example `mcp.py`), which legitimately does, since
    holding format knowledge is exactly what a concrete adapter is for.
    `__init__.py` is exempt too: aggregating and re-exporting concrete
    adapters by name is its job."""
    adapters_framework = _CLI_ROOT / "src/controlloop/adapters"
    violations = []
    for filename in _FRAMEWORK_MODULES:
        path = adapters_framework / filename
        text = path.read_text(encoding="utf-8").casefold()
        for name in _FORBIDDEN_FORMAT_NAMES:
            if re.search(rf"\b{re.escape(name)}\b", text):
                violations.append(f"{path.relative_to(_CLI_ROOT)}: {name!r}")

    assert violations == [], f"found: {violations}"
