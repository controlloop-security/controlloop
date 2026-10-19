"""Three synthetic scannable fixtures for the golden-baseline tests.

Each fixture is a builder function (`root: Path -> None`), never a directory
of files committed inside this repository -- a fixture committed *inside*
controlloop's own git tree would have `resolve_repository_root` resolve to
controlloop's own enclosing `.git`, making `ACBOMDocument.repository.commit`
the actual current commit hash of controlloop itself: non-reproducible
across every future commit here, which defeats a golden comparison.
Building fresh into an isolated `tmp_path` at test/regeneration time (never
inside a git repository) gives the same deterministic
`repository.commit == "unknown"` `TestBom` already established as this
codebase's own precedent for a non-git scan target.

`single-agent` and `agent-with-ceiling-breach` reuse the identical
agent-card/ceiling shape `test_cli.py`'s
`_write_agent_card_with_a_prohibited_tool` already established, rather than
inventing a fourth fixture shape -- traceable to already-reviewed precedent.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

FIXTURES: dict[str, Callable[[Path], None]] = {}


def _register(name: str) -> Callable[[Callable[[Path], None]], Callable[[Path], None]]:
    def decorator(builder: Callable[[Path], None]) -> Callable[[Path], None]:
        FIXTURES[name] = builder
        return builder

    return decorator


@_register("empty")
def build_empty(root: Path) -> None:
    """Nothing discovered, nothing to evaluate -- the floor case."""

    (root / "README.md").write_text("This repository has no agents.\n")


@_register("single-agent")
def build_single_agent(root: Path) -> None:
    """One agent, one tool, one `invokes` edge, no manifest -- a
    minimal non-empty ACBOM and a clean `scan` pass (no manifest means
    `undeclared_tools` reports only an advisory observation, never a
    `Finding`)."""

    (root / "agent-card.json").write_text(
        json.dumps(
            {
                "name": "librarian",
                "skills": [{"id": "search-catalog", "name": "search-catalog"}],
            }
        )
    )


@_register("agent-with-ceiling-breach")
def build_agent_with_ceiling_breach(root: Path) -> None:
    """The exact shape `test_cli.py`'s `TestScan` already established: an
    agent invoking a tool a declared capability ceiling prohibits by name --
    a real `policy.capability-ceiling` `Finding`,
    `Verdict.DEPLOYMENT_BLOCKED`, exit `1`."""

    (root / "agent-card.json").write_text(
        json.dumps(
            {
                "name": "refund-agent",
                "skills": [{"id": "delete-database", "name": "delete-database"}],
            }
        )
    )
    (root / "controlloop.yaml").write_text(
        "schema_version: '1.0.0'\n"
        "owner: security-team\n"
        "ceilings:\n"
        "  - agent: refund-agent\n"
        "    prohibited_resources: [delete-database]\n"
    )
