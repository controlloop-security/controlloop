"""The adapter contract: one interface every discovery adapter implements.

An adapter declares which inputs it claims (`detect`), then emits candidate
nodes, edges, and diagnostics (`discover`) -- never source content, never a
policy decision, never a live call to a declared endpoint or tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from controlloop.acbom.models import (
    Diagnostic,
    Edge,
    Node,
    RelativePath,
    SafeIdentifier,
)
from controlloop.repository import RepositoryRoot


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Bounded, read-only context passed to every adapter.

    Wraps a `RepositoryRoot` (`controlloop.repository`, already
    containment- and bounds-safe) rather than granting an adapter direct
    filesystem or network access -- per `docs/adapters/readme.md`,
    "Adapters receive immutable, bounded artifacts rather than arbitrary
    filesystem or network clients." An adapter calls `walk_repository`
    itself with `root` to enumerate files.
    """

    root: RepositoryRoot


class _AdapterModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class DetectionResult(_AdapterModel):
    """What an adapter claims to be able to handle."""

    adapter: SafeIdentifier
    claimed_paths: tuple[RelativePath, ...]


class DiscoveryResult(_AdapterModel):
    """What an adapter found: nodes, edges, and diagnostics -- evidence
    lives inside each, per the evidence contract."""

    nodes: tuple[Node, ...] = ()
    edges: tuple[Edge, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()


class DiscoveryAdapter(Protocol):
    """One interface every discovery adapter implements."""

    name: str
    supported_versions: tuple[str, ...]

    def detect(self, context: ScanContext) -> DetectionResult: ...

    def discover(self, context: ScanContext) -> DiscoveryResult: ...
