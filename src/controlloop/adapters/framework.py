"""The adapter contract: one interface every discovery adapter implements.

An adapter declares which inputs it claims (`detect`), then emits candidate
nodes, edges, and diagnostics (`discover`) -- never source content, never a
policy decision, never a live call to a declared endpoint or tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple, Protocol

from pydantic import BaseModel, ConfigDict

from controlloop.acbom.models import (
    Diagnostic,
    Edge,
    Node,
    RelativePath,
    SafeIdentifier,
)
from controlloop.repository import RepositoryRoot, walk_repository


class RepositoryFile(NamedTuple):
    """One file the repository walk yielded.

    `path` is the path `walk_repository` yielded (under `root.path`, for
    an adapter to open); `relative` is its repository-relative POSIX
    form, which is what every adapter claims and reports.
    """

    path: Path
    relative: str


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Bounded, read-only context passed to every adapter.

    Wraps a `RepositoryRoot` (`controlloop.repository`, already
    containment- and bounds-safe) rather than granting an adapter direct
    filesystem or network access -- per `docs/adapters/readme.md`,
    "Adapters receive immutable, bounded artifacts rather than arbitrary
    filesystem or network clients."

    An adapter enumerates files with `repository_files()`, never by
    calling `walk_repository` itself. The first call walks
    the repository once with default bounds and every later call, from
    any adapter, replays the same immutable tuple, so one scan walks the
    repository once however many adapters are registered, where each
    adapter used to walk on its own: 20 walks per scan with 15 adapters.

    `walked_files`, when given, is a walk the caller already performed
    with default bounds (`build_acbom_document` passes its own), and is
    used instead of walking again. A caller that walked with any other
    bounds must not pass it: adapters have always seen a default-bounds
    walk, and this keeps that true.
    """

    root: RepositoryRoot
    walked_files: tuple[Path, ...] | None = field(
        default=None, kw_only=True, repr=False, compare=False
    )
    _files: list[tuple[RepositoryFile, ...]] = field(
        default_factory=list, init=False, repr=False, compare=False
    )

    def repository_files(self) -> tuple[RepositoryFile, ...]:
        """Every file in the repository, in the walk's deterministic
        order, walked at most once for this context.

        A walk that raises leaves nothing cached, so the next caller
        walks (and fails) again, exactly as each adapter did when it
        walked on its own; `run_adapters` isolates the failure per
        adapter.
        """

        if not self._files:
            paths = self.walked_files
            if paths is None:
                walked = walk_repository(self.root)
                paths = tuple(item for item in walked if isinstance(item, Path))
            self._files.append(
                tuple(
                    RepositoryFile(path, path.relative_to(self.root.path).as_posix())
                    for path in paths
                )
            )
        return self._files[0]


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
