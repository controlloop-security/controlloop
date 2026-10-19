"""Tests for the adapter contract shape."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes import ConformantAdapter
from pydantic import ValidationError

from controlloop.acbom import Confidence, Evidence, Node, NodeType, SecurityAttributes
from controlloop.adapters import (
    DetectionResult,
    DiscoveryAdapter,
    DiscoveryResult,
    ScanContext,
)
from controlloop.repository import RepositoryRoot


def test_scan_context_wraps_a_repository_root(tmp_path: Path) -> None:
    root = RepositoryRoot(path=tmp_path)

    context = ScanContext(root=root)

    assert context.root is root


def test_detection_result_declares_claimed_paths() -> None:
    """An adapter declares which inputs it claims."""
    result = DetectionResult(adapter="fake", claimed_paths=("a.json", "b.json"))

    assert result.claimed_paths == ("a.json", "b.json")


def test_detection_result_requires_a_safe_adapter_identifier() -> None:
    with pytest.raises(ValidationError):
        DetectionResult(adapter="../not-safe", claimed_paths=())


def test_discovery_result_carries_nodes_edges_and_diagnostics() -> None:
    """Returns nodes, edges, and diagnostics through one interface --
    evidence already lives inside each, per the evidence contract."""
    node = Node(
        id=f"clp:agent:sha256:{'a' * 64}",
        type=NodeType.AGENT,
        name="x",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="fake", path="a.json"),),
    )

    result = DiscoveryResult(nodes=(node,))

    assert result.nodes == (node,)
    assert result.edges == ()
    assert result.diagnostics == ()


def test_discovery_result_defaults_to_empty() -> None:
    assert DiscoveryResult() == DiscoveryResult(nodes=(), edges=(), diagnostics=())


def test_discovery_result_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        DiscoveryResult.model_validate({"nodes": (), "raw_source": "leaked"})


def test_a_conformant_adapter_satisfies_the_protocol(tmp_path: Path) -> None:
    adapter: DiscoveryAdapter = ConformantAdapter()
    context = ScanContext(root=RepositoryRoot(path=tmp_path))

    detection = adapter.detect(context)
    discovery = adapter.discover(context)

    assert detection.adapter == adapter.name
    assert len(discovery.nodes) == 1
