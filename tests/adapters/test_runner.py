"""Tests for run_adapters."""

from __future__ import annotations

import random
from pathlib import Path

from fakes import (
    AGENT_ID,
    ConformantAdapter,
    DetectFailureAdapter,
    DiscoverFailureAdapter,
    FileWritingAdapter,
    NothingClaimedAdapter,
    OtherConformantAdapter,
    SocketAdapter,
    SubprocessAdapter,
)

from controlloop.acbom import Confidence, Evidence, Node, NodeType, SecurityAttributes
from controlloop.adapters import (
    DetectionResult,
    DiscoveryAdapter,
    DiscoveryResult,
    ScanContext,
    run_adapters,
)
from controlloop.repository import RepositoryRoot


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=RepositoryRoot(path=tmp_path))


def test_a_single_conformant_adapter_contributes_its_nodes(tmp_path: Path) -> None:
    result = run_adapters([ConformantAdapter()], _context(tmp_path))

    assert len(result.nodes) == 1
    assert result.nodes[0].id == AGENT_ID
    assert result.diagnostics == ()


def test_nothing_claimed_never_calls_discover(tmp_path: Path) -> None:
    """discover() raises AssertionError if called; a clean run proves it
    was skipped."""
    result = run_adapters([NothingClaimedAdapter()], _context(tmp_path))

    assert result == DiscoveryResult()


def test_a_detect_failure_is_isolated_and_becomes_a_diagnostic(
    tmp_path: Path,
) -> None:
    """An adapter that raises is isolated -- the scan continues,
    and the failure becomes a diagnostic."""
    result = run_adapters(
        [ConformantAdapter(), DetectFailureAdapter()], _context(tmp_path)
    )

    assert len(result.nodes) == 1  # the conformant adapter still contributed
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "INCOMPLETE-ADAPTER-FAILURE"
    assert diagnostic.incomplete is True
    assert "fake-detect-failure" in diagnostic.message


def test_a_discover_failure_is_isolated_and_never_leaks_its_message(
    tmp_path: Path,
) -> None:
    """Isolation, and privacy: the raw exception message (which could
    carry arbitrary interpolated content) never appears in the diagnostic
    -- only the exception's class name, matching the pattern the CLI's
    global exception handler already established."""
    result = run_adapters(
        [ConformantAdapter(), DiscoverFailureAdapter()], _context(tmp_path)
    )

    assert len(result.nodes) == 1
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "INCOMPLETE-ADAPTER-FAILURE"
    assert "ValueError" in diagnostic.message
    assert "secret" not in diagnostic.message
    assert "/Users/example/private-repo-path" not in diagnostic.message


def test_execution_order_does_not_affect_the_canonical_result(tmp_path: Path) -> None:
    """Asserted by running adapters in shuffled order."""
    adapters: list[DiscoveryAdapter] = [
        ConformantAdapter(),
        OtherConformantAdapter(),
        DetectFailureAdapter(),
        DiscoverFailureAdapter(),
    ]
    context = _context(tmp_path)

    baseline = run_adapters(adapters, context)

    rng = random.Random(1234)
    for _ in range(5):
        shuffled = list(adapters)
        rng.shuffle(shuffled)
        result = run_adapters(shuffled, context)
        assert result == baseline


class _DuplicateAgentAdapter:
    """Contributes a second evidence record for the same agent node
    `ConformantAdapter` already declares, to prove the runner merges
    same-ID contributions from different adapters."""

    name = "fake-duplicate-agent"
    supported_versions: tuple[str, ...] = ("1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=("other.json",))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        node = Node(
            id=AGENT_ID,
            type=NodeType.AGENT,
            name="Refund agent",
            security_attributes=SecurityAttributes(),
            confidence=Confidence.HIGH,
            evidence=(Evidence(adapter=self.name, path="other.json"),),
        )
        return DiscoveryResult(nodes=(node,))


def test_two_adapters_contributing_the_same_node_are_merged(tmp_path: Path) -> None:
    """The runner composes with the existing merge functions."""
    result = run_adapters(
        [ConformantAdapter(), _DuplicateAgentAdapter()], _context(tmp_path)
    )

    assert len(result.nodes) == 1
    assert {evidence.adapter for evidence in result.nodes[0].evidence} == {
        "fake-conformant",
        "fake-duplicate-agent",
    }


def test_adapter_output_is_sorted_by_id_regardless_of_input_order(
    tmp_path: Path,
) -> None:
    forward = run_adapters(
        [ConformantAdapter(), OtherConformantAdapter()], _context(tmp_path)
    )
    reverse = run_adapters(
        [OtherConformantAdapter(), ConformantAdapter()], _context(tmp_path)
    )

    assert [node.id for node in forward.nodes] == sorted(
        node.id for node in forward.nodes
    )
    assert forward == reverse


def test_file_writing_adapter_is_blocked_by_the_sandbox(tmp_path: Path) -> None:
    """The sandbox, exercised through the real runner rather than in
    isolation."""
    result = run_adapters([FileWritingAdapter()], _context(tmp_path))

    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-ADAPTER-FAILURE"
    assert not Path("/tmp/adapter-should-not-write-this.txt").exists()


def test_subprocess_adapter_is_blocked_by_the_sandbox(tmp_path: Path) -> None:
    result = run_adapters([SubprocessAdapter()], _context(tmp_path))

    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-ADAPTER-FAILURE"


def test_socket_adapter_is_blocked_by_the_sandbox(tmp_path: Path) -> None:
    result = run_adapters([SocketAdapter()], _context(tmp_path))

    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-ADAPTER-FAILURE"
