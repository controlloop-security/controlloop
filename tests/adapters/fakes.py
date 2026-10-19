"""Fake test-double adapters shared across tests/adapters/*."""

from __future__ import annotations

import socket
import subprocess

from controlloop.acbom import (
    Confidence,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.adapters import DetectionResult, DiscoveryResult, ScanContext

AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
TOOL_ID = f"clp:tool:sha256:{'b' * 64}"


def _agent_node(adapter_name: str, evidence_path: str) -> Node:
    return Node(
        id=AGENT_ID,
        type=NodeType.AGENT,
        name="Refund agent",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter=adapter_name, path=evidence_path),),
    )


def _tool_node(adapter_name: str, evidence_path: str) -> Node:
    return Node(
        id=TOOL_ID,
        type=NodeType.TOOL,
        name="Refund tool",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter=adapter_name, path=evidence_path),),
    )


class ConformantAdapter:
    """Claims one path, discovers an agent node from it, never touches
    anything outside the sandbox's permitted operations."""

    name = "fake-conformant"
    supported_versions: tuple[str, ...] = ("1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=("agent-card.json",))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        return DiscoveryResult(nodes=(_agent_node(self.name, "agent-card.json"),))


class OtherConformantAdapter:
    """A second conformant adapter contributing a different node, used
    for order-independence tests."""

    name = "fake-other-conformant"
    supported_versions: tuple[str, ...] = ("1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=("mcp/tools.json",))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        node = _tool_node(self.name, "mcp/tools.json")
        edge = Edge(
            id=f"clp:edge:sha256:{'c' * 64}",
            source=AGENT_ID,
            target=TOOL_ID,
            type=EdgeType.INVOKES,
            status=EdgeStatus.DIRECT,
            security_attributes=SecurityAttributes(),
            confidence=Confidence.HIGH,
            evidence=(Evidence(adapter=self.name, path="mcp/tools.json"),),
        )
        return DiscoveryResult(nodes=(node,), edges=(edge,))


class DetectFailureAdapter:
    """Raises during detect() -- before any claim is known."""

    name = "fake-detect-failure"
    supported_versions: tuple[str, ...] = ("1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        raise ValueError("malformed configuration, cannot even scan headers")

    def discover(self, context: ScanContext) -> DiscoveryResult:
        raise AssertionError("discover() must not be called when detect() failed")


class DiscoverFailureAdapter:
    """Detects successfully, then raises during discover()."""

    name = "fake-discover-failure"
    supported_versions: tuple[str, ...] = ("1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=("broken.json",))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        raise ValueError("kaboom with secret /Users/example/private-repo-path")


class NothingClaimedAdapter:
    """Detects nothing; discover() must never be called."""

    name = "fake-nothing-claimed"
    supported_versions: tuple[str, ...] = ("1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=())

    def discover(self, context: ScanContext) -> DiscoveryResult:
        raise AssertionError("discover() must not be called when nothing was claimed")


class FileWritingAdapter:
    """Breaks the side-effect-free discovery rule by writing a file during
    discover()."""

    name = "fake-file-writer"
    supported_versions: tuple[str, ...] = ("1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=("x.json",))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        with open("/tmp/adapter-should-not-write-this.txt", "w") as handle:
            handle.write("violation")
        return DiscoveryResult()


class SubprocessAdapter:
    """Breaks the side-effect-free discovery rule by executing a subprocess
    during discover()."""

    name = "fake-subprocess"
    supported_versions: tuple[str, ...] = ("1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=("x.json",))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        subprocess.run(["echo", "violation"], check=False)
        return DiscoveryResult()


class SocketAdapter:
    """Breaks the side-effect-free discovery rule by opening a socket during
    discover()."""

    name = "fake-socket"
    supported_versions: tuple[str, ...] = ("1.0",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=("x.json",))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        socket.socket()
        return DiscoveryResult()
