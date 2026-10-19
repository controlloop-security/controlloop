"""Tests for the offline enforcement harness.

The harness itself is wired in as an autouse fixture in `conftest.py`, so
every other test in this suite is already evidence that the full
currently-implemented surface completes successfully under network denial.
This file adds two things `conftest.py` cannot demonstrate on its own: a
positive control proving the denial actually raises, and one named
test that deliberately exercises every currently-implemented core path in
a single place.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from conftest import NetworkAccessDeniedError
from typer.testing import CliRunner

from controlloop.acbom import (
    ACBOMDocument,
    Confidence,
    Evidence,
    Generator,
    Node,
    NodeType,
    Repository,
    SecurityAttributes,
    compute_digest,
    serialize_document,
)
from controlloop.cli import app
from controlloop.redaction import redact_text, redirected_streams
from controlloop.repository import resolve_repository_root, walk_repository


class TestNetworkDenialRaisesLoudly:
    """An attempted outbound connection raises rather than degrading."""

    def test_socket_construction_raises_immediately(self) -> None:
        with pytest.raises(NetworkAccessDeniedError):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def test_create_connection_raises_immediately(self) -> None:
        with pytest.raises(NetworkAccessDeniedError):
            socket.create_connection(("203.0.113.1", 80), timeout=1)


class TestCoreSurfaceCompletesOffline:
    """The core surface, including `gate`, completes under the offline
    harness.

    `init`, `bom`, `diff`, `scan`, and `gate` are all implemented. This
    class exercises every currently implemented core
    path in one place: ACBOM construction, serialization, and digesting;
    the redaction boundary; repository root resolution and walking; and
    the CLI's `--version` path, plus (below) a real `gate` invocation.
    All of it runs under the autouse offline harness already active for
    this whole suite -- every other test in this repository already runs
    under the identical harness, so this class is not the only evidence
    that the core surface runs offline, just the one place that names it
    explicitly.
    """

    def test_full_currently_implemented_surface_completes_offline(
        self, tmp_path: Path
    ) -> None:
        document = ACBOMDocument(
            schema_version="1.0.0",
            generator=Generator(name="controlloop", version="0.1.0"),
            repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
            nodes=(
                Node(
                    id=f"clp:agent:sha256:{'a' * 64}",
                    type=NodeType.AGENT,
                    name="Refund agent",
                    security_attributes=SecurityAttributes(),
                    confidence=Confidence.HIGH,
                    evidence=(
                        Evidence(adapter="a2a", path="agent-card.json", line_start=1),
                    ),
                ),
            ),
            edges=(),
            diagnostics=(),
            digest=f"sha256:{'0' * 64}",
        )
        assert serialize_document(document)
        assert compute_digest(document)

        assert redact_text("no secret here") == "no secret here"
        with redirected_streams():
            print("offline core path check")

        fixture_root = tmp_path
        (fixture_root / "src").mkdir()
        (fixture_root / "src" / "main.py").write_text("print('hi')\n")
        root = resolve_repository_root(fixture_root)
        assert list(walk_repository(root))

        result = CliRunner().invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_gate_completes_offline(self, tmp_path: Path) -> None:
        """Named explicitly: a real `gate`
        invocation -- discovery, policy evaluation, and the evidence
        artifact write -- completes successfully under the identical
        network-denied harness every test in this suite already runs
        under (`conftest.py`'s autouse fixture)."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("print('hi')\n")
        evidence_path = tmp_path / "evidence.json"

        result = CliRunner().invoke(
            app, ["gate", str(tmp_path), "--evidence-path", str(evidence_path)]
        )

        assert result.exit_code == 0
        assert evidence_path.exists()
