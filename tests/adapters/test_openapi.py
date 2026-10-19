"""Tests for OpenApiAdapter."""

from __future__ import annotations

import json
from pathlib import Path

from controlloop.acbom import EdgeType, NodeType
from controlloop.adapters import OpenApiAdapter, ScanContext, run_adapters
from controlloop.repository import resolve_repository_root


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _write(tmp_path: Path, relative_path: str, payload: object) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) if not isinstance(payload, str) else payload)


def test_operations_become_tool_and_resource_nodes_with_reads_writes_edges(
    tmp_path: Path,
) -> None:
    """Operations become tools, paths become resources, and the HTTP
    method decides between a reads and a writes edge."""
    _write(
        tmp_path,
        "openapi.json",
        {
            "openapi": "3.0.1",
            "info": {"title": "x", "version": "1.0"},
            "paths": {
                "/users": {
                    "get": {"operationId": "listUsers"},
                    "post": {"operationId": "createUser"},
                }
            },
        },
    )

    result = run_adapters([OpenApiAdapter()], _context(tmp_path))

    tools = [n for n in result.nodes if n.type is NodeType.TOOL]
    resources = [n for n in result.nodes if n.type is NodeType.RESOURCE]
    assert {t.name for t in tools} == {"listUsers", "createUser"}
    assert [r.name for r in resources] == ["/users"]
    assert {e.type for e in result.edges} == {EdgeType.READS, EdgeType.WRITES}


def test_security_schemes_become_identity_and_permission_nodes(tmp_path: Path) -> None:
    """Security schemes become identity nodes and their scopes become
    permission nodes."""
    _write(
        tmp_path,
        "openapi.json",
        {
            "openapi": "3.0.1",
            "paths": {},
            "components": {
                "securitySchemes": {
                    "oauth": {
                        "type": "oauth2",
                        "flows": {
                            "authorizationCode": {
                                "scopes": {"read:users": "x", "write:users": "y"}
                            }
                        },
                    }
                }
            },
        },
    )

    result = run_adapters([OpenApiAdapter()], _context(tmp_path))

    identities = [n for n in result.nodes if n.type is NodeType.IDENTITY]
    permissions = [n for n in result.nodes if n.type is NodeType.PERMISSION]
    assert [i.name for i in identities] == ["oauth"]
    assert {p.name for p in permissions} == {"read:users", "write:users"}


def test_remote_ref_is_never_fetched_and_produces_an_unknown(tmp_path: Path) -> None:
    """A remote `$ref` is never fetched; it is reported as unresolved."""
    _write(
        tmp_path,
        "openapi.json",
        {
            "openapi": "3.0.1",
            "paths": {"/remote": {"$ref": "https://example.com/paths.yaml#/foo"}},
        },
    )

    result = run_adapters([OpenApiAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-UNRESOLVED-REFERENCE"
    assert "remote" in result.diagnostics[0].message


def test_cyclic_local_ref_is_detected_and_does_not_hang(tmp_path: Path) -> None:
    """A cyclic local `$ref` is detected and reported, never followed
    forever."""
    _write(
        tmp_path,
        "openapi.json",
        {
            "openapi": "3.0.1",
            "paths": {"/cyclic": {"$ref": "#/components/a"}},
            "components": {
                "a": {"$ref": "#/components/b"},
                "b": {"$ref": "#/components/a"},
            },
        },
    )

    result = run_adapters([OpenApiAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-UNRESOLVED-REFERENCE"


def test_local_ref_resolves_correctly(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "openapi.json",
        {
            "openapi": "3.0.1",
            "paths": {"/users": {"$ref": "#/components/userPath"}},
            "components": {"userPath": {"get": {"operationId": "listUsers"}}},
        },
    )

    result = run_adapters([OpenApiAdapter()], _context(tmp_path))

    assert len(result.diagnostics) == 0
    assert any(n.name == "listUsers" for n in result.nodes)


def test_swagger_2_is_rejected_not_misparsed(tmp_path: Path) -> None:
    """A Swagger 2.0 document is rejected rather than misparsed."""
    _write(
        tmp_path,
        "swagger.json",
        {"swagger": "2.0", "paths": {"/users": {"get": {}}}},
    )

    result = run_adapters([OpenApiAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert "Swagger 2.0" in result.diagnostics[0].message


def test_non_openapi_files_are_ignored(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", {"name": "not-an-api"})

    detection = OpenApiAdapter().detect(_context(tmp_path))

    assert detection.claimed_paths == ()


def test_result_is_deterministic_regardless_of_input_order(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "openapi.json",
        {
            "openapi": "3.0.1",
            "paths": {
                "/a": {"get": {"operationId": "a"}},
                "/b": {"post": {"operationId": "b"}},
            },
        },
    )
    context = _context(tmp_path)

    first = run_adapters([OpenApiAdapter()], context)
    second = run_adapters([OpenApiAdapter()], context)

    assert first == second
