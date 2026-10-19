"""OpenAPI ingestion.

Discovers OpenAPI 3.x documents by content (no fixed filename convention
exists for OpenAPI, unlike MCP's client configs), maps each operation to
a tool node and the path it addresses to a resource node connected by a
method-appropriate reads/writes edge, and maps declared security schemes
to identity/permission nodes. No network request is ever made: a remote
`$ref` becomes an explicit unknown rather than being fetched, and a local
`$ref` cycle is detected and stopped rather than followed forever.
Swagger 2.0 is recognized and explicitly rejected, never silently
misparsed as OpenAPI 3.x.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.acbom.completeness import incomplete_diagnostic
from controlloop.acbom.identity import (
    EdgeIdentityMaterial,
    NodeIdentityMaterial,
    SemanticIdentity,
    edge_id,
    node_id,
)
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.bounded_recursion import bounded_recursion

_NAME = "openapi"
_SUPPORTED_VERSIONS: tuple[str, ...] = ("3.0", "3.1")
_CANDIDATE_SUFFIXES = (".json", ".yaml", ".yml")
_NAMESPACE = "openapi.document"
_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_READ_METHODS = frozenset({"get", "head", "options"})
_REMOTE_REF_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _load(absolute: Path) -> object:
    with bounded_recursion(margin=500):
        return yaml.safe_load(absolute.read_text(encoding="utf-8"))


def _candidate_paths(context: ScanContext) -> tuple[str, ...]:
    found = set()
    for file in context.repository_files():
        if file.path.suffix.lower() in _CANDIDATE_SUFFIXES:
            relative = file.relative
            try:
                document = _load(file.path)
            except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError):
                continue
            if isinstance(document, dict) and (
                isinstance(document.get("openapi"), str)
                or isinstance(document.get("swagger"), str)
            ):
                found.add(relative)
    return tuple(sorted(found))


def _malformed_diagnostic(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNPARSED-REGION",
        message=f"OpenAPI document could not be fully parsed: {reason}.",
        evidence=evidence,
    )


def _unresolved_diagnostic(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNRESOLVED-REFERENCE",
        message=f"OpenAPI reference could not be resolved: {reason}.",
        evidence=evidence,
    )


def _resolve_local_ref(
    document: dict[str, Any], ref: str, visited: frozenset[str]
) -> dict[str, Any] | None:
    """Resolve a same-document JSON Pointer `$ref`, stopping (returning
    `None`) rather than looping forever if a cycle is found."""

    if ref in visited or not ref.startswith("#/"):
        return None
    visited = visited | {ref}

    target: object = document
    for raw_part in ref[2:].split("/"):
        if raw_part == "":
            continue
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(target, dict) and part in target:
            target = target[part]
        else:
            return None

    if isinstance(target, dict) and isinstance(target.get("$ref"), str):
        return _resolve_local_ref(document, target["$ref"], visited)
    return target if isinstance(target, dict) else None


def _path_item(
    document: dict[str, Any], raw_item: object, evidence: tuple[Evidence, ...]
) -> tuple[dict[str, Any] | None, Diagnostic | None]:
    if not isinstance(raw_item, dict):
        return None, _malformed_diagnostic(
            evidence, "a path entry is not a JSON object"
        )

    ref = raw_item.get("$ref")
    if not isinstance(ref, str):
        return raw_item, None

    if _REMOTE_REF_PATTERN.match(ref):
        return None, _unresolved_diagnostic(
            evidence, "a path $ref targets a remote document"
        )

    resolved = _resolve_local_ref(document, ref, frozenset())
    if resolved is None:
        return None, _unresolved_diagnostic(
            evidence, "a path $ref could not be resolved (missing target or a cycle)"
        )
    return resolved, None


def _security_scheme_nodes(
    document: dict[str, Any], relative_path: str, evidence: tuple[Evidence, ...]
) -> list[Node]:
    components = document.get("components")
    schemes = (
        components.get("securitySchemes") if isinstance(components, dict) else None
    )
    if not isinstance(schemes, dict):
        return []

    nodes: list[Node] = []
    for scheme_name, scheme_def in schemes.items():
        if not isinstance(scheme_name, str) or not isinstance(scheme_def, dict):
            continue
        try:
            nodes.append(
                _build_node(
                    relative_path,
                    f"securityScheme:{scheme_name}",
                    NodeType.IDENTITY,
                    "openapi-security-scheme",
                    scheme_name,
                    evidence,
                )
            )
        except ValueError:
            continue

        if scheme_def.get("type") != "oauth2":
            continue
        flows = scheme_def.get("flows")
        scope_names: set[str] = set()
        if isinstance(flows, dict):
            for flow in flows.values():
                if isinstance(flow, dict) and isinstance(flow.get("scopes"), dict):
                    scope_names.update(
                        scope for scope in flow["scopes"] if isinstance(scope, str)
                    )
        for scope_name in sorted(scope_names):
            try:
                nodes.append(
                    _build_node(
                        relative_path,
                        f"securityScheme:{scheme_name}:scope:{scope_name}",
                        NodeType.PERMISSION,
                        "openapi-oauth2-scope",
                        scope_name,
                        evidence,
                    )
                )
            except ValueError:
                continue
    return nodes


def _build_node(
    relative_path: str,
    in_document_key: str,
    node_type: NodeType,
    subtype: str,
    name: str,
    evidence: tuple[Evidence, ...],
) -> Node:
    identity_material = NodeIdentityMaterial(
        node_type=node_type,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative_path, in_document_key=in_document_key
        ),
    )
    return Node(
        id=node_id(identity_material),
        type=node_type,
        subtype=subtype,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


def _operation_and_resource(
    relative_path: str,
    path: str,
    method: str,
    operation: dict[str, Any],
    evidence: tuple[Evidence, ...],
) -> tuple[Node, Node, Edge]:
    operation_id = operation.get("operationId")
    tool_name = (
        operation_id
        if isinstance(operation_id, str) and operation_id
        else f"{method.upper()} {path}"
    )

    tool_node = _build_node(
        relative_path,
        f"operation:{method}:{path}",
        NodeType.TOOL,
        "openapi-operation",
        tool_name,
        evidence,
    )
    resource_node = _build_node(
        relative_path, f"path:{path}", NodeType.RESOURCE, "openapi-path", path, evidence
    )

    edge_material = EdgeIdentityMaterial(
        relationship_type=EdgeType.READS
        if method in _READ_METHODS
        else EdgeType.WRITES,
        source_id=tool_node.id,
        target_id=resource_node.id,
        relationship_discriminator=f"openapi:{method}:{path}",
    )
    edge = Edge(
        id=edge_id(edge_material),
        source=tool_node.id,
        target=resource_node.id,
        type=edge_material.relationship_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )
    return tool_node, resource_node, edge


def _discover_file(
    context: ScanContext, relative_path: str
) -> tuple[tuple[Node, ...], tuple[Edge, ...], tuple[Diagnostic, ...]]:
    absolute = context.root.path / relative_path
    evidence = (Evidence(adapter=_NAME, path=relative_path),)

    try:
        document = _load(absolute)
    except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError):
        return (), (), (_malformed_diagnostic(evidence, "the file could not be read"),)

    if not isinstance(document, dict):
        return (
            (),
            (),
            (_malformed_diagnostic(evidence, "the top level is not a JSON object"),),
        )

    if isinstance(document.get("swagger"), str):
        return (
            (),
            (),
            (
                incomplete_diagnostic(
                    code="INCOMPLETE-UNPARSED-REGION",
                    message="Swagger 2.0 is not supported; only OpenAPI 3.x is parsed.",
                    evidence=evidence,
                ),
            ),
        )

    version = document.get("openapi")
    if not isinstance(version, str) or not any(
        version.startswith(supported) for supported in _SUPPORTED_VERSIONS
    ):
        return (
            (),
            (),
            (
                _malformed_diagnostic(
                    evidence, f"unsupported openapi version {version!r}"
                ),
            ),
        )

    nodes: list[Node] = list(_security_scheme_nodes(document, relative_path, evidence))
    edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []

    paths = document.get("paths")
    if isinstance(paths, dict):
        for path, raw_item in paths.items():
            if not isinstance(path, str):
                continue
            resolved_item, diagnostic = _path_item(document, raw_item, evidence)
            if diagnostic is not None:
                diagnostics.append(diagnostic)
                continue
            if resolved_item is None:
                continue
            for method in _HTTP_METHODS:
                operation = resolved_item.get(method)
                if not isinstance(operation, dict):
                    continue
                try:
                    tool_node, resource_node, edge = _operation_and_resource(
                        relative_path, path, method, operation, evidence
                    )
                except ValueError:
                    diagnostics.append(
                        _malformed_diagnostic(
                            evidence, "an operation could not be represented"
                        )
                    )
                    continue
                nodes.append(tool_node)
                nodes.append(resource_node)
                edges.append(edge)

    return tuple(nodes), tuple(edges), tuple(diagnostics)


class OpenApiAdapter:
    """Discovers OpenAPI 3.x documents and maps operations, paths, and
    security schemes to canonical nodes and edges."""

    name = _NAME
    supported_versions: tuple[str, ...] = _SUPPORTED_VERSIONS

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(
            adapter=self.name, claimed_paths=_candidate_paths(context)
        )

    def discover(self, context: ScanContext) -> DiscoveryResult:
        nodes: list[Node] = []
        edges: list[Edge] = []
        diagnostics: list[Diagnostic] = []
        for relative_path in _candidate_paths(context):
            file_nodes, file_edges, file_diagnostics = _discover_file(
                context, relative_path
            )
            nodes.extend(file_nodes)
            edges.extend(file_edges)
            diagnostics.extend(file_diagnostics)
        return DiscoveryResult(
            nodes=tuple(nodes), edges=tuple(edges), diagnostics=tuple(diagnostics)
        )
