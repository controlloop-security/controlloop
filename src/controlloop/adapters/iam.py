"""IAM in-repo policy ingestion.

Scope is deliberately in-repo only: native AWS IAM policy JSON and
Terraform HCL (`.tf`) IAM resources. No live cloud API reads, no
condition-key evaluation. GCP and Azure policy documents are recognized
and rejected, never misparsed as AWS.

Terraform parsing uses `python-hcl2`, verified empirically rather than
assumed: `hcl2.load`/`hcl2.loads` does not evaluate `jsonencode(...)`
-- it captures the call as a raw HCL-syntax interpolation string, which
this module extracts and re-parses with hcl2 itself (the real parser,
used twice, never approximated with regex-guessed JSON). Every string
leaf hcl2 returns retains its literal surrounding quote characters,
stripped mechanically before use.
"""

from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path
from typing import Any

import hcl2  # type: ignore[import-untyped]

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.acbom.completeness import incomplete_diagnostic
from controlloop.acbom.identity import NodeIdentityMaterial, SemanticIdentity, node_id
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.bounded_recursion import bounded_recursion
from controlloop.repository import walk_repository

# python-hcl2 lazily builds its LALR grammar on first use and caches it to a
# file inside its own package directory (hcl2/parser.py, memoized with
# functools.lru_cache). If that first build happens inside adapter_sandbox,
# the cache write is denied -- and raises AdapterSandboxViolationError, a
# RuntimeError, not an OSError/IOError, so python-hcl2's own
# `except IOError` around the cache write does not catch it. The
# RuntimeError then propagates out of hcl2.loads and is swallowed by this
# module's broad `except Exception`, producing a spurious
# INCOMPLETE-UNPARSED-REGION for perfectly valid HCL. Confirmed empirically:
# a fresh process's first hcl2.loads() call, made inside adapter_sandbox,
# reproducibly raises AdapterSandboxViolationError; this was the real cause
# of a CI-only failure (every adapter call runs inside the sandbox, so
# without this warmup call there is no code path that ever builds the
# grammar unsandboxed first). Warming it here, once, at import time --
# before any adapter_sandbox is ever entered -- means the grammar is
# already built and cached in-process; lru_cache then returns the same
# Lark object on every later call, sandboxed or not, with no further file
# I/O attempted.
with contextlib.suppress(Exception):
    hcl2.loads("_controlloop_hcl2_grammar_warmup = 1\n")

_NAME = "iam"
_SUPPORTED_VERSIONS: tuple[str, ...] = ("2012-10-17",)
_NAMESPACE = "iam.policy"
_TERRAFORM_POLICY_RESOURCE_TYPES = frozenset(
    {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }
)
_TERRAFORM_POLICY_DOCUMENT_TYPE = "aws_iam_policy_document"
_JSONENCODE_PATTERN = re.compile(r"^\$\{jsonencode\((.*)\)\}$", re.DOTALL)
_INTERPOLATION_PATTERN = re.compile(r"\$\{[^}]*\}")
_CONDITION_MARKER = "condition:present"


def _strip_literal_quotes(value: object) -> object:
    if isinstance(value, str):
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            return value[1:-1]
        return value
    if isinstance(value, list):
        return [_strip_literal_quotes(item) for item in value]
    if isinstance(value, dict):
        return {
            _strip_literal_quotes(key): _strip_literal_quotes(item)
            for key, item in value.items()
        }
    return value


def _encode_scope(value: str) -> str:
    """`SecurityAttributes.permission_scopes` is `SafeIdentifier`-typed,
    whose pattern (`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`) does not allow a
    literal `*` -- discovered empirically when a real wildcard action
    (`s3:*`) failed `Node` construction. Wildcards must be preserved,
    not silently dropped, so `*` is replaced with the unambiguous, safe
    token `WILDCARD` rather than stripped -- the same "encode, don't
    discard" approach used for hostile characters in evidence paths."""

    return value.replace("*", "WILDCARD")


def _as_string_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _has_unresolved_interpolation(values: list[str]) -> bool:
    return any(_INTERPOLATION_PATTERN.search(value) for value in values)


def _iter_hcl_blocks(
    document: dict[str, Any], block_kind: str
) -> list[tuple[str, str, dict[str, Any]]]:
    blocks: list[tuple[str, str, dict[str, Any]]] = []
    for entry in document.get(block_kind, []):
        if not isinstance(entry, dict):
            continue
        for type_label, named in entry.items():
            resource_type = _strip_literal_quotes(type_label)
            if not isinstance(resource_type, str) or not isinstance(named, dict):
                continue
            for name_label, attrs in named.items():
                resource_name = _strip_literal_quotes(name_label)
                if isinstance(resource_name, str) and isinstance(attrs, dict):
                    blocks.append((resource_type, resource_name, attrs))
    return blocks


def _extract_jsonencode_policy(raw_value: object) -> dict[str, Any] | None:
    if not isinstance(raw_value, str):
        return None
    match = _JSONENCODE_PATTERN.match(raw_value.strip())
    if not match:
        return None
    try:
        parsed = hcl2.loads("policy = " + match.group(1))
    except Exception:
        return None
    policy = parsed.get("policy") if isinstance(parsed, dict) else None
    stripped = _strip_literal_quotes(policy) if isinstance(policy, dict) else None
    return stripped if isinstance(stripped, dict) else None


def _malformed_diagnostic(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNPARSED-REGION",
        message=f"IAM policy could not be parsed: {reason}.",
        evidence=evidence,
    )


def _unsupported_provider_diagnostic(
    evidence: tuple[Evidence, ...], provider: str
) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNPARSED-REGION",
        message=(
            f"{provider} IAM policy documents are recognized but not "
            "supported (AWS only)."
        ),
        evidence=evidence,
    )


def _statement_node(
    relative_path: str,
    in_document_key: str,
    statement: dict[str, Any],
    evidence: tuple[Evidence, ...],
) -> Node | None:
    effect = statement.get("Effect", statement.get("effect"))
    actions = _as_string_list(statement.get("Action", statement.get("actions")))
    resources = _as_string_list(statement.get("Resource", statement.get("resources")))
    condition = statement.get("Condition", statement.get("condition"))

    if not isinstance(effect, str) or not effect or not actions or not resources:
        return None

    if _has_unresolved_interpolation(actions) or _has_unresolved_interpolation(
        resources
    ):
        return None

    permission_scopes = tuple(
        sorted({_encode_scope(value) for value in (*actions, *resources)})
    )
    if isinstance(condition, dict) and condition:
        permission_scopes = (*permission_scopes, _CONDITION_MARKER)

    display_name = f"{effect}: " + (
        actions[0] if len(actions) == 1 else f"{len(actions)} actions"
    )

    try:
        identity_material = NodeIdentityMaterial(
            node_type=NodeType.PERMISSION,
            namespace=_NAMESPACE,
            semantic_identity=SemanticIdentity(
                source_path=relative_path, in_document_key=in_document_key
            ),
        )
        return Node(
            id=node_id(identity_material),
            type=NodeType.PERMISSION,
            subtype="iam-statement",
            name=display_name,
            security_attributes=SecurityAttributes(permission_scopes=permission_scopes),
            confidence=Confidence.HIGH,
            evidence=evidence,
        )
    except ValueError:
        return None


def _statements_from_policy(policy: object) -> list[dict[str, Any]] | None:
    if not isinstance(policy, dict):
        return None
    version = policy.get("Version", policy.get("version"))
    statements = policy.get("Statement", policy.get("statement"))
    if version not in _SUPPORTED_VERSIONS and version is not None:
        return None
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return None
    return [statement for statement in statements if isinstance(statement, dict)]


def _looks_like_aws_statement_shape(policy: object) -> bool:
    """Recognizes the AWS IAM policy *shape* -- a Statement/statement key
    holding a dict or a list of dicts -- independent of the declared
    Version. Used only for the native-JSON claim decision and its
    version check, so a document with an unrecognized version is still
    claimed and gets its own diagnostic (unknown, never silently
    dropped) rather than being indistinguishable from a document that
    was never IAM-shaped at all. `_statements_from_policy` above stays
    version-sensitive for its other caller (Terraform discovery), which
    is unaffected by this distinction."""

    if not isinstance(policy, dict):
        return False
    statements = policy.get("Statement", policy.get("statement"))
    if isinstance(statements, dict):
        statements = [statements]
    return isinstance(statements, list) and any(
        isinstance(item, dict) for item in statements
    )


def _unsupported_version_diagnostic(
    evidence: tuple[Evidence, ...], version: str
) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNPARSED-REGION",
        message=f"IAM policy declares unsupported Version {version!r}.",
        evidence=evidence,
    )


def _nodes_from_statements(
    relative_path: str,
    key_prefix: str,
    statements: list[dict[str, Any]],
    evidence: tuple[Evidence, ...],
) -> tuple[list[Node], list[Diagnostic]]:
    nodes: list[Node] = []
    diagnostics: list[Diagnostic] = []
    for index, statement in enumerate(statements):
        node = _statement_node(
            relative_path, f"{key_prefix}:{index}", statement, evidence
        )
        if node is None:
            diagnostics.append(
                incomplete_diagnostic(
                    code="INCOMPLETE-UNRESOLVED-REFERENCE",
                    message=(
                        "An IAM statement could not be resolved statically "
                        "(missing fields or an unresolved interpolation)."
                    ),
                    evidence=evidence,
                )
            )
            continue
        nodes.append(node)
    return nodes, diagnostics


def _is_gcp_shaped(document: dict[str, Any]) -> bool:
    bindings = document.get("bindings")
    return isinstance(bindings, list) and any(
        isinstance(item, dict) and "role" in item and "members" in item
        for item in bindings
    )


def _is_azure_shaped(document: dict[str, Any]) -> bool:
    properties = document.get("properties")
    return isinstance(properties, dict) and (
        "roleName" in properties or "assignableScopes" in properties
    )


def _discover_json_file(
    context: ScanContext, relative_path: str
) -> tuple[tuple[Node, ...], tuple[Diagnostic, ...]]:
    absolute = context.root.path / relative_path
    evidence = (Evidence(adapter=_NAME, path=relative_path),)

    try:
        with bounded_recursion(margin=500):
            document = json.loads(absolute.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return (), (
            _malformed_diagnostic(evidence, "the file could not be read as UTF-8 JSON"),
        )

    if not isinstance(document, dict):
        return (), (
            _malformed_diagnostic(evidence, "the top level is not a JSON object"),
        )

    if _is_gcp_shaped(document):
        return (), (_unsupported_provider_diagnostic(evidence, "GCP"),)
    if _is_azure_shaped(document):
        return (), (_unsupported_provider_diagnostic(evidence, "Azure"),)

    if not _looks_like_aws_statement_shape(document):
        return (), (
            _malformed_diagnostic(evidence, "no recognizable AWS IAM policy document"),
        )

    version = document.get("Version", document.get("version"))
    if version is not None and version not in _SUPPORTED_VERSIONS:
        return (), (_unsupported_version_diagnostic(evidence, str(version)),)

    statements = _statements_from_policy(document)
    if statements is None:
        return (), (
            _malformed_diagnostic(evidence, "no recognizable AWS IAM policy document"),
        )

    nodes, diagnostics = _nodes_from_statements(
        relative_path, "statement", statements, evidence
    )
    return tuple(nodes), tuple(diagnostics)


def _discover_terraform_file(
    context: ScanContext, relative_path: str
) -> tuple[tuple[Node, ...], tuple[Diagnostic, ...]]:
    absolute = context.root.path / relative_path
    evidence = (Evidence(adapter=_NAME, path=relative_path),)

    try:
        document = hcl2.loads(absolute.read_text(encoding="utf-8"))
    except Exception:
        return (), (
            _malformed_diagnostic(evidence, "the file could not be parsed as HCL"),
        )

    if not isinstance(document, dict):
        return (), (
            _malformed_diagnostic(evidence, "the file did not parse into a document"),
        )

    nodes: list[Node] = []
    diagnostics: list[Diagnostic] = []

    for resource_type, resource_name, attrs in _iter_hcl_blocks(document, "resource"):
        if resource_type.startswith(("google_", "azurerm_")) and (
            "iam" in resource_type or "role" in resource_type
        ):
            provider = "GCP" if resource_type.startswith("google_") else "Azure"
            diagnostics.append(_unsupported_provider_diagnostic(evidence, provider))
            continue
        if resource_type not in _TERRAFORM_POLICY_RESOURCE_TYPES:
            continue
        policy = _extract_jsonencode_policy(attrs.get("policy"))
        if policy is None:
            diagnostics.append(
                _malformed_diagnostic(
                    evidence,
                    f"resource {resource_type}.{resource_name} has no parseable policy",
                )
            )
            continue
        statements = _statements_from_policy(policy)
        if statements is None:
            diagnostics.append(
                _malformed_diagnostic(
                    evidence,
                    f"resource {resource_type}.{resource_name}'s policy is "
                    "not a recognizable AWS IAM document",
                )
            )
            continue
        file_nodes, file_diagnostics = _nodes_from_statements(
            relative_path, f"{resource_type}.{resource_name}", statements, evidence
        )
        nodes.extend(file_nodes)
        diagnostics.extend(file_diagnostics)

    for resource_type, resource_name, attrs in _iter_hcl_blocks(document, "data"):
        if resource_type != _TERRAFORM_POLICY_DOCUMENT_TYPE:
            continue
        raw_statements = attrs.get("statement")
        raw_statement_list: list[object] = (
            raw_statements if isinstance(raw_statements, list) else [raw_statements]
        )
        stripped_statements = [
            _strip_literal_quotes(statement)
            for statement in raw_statement_list
            if isinstance(statement, dict)
        ]
        file_nodes, file_diagnostics = _nodes_from_statements(
            relative_path,
            f"{resource_type}.{resource_name}",
            [s for s in stripped_statements if isinstance(s, dict)],
            evidence,
        )
        nodes.extend(file_nodes)
        diagnostics.extend(file_diagnostics)

    return tuple(nodes), tuple(diagnostics)


def _candidate_paths(context: ScanContext) -> tuple[str, ...]:
    found = set()
    for item in walk_repository(context.root):
        if not isinstance(item, Path):
            continue
        suffix = item.suffix.lower()
        if suffix == ".tf":
            found.add(item.relative_to(context.root.path).as_posix())
        elif suffix == ".json":
            try:
                with bounded_recursion(margin=500):
                    document = json.loads(item.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                continue
            if isinstance(document, dict) and (
                _looks_like_aws_statement_shape(document)
                or _is_gcp_shaped(document)
                or _is_azure_shaped(document)
            ):
                found.add(item.relative_to(context.root.path).as_posix())
    return tuple(sorted(found))


class IamPolicyAdapter:
    """Discovers AWS IAM policy documents committed to a repository as
    native JSON or Terraform HCL resources; recognizes and rejects GCP
    and Azure policy documents rather than misparsing them."""

    name = _NAME
    supported_versions: tuple[str, ...] = _SUPPORTED_VERSIONS

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(
            adapter=self.name, claimed_paths=_candidate_paths(context)
        )

    def discover(self, context: ScanContext) -> DiscoveryResult:
        nodes: list[Node] = []
        diagnostics: list[Diagnostic] = []
        for relative_path in _candidate_paths(context):
            if relative_path.endswith(".tf"):
                file_nodes, file_diagnostics = _discover_terraform_file(
                    context, relative_path
                )
            else:
                file_nodes, file_diagnostics = _discover_json_file(
                    context, relative_path
                )
            nodes.extend(file_nodes)
            diagnostics.extend(file_diagnostics)
        return DiscoveryResult(nodes=tuple(nodes), diagnostics=tuple(diagnostics))
