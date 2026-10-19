"""Shared building blocks for agent host configuration adapters.

Every agent host adapter reads a committed file that grants a coding
agent authority -- a Claude Code settings file, a skill, a Codex
config, a workflow -- and emits the same canonical shapes from ACBOM
schema 1.2.0 (`controlloop.acbom.AuthoritySubtype`). This module holds
the parts they share so the conventions cannot drift between hosts:

- bounded loading of JSON with comments and trailing commas;
- structural key paths, the identity material for every component;
- `authority_text`, the only way a command string, rule pattern, or
  setting value reaches an attribute: redacted first, then bounded;
- node builders for hosts, hooks, helper commands, permission rules,
  plugins, marketplaces, and resources;
- the unknown-key and unresolved-reference diagnostics.

Nothing here executes, connects to, or writes anything. A value is
recorded only after it has been through `controlloop.redaction`, and a
value category the ACBOM must never carry (an environment value, a
header value, a prompt body) has no parameter here to pass it through.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    KnownBoolean,
    Node,
    NodeType,
    SecurityAttributes,
    authority_component_node_id,
    bound_attribute_text,
    host_node_id,
)
from controlloop.acbom.completeness import incomplete_diagnostic
from controlloop.acbom.identity import EdgeIdentityMaterial, edge_id
from controlloop.bounded_recursion import bounded_recursion
from controlloop.redaction import redact_text

#: Largest configuration file an agent host adapter reads, in bytes. The
#: repository walker bounds files already; this is a second, tighter
#: bound for files that are parsed whole into memory.
MAX_CONFIG_BYTES = 1_048_576

#: Most entries read from any one list or object in a configuration
#: file (hooks per event, rules per list, plugins). Entries past the
#: bound produce one `INCOMPLETE-BOUND-EXCEEDED` diagnostic, never a
#: silent drop.
MAX_ENTRIES = 512

#: Replaces an absolute or home-relative path in an attribute. A path
#: outside the repository identifies the machine it came from.
OUTSIDE_REPOSITORY_PATH = "<outside-repository>"

_KEY_SEGMENT_SAFE = re.compile(r"^[A-Za-z0-9_$-]+$")

#: Placeholder for a value removed by `_scrub_secret_like`.
REDACTED_VALUE = "<redacted>"

#: Secret-carrying positions in a command line that the signature-based
#: shapes in `controlloop.redaction` cannot see because the value itself
#: has no recognizable format: a bearer token, a `--token=` style flag,
#: and a `NAME_TOKEN=` style assignment. `${NAME}` references are names,
#: not values, and are left as they are.
_SECRET_LIKE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(\bbearer\s+)(?!\$\{)[^\s'\"]+"),
    re.compile(r"(?i)(\bbasic\s+)(?!\$\{)[A-Za-z0-9+/=]{8,}"),
    re.compile(
        r"(?i)(--?(?:token|password|passwd|pwd|secret|key|api[-_]?key|access[-_]?key|"
        r"auth(?:orization)?|client[-_]?secret)(?:=|\s+))(?!\$\{)[^\s'\"]+"
    ),
    re.compile(
        r"(?i)(\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|"
        r"PRIVATE_?KEY|CREDENTIALS?)[A-Z0-9_]*=)(?!\$\{)[^\s'\";&|]+"
    ),
    re.compile(r"(?i)(://[^/\s:@]+:)[^@/\s]+(@)"),
)
_SHA_PIN = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")


class ConfigLoadError(ValueError):
    """A configuration file could not be loaded as an object.

    The message is fixed text naming the category of failure, never the
    file's content.
    """


def _strip_jsonc(text: str) -> str:
    """Remove `//` and `/* */` comments and trailing commas, outside
    strings. Many agent hosts accept JSON with comments in their
    settings files, and a stray comment must not hide a whole file."""

    out: list[str] = []
    index = 0
    length = len(text)
    in_string = False
    while index < length:
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < length:
                out.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = length if newline == -1 else newline
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end == -1:
                raise ConfigLoadError("an unterminated block comment")
            index = end + 2
            continue
        out.append(char)
        index += 1
    stripped = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", stripped)


def load_json_object(path: Path, *, allow_comments: bool = True) -> dict[str, Any]:
    """Return the top-level object in the JSON (or JSONC) file at `path`.

    Raises `ConfigLoadError` for an unreadable, oversized, malformed,
    pathologically nested, or non-object file. Duplicate keys keep the
    last value, as `json` does and as the hosts do.
    """

    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigLoadError("the file is larger than the configuration bound")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise ConfigLoadError("the file could not be read as UTF-8") from None
    try:
        with bounded_recursion(margin=500):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                if not allow_comments:
                    raise
                payload = json.loads(_strip_jsonc(text))
    except (json.JSONDecodeError, RecursionError):
        raise ConfigLoadError("the file is not valid JSON") from None
    if not isinstance(payload, dict):
        raise ConfigLoadError("the file's top level is not an object")
    return payload


def key_path(*segments: str | int) -> str:
    """Return a structural key path such as `hooks.SessionStart[0].hooks[1]`.

    Object keys join with `.`; list indexes are bracketed. A key that is
    not a plain name is quoted in brackets so two different paths can
    never render the same.
    """

    parts: list[str] = []
    for segment in segments:
        if isinstance(segment, int):
            parts.append(f"[{segment}]")
        elif _KEY_SEGMENT_SAFE.fullmatch(segment):
            parts.append(f".{segment}" if parts else segment)
        else:
            parts.append(f"[{json.dumps(segment, ensure_ascii=True)}]")
    return "".join(parts)[:512] or "$"


def authority_text(value: object) -> str:
    """Return `value` as text fit for an attribute: redacted, then bounded.

    Every command string, rule pattern, and setting value an agent host
    adapter records passes through here. Credential-shaped substrings
    are replaced by `controlloop.redaction.redact_text` before the text
    is bounded, so neither the full value nor a truncated prefix of a
    secret can reach the ACBOM.
    """

    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return bound_attribute_text(_scrub_secret_like(redact_text(text)))


def _scrub_secret_like(text: str) -> str:
    scrubbed = text
    for pattern in _SECRET_LIKE_PATTERNS:
        if pattern.groups == 2:
            scrubbed = pattern.sub(rf"\g<1>{REDACTED_VALUE}\g<2>", scrubbed)
        else:
            scrubbed = pattern.sub(rf"\g<1>{REDACTED_VALUE}", scrubbed)
    return scrubbed


def command_text(command: object, args: object = None) -> str:
    """Join a command and an optional argument list into one bounded,
    redacted attribute value."""

    parts: list[str] = []
    if isinstance(command, str):
        parts.append(command)
    elif isinstance(command, list):
        parts.extend(str(part) for part in command[:MAX_ENTRIES])
    if isinstance(args, list):
        parts.extend(str(part) for part in args[:MAX_ENTRIES])
    return authority_text(" ".join(parts)) if parts else "unknown"


def repository_path_text(value: str) -> str:
    """Return a path setting safe to record: repository-relative paths
    are kept, anything absolute or home-relative becomes a marker."""

    if value.startswith(("/", "~", "\\")) or re.match(r"^[A-Za-z]:[\\/]", value):
        return OUTSIDE_REPOSITORY_PATH
    return authority_text(value)


def url_host(url: str) -> str:
    """Return only the host of `url`, never its path, query, or
    credentials, or `unknown` when none can be read."""

    match = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://(?:[^@/?#]*@)?([^/:?#]+)", url)
    if match is None:
        return "unknown"
    return authority_text(match.group(1).lower())


def is_pinned_ref(value: object) -> bool:
    """Whether `value` is a full commit SHA or a SHA-256 digest."""

    return isinstance(value, str) and _SHA_PIN.fullmatch(value.lower()) is not None


def evidence_for(adapter: str, path: str) -> tuple[Evidence, ...]:
    return (Evidence(adapter=adapter, path=path),)


def host_node(
    *,
    host: str,
    display_name: str,
    evidence: Sequence[Evidence],
    attributes: Mapping[str, str],
    bypass_mode: KnownBoolean | None,
) -> Node:
    """Return the one `agent/host` node for `host` in a repository."""

    return Node(
        id=host_node_id(host),
        type=NodeType.AGENT,
        subtype="host",
        name=display_name,
        attributes={"host": host, **attributes},
        security_attributes=SecurityAttributes(bypass_mode=bypass_mode),
        confidence=Confidence.HIGH,
        evidence=tuple(sorted(set(evidence), key=lambda item: item.path or ""))[:32],
    )


def host_reference_node(
    *, host: str, display_name: str, evidence: Sequence[Evidence]
) -> Node:
    """Return a *reference* to the host node another adapter owns.

    An adapter that connects something to a host it does not configure
    (a CI workflow that runs Claude Code) emits this instead of a full
    host node: the host key only, default security attributes.
    `controlloop.adapters.runner` folds every reference into the full
    node with the same ID, or keeps a single reference when no adapter
    owns the host, so two adapters never emit conflicting copies.
    """

    return Node(
        id=host_node_id(host),
        type=NodeType.AGENT,
        subtype="host",
        name=display_name,
        attributes={"host": host},
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=tuple(sorted(set(evidence), key=lambda item: item.path or ""))[:32],
    )


def is_host_reference(node: Node) -> bool:
    return (
        node.subtype == "host"
        and set(node.attributes) == {"host"}
        and node.security_attributes == SecurityAttributes()
    )


def component_node(
    *,
    node_type: NodeType,
    subtype: str,
    namespace: str,
    declaring_path: str,
    component_key: str,
    name: str,
    attributes: Mapping[str, str],
    security_attributes: SecurityAttributes,
    evidence: Sequence[Evidence],
    confidence: Confidence = Confidence.HIGH,
) -> Node:
    """Return an authority component node identified by its declaring
    file and structural key path."""

    return Node(
        id=authority_component_node_id(
            node_type,
            namespace=namespace,
            declaring_path=declaring_path,
            key_path=component_key,
        ),
        type=node_type,
        subtype=subtype,
        name=bound_display_name(name),
        # The key path names where in its file the component is declared,
        # for findings and the authority statement.
        attributes={**attributes, "key_path": authority_text(component_key)},
        security_attributes=security_attributes,
        confidence=confidence,
        evidence=tuple(evidence),
    )


def bound_display_name(name: str) -> str:
    """Bound a display name to the canonical 256-character limit."""

    text = authority_text(name)
    return text if len(text) <= 256 else text[:253] + "..."


def edge(
    *,
    source: str,
    target: str,
    relationship: EdgeType,
    discriminator: str,
    evidence: Sequence[Evidence],
    security_attributes: SecurityAttributes | None = None,
) -> Edge:
    return Edge(
        id=edge_id(
            EdgeIdentityMaterial(
                relationship_type=relationship,
                source_id=source,
                target_id=target,
                relationship_discriminator=discriminator[:512],
            )
        ),
        source=source,
        target=target,
        type=relationship,
        status=EdgeStatus.DIRECT,
        security_attributes=security_attributes or SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=tuple(evidence),
    )


def unrecognized_key_diagnostic(
    *, host_label: str, path: str, adapter: str, key_paths: Iterable[str]
) -> Diagnostic:
    """One diagnostic per file naming every key the adapter does not
    recognize. Key names are configuration structure, not values; they
    are still bounded and redacted."""

    names = sorted({authority_text(item) for item in key_paths})
    shown = ", ".join(names[:20])
    more = f" and {len(names) - 20} more" if len(names) > 20 else ""
    message = (
        f"{host_label} setting keys not recognized by this adapter's "
        f"documentation snapshot, so what they grant is unknown: {shown}{more}."
    )
    return incomplete_diagnostic(
        code="INCOMPLETE-UNRECOGNIZED-KEY",
        message=message[:1024],
        evidence=evidence_for(adapter, path),
    )


def unparsed_diagnostic(*, adapter: str, path: str, reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNPARSED-REGION",
        message=f"Agent configuration could not be fully read: {reason}.",
        evidence=evidence_for(adapter, path),
    )


def bound_exceeded_diagnostic(*, adapter: str, path: str, what: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-BOUND-EXCEEDED",
        message=(
            f"Only the first {MAX_ENTRIES} {what} were read; the rest are not "
            "represented."
        ),
        evidence=evidence_for(adapter, path),
    )


def unresolved_reference_diagnostic(
    *, adapter: str, path: str, what: str
) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNRESOLVED-REFERENCE",
        message=f"{what} could not be resolved to a discovered component."[:1024],
        evidence=evidence_for(adapter, path),
    )


# --- Permission rules ------------------------------------------------------

_RULE_PATTERN = re.compile(r"^(?P<tool>[^()]+?)(?:\((?P<specifier>.*)\))?$", re.DOTALL)
#: Shell-running tools across hosts: Claude Code `Bash` and `PowerShell`,
#: Cursor CLI `Shell`, Gemini CLI `run_shell_command`, Kiro `shell`.
_SHELL_TOOLS = frozenset({"Bash", "PowerShell", "Shell", "run_shell_command", "shell"})


def classify_permission_rule(rule: str) -> tuple[str, bool]:
    """Return `(tool, wildcard)` for a Claude Code-style permission rule.

    A rule is a wildcard when it is a bare tool name (`Bash`), a
    match-all specifier (`Bash(*)`, `Read(**)`), a shell rule with any
    `*` in it (`Bash(npm *)`, `Bash(git:*)`), an MCP server rule without
    one named tool (`mcp__github`, `mcp__github__*`), or a tool-name
    glob (`mcp__*`, `*`). A rule is classified, never expanded into the
    commands or tools it might match.
    """

    text = rule.strip()
    match = _RULE_PATTERN.fullmatch(text)
    if match is None:
        return "unknown", True
    tool = match.group("tool").strip()
    specifier = match.group("specifier")
    if "*" in tool:
        return tool, True
    if tool.startswith("mcp__"):
        parts = tool.split("__")
        # mcp__<server> or mcp__<server>__* name every tool on a server.
        return tool, len(parts) <= 2
    if specifier is None:
        return tool, True
    stripped = specifier.strip()
    if stripped in {"*", "**", ""}:
        return tool, True
    if tool in _SHELL_TOOLS and "*" in stripped:
        return tool, True
    return tool, False


def is_shell_tool(tool: str) -> bool:
    return tool in _SHELL_TOOLS
