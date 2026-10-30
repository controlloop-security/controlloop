"""The script a hook or helper command runs, tracked by digest.

A hook records its command line, so a pull request that edits
`.claude/settings.json` is reported. One that leaves the settings alone
and edits `.claude/hooks/setup.sh`, the file the hook runs, used to pass
unseen. This module closes that gap for scripts committed in the
repository: when a recorded command names a repository file, the node
gains two attributes,

    script_path     the file's repository-relative path
    script_digest   sha256 of its bytes, or "unknown"

and `policy.hook-script-changed` reports a digest that moves while the
command does not. A plugin's `bin/` directory gets one digest over the
sorted names and digests of the files in it.

**Which commands name a file.** The first word of the command when it is
a path (`./scripts/check.sh`, `"$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh`),
or the first word after a known interpreter (`node`, `python`, `bash`,
`uv run`, `npx` with a local path, and a few more). A bare command name
(`prettier`) is looked up on `PATH`, not in the repository, and an
interpreter given inline code (`python -c`, `node -e`) names no file:
neither records anything.

**Only files the walker listed are opened.** A path is resolved against
`ScanContext.repository_files()`, which is already contained to the
repository root and bounded in size, so a path outside the root, a
symlink that escapes, and a file over the byte bound are never read. An
absolute, home-relative, or `..`-escaping path records `script_digest:
unknown` with an informational diagnostic; a named file the walker did
not list (too large, an escaping symlink, ignored, or missing) records
`unknown`, and the walker's own diagnostic says why where it has one.

No file content enters any output. The digest is the only thing recorded.
"""

from __future__ import annotations

import hashlib
import posixpath
import shlex
from collections.abc import Mapping

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Node,
)
from controlloop.adapters import agent_authority as aa
from controlloop.adapters.framework import (
    DiscoveryResult,
    RepositoryFile,
    ScanContext,
)
from controlloop.repository import TraversalBounds

UNKNOWN = "unknown"
_OUTSIDE_CODE = "SCRIPT-OUTSIDE-REPOSITORY"

#: Interpreters whose first non-option argument is the script they run,
#: each with the options that hand it inline code or a module instead.
_INLINE_OPTIONS: dict[str, frozenset[str]] = {
    "bash": frozenset({"-c"}),
    "sh": frozenset({"-c"}),
    "zsh": frozenset({"-c"}),
    "python": frozenset({"-c", "-m"}),
    "python3": frozenset({"-c", "-m"}),
    "node": frozenset({"-e", "-p", "--eval", "--print"}),
    "bun": frozenset({"-e", "-p", "--eval", "--print"}),
    "tsx": frozenset({"-e", "-p", "--eval", "--print"}),
    "ruby": frozenset({"-e"}),
    "perl": frozenset({"-e", "-E"}),
}
_INTERPRETERS = frozenset(_INLINE_OPTIONS)
#: Variables that name the project root in a hook command.
_PROJECT_ROOT_PREFIXES = ("$CLAUDE_PROJECT_DIR/", "${CLAUDE_PROJECT_DIR}/")
_PLUGIN_ROOT_PREFIXES = ("$CLAUDE_PLUGIN_ROOT/", "${CLAUDE_PLUGIN_ROOT}/")
_PLUGIN_MANIFEST = ".claude-plugin/plugin.json"
_PLUGIN_HOOKS = "hooks/hooks.json"


def _words(command: str) -> list[str]:
    """The first simple command's words, after `env` and assignments."""

    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return []
    for index, word in enumerate(words):
        if word in {"&&", "||", ";", "|"}:
            words = words[:index]
            break
    while words and (
        words[0] in {"env", "exec"}
        or ("=" in words[0] and not words[0].startswith(("-", "/", ".")))
    ):
        words = words[1:]
    return words


def script_reference(command: str) -> str | None:
    """The path word in `command` that names a script, as written, or
    `None` when the command runs no repository file."""

    words = _words(command)
    if not words:
        return None
    first = words[0]
    if posixpath.basename(first) not in _INTERPRETERS | {"uv", "npx"}:
        return first if "/" in first else None
    rest = words[1:]
    interpreter = posixpath.basename(first)
    local_only = interpreter == "npx"
    if interpreter == "uv":
        if not rest or rest[0] != "run":
            return None
        rest = rest[1:]
        if rest and rest[0] in _INTERPRETERS:
            interpreter = rest[0]
            rest = rest[1:]
    inline = _INLINE_OPTIONS.get(interpreter, frozenset())
    for word in rest:
        if word in inline:
            return None
        if word.startswith("-"):
            continue
        if local_only and "/" not in word:
            return None
        return word
    return None


def _plugin_root(declaring_path: str) -> str | None:
    for suffix in (_PLUGIN_MANIFEST, _PLUGIN_HOOKS):
        if declaring_path == suffix:
            return ""
        if declaring_path.endswith("/" + suffix):
            return declaring_path[: -len(suffix)]
    return None


def _normalize(word: str, declaring_path: str) -> str | None:
    """The repository-relative path `word` names, `""` for a path outside
    the repository, or `None` when it cannot be resolved statically."""

    for prefix in _PROJECT_ROOT_PREFIXES:
        if word.startswith(prefix):
            word = word[len(prefix) :]
            break
    else:
        for prefix in _PLUGIN_ROOT_PREFIXES:
            if word.startswith(prefix):
                root = _plugin_root(declaring_path)
                if root is None:
                    return None
                word = root + word[len(prefix) :]
                break
    if word.startswith(("/", "~", "\\")):
        return ""
    if "$" in word or "`" in word:
        return None
    normalized = posixpath.normpath(word)
    if normalized == ".." or normalized.startswith("../"):
        return ""
    return normalized


def _file_digest(file: RepositoryFile) -> str:
    try:
        if file.path.stat().st_size > TraversalBounds().max_file_size_bytes:
            return UNKNOWN
        return "sha256:" + hashlib.sha256(file.path.read_bytes()).hexdigest()
    except OSError:
        return UNKNOWN


def _directory_digest(files: Mapping[str, RepositoryFile], directory: str) -> str:
    entries: list[str] = []
    for relative in sorted(files):
        if relative.startswith(directory):
            digest = _file_digest(files[relative])
            if digest == UNKNOWN:
                return UNKNOWN
            entries.append(f"{relative[len(directory) :]} {digest}")
    if not entries:
        return UNKNOWN
    return "sha256:" + hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()


def _outside(node: Node) -> Diagnostic:
    return Diagnostic(
        code=_OUTSIDE_CODE,
        severity=DiagnosticSeverity.INFO,
        message=(
            f"{node.name} runs a script outside the repository, so its "
            "contents are not tracked by digest."
        )[:1024],
        confidence=Confidence.HIGH,
        incomplete=False,
        evidence=node.evidence,
    )


def _tracked(
    node: Node, files: Mapping[str, RepositoryFile]
) -> tuple[Node, Diagnostic | None]:
    attributes = dict(node.attributes)
    declaring = node.evidence[0].path or ""
    if node.subtype == "helper-command" and attributes.get("setting") == "plugin-bin":
        directory = attributes.get("command", "")
        attributes["script_path"] = directory
        attributes["script_digest"] = _directory_digest(files, directory)
        return node.model_copy(update={"attributes": attributes}), None
    if node.subtype == "hook" and attributes.get("hook_type") != "command":
        return node, None
    command = attributes.get("command")
    if node.subtype not in {"hook", "helper-command"} or not command:
        return node, None
    word = script_reference(command)
    if word is None:
        return node, None
    relative = _normalize(word, declaring)
    if relative is None:
        return node, None
    if relative == "":
        attributes["script_path"] = aa.OUTSIDE_REPOSITORY_PATH
        attributes["script_digest"] = UNKNOWN
        return node.model_copy(update={"attributes": attributes}), _outside(node)
    file = files.get(relative)
    attributes["script_path"] = aa.authority_text(relative)
    attributes["script_digest"] = _file_digest(file) if file is not None else UNKNOWN
    return node.model_copy(update={"attributes": attributes}), None


def with_script_digests(
    result: DiscoveryResult, context: ScanContext
) -> DiscoveryResult:
    """`result` with `script_path` and `script_digest` on every hook,
    helper command, skill shell line, and plugin `bin/` node whose
    command names a repository file."""

    if not any(node.subtype in {"hook", "helper-command"} for node in result.nodes):
        return result
    files = {file.relative: file for file in context.repository_files()}
    nodes: list[Node] = []
    diagnostics = list(result.diagnostics)
    for node in result.nodes:
        tracked, diagnostic = _tracked(node, files)
        nodes.append(tracked)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
    return result.model_copy(
        update={"nodes": tuple(nodes), "diagnostics": tuple(diagnostics)}
    )


__all__ = ["UNKNOWN", "script_reference", "with_script_digests"]
