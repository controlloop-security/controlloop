"""Editor startup files and JetBrains required plugins.

Two kinds of committed file make an editor act when the project opens:

- **Startup files** at the repository root, which the editor sources as
  code: `.nvim.lua`, `.nvimrc`, and `.exrc` (Neovim and Vim with
  `'exrc'` set; Neovim 0.9 and later asks before running one it has not
  trusted), `.lvimrc` (the localvimrc plugin), and `.dir-locals.el` and
  `.dir-locals-2.el` (Emacs directory variables, whose `eval` forms run
  code once allowed). Each becomes a `helper-command` with `event:
  project-open`, the editor as its host, the file's path as the command,
  and the file's SHA-256 as `script_digest`, so
  `policy.agent-hook-command-change` reports a new file and
  `policy.hook-script-changed` a changed one. The file is never parsed,
  evaluated, or read into any output: only its presence, path, and
  digest are recorded. A file past the walker's per-file bound is
  skipped by the walker, which reports it.
- **`.idea/externalDependencies.xml`**, the JetBrains "Required plugins"
  list: a `plugin` component per `<plugin>` with `source_type:
  editor-extension`, pinned only when `min-version` equals
  `max-version`, unpinned for a range or one bound, and `unknown` with
  neither. The IDE asks to install or enable a missing plugin, so the
  host `receives-from` it rather than `invokes` it. The element and
  attribute names (`<project version="4">`, `<component
  name="ExternalDependencies">`, `<plugin id min-version max-version>`)
  are IntelliJ's own: `DependencyOnPluginState` and
  `ExternalDependenciesManagerImpl` in JetBrains/intellij-community
  (read at commit 46ae258e on 2026-11-03), whose `.idea/externalDependencies.xml`
  is written the same way. A document type declaration is refused
  before parsing, so no entity is ever expanded or fetched.

Zed's `.zed/settings.json` is deliberately not read: its
`auto_install_extensions` setting belongs to the user settings
(`ExtensionSettingsContent` in `SettingsContent`), and a project
settings file is parsed as `ProjectSettingsContent`, which has no such
field (zed-industries/zed `crates/settings_content` and
`crates/settings/src/settings_store.rs`, read at commit 8a47b351 on
2026-11-03), so a repository cannot make Zed install an extension.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from typing import NamedTuple

from controlloop.acbom import KnownBoolean
from controlloop.adapters import agent_authority as aa
from controlloop.adapters.claude_code import ComponentDiscovery
from controlloop.adapters.environment import (
    EnvironmentHost,
    installed_component,
    merge,
    startup_command,
)
from controlloop.adapters.framework import (
    DetectionResult,
    DiscoveryResult,
    RepositoryFile,
    ScanContext,
)
from controlloop.adapters.script_digest import file_digest

_NAME = "editor-startup"
DOCUMENTATION_SNAPSHOT = "2026-11-03"


class _Editor(NamedTuple):
    key: str
    display_name: str


_NEOVIM = _Editor("neovim", "Neovim")
_VIM = _Editor("vim", "Vim")
_EMACS = _Editor("emacs", "Emacs")
_JETBRAINS = _Editor("jetbrains", "JetBrains IDEs")

#: Root-level startup files and the editor that sources each.
STARTUP_FILES: dict[str, _Editor] = {
    ".nvim.lua": _NEOVIM,
    ".nvimrc": _NEOVIM,
    ".exrc": _VIM,
    ".lvimrc": _VIM,
    ".dir-locals.el": _EMACS,
    ".dir-locals-2.el": _EMACS,
}
_EXTERNAL_DEPENDENCIES = ".idea/externalDependencies.xml"
_PROJECT_FORMAT_VERSION = "4"

_STARTUP_NAMESPACE = "editor.startup-file"
_PLUGIN_NAMESPACE = "jetbrains.plugin"
_EVENT = "project-open"

_DECLARATION = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)
#: A version bound that resolves at run time, such as `<ide.build.baseline>`.
_PLACEHOLDER = re.compile(r"[<>${}]")


def _startup_file(host: EnvironmentHost, file: RepositoryFile) -> None:
    found = host.file(file.relative)
    startup_command(
        found,
        namespace=_STARTUP_NAMESPACE,
        setting=file.relative,
        command=aa.authority_text(file.relative),
        event=_EVENT,
        component_key=file.relative,
        attributes={
            "script_path": aa.authority_text(file.relative),
            "script_digest": file_digest(file),
        },
    )
    host.take(found)


def plugin_pin(minimum: str | None, maximum: str | None) -> KnownBoolean:
    """Pinned only when both bounds name the same fixed version."""

    if minimum is None and maximum is None:
        return "unknown"
    if minimum is None or maximum is None or minimum != maximum:
        return False
    return _PLACEHOLDER.search(minimum) is None


def _bounds_text(minimum: str | None, maximum: str | None) -> str | None:
    if minimum is not None and minimum == maximum:
        return minimum
    parts = [
        f"{label} {value}"
        for label, value in (("min", minimum), ("max", maximum))
        if value is not None
    ]
    return ", ".join(parts) or None


def _parse(
    found: ComponentDiscovery, file: RepositoryFile
) -> ElementTree.Element | None:
    try:
        if file.path.stat().st_size > aa.MAX_CONFIG_BYTES:
            found.unparsed("the file is larger than the configuration bound")
            return None
        raw = file.path.read_bytes()
    except OSError:
        found.unparsed("the file could not be read")
        return None
    if b"\x00" in raw:
        # UTF-16 or UTF-32, which would hide a declaration from the check
        # below; IntelliJ writes UTF-8.
        found.unparsed("the file is not UTF-8")
        return None
    if _DECLARATION.search(raw):
        found.unparsed("the file declares a document type, which is not read")
        return None
    try:
        return ElementTree.fromstring(raw)
    except (ElementTree.ParseError, ValueError, RecursionError):
        found.unparsed("the file is not valid XML")
        return None


def _required_plugins(host: EnvironmentHost, file: RepositoryFile) -> None:
    found = host.file(file.relative)
    root = _parse(found, file)
    if root is None:
        host.take(found)
        return
    version = root.get("version")
    if root.tag != "project":
        found.unparsed("the top-level element is not a project")
        host.take(found)
        return
    if version is not None and version != _PROJECT_FORMAT_VERSION:
        found.unparsed(f"project format version {aa.authority_text(version)} is not 4")
        host.take(found)
        return
    plugins = [
        plugin
        for component in root.findall("component")
        if component.get("name") == "ExternalDependencies"
        for plugin in component.findall("plugin")
    ]
    seen: set[str] = set()
    for plugin in found.bounded(plugins, "required plugins"):
        plugin_id = (plugin.get("id") or "").strip()
        if not plugin_id:
            found.unparsed("a required plugin has no id")
            continue
        if plugin_id in seen:
            continue
        seen.add(plugin_id)
        minimum = plugin.get("min-version")
        maximum = plugin.get("max-version")
        attributes = {"plugin_id": aa.authority_text(plugin_id)}
        if minimum is not None:
            attributes["min_version"] = aa.authority_text(minimum)
        if maximum is not None:
            attributes["max_version"] = aa.authority_text(maximum)
        bounds = _bounds_text(minimum, maximum)
        if bounds is not None:
            attributes["ref"] = aa.authority_text(bounds)
        installed_component(
            found,
            kind="editor-extension",
            namespace=_PLUGIN_NAMESPACE,
            component_key=aa.key_path("ExternalDependencies", plugin_id),
            name=f"editor plugin {plugin_id}",
            pinned=plugin_pin(minimum, maximum),
            attributes=attributes,
            installs=False,
        )
    host.take(found)


class EditorStartupAdapter:
    """Root-level editor startup files and JetBrains required plugins."""

    name = _NAME
    supported_versions: tuple[str, ...] = (f"docs-{DOCUMENTATION_SNAPSHOT}",)

    def _files(self, context: ScanContext) -> list[RepositoryFile]:
        return sorted(
            (
                file
                for file in context.repository_files()
                if file.relative in STARTUP_FILES
                or file.relative == _EXTERNAL_DEPENDENCIES
            ),
            key=lambda file: file.relative,
        )

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(
            adapter=self.name,
            claimed_paths=tuple(file.relative for file in self._files(context)),
        )

    def discover(self, context: ScanContext) -> DiscoveryResult:
        hosts = {
            editor.key: EnvironmentHost(editor.key, editor.display_name, self.name)
            for editor in (_NEOVIM, _VIM, _EMACS, _JETBRAINS)
        }
        for file in self._files(context):
            if file.relative == _EXTERNAL_DEPENDENCIES:
                _required_plugins(hosts[_JETBRAINS.key], file)
            else:
                _startup_file(hosts[STARTUP_FILES[file.relative].key], file)
        return merge(*(host.result() for host in hosts.values()))


__all__ = [
    "DOCUMENTATION_SNAPSHOT",
    "STARTUP_FILES",
    "EditorStartupAdapter",
    "plugin_pin",
]
