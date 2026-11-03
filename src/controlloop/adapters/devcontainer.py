"""Dev container configuration and VS Code extension recommendations.

Reads `devcontainer.json` where the specification looks for it
(`.devcontainer/devcontainer.json`, `.devcontainer/<folder>/devcontainer.json`,
and `.devcontainer.json`), plus `.vscode/extensions.json` and any
`*.code-workspace` file. Opening the repository in a dev container
installs the extensions and features those files name and runs their
lifecycle commands, one of them on the developer's own machine, so a
pull request that adds, swaps, or unpins one changes what runs on every
clone. Each becomes a shape the agent-authority rules already read
(`controlloop.adapters.environment`):

- `customizations.vscode.extensions` (and the older top-level
  `extensions`): a `plugin` component with `source_type:
  editor-extension`, pinned only when the id carries `@<major.minor.patch>`.
  The `@version` form, an optional semver pre-release or build suffix,
  and the `@prerelease` channel are VS Code's, from the item pattern in
  `extensions/configuration-editing/schemas/devContainer.vscode.schema.json`
  in microsoft/vscode (read at commit 53d2211d on 2026-11-03); the
  specification itself (containers.dev/supporting) only says "an array
  of extension IDs". `@prerelease` and a bare id are unpinned. An id
  with a leading `-` removes an extension, and is not recorded.
- `features`: a `plugin` component with `source_type:
  devcontainer-feature`, pinned by an `@sha256:` digest or an exact
  `major.minor.patch` tag. Features are published under semver and
  every major and minor tag is republished on each release, while an
  exact version is never republished (containers.dev
  "Distribution and Discovery of Dev Container Features"), so `:1`,
  `:1.2`, `:latest`, and no tag are unpinned. A local `./feature` is
  committed in the repository and pinned by the commit; an `https://`
  tarball is unpinned.
- `initializeCommand`, `onCreateCommand`, `updateContentCommand`,
  `postCreateCommand`, `postStartCommand`, `postAttachCommand`, in
  string, array, and object (named parallel commands) form: a
  `helper-command` per command with `event` naming the key and
  `runs_on_host: true` for `initializeCommand`, the one that runs
  outside the container (containers.dev/implementors/json_reference).
- `.vscode/extensions.json` and `*.code-workspace` `recommendations`: a
  `plugin` component with `recommended_only: true` and `pinned`
  `unknown`, because the format has no place for a pin. VS Code only
  suggests these, so the VS Code host `receives-from` them rather than
  `invokes` them.
  `unwantedRecommendations` is ignored.

A `dockerComposeFile` is recorded on the host as a path and never
opened; the image, Dockerfile, environment variables, and mounts are not
read. A file with only an image is silent. Nothing is executed, pulled,
or resolved.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any

from controlloop.acbom import KnownBoolean
from controlloop.adapters import agent_authority as aa
from controlloop.adapters.claude_code import ComponentDiscovery
from controlloop.adapters.environment import (
    EnvironmentHost,
    installed_component,
    is_exact_version,
    merge,
    startup_command,
)
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.adapters.script_digest import with_script_digests

_NAME = "devcontainer"
#: The date the specification pages and VS Code schema cited above were read.
DOCUMENTATION_SNAPSHOT = "2026-11-03"

_ROOT_CONFIG = ".devcontainer.json"
_FOLDER = ".devcontainer/"
_CONFIG_NAME = "devcontainer.json"
_EXTENSIONS_JSON = ".vscode/extensions.json"
_WORKSPACE_SUFFIX = ".code-workspace"

_EXTENSION_NAMESPACE = "vscode.extension"
_FEATURE_NAMESPACE = "devcontainer.feature"
_LIFECYCLE_NAMESPACE = "devcontainer.lifecycle-command"

#: The lifecycle commands, in the order the specification runs them.
LIFECYCLE_COMMANDS = (
    "initializeCommand",
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
)
_HOST_COMMANDS = frozenset({"initializeCommand"})

_EXTENSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9-]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _is_devcontainer_config(path: str) -> bool:
    if path == _ROOT_CONFIG:
        return True
    if not path.startswith(_FOLDER) or not path.endswith("/" + _CONFIG_NAME):
        return False
    # `.devcontainer/devcontainer.json` or exactly one folder below it.
    return path.count("/") in (1, 2)


def _is_recommendations(path: str) -> bool:
    return path == _EXTENSIONS_JSON or path.endswith(_WORKSPACE_SUFFIX)


def _claimed(context: ScanContext) -> list[str]:
    return sorted(
        file.relative
        for file in context.repository_files()
        if _is_devcontainer_config(file.relative) or _is_recommendations(file.relative)
    )


def _extension(
    found: ComponentDiscovery,
    entry: object,
    *,
    base_key: tuple[str, ...],
    seen: set[str],
    recommended: bool,
) -> None:
    if not isinstance(entry, str):
        found.unparsed("an extension entry is not a string")
        return
    text = entry.strip()
    if text.startswith("-"):
        # Removes an extension a feature or base config added.
        return
    extension_id, _, version = text.partition("@")
    if not _EXTENSION_ID.fullmatch(extension_id):
        found.unparsed("an extension entry is not a publisher.name id")
        return
    identity = extension_id.lower()
    if identity in seen:
        return
    seen.add(identity)
    attributes = {"extension_id": aa.authority_text(extension_id)}
    if version:
        attributes["ref"] = aa.authority_text(version)
    if recommended:
        attributes["recommended_only"] = "true"
        pinned: KnownBoolean = "unknown"
    else:
        pinned = is_exact_version(version)
    installed_component(
        found,
        kind="editor-extension",
        namespace=_EXTENSION_NAMESPACE,
        component_key=aa.key_path(*base_key, identity),
        name=f"editor extension {extension_id}",
        pinned=pinned,
        attributes=attributes,
        installs=not recommended,
    )


def _extensions(
    found: ComponentDiscovery,
    value: object,
    *,
    base_key: tuple[str, ...],
    recommended: bool = False,
) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        found.unparsed(f"{'.'.join(base_key)} is not a list")
        return
    seen: set[str] = set()
    for entry in found.bounded(value, "extensions"):
        _extension(found, entry, base_key=base_key, seen=seen, recommended=recommended)


def _feature_reference(
    reference: str, config_path: str
) -> tuple[str, str | None, KnownBoolean, str]:
    """`(feature, version, pinned, origin)` for one `features` key."""

    if reference.startswith(("./", "../")):
        folder = posixpath.dirname(config_path)
        resolved = posixpath.normpath(posixpath.join(folder, reference))
        inside = resolved != ".." and not resolved.startswith("../")
        return reference, None, True if inside else "unknown", "local"
    if re.match(r"^https?://", reference, re.IGNORECASE):
        return reference, None, False, "tarball"
    if "@" in reference:
        feature, _, digest = reference.partition("@")
        return feature, digest, _DIGEST.fullmatch(digest) is not None, "registry"
    last_slash = reference.rfind("/")
    colon = reference.rfind(":")
    if colon > last_slash:
        tag = reference[colon + 1 :]
        return reference[:colon], tag, is_exact_version(tag), "registry"
    return reference, None, False, "registry"


def _features(found: ComponentDiscovery, value: object) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        found.unparsed("features is not an object")
        return
    seen: set[str] = set()
    for reference in found.bounded(list(value), "features"):
        text = str(reference).strip()
        if not text:
            found.unparsed("a feature has an empty id")
            continue
        feature, version, pinned, origin = _feature_reference(text, found.path)
        if feature in seen:
            found.unparsed("two features share an id")
            continue
        seen.add(feature)
        attributes = {
            "feature": aa.authority_text(feature),
            "origin": origin,
        }
        if origin == "registry" and "/" in feature:
            attributes["registry"] = aa.authority_text(feature.split("/", 1)[0])
        if version:
            attributes["ref"] = aa.authority_text(version)
        installed_component(
            found,
            kind="devcontainer-feature",
            namespace=_FEATURE_NAMESPACE,
            component_key=aa.key_path("features", feature),
            name=f"devcontainer feature {feature}",
            pinned=pinned,
            attributes=attributes,
        )


def _command_text(value: object) -> str | None:
    if isinstance(value, str):
        return aa.command_text(value) if value.strip() else None
    if isinstance(value, list) and all(isinstance(part, str) for part in value):
        return aa.command_text(value) if value else None
    return None


def _lifecycle(found: ComponentDiscovery, key: str, value: object) -> None:
    attributes = {"runs_on_host": "true" if key in _HOST_COMMANDS else "false"}
    if isinstance(value, dict):
        for name in found.bounded(list(value), f"{key} commands"):
            command = _command_text(value[name])
            if command is None:
                if value[name] not in ("", [], None):
                    found.unparsed(f"a named {key} entry is not a command")
                continue
            startup_command(
                found,
                namespace=_LIFECYCLE_NAMESPACE,
                setting=f"{key}.{name}",
                command=command,
                event=key,
                component_key=aa.key_path(key, str(name)),
                attributes=attributes,
            )
        return
    command = _command_text(value)
    if command is None:
        if value not in ("", []):
            found.unparsed(f"{key} is not a command string, list, or object")
        return
    startup_command(
        found,
        namespace=_LIFECYCLE_NAMESPACE,
        setting=key,
        command=command,
        event=key,
        component_key=key,
        attributes=attributes,
    )


def _compose_files(found: ComponentDiscovery, value: object) -> list[str]:
    files = value if isinstance(value, list) else [value]
    paths = [item for item in files if isinstance(item, str) and item.strip()]
    if len(paths) != len(files):
        found.unparsed("dockerComposeFile is not a path or a list of paths")
    folder = posixpath.dirname(found.path)
    recorded: list[str] = []
    for item in paths[: aa.MAX_ENTRIES]:
        text = aa.repository_path_text(item)
        if text != aa.OUTSIDE_REPOSITORY_PATH:
            text = aa.authority_text(posixpath.normpath(posixpath.join(folder, item)))
        recorded.append(text)
    return recorded


def _devcontainer(host: EnvironmentHost, context: ScanContext, path: str) -> None:
    found = host.file(path)
    try:
        payload: dict[str, Any] = aa.load_json_object(context.root.path / path)
    except aa.ConfigLoadError as error:
        found.unparsed(str(error))
        host.take(found)
        return
    customizations = payload.get("customizations")
    vscode = customizations.get("vscode") if isinstance(customizations, dict) else None
    if isinstance(vscode, dict):
        _extensions(
            found,
            vscode.get("extensions"),
            base_key=("customizations", "vscode", "extensions"),
        )
    # The pre-`customizations` form, still honored by VS Code.
    _extensions(found, payload.get("extensions"), base_key=("extensions",))
    _features(found, payload.get("features"))
    for key in LIFECYCLE_COMMANDS:
        if key in payload:
            _lifecycle(found, key, payload[key])
    if "dockerComposeFile" in payload:
        host.note(
            found,
            "docker_compose_files",
            _compose_files(found, payload["dockerComposeFile"]),
        )
    host.take(found)


def _recommendations(host: EnvironmentHost, context: ScanContext, path: str) -> None:
    found = host.file(path)
    try:
        payload = aa.load_json_object(context.root.path / path)
    except aa.ConfigLoadError as error:
        found.unparsed(str(error))
        host.take(found)
        return
    if path.endswith(_WORKSPACE_SUFFIX):
        extensions = payload.get("extensions")
        if extensions is None:
            host.take(found)
            return
        if not isinstance(extensions, dict):
            found.unparsed("extensions is not an object")
            host.take(found)
            return
        base_key: tuple[str, ...] = ("extensions", "recommendations")
    else:
        extensions = payload
        base_key = ("recommendations",)
    _extensions(
        found,
        extensions.get("recommendations"),
        base_key=base_key,
        recommended=True,
    )
    host.take(found)


class DevcontainerAdapter:
    """`devcontainer.json` extensions, features, and lifecycle commands,
    and VS Code extension recommendations."""

    name = _NAME
    supported_versions: tuple[str, ...] = (f"docs-{DOCUMENTATION_SNAPSHOT}",)

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(
            adapter=self.name, claimed_paths=tuple(_claimed(context))
        )

    def discover(self, context: ScanContext) -> DiscoveryResult:
        devcontainer = EnvironmentHost("devcontainer", "Dev Containers", self.name)
        vscode = EnvironmentHost("vscode", "VS Code", self.name)
        for path in _claimed(context):
            if _is_devcontainer_config(path):
                _devcontainer(devcontainer, context, path)
            else:
                _recommendations(vscode, context, path)
        return with_script_digests(
            merge(devcontainer.result(), vscode.result()), context
        )


__all__ = ["DOCUMENTATION_SNAPSHOT", "LIFECYCLE_COMMANDS", "DevcontainerAdapter"]
