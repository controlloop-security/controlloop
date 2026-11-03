"""pre-commit hook repositories, revisions, and local hooks.

Reads `.pre-commit-config.yaml` (or `.pre-commit-config.yml`) at the
repository root. Once a developer runs `pre-commit install`, every
commit -- including every commit a coding agent makes -- clones each
hook repository at its `rev`, installs it with its
`additional_dependencies`, and runs it. A pull request that adds a
repository, moves a `rev`, swaps a commit for a tag, or changes a local
hook's command changes what runs on every machine that commits. Each
becomes a shape the agent-authority rules already read
(`controlloop.adapters.environment`):

- `repos[]` with a `repo` URL: a `plugin` component with `source_type:
  pre-commit-hook`, named by the URL without its scheme, credentials,
  and `.git`, pinned only when `rev` is a full 40-character commit SHA.
  A tag, a branch, or a short SHA can be moved upstream, so it is
  unpinned. The hook ids are recorded as an attribute. A `rev` change
  keeps the component and changes its `ref`.
- `repo: local` hooks: a `helper-command` per hook, named by its `id`,
  with `entry` and `args` recorded through `agent_authority.command_text`
  and `event` naming its stages, so `policy.agent-hook-command-change`
  reports a changed command and the script digest tracks a committed
  script it runs. A remote hook that overrides `entry` is recorded the
  same way, since that command is what runs.
- `additional_dependencies` on any hook: a `plugin` component per
  dependency with `source_type: pre-commit-dependency`, pinned only by
  an exact version (`name==1.2.3`, `name@1.2.3`), so a finding names the
  dependency that can float. They are separate from the repository's
  component so the finding says which dependency it is.

`repo: meta` hooks run pre-commit's own checks and are ignored, as are
`default_language_version`, `default_stages`, `exclude`, and the `ci:`
block. The pre-1.0 form, a bare list of repositories, is read as
`repos`. The file is parsed with `yaml.safe_load`; nothing is cloned,
installed, or run.

The file format is pre-commit's "Adding pre-commit plugins to your
project" reference (pre-commit.com), read on 2026-11-03.
"""

from __future__ import annotations

import re
from typing import Any

import yaml

from controlloop.acbom import KnownBoolean
from controlloop.adapters import agent_authority as aa
from controlloop.adapters.claude_code import ComponentDiscovery
from controlloop.adapters.environment import (
    EnvironmentHost,
    installed_component,
    is_exact_version,
    startup_command,
)
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.adapters.script_digest import with_script_digests
from controlloop.bounded_recursion import bounded_recursion

_NAME = "pre-commit"
DOCUMENTATION_SNAPSHOT = "2026-11-03"

_CONFIG_PATHS = (".pre-commit-config.yaml", ".pre-commit-config.yml")
_REPO_NAMESPACE = "pre-commit.repo"
_DEPENDENCY_NAMESPACE = "pre-commit.dependency"
_HOOK_NAMESPACE = "pre-commit.hook"
_DEFAULT_STAGE = "pre-commit"

#: Most nodes one file may produce. Each list is bounded on its own;
#: this bounds their product, which YAML aliases can make large from a
#: small file.
MAX_NODES = aa.MAX_ENTRIES * 4

_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_SCP_LIKE = re.compile(r"^(?:[^@/\s]+@)?(?P<host>[^:/\s]+):(?P<path>[^/].*)$")
#: A Python requirement: a name (with extras), then a specifier that
#: starts with a PEP 440 operator.
_PYTHON_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?)\s*"
    r"(?P<specifier>(?:===|==|~=|!=|>=|<=|>|<).*)?$"
)
#: `==` or `===` one version, with no wildcard and no second clause.
_PYTHON_EXACT = re.compile(r"^===?\s*[^\s*,;<>=!~]+$")


def repository_name(url: str) -> str:
    """`url` without its scheme, credentials, and `.git`:
    `https://github.com/psf/black.git` -> `github.com/psf/black`,
    `git@github.com:psf/black` -> `github.com/psf/black`."""

    text = url.strip()
    scheme = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", text)
    if scheme is not None:
        text = text[scheme.end() :]
        text = re.sub(r"^[^@/]*@", "", text)
    else:
        scp = _SCP_LIKE.fullmatch(text)
        if scp is not None:
            text = f"{scp.group('host')}/{scp.group('path')}"
    text = text.rstrip("/")
    if text.endswith(".git"):
        text = text[: -len(".git")]
    return text or url


def dependency_pin(requirement: str) -> tuple[str, KnownBoolean]:
    """`(name, pinned)` for one `additional_dependencies` entry.

    Pinned only for an exact version: `name==1.2.3` (Python), or
    `name@1.2.3` (npm, Go). A range, a wildcard, or no version is not.
    """

    text = requirement.strip()
    python = _PYTHON_REQUIREMENT.fullmatch(text)
    if python is not None and python.group("specifier"):
        return python.group("name"), (
            _PYTHON_EXACT.fullmatch(python.group("specifier")) is not None
        )
    at = text.rfind("@")
    if at > 0:
        name, version = text[:at], text[at + 1 :]
        return name, is_exact_version(version.removeprefix("v"))
    return text, False


def _stages(hook: dict[str, Any], default: list[str]) -> str:
    stages = hook.get("stages")
    values = stages if isinstance(stages, list) else default
    names = [str(value) for value in values if isinstance(value, str)]
    return ",".join(sorted(set(names))) or _DEFAULT_STAGE


def _load(path: Any) -> object:
    if path.stat().st_size > aa.MAX_CONFIG_BYTES:
        raise aa.ConfigLoadError("the file is larger than the configuration bound")
    try:
        with bounded_recursion(margin=500):
            return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError, yaml.YAMLError):
        raise aa.ConfigLoadError("the file is not valid YAML") from None


class _File:
    """One configuration file's discovery, with a budget on its nodes."""

    def __init__(self, found: ComponentDiscovery, default_stages: list[str]) -> None:
        self.found = found
        self.default_stages = default_stages
        self.keys: set[str] = set()
        self.exhausted = False

    def room(self) -> bool:
        if len(self.found.nodes) < MAX_NODES:
            return True
        if not self.exhausted:
            self.exhausted = True
            self.found.diagnostics.append(
                aa.bound_exceeded_diagnostic(
                    adapter=_NAME, path=self.found.path, what="hooks and dependencies"
                )
            )
        return False

    def unique(self, *segments: str | int) -> str:
        """A component key, made distinct when the file repeats one."""

        key = aa.key_path(*segments)
        candidate, count = key, 1
        while candidate in self.keys:
            count += 1
            candidate = aa.key_path(*segments, count)
        self.keys.add(candidate)
        return candidate

    def dependencies(self, hook: dict[str, Any], hook_key: tuple[str, ...]) -> None:
        dependencies = hook.get("additional_dependencies")
        if dependencies is None:
            return
        if not isinstance(dependencies, list):
            self.found.unparsed("additional_dependencies is not a list")
            return
        for entry in self.found.bounded(dependencies, "additional dependencies"):
            if not self.room():
                return
            if not isinstance(entry, str) or not entry.strip():
                self.found.unparsed("an additional dependency is not a string")
                continue
            name, pinned = dependency_pin(entry)
            installed_component(
                self.found,
                kind="pre-commit-dependency",
                namespace=_DEPENDENCY_NAMESPACE,
                component_key=self.unique(*hook_key, "additional_dependencies", name),
                name=f"pre-commit dependency {name} for hook {hook_key[-1]}",
                pinned=pinned,
                attributes={
                    "dependency": aa.authority_text(name),
                    "ref": aa.authority_text(entry.strip()),
                },
            )

    def command(self, hook: dict[str, Any], hook_id: str, key: str) -> None:
        if not self.room():
            return
        entry = hook.get("entry")
        if not isinstance(entry, str) or not entry.strip():
            self.found.unparsed(f"hook {hook_id} has no entry")
            return
        args = hook.get("args")
        language = hook.get("language")
        attributes = {
            "language": aa.authority_text(language)
            if isinstance(language, str)
            else "unknown"
        }
        startup_command(
            self.found,
            namespace=_HOOK_NAMESPACE,
            setting=hook_id,
            command=aa.command_text(entry, args if isinstance(args, list) else None),
            event=_stages(hook, self.default_stages),
            component_key=key,
            attributes=attributes,
        )

    def hooks(self, repo: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        hooks = repo.get("hooks")
        if not isinstance(hooks, list):
            self.found.unparsed("a repos entry has no list of hooks")
            return []
        found: list[tuple[str, dict[str, Any]]] = []
        for hook in self.found.bounded(hooks, "hooks"):
            hook_id = hook.get("id") if isinstance(hook, dict) else None
            if not isinstance(hook_id, str) or not hook_id.strip():
                self.found.unparsed("a hook has no id")
                continue
            found.append((hook_id, hook))
        return found

    def local(self, repo: dict[str, Any]) -> None:
        for hook_id, hook in self.hooks(repo):
            key = self.unique("repos", "local", "hooks", hook_id)
            self.command(hook, hook_id, key)
            self.dependencies(hook, ("repos", "local", "hooks", hook_id))

    def remote(self, repo: dict[str, Any], url: str) -> None:
        if not self.room():
            return
        name = repository_name(url)
        rev = repo.get("rev")
        rev_text = str(rev) if isinstance(rev, (str, int, float)) else ""
        hooks = self.hooks(repo)
        attributes = {
            "repository": aa.authority_text(name),
            "hook_ids": aa.authority_text(",".join(hook_id for hook_id, _ in hooks)),
        }
        if rev_text:
            attributes["ref"] = aa.authority_text(rev_text)
        else:
            self.found.unparsed(f"repository {name} has no rev")
        installed_component(
            self.found,
            kind="pre-commit-hook",
            namespace=_REPO_NAMESPACE,
            component_key=self.unique("repos", name),
            name=f"pre-commit hook repository {name}",
            pinned=_FULL_SHA.fullmatch(rev_text) is not None,
            attributes=attributes,
        )
        for hook_id, hook in hooks:
            if "entry" in hook:
                key = self.unique("repos", name, "hooks", hook_id, "entry")
                self.command(hook, hook_id, key)
            self.dependencies(hook, ("repos", name, "hooks", hook_id))


def _discover_file(host: EnvironmentHost, context: ScanContext, path: str) -> None:
    found = host.file(path)
    try:
        payload = _load(context.root.path / path)
    except aa.ConfigLoadError as error:
        found.unparsed(str(error))
        host.take(found)
        return
    if isinstance(payload, list):
        payload = {"repos": payload}
    if payload is None:
        host.take(found)
        return
    if not isinstance(payload, dict):
        found.unparsed("the file's top level is not a mapping")
        host.take(found)
        return
    repos = payload.get("repos")
    if not isinstance(repos, list):
        found.unparsed("repos is not a list")
        host.take(found)
        return
    default_stages = payload.get("default_stages")
    discovery = _File(
        found,
        [str(item) for item in default_stages]
        if isinstance(default_stages, list)
        else [],
    )
    for repo in found.bounded(repos, "repositories"):
        if not isinstance(repo, dict):
            found.unparsed("a repos entry is not a mapping")
            continue
        url = repo.get("repo")
        if not isinstance(url, str) or not url.strip():
            found.unparsed("a repos entry has no repo")
            continue
        if url == "meta":
            continue
        if url == "local":
            discovery.local(repo)
        else:
            discovery.remote(repo, url)
    host.take(found)


class PreCommitAdapter:
    """`.pre-commit-config.yaml` hook repositories, revisions, local hooks,
    and additional dependencies."""

    name = _NAME
    supported_versions: tuple[str, ...] = (f"docs-{DOCUMENTATION_SNAPSHOT}",)

    def _paths(self, context: ScanContext) -> list[str]:
        return sorted(
            file.relative
            for file in context.repository_files()
            if file.relative in _CONFIG_PATHS
        )

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(
            adapter=self.name, claimed_paths=tuple(self._paths(context))
        )

    def discover(self, context: ScanContext) -> DiscoveryResult:
        host = EnvironmentHost("pre-commit", "pre-commit", self.name)
        for path in self._paths(context):
            _discover_file(host, context, path)
        return with_script_digests(host.result(), context)


__all__ = [
    "DOCUMENTATION_SNAPSHOT",
    "MAX_NODES",
    "PreCommitAdapter",
    "dependency_pin",
    "repository_name",
]
