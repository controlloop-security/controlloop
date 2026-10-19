#!/usr/bin/env python3
"""Derive one authoritative release-metadata manifest from a git tag.

Invoked by `.github/workflows/release.yml` as:

    python3 release-scripts/derive_release_metadata.py "$GITHUB_REF_NAME" \\
        --output release-manifest.json

Deliberately dependency-free (stdlib only: `tomllib`, `re`, `json`,
`argparse`, `pathlib`, `subprocess` for the commit SHA only). It never
imports the `controlloop` package -- every version it reports is read
statically from source text, so this script runs correctly even before
`uv sync` has installed anything, and can never trigger a side effect from
executing repository code.

"Derived from one source and consistent across every artifact" does not
mean the package version, the rule pack version, and every ACBOM-family
schema version must be numerically equal to each other -- they are
deliberately versioned independently (rule packs are versioned
independently from the CLI, and each `CURRENT_*_SCHEMA_VERSION` constant
in `src/controlloop` already carries its own semantic version). It means
every published release artifact is stamped from the exact one manifest
this script computes once, rather than each publish step re-deriving or
hand-typing its own copy that could drift from the others.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

_TAG_PATTERN = re.compile(r"^v(\d+\.\d+\.\d+)$")
_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
#: Matches every `CURRENT_*_SCHEMA_VERSION` constant this repository
#: declares, including the bare `CURRENT_SCHEMA_VERSION` (the ACBOM schema
#: itself, `controlloop.acbom.versioning.CURRENT_SCHEMA_VERSION`) that has
#: no infix between `CURRENT_` and `_SCHEMA_VERSION` -- `name` is optional
#: and, when absent, is normalized to the literal key `"acbom"` below.
_SCHEMA_VERSION_PATTERN = re.compile(
    r"^CURRENT_(?:(?P<name>[A-Z0-9]+(?:_[A-Z0-9]+)*)_)?SCHEMA_VERSION"
    r'\s*=\s*"(?P<version>[^"]+)"',
    re.MULTILINE,
)
_RULE_PACK_VERSION_PATTERN = re.compile(
    r'CURRENT_RULE_PACK\s*=\s*RulePack\(.*?version\s*=\s*"(?P<version>[^"]+)"',
    re.DOTALL,
)
_RULE_PACK_NAME_PATTERN = re.compile(
    r'CURRENT_RULE_PACK\s*=\s*RulePack\(.*?name\s*=\s*"(?P<name>[^"]+)"',
    re.DOTALL,
)


class ReleaseMetadataError(RuntimeError):
    """Raised for any condition this script must fail loudly on: a
    malformed tag, an unparseable `pyproject.toml`, or a tag that does not
    match the package version this checkout declares."""


def parse_tag(tag: str) -> str:
    """Return the bare semantic version for a `vX.Y.Z` tag, or raise
    `ReleaseMetadataError` for anything else. Deliberately strict: a
    prerelease/build-metadata suffix (`v0.2.0-rc1`, `v0.2.0+abc`) is
    rejected rather than silently truncated, since this repository has not
    approved a prerelease-tag convention."""
    match = _TAG_PATTERN.match(tag)
    if match is None:
        raise ReleaseMetadataError(
            f"tag {tag!r} does not match the required vX.Y.Z shape "
            "(a bare semantic version with a leading 'v', no prerelease or "
            "build-metadata suffix)"
        )
    return match.group(1)


def read_package_version(pyproject_path: Path) -> str:
    """Read `[project].version` from `pyproject.toml` -- the one
    human-edited source of the package version."""
    try:
        raw = pyproject_path.read_bytes()
    except OSError as error:
        raise ReleaseMetadataError(
            f"could not read {pyproject_path}: {error}"
        ) from error
    try:
        data: dict[str, Any] = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise ReleaseMetadataError(
            f"{pyproject_path} is not valid TOML: {error}"
        ) from error
    try:
        version = data["project"]["version"]
    except (KeyError, TypeError) as error:
        raise ReleaseMetadataError(
            f"{pyproject_path} has no [project].version"
        ) from error
    if not isinstance(version, str) or not _SEMVER_PATTERN.match(version):
        raise ReleaseMetadataError(
            f"{pyproject_path} [project].version {version!r} is not a bare "
            "X.Y.Z semantic version"
        )
    return version


def read_rule_pack_metadata(rulepack_path: Path) -> dict[str, str]:
    """Statically extract `CURRENT_RULE_PACK`'s `name` and `version` from
    `src/controlloop/policy/rulepack.py` by regex over the source text
    -- no import, so this never requires an installed environment and can
    never execute repository code."""
    try:
        text = rulepack_path.read_text(encoding="utf-8")
    except OSError as error:
        raise ReleaseMetadataError(
            f"could not read {rulepack_path}: {error}"
        ) from error
    name_match = _RULE_PACK_NAME_PATTERN.search(text)
    version_match = _RULE_PACK_VERSION_PATTERN.search(text)
    if name_match is None or version_match is None:
        raise ReleaseMetadataError(
            f"could not find CURRENT_RULE_PACK name/version in {rulepack_path}"
        )
    return {"name": name_match.group("name"), "version": version_match.group("version")}


def read_schema_versions(src_root: Path) -> dict[str, str]:
    """Statically collect every `CURRENT_*_SCHEMA_VERSION = "X.Y.Z"`
    constant under `src/controlloop`, keyed by its lowercased,
    underscore-joined name (for example `acbom`, `manifest`,
    `evidence_report` stays as its own key per constant found -- no
    normalization beyond case, so a newly added schema constant is picked
    up automatically without touching this script)."""
    versions: dict[str, str] = {}
    for path in sorted(src_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for match in _SCHEMA_VERSION_PATTERN.finditer(text):
            name = match.group("name")
            key = name.lower() if name is not None else "acbom"
            version = match.group("version")
            existing = versions.get(key)
            if existing is not None and existing != version:
                raise ReleaseMetadataError(
                    f"schema version constant {key!r} disagrees across the "
                    f"source tree: {existing!r} vs {version!r} (in {path})"
                )
            versions[key] = version
    if not versions:
        raise ReleaseMetadataError(
            f"no CURRENT_*_SCHEMA_VERSION constants found under {src_root}"
        )
    return versions


def read_commit_sha(repo_root: Path) -> str:
    """The exact commit this manifest describes, via `git rev-parse HEAD`
    -- bounded by a real timeout, never left to hang."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise ReleaseMetadataError(
            f"git rev-parse HEAD failed: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def derive_metadata(
    tag: str,
    *,
    repo_root: Path,
    cli_root: Path,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    version = parse_tag(tag)
    package_version = read_package_version(cli_root / "pyproject.toml")
    if version != package_version:
        raise ReleaseMetadataError(
            f"tag {tag!r} (version {version!r}) does not match "
            f"pyproject.toml's [project].version {package_version!r} -- "
            "bump pyproject.toml and merge that change before tagging"
        )
    rule_pack = read_rule_pack_metadata(
        cli_root / "src" / "controlloop" / "policy" / "rulepack.py"
    )
    schema_versions = read_schema_versions(cli_root / "src" / "controlloop")
    if commit_sha is None:
        commit_sha = read_commit_sha(repo_root)
    return {
        "tag": tag,
        "package_version": package_version,
        "rule_pack": rule_pack,
        "schema_versions": schema_versions,
        "commit_sha": commit_sha,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="The pushed git tag, e.g. v0.2.0")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root (default: this script's own parent directory)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path to write the JSON manifest to (default: stdout only)",
    )
    parser.add_argument(
        "--commit-sha",
        default=None,
        help=(
            "Override the commit SHA instead of running 'git rev-parse "
            "HEAD' (mainly for tests against a non-git fixture tree)"
        ),
    )
    args = parser.parse_args(argv)

    cli_root = args.repo_root
    try:
        metadata = derive_metadata(
            args.tag,
            repo_root=args.repo_root,
            cli_root=cli_root,
            commit_sha=args.commit_sha,
        )
    except ReleaseMetadataError as error:
        print(f"derive_release_metadata: {error}", file=sys.stderr)
        return 1

    rendered = json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
