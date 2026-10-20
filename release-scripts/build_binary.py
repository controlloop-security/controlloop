#!/usr/bin/env python3
"""Build one standalone, single-file `controlloop` executable via
PyInstaller.

Invoked by `.github/workflows/release.yml`'s `build-binaries` job, once
per matrix leg, as:

    python3 release-scripts/build_binary.py \\
        --platform linux --arch x86_64 --repo-root .

Also runnable directly for local verification.

## Why `--add-data` for `policy/rules/*.py` is not optional

`controlloop.policy.engine._validate_rule_safety` runs
`inspect.getsource` on every active rule module before any `scan`/`gate`
evaluates it, as a defense-in-depth check that a rule's own module
imports nothing forbidden (file writes, subprocess, network, a
known LLM SDK). PyInstaller's default onefile bundle ships compiled
bytecode only -- no real `.py` file exists anywhere the frozen
interpreter can read at runtime, so `inspect.getsource` unconditionally
raises `OSError: could not get source code` for every rule module in an
unmodified onefile build, and every `scan`/`gate` invocation of that
binary would fail with `CLI-INTERNAL-ERROR` before producing a verdict.

This was not a hypothetical: it was reproduced for real while building
this binary locally. The fix needs no change to
`controlloop.policy.engine` at all: PyInstaller's `--add-data
SRC:DEST` copies real files into the frozen bundle's extraction
directory (`sys._MEIPASS`) at the exact `DEST` path given. Pointing
`DEST` at `controlloop/policy/rules` -- the identical relative path
PyInstaller's own frozen loader already reports as each rule module's
`__file__` -- makes a real, readable `.py` file appear at exactly the
path `inspect.getsource`/`linecache` already look for, with no other
change. Confirmed directly: `inspect.getsource` and the frozen loader's
own `get_source()` both succeed once this flag is present, and both fail
identically without it, on the same build.

No other package in `controlloop.policy.rules` needs this treatment
individually -- the single `*.py` glob covers every current and future
rule module in that one package, including `_shared.py` and
`__init__.py`, without this script needing to enumerate rule modules by
name.

## Reproducibility

Two independent invocations of this script against the same commit
produce byte-different binaries (PyInstaller embeds a fresh build UUID
and absolute temp-directory paths into its bootloader metadata every
run -- a well-known PyInstaller property, not a bug here) but
byte-identical `controlloop scan`/`gate` output against the same
fixture, since none of that embedded build-specific data is ever part
of a scan's own output. See `.github/workflows/release.yml`'s
`build-binaries` job for this check run as a real workflow step.

Deliberately not dependency-free like `derive_release_metadata.py`/
`changelog_release_notes.py`: building a real binary requires PyInstaller
itself, already declared in `pyproject.toml`'s `release` dependency
group and installed by `uv sync --locked --all-groups`, the one already-
established verified command surface (`.github/workflows/verify.yml`).
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

#: The two platform/architecture axes the standalone binaries target
#: ("macOS and Linux, on x86_64 and arm64"). Windows is out of scope
#: (`docs/reference/supported-platforms.md`); see
#: `docs/reference/standalone-binaries.md` for the disclosed macOS x86_64
#: gap (no free-tier GitHub-hosted runner exists for it today).
SUPPORTED_PLATFORMS: frozenset[str] = frozenset({"linux", "macos"})
SUPPORTED_ARCHES: frozenset[str] = frozenset({"x86_64", "arm64"})

_DEFAULT_TIMEOUT_SECONDS = 900


class BinaryBuildError(RuntimeError):
    """Raised for any condition this script must fail loudly on: an
    unsupported platform/architecture, a missing entry point, or a
    nonzero PyInstaller exit."""


def binary_name(platform: str, arch: str) -> str:
    """Return the one fixed naming scheme,
    `controlloop-<platform>-<arch>` -- no extension, since Windows (the
    only platform that would need one) is out of scope. Raises
    `BinaryBuildError` for anything outside `SUPPORTED_PLATFORMS`/
    `SUPPORTED_ARCHES` rather than silently building a nonsense name."""

    if platform not in SUPPORTED_PLATFORMS:
        raise BinaryBuildError(
            f"unsupported platform {platform!r}; expected one of "
            f"{sorted(SUPPORTED_PLATFORMS)}"
        )
    if arch not in SUPPORTED_ARCHES:
        raise BinaryBuildError(
            f"unsupported architecture {arch!r}; expected one of "
            f"{sorted(SUPPORTED_ARCHES)}"
        )
    return f"controlloop-{platform}-{arch}"


def build_binary(
    *,
    cli_root: Path,
    platform: str,
    arch: str,
    dist_dir: Path,
    work_dir: Path,
    spec_dir: Path,
    timeout: int = _DEFAULT_TIMEOUT_SECONDS,
) -> Path:
    """Run PyInstaller for real and return the built binary's path.

    `--onefile --clean --noconfirm` matches the verified local invocation
    exactly. `cwd=cli_root` so every path PyInstaller reports in its own
    log is relative to the package root, matching this repository's other
    subprocess-invoking scripts (`derive_release_metadata.py`'s
    `git rev-parse` call). Bounded by a
    real `timeout`, never left to hang; a `subprocess.TimeoutExpired`
    propagates uncaught -- never invent a passing result.
    """

    # PyInstaller resolves a relative `--add-data` source against the
    # `--specpath` directory, not the working directory, so a relative
    # `cli_root` (the release workflow passes `--repo-root .`) points the
    # rules glob inside `build-binary/spec/`. Absolute paths everywhere.
    cli_root = cli_root.resolve()
    dist_dir = dist_dir.resolve()
    work_dir = work_dir.resolve()
    spec_dir = spec_dir.resolve()

    name = binary_name(platform, arch)
    entry = cli_root / "src" / "controlloop" / "__main__.py"
    if not entry.is_file():
        raise BinaryBuildError(f"entry point not found: {entry}")

    rules_glob = cli_root / "src" / "controlloop" / "policy" / "rules" / "*.py"

    dist_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    spec_dir.mkdir(parents=True, exist_ok=True)

    args = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--clean",
        "--noconfirm",
        "--name",
        name,
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(spec_dir),
        "--add-data",
        f"{rules_glob}:controlloop/policy/rules",
        str(entry),
    ]
    result = subprocess.run(
        args,
        cwd=cli_root,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise BinaryBuildError(
            f"pyinstaller exited {result.returncode} building {name!r}; "
            f"stderr tail: {result.stderr[-2000:]}"
        )

    binary_path = dist_dir / name
    if not binary_path.is_file():
        raise BinaryBuildError(
            f"pyinstaller reported success but {binary_path} does not exist"
        )
    return binary_path


def write_checksum(binary_path: Path) -> Path:
    """Write a `sha256sum`-compatible checksum file
    (`<hex digest>  <filename>\\n`) alongside `binary_path` and return its
    path. This is the digest a caller compares across two
    separately built binaries to confirm they differ (expected -- see this
    module's own docstring), and the digest recorded in the release
    manifest so a downloaded binary can be verified against what this
    pipeline actually built."""

    digest = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    checksum_path = binary_path.with_name(binary_path.name + ".sha256")
    checksum_path.write_text(f"{digest}  {binary_path.name}\n", encoding="utf-8")
    return checksum_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform", required=True, choices=sorted(SUPPORTED_PLATFORMS)
    )
    parser.add_argument("--arch", required=True, choices=sorted(SUPPORTED_ARCHES))
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root (default: this script's own parent directory)",
    )
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=None,
        help="Where the built binary is written (default: dist-binary)",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="PyInstaller's own scratch directory (default: build-binary)",
    )
    parser.add_argument(
        "--spec-dir",
        type=Path,
        default=None,
        help="Where the generated .spec file is written (default: build-binary/spec)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=_DEFAULT_TIMEOUT_SECONDS,
        help="Bound, in seconds, on the PyInstaller subprocess",
    )
    args = parser.parse_args(argv)

    cli_root = args.repo_root
    dist_dir = args.dist_dir or (cli_root / "dist-binary")
    work_dir = args.work_dir or (cli_root / "build-binary")
    spec_dir = args.spec_dir or (cli_root / "build-binary" / "spec")

    try:
        binary_path = build_binary(
            cli_root=cli_root,
            platform=args.platform,
            arch=args.arch,
            dist_dir=dist_dir,
            work_dir=work_dir,
            spec_dir=spec_dir,
            timeout=args.timeout,
        )
        checksum_path = write_checksum(binary_path)
    except BinaryBuildError as error:
        print(f"build_binary: {error}", file=sys.stderr)
        return 1

    print(f"built {binary_path} ({checksum_path.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
