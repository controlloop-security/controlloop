"""Structural tests for the container image definition.

`Dockerfile`, `.dockerignore` and `scripts/container-smoke.sh` are read as
text and asserted against, in the same drift-guard style
`test_release_workflow_structure.py` uses for the workflows: no Docker
daemon is needed, so these run on every matrix leg. The real build and the
real offline scan run in `.github/workflows/ci.yml`'s `container` job and
again in the release pipeline before an image is pushed; what is pinned
here is the shape those runs rely on:

- the published stage runs as a numeric non-root user;
- the published stage never copies uv in and never installs a compiler;
- every base image is pinned by digest, not by a moving tag;
- the builder installs from the lockfile and nothing else;
- the smoke test really runs the scan with networking disabled.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOCKERFILE = _REPO_ROOT / "Dockerfile"
_DOCKERIGNORE = _REPO_ROOT / ".dockerignore"
_SMOKE = _REPO_ROOT / "scripts" / "container-smoke.sh"
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
_VERIFY_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "verify.yml"


def _instructions(text: str) -> list[tuple[str, str]]:
    """(INSTRUCTION, argument) pairs, with comments and blank lines dropped
    and backslash continuations joined."""
    joined = re.sub(r"\\\n\s*", " ", text)
    out: list[tuple[str, str]] = []
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        head, _, rest = stripped.partition(" ")
        out.append((head.upper(), rest.strip()))
    return out


def _stages(text: str) -> list[list[tuple[str, str]]]:
    stages: list[list[tuple[str, str]]] = []
    for instruction in _instructions(text):
        if instruction[0] == "FROM":
            stages.append([instruction])
        elif stages:
            stages[-1].append(instruction)
    return stages


class TestPublishedStage:
    def test_last_stage_runs_as_a_numeric_non_root_user(self) -> None:
        final = _stages(_DOCKERFILE.read_text(encoding="utf-8"))[-1]
        users = [arg for name, arg in final if name == "USER"]

        assert users, "the published stage sets no USER"
        uid = users[-1].split(":")[0]
        assert uid.isdigit() and int(uid) != 0, (
            f"USER must be a non-zero numeric uid, got {users[-1]!r}"
        )

    def test_last_stage_has_no_toolchain(self) -> None:
        final = _stages(_DOCKERFILE.read_text(encoding="utf-8"))[-1]
        copies = [arg for name, arg in final if name == "COPY"]
        runs = " ".join(arg for name, arg in final if name == "RUN")

        for copy in copies:
            assert "--from=uv" not in copy, "the published stage must not copy uv in"
        assert "/opt/controlloop" in " ".join(copies)
        for forbidden in (
            "build-essential",
            "gcc",
            "g++",
            "clang",
            "pip install",
            "uv sync",
        ):
            assert forbidden not in runs, f"the published stage runs {forbidden!r}"

    def test_entrypoint_is_the_cli(self) -> None:
        final = _stages(_DOCKERFILE.read_text(encoding="utf-8"))[-1]
        entrypoints = [arg for name, arg in final if name == "ENTRYPOINT"]

        assert entrypoints == ['["controlloop"]']

    def test_git_is_present_for_the_merge_base_baseline(self) -> None:
        final = _stages(_DOCKERFILE.read_text(encoding="utf-8"))[-1]
        runs = " ".join(arg for name, arg in final if name == "RUN")

        assert "apt-get install -y --no-install-recommends git" in runs
        assert "rm -rf /var/lib/apt/lists/*" in runs

    def test_oci_labels_name_source_and_license(self) -> None:
        text = _DOCKERFILE.read_text(encoding="utf-8")

        assert (
            'org.opencontainers.image.source="https://github.com/controlloop-security/controlloop"'
            in text
        )
        assert 'org.opencontainers.image.licenses="Apache-2.0"' in text
        assert 'org.opencontainers.image.version="${VERSION}"' in text
        assert 'org.opencontainers.image.revision="${REVISION}"' in text


class TestPinning:
    def test_every_base_image_is_pinned_exactly(self) -> None:
        text = _DOCKERFILE.read_text(encoding="utf-8")
        args = dict(re.findall(r"^ARG (\w+)=(\S+)", text, flags=re.MULTILINE))

        for name, arg in _instructions(text):
            if name != "FROM":
                continue
            image = arg.split()[0]
            if image.startswith("${") and image.endswith("}"):
                image = args[image[2:-1]]
            assert "@sha256:" in image or re.search(r":\d+\.\d+\.\d+$", image), (
                f"base image {image!r} is not pinned by digest or exact version"
            )

    def test_python_base_is_pinned_by_digest(self) -> None:
        text = _DOCKERFILE.read_text(encoding="utf-8")

        assert re.search(
            r"^ARG PYTHON_IMAGE=python:3\.12-[\w-]+@sha256:[0-9a-f]{64}$",
            text,
            flags=re.MULTILINE,
        )

    def test_uv_matches_the_version_ci_installs(self) -> None:
        text = _DOCKERFILE.read_text(encoding="utf-8")
        match = re.search(r"ghcr\.io/astral-sh/uv:(\d+\.\d+\.\d+)", text)
        assert match is not None
        verify = _VERIFY_WORKFLOW.read_text(encoding="utf-8")

        assert f'version: "{match.group(1)}"' in verify, (
            "the Dockerfile's uv version must match .github/workflows/verify.yml's"
        )


class TestBuilderStage:
    def test_installs_from_the_lockfile_without_dev_groups(self) -> None:
        stages = _stages(_DOCKERFILE.read_text(encoding="utf-8"))
        builder = next(stage for stage in stages if stage[0][1].endswith("AS builder"))
        runs = " ".join(arg for name, arg in builder if name == "RUN")

        assert "uv sync --locked --no-dev --no-editable" in runs
        assert "UV_PYTHON_DOWNLOADS=never" in " ".join(
            arg for name, arg in builder if name == "ENV"
        )

    def test_dockerignore_sends_only_what_the_build_copies(self) -> None:
        lines = [
            line.strip()
            for line in _DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]

        assert lines[0] == "*"
        allowed = {line[1:] for line in lines if line.startswith("!")}
        assert allowed == {
            "pyproject.toml",
            "uv.lock",
            "README.md",
            "CHANGELOG.md",
            "LICENSE",
            "NOTICE",
            "src/",
        }

    def test_build_copies_only_files_the_dockerignore_allows(self) -> None:
        text = _DOCKERFILE.read_text(encoding="utf-8")
        stages = _stages(text)
        builder = next(stage for stage in stages if stage[0][1].endswith("AS builder"))
        copied: set[str] = set()
        for name, arg in builder:
            if name == "COPY" and "--from=" not in arg:
                copied.update(arg.split()[:-1])

        assert copied == {
            "pyproject.toml",
            "uv.lock",
            "README.md",
            "CHANGELOG.md",
            "LICENSE",
            "NOTICE",
            "src",
        }


class TestSmokeTest:
    def test_scan_runs_with_networking_disabled(self) -> None:
        text = _SMOKE.read_text(encoding="utf-8")

        scan_lines = [
            line
            for line in text.splitlines()
            if "docker run" in line and " scan " in line
        ]
        assert scan_lines, "the smoke test runs no scan"
        for line in scan_lines:
            assert "--network none" in line

    def test_checks_non_root_and_no_toolchain(self) -> None:
        text = _SMOKE.read_text(encoding="utf-8")

        assert "--entrypoint id" in text
        for tool in ("uv", "pip", "gcc", "cc", "make"):
            assert tool in text

    def test_ci_builds_the_image_and_runs_the_smoke_test(self) -> None:
        workflow = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
        job = workflow["jobs"]["container"]
        steps = " ".join(str(step.get("run", "")) for step in job["steps"])

        assert job["runs-on"] == "ubuntu-latest"
        assert "docker build" in steps or "docker buildx build" in steps
        assert "scripts/container-smoke.sh" in steps
