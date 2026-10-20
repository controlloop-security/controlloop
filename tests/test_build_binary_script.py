"""Tests for `release-scripts/build_binary.py`.

Like `test_release_scripts.py`'s two release scripts, `build_binary.py`
lives outside the `controlloop` package (invoked directly by
`.github/workflows/release.yml`'s `build-binaries` job, never imported by
product code). Unlike those two scripts, it is not dependency-free -- it
shells out to PyInstaller, already declared in `pyproject.toml`'s `release`
dependency group and installed by `uv sync --locked --all-groups`, the one
documented verified command surface. Every class below that needs a real
PyInstaller build guards on `pytest.importorskip("PyInstaller")` so a
partial `uv sync` (missing `--all-groups`) skips cleanly with a clear reason
rather than failing.

Two test styles are used, deliberately:

- Fast, argument-level and mocked-subprocess cases are exercised through
  a direct dynamic import of the script module (`importlib.util`, since
  the script is not part of the installed `controlloop` package) --
  `binary_name`, `write_checksum`, and `build_binary`'s own error paths
  with `subprocess.run` monkeypatched to return a synthetic nonzero
  result, never invoking a real PyInstaller build.
- One real, slow, end-to-end case (`TestRealBuildEndToEnd`) that
  actually runs PyInstaller against this real repository's own source
  tree, on whatever host platform/architecture pytest is currently
  running on (PyInstaller cannot cross-compile -- a build only ever
  targets its own host), producing a real onefile executable and
  running two real assertions against it:

  1. A real `controlloop scan` against a small synthetic fixture
     directory returns `verdict == "passed"` -- proving
     `controlloop.policy.engine._validate_rule_safety`'s runtime
     `inspect.getsource` check (which this script's own `--add-data`
     flag exists specifically to satisfy under a frozen build; see
     `build_binary.py`'s own module docstring) actually works end to
     end, not merely that the binary starts.
  2. Building the same commit a second time and running the
     identical scan again produces byte-identical JSON output, even
     though the two binaries' own bytes differ (PyInstaller embeds a
     fresh build UUID and absolute temp-path metadata every run).

  This mirrors `tests/performance/test_benchmark.py`'s own
  established precedent of real, comparatively slow subprocess-level
  verification running inside the default `pytest` invocation rather
  than being sequestered behind an opt-in marker -- this repository has
  no registered pytest markers (`--strict-markers` with none declared),
  so a new marker is not introduced here either.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import platform
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CLI_ROOT = _REPO_ROOT
_SCRIPT_PATH = _REPO_ROOT / "release-scripts" / "build_binary.py"


def _load_module() -> ModuleType:
    """Dynamically import `build_binary.py` by file path -- it is not
    part of the installed `controlloop` package (see this module's own
    docstring), the same reason it is exercised as a real subprocess in
    the workflow itself but can still be imported directly here for
    fast, mocked unit coverage of its pure helper functions."""

    spec = importlib.util.spec_from_file_location("build_binary", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_MODULE = _load_module()


class TestBinaryNamePositive:
    def test_linux_x86_64(self) -> None:
        assert _MODULE.binary_name("linux", "x86_64") == "controlloop-linux-x86_64"

    def test_macos_arm64(self) -> None:
        assert _MODULE.binary_name("macos", "arm64") == "controlloop-macos-arm64"


class TestBinaryNameNegative:
    def test_unsupported_platform_raises(self) -> None:
        with pytest.raises(_MODULE.BinaryBuildError, match="unsupported platform"):
            _MODULE.binary_name("windows", "x86_64")

    def test_unsupported_arch_raises(self) -> None:
        with pytest.raises(_MODULE.BinaryBuildError, match="unsupported architecture"):
            _MODULE.binary_name("linux", "arm32")


class TestWriteChecksum:
    def test_checksum_matches_real_sha256(self, tmp_path: Path) -> None:
        binary_path = tmp_path / "controlloop-linux-x86_64"
        binary_path.write_bytes(b"synthetic binary bytes for a checksum test")

        checksum_path = _MODULE.write_checksum(binary_path)

        expected_digest = hashlib.sha256(binary_path.read_bytes()).hexdigest()
        assert checksum_path == binary_path.with_name("controlloop-linux-x86_64.sha256")
        assert (
            checksum_path.read_text(encoding="utf-8")
            == f"{expected_digest}  controlloop-linux-x86_64\n"
        )


class TestBuildBinaryMalformed:
    def test_missing_entry_point_raises(self, tmp_path: Path) -> None:
        """A `--repo-root` whose `src/controlloop/__main__.py` does
        not exist fails fast, before any subprocess is spawned --
        malformed input, never a silent partial build."""

        cli_root = tmp_path
        (cli_root / "src" / "controlloop").mkdir(parents=True)

        with pytest.raises(_MODULE.BinaryBuildError, match="entry point not found"):
            _MODULE.build_binary(
                cli_root=cli_root,
                platform="linux",
                arch="x86_64",
                dist_dir=tmp_path / "dist",
                work_dir=tmp_path / "build",
                spec_dir=tmp_path / "spec",
            )

    def test_unsupported_platform_raises_before_any_subprocess(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        called = False

        def _fail_if_called(*args: object, **kwargs: object) -> None:
            nonlocal called
            called = True
            raise AssertionError("subprocess.run must not be called")

        monkeypatch.setattr(_MODULE.subprocess, "run", _fail_if_called)

        with pytest.raises(_MODULE.BinaryBuildError, match="unsupported platform"):
            _MODULE.build_binary(
                cli_root=tmp_path,
                platform="windows",
                arch="x86_64",
                dist_dir=tmp_path / "dist",
                work_dir=tmp_path / "build",
                spec_dir=tmp_path / "spec",
            )
        assert called is False


class TestBuildBinaryNonzeroExit:
    """A real entry point exists, but the PyInstaller subprocess itself
    fails -- `subprocess.run` is monkeypatched to a synthetic nonzero
    result rather than invoking a real, slow PyInstaller build for this
    negative-path case."""

    def test_nonzero_exit_raises_with_stderr_tail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cli_root = tmp_path
        entry = cli_root / "src" / "controlloop" / "__main__.py"
        entry.parent.mkdir(parents=True)
        entry.write_text("# synthetic entry point\n")
        (cli_root / "src" / "controlloop" / "policy" / "rules").mkdir(parents=True)

        def _fake_run(
            *args: object, **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=["pyinstaller"],
                returncode=1,
                stdout="",
                stderr="synthetic failure",
            )

        monkeypatch.setattr(_MODULE.subprocess, "run", _fake_run)

        with pytest.raises(_MODULE.BinaryBuildError, match="synthetic failure"):
            _MODULE.build_binary(
                cli_root=cli_root,
                platform="linux",
                arch="x86_64",
                dist_dir=tmp_path / "dist",
                work_dir=tmp_path / "build",
                spec_dir=tmp_path / "spec",
            )


class TestRelativeRepoRoot:
    """The release workflow runs `build_binary.py --repo-root .`.
    PyInstaller resolves a relative `--add-data` source against the
    `--specpath` directory, so every path it is given must be absolute,
    or the rules glob lands inside `build-binary/spec/` and the build
    fails."""

    def test_a_relative_repo_root_reaches_pyinstaller_as_absolute_paths(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entry = tmp_path / "src" / "controlloop" / "__main__.py"
        entry.parent.mkdir(parents=True)
        entry.write_text("# synthetic entry point\n")
        (tmp_path / "src" / "controlloop" / "policy" / "rules").mkdir(parents=True)
        captured: list[list[str]] = []

        def _fake_run(
            args: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            captured.append(args)
            return subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr="stop here"
            )

        monkeypatch.setattr(_MODULE.subprocess, "run", _fake_run)
        monkeypatch.chdir(tmp_path)

        with pytest.raises(_MODULE.BinaryBuildError):
            _MODULE.build_binary(
                cli_root=Path("."),
                platform="linux",
                arch="x86_64",
                dist_dir=Path("dist-binary"),
                work_dir=Path("build-binary"),
                spec_dir=Path("build-binary") / "spec",
            )

        (args,) = captured
        add_data = args[args.index("--add-data") + 1]
        source = add_data.rsplit(":", 1)[0]
        assert Path(source).is_absolute()
        assert (
            Path(source).parent
            == (tmp_path / "src" / "controlloop" / "policy" / "rules").resolve()
        )
        for flag in ("--distpath", "--workpath", "--specpath"):
            assert Path(args[args.index(flag) + 1]).is_absolute(), flag
        assert Path(args[-1]).is_absolute()


def _host_platform_and_arch() -> tuple[str, str] | None:
    """Map the real host this test is running on to this script's own
    `--platform`/`--arch` vocabulary, or `None` when the host is neither
    Linux nor macOS (PyInstaller cannot cross-compile, so a real build
    test can only ever target its own host -- see this module's own
    docstring)."""

    system = platform.system()
    machine = platform.machine().lower()
    arch = (
        "arm64"
        if machine in {"arm64", "aarch64"}
        else ("x86_64" if machine in {"x86_64", "amd64"} else None)
    )
    if arch is None:
        return None
    if system == "Linux":
        return "linux", arch
    if system == "Darwin":
        return "macos", arch
    return None


class TestRealBuildEndToEnd:
    """A real smoke test, reproducible scan output, and the "requiring no
    Python" observable outcome, against two genuine PyInstaller builds of
    this repository's own source tree -- the deliberately-bounded real-build
    cost for this whole class (see this module's own docstring for why real,
    slower cases run unconditionally here rather than behind an opt-in
    marker, and why two builds, not three, is where this test class draws
    its own cost/evidence line)."""

    def test_real_binary_scans_and_is_reproducible(self, tmp_path: Path) -> None:
        pytest.importorskip("PyInstaller")
        host = _host_platform_and_arch()
        if host is None:
            pytest.skip(
                "standalone binaries are only built for Linux/macOS "
                "x86_64/arm64 hosts -- see docs/reference/"
                "supported-platforms.md"
            )
        host_platform, host_arch = host

        fixture_repo = tmp_path / "fixture-repo"
        fixture_repo.mkdir()
        (fixture_repo / "agent-card.json").write_text(
            '{"name": "report-agent", "skills": '
            '[{"id": "read-quarterly-metrics", "name": "read-quarterly-metrics"}]}'
        )

        def _build_and_scan(build_id: str) -> tuple[Path, str]:
            binary_path = _MODULE.build_binary(
                cli_root=_CLI_ROOT,
                platform=host_platform,
                arch=host_arch,
                dist_dir=tmp_path / f"dist-{build_id}",
                work_dir=tmp_path / f"build-{build_id}",
                spec_dir=tmp_path / f"spec-{build_id}",
                timeout=600,
            )
            checksum_path = _MODULE.write_checksum(binary_path)
            assert checksum_path.exists()

            version_result = subprocess.run(
                [str(binary_path), "--version"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            assert version_result.returncode == 0
            assert "ControlLoop" in version_result.stdout

            scan_result = subprocess.run(
                [str(binary_path), "scan", str(fixture_repo), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            assert scan_result.returncode == 0, (
                f"real scan against a synthetic fixture failed "
                f"(exit {scan_result.returncode}): {scan_result.stderr}"
            )
            report = json.loads(scan_result.stdout)
            assert report["verdict"] == "passed"
            return binary_path, scan_result.stdout

        first_binary, first_output = _build_and_scan("first")
        second_binary, second_output = _build_and_scan("second")

        # Identical scan output from two independent builds of the same
        # commit -- proven here at the unit-test level, and again as a real
        # workflow step in `.github/workflows/release.yml`'s
        # `build-binaries` job.
        assert first_output == second_output

        # The two binaries' own bytes are expected to differ (PyInstaller
        # embeds a fresh build UUID and absolute temp-path metadata every
        # run) -- asserted explicitly so a future PyInstaller version that
        # somehow made this byte-identical would not silently invalidate
        # this test's own documented assumption.
        assert first_binary.read_bytes() != second_binary.read_bytes()

        self._assert_runs_with_python_removed_from_path(first_binary)

    @staticmethod
    def _assert_runs_with_python_removed_from_path(binary_path: Path) -> None:
        """REQ (observable outcome): "requiring no Python." Reuses the
        first binary this test already built rather than paying for a
        third real PyInstaller build -- two real builds are already the
        deliberately-bounded cost for this real, slow test class (see
        this module's own docstring).

        Runs the binary with a completely replaced (not merged) `env=`,
        containing only `/usr/bin` and `/bin` on `PATH` and no
        `PYTHONPATH`/`VIRTUAL_ENV` -- so a passing run genuinely exercises
        the frozen interpreter PyInstaller embedded, never an ambient
        `python3` or this repository's own `.venv` reachable through the
        *test process's* own environment, since a real subprocess `env=`
        replacement (not `os.environ` mutation) is used.
        """

        stripped_path = ":".join(
            part for part in ["/usr/bin", "/bin"] if Path(part).is_dir()
        )
        result = subprocess.run(
            [str(binary_path), "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env={"PATH": stripped_path},
        )
        assert result.returncode == 0, result.stderr
        assert "ControlLoop" in result.stdout
