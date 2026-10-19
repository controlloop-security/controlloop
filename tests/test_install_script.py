"""Tests for `install.sh`.

`install.sh` lives at the repository root (the canonical location a
`curl -fsSL .../install.sh | bash` one-liner expects), invoked directly by
an end user's shell, never imported. It is exercised as a real subprocess,
the same precedent `test_release_scripts.py`/
`test_build_binary_script.py`/`test_checksums_script.py` already establish
for scripts outside the `controlloop` package.

No release has ever been published (`docs/reference/release-pipeline.md`),
so every test here points `install.sh`'s own overridable network
endpoints (`CONTROLLOOP_INSTALL_RELEASE_API_URL`,
`CONTROLLOOP_INSTALL_BASE_URL`) at real synthetic release files on disk,
addressed with `file://` URLs. `install.sh` fetches both endpoints with
plain `curl -fsSL`, which resolves a `file://` URL exactly the same way
it resolves `http://` -- same exit codes on success and on a missing
file, same `-o`-writes-the-body behavior -- so every real code path in
`install.sh` (URL construction, download, checksum computation, error
handling) is exercised faithfully without needing a real listening
socket. This was a deliberate revision: an earlier version of this file
spun up a real loopback `http.server` in a child subprocess, which hung
indefinitely at the socket bind itself on this repository's macOS CI
runner specifically (confirmed via flushed progress logging in the child
before removing that approach) -- `file://` URLs need no bind, no port,
and no platform-specific networking behavior at all, so they sidestep
the problem entirely rather than working around it.

Every test also runs `install.sh` with a *minimal*, explicitly
constructed `PATH` containing only real symlinks to the handful of tools
the script actually needs (`uname`, `curl`, `sha256sum`/`shasum`, etc.)
-- never the ambient test-runner `PATH` -- so `gh` is reliably absent
unless a test explicitly adds a fake `gh` stub to exercise the
signature-verification branch deterministically and offline (real `gh`
would need real network access to GitHub's attestation API for a real
attestation that does not exist for these synthetic fixtures).
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_INSTALL_SCRIPT = _REPO_ROOT / "install.sh"
_BASH = shutil.which("bash")

#: Every real external command `install.sh` itself invokes. Deliberately
#: exhaustive and minimal -- a tool missing from this list that the
#: script actually needs makes a test fail with "command not found",
#: not a false pass, so nothing here is silently over-included either.
_REQUIRED_TOOLS = (
    "uname",
    "mktemp",
    "chmod",
    "mv",
    "mkdir",
    "grep",
    "awk",
    "sed",
    "rm",
    "curl",
    "sha256sum",
    "shasum",
    "head",
)

_FAKE_GH_SUCCEED = """#!/bin/sh
if [ "$1" = "attestation" ] && [ "$2" = "verify" ]; then
  exit 0
fi
exit 1
"""

_FAKE_GH_FAIL = """#!/bin/sh
if [ "$1" = "attestation" ] && [ "$2" = "verify" ]; then
  exit 1
fi
exit 1
"""


def _minimal_bin_dir(tmp_path: Path, *, fake_gh: str | None = None) -> Path:
    """A directory containing only real symlinks to `_REQUIRED_TOOLS`
    (resolved via `shutil.which`, which searches this *test process's*
    real `PATH`, independent of any shell alias/function the interactive
    development environment might define) -- so a subprocess given only
    this directory as its `PATH` cannot reach anything else, including a
    real `gh`. `fake_gh`, when given, is written as an executable `gh`
    stub into this same directory."""

    # A fresh, uniquely named directory each call -- some tests invoke
    # this more than once against the same `tmp_path` (idempotency:
    # installing twice in a row), and a fixed name would collide.
    bin_dir = Path(tempfile.mkdtemp(dir=tmp_path, prefix="minimal-bin-"))
    for tool in _REQUIRED_TOOLS:
        real = shutil.which(tool)
        if real is not None:
            (bin_dir / tool).symlink_to(real)

    if fake_gh is not None:
        gh_path = bin_dir / "gh"
        gh_path.write_text(fake_gh, encoding="utf-8")
        gh_path.chmod(0o755)

    return bin_dir


def _write_release_fixture(
    root: Path, *, tag: str, asset_name: str, binary_bytes: bytes
) -> None:
    """Write a synthetic release tree at `root`: `releases/latest` (shaped
    like GitHub's own Releases API response) and
    `releases/download/<tag>/<asset_name>` plus a real `SHA256SUMS` computed
    from `binary_bytes` -- exactly the shape the release workflow's
    `attest-artifacts` job publishes. Addressed by `install.sh` via
    `file://` URLs built from `root` -- see `_run_install`."""

    download_dir = root / "releases" / "download" / tag
    download_dir.mkdir(parents=True)
    binary_path = download_dir / asset_name
    binary_path.write_bytes(binary_bytes)
    digest = hashlib.sha256(binary_bytes).hexdigest()
    (download_dir / "SHA256SUMS").write_text(
        f"{digest}  {asset_name}\n", encoding="utf-8"
    )
    (root / "releases" / "latest").write_text(
        f'{{"tag_name": "{tag}"}}', encoding="utf-8"
    )


def _run_install(
    tmp_path: Path,
    *,
    root: Path,
    install_dir: Path,
    platform: str = "Darwin",
    arch: str = "arm64",
    version: str | None = None,
    fake_gh: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    bin_dir = _minimal_bin_dir(tmp_path, fake_gh=fake_gh)
    env = {
        "PATH": str(bin_dir),
        "HOME": str(tmp_path),
        "CONTROLLOOP_INSTALL_RELEASE_API_URL": f"file://{root}/releases/latest",
        "CONTROLLOOP_INSTALL_BASE_URL": f"file://{root}/releases/download",
        "CONTROLLOOP_INSTALL_DIR": str(install_dir),
        "CONTROLLOOP_INSTALL_PLATFORM": platform,
        "CONTROLLOOP_INSTALL_ARCH": arch,
    }
    if version is not None:
        env["CONTROLLOOP_INSTALL_VERSION"] = version
    if extra_env:
        env.update(extra_env)

    assert _BASH is not None
    return subprocess.run(
        [_BASH, str(_INSTALL_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


class TestPositive:
    def test_installs_the_correct_asset_for_the_detected_platform(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root,
            tag="v0.9.9-test",
            asset_name="controlloop-macos-arm64",
            binary_bytes=b"real binary bytes for this release",
        )
        install_dir = tmp_path / "install-dir"
        result = _run_install(
            tmp_path,
            root=root,
            install_dir=install_dir,
            platform="Darwin",
            arch="arm64",
        )

        assert result.returncode == 0, result.stderr
        installed = install_dir / "controlloop"
        assert installed.is_file()
        assert installed.read_bytes() == b"real binary bytes for this release"
        assert "checksum verified" in result.stderr

    def test_resolves_latest_when_no_version_is_pinned(self, tmp_path: Path) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root,
            tag="v3.4.5",
            asset_name="controlloop-linux-x86_64",
            binary_bytes=b"linux binary",
        )
        install_dir = tmp_path / "install-dir"
        result = _run_install(
            tmp_path,
            root=root,
            install_dir=install_dir,
            platform="Linux",
            arch="x86_64",
        )

        assert result.returncode == 0, result.stderr
        assert "v3.4.5" in result.stderr


class TestSignatureVerification:
    def test_disclosed_skip_when_gh_is_not_installed(self, tmp_path: Path) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root, tag="v1.0.0", asset_name="controlloop-macos-arm64", binary_bytes=b"x"
        )
        install_dir = tmp_path / "install-dir"
        result = _run_install(tmp_path, root=root, install_dir=install_dir)

        assert result.returncode == 0, result.stderr
        assert "skipping signature verification" in result.stderr
        assert "gh" in result.stderr
        assert (install_dir / "controlloop").is_file()

    def test_succeeds_when_gh_attestation_verify_succeeds(self, tmp_path: Path) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root, tag="v1.0.0", asset_name="controlloop-macos-arm64", binary_bytes=b"x"
        )
        install_dir = tmp_path / "install-dir"
        result = _run_install(
            tmp_path, root=root, install_dir=install_dir, fake_gh=_FAKE_GH_SUCCEED
        )

        assert result.returncode == 0, result.stderr
        assert "signature verified" in result.stderr
        assert (install_dir / "controlloop").is_file()

    def test_aborts_when_gh_attestation_verify_fails(self, tmp_path: Path) -> None:
        """Aborts on mismatch -- a real (stubbed) attestation rejection must
        block installation, not merely warn."""
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root, tag="v1.0.0", asset_name="controlloop-macos-arm64", binary_bytes=b"x"
        )
        install_dir = tmp_path / "install-dir"
        result = _run_install(
            tmp_path, root=root, install_dir=install_dir, fake_gh=_FAKE_GH_FAIL
        )

        assert result.returncode != 0
        assert "signature verification failed" in result.stderr
        assert not (install_dir / "controlloop").exists()


class TestChecksumTamperNegative:
    """A tampered artifact fails verification."""

    def test_a_binary_that_does_not_match_sha256sums_is_rejected(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root,
            tag="v1.0.0",
            asset_name="controlloop-macos-arm64",
            binary_bytes=b"the original bytes",
        )
        # Tamper: overwrite the published binary after SHA256SUMS was
        # already computed from the original bytes.
        binary_path = (
            root / "releases" / "download" / "v1.0.0" / "controlloop-macos-arm64"
        )
        binary_path.write_bytes(b"a tampered payload of a different length")

        install_dir = tmp_path / "install-dir"
        result = _run_install(tmp_path, root=root, install_dir=install_dir)

        assert result.returncode != 0
        assert "checksum mismatch" in result.stderr
        assert not install_dir.exists() or not (install_dir / "controlloop").exists()

    def test_missing_sha256sums_entry_is_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root,
            tag="v1.0.0",
            asset_name="controlloop-macos-arm64",
            binary_bytes=b"payload",
        )
        (root / "releases" / "download" / "v1.0.0" / "SHA256SUMS").write_text(
            "deadbeef" * 8 + "  some-other-file\n", encoding="utf-8"
        )

        install_dir = tmp_path / "install-dir"
        result = _run_install(tmp_path, root=root, install_dir=install_dir)

        assert result.returncode != 0
        assert "no entry" in result.stderr


class TestMalformedPlatformDetection:
    """Platform/arch detection, including the unsupported case."""

    def test_unsupported_platform_is_rejected_before_any_download(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        install_dir = tmp_path / "install-dir"
        result = _run_install(
            tmp_path,
            root=root,
            install_dir=install_dir,
            platform="Windows_NT",
            arch="x86_64",
        )

        assert result.returncode != 0
        assert "unsupported platform" in result.stderr
        assert not install_dir.exists()

    def test_unsupported_architecture_is_rejected_before_any_download(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        install_dir = tmp_path / "install-dir"
        result = _run_install(
            tmp_path,
            root=root,
            install_dir=install_dir,
            platform="Linux",
            arch="riscv64",
        )

        assert result.returncode != 0
        assert "unsupported architecture" in result.stderr
        assert not install_dir.exists()

    def test_macos_x86_64_disclosed_gap_is_rejected(self, tmp_path: Path) -> None:
        """The binary build's own disclosed gap: no macOS x86_64 binary is
        ever published, so the installer must refuse rather than attempt a
        download that can never succeed."""
        root = tmp_path / "fixture-root"
        root.mkdir()
        install_dir = tmp_path / "install-dir"
        result = _run_install(
            tmp_path,
            root=root,
            install_dir=install_dir,
            platform="Darwin",
            arch="x86_64",
        )

        assert result.returncode != 0
        assert "macOS x86_64" in result.stderr
        assert not install_dir.exists()


class TestPinnedVersionAndIdempotency:
    def test_a_pinned_version_is_installed_even_when_a_newer_release_exists(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root,
            tag="v2.0.0",
            asset_name="controlloop-macos-arm64",
            binary_bytes=b"new",
        )
        _write_release_fixture(
            root,
            tag="v1.0.0",
            asset_name="controlloop-macos-arm64",
            binary_bytes=b"old",
        )
        install_dir = tmp_path / "install-dir"
        result = _run_install(
            tmp_path, root=root, install_dir=install_dir, version="v1.0.0"
        )

        assert result.returncode == 0, result.stderr
        assert (install_dir / "controlloop").read_bytes() == b"old"

    def test_a_pinned_version_without_its_leading_v_is_normalized(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root,
            tag="v1.2.3",
            asset_name="controlloop-macos-arm64",
            binary_bytes=b"data",
        )
        install_dir = tmp_path / "install-dir"
        result = _run_install(
            tmp_path, root=root, install_dir=install_dir, version="1.2.3"
        )

        assert result.returncode == 0, result.stderr
        assert (install_dir / "controlloop").is_file()

    def test_installing_twice_converges_to_the_identical_end_state(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root,
            tag="v1.0.0",
            asset_name="controlloop-macos-arm64",
            binary_bytes=b"stable",
        )
        install_dir = tmp_path / "install-dir"
        first = _run_install(tmp_path, root=root, install_dir=install_dir)
        second = _run_install(tmp_path, root=root, install_dir=install_dir)

        assert first.returncode == 0, first.stderr
        assert second.returncode == 0, second.stderr
        assert (install_dir / "controlloop").read_bytes() == b"stable"


class TestNoElevatedPrivileges:
    """Never requires elevated privileges for a default user-local
    install."""

    def test_script_never_references_sudo(self) -> None:
        text = _INSTALL_SCRIPT.read_text(encoding="utf-8")
        assert "sudo" not in text

    def test_default_install_dir_is_under_home_and_needs_no_privilege(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "fixture-root"
        root.mkdir()
        _write_release_fixture(
            root, tag="v1.0.0", asset_name="controlloop-macos-arm64", binary_bytes=b"x"
        )
        fake_home = tmp_path / "fake-home"
        fake_home.mkdir()
        bin_dir = _minimal_bin_dir(tmp_path)
        env = {
            "PATH": str(bin_dir),
            "HOME": str(fake_home),
            "CONTROLLOOP_INSTALL_RELEASE_API_URL": f"file://{root}/releases/latest",
            "CONTROLLOOP_INSTALL_BASE_URL": f"file://{root}/releases/download",
            "CONTROLLOOP_INSTALL_PLATFORM": "Darwin",
            "CONTROLLOOP_INSTALL_ARCH": "arm64",
        }
        assert _BASH is not None
        result = subprocess.run(
            [_BASH, str(_INSTALL_SCRIPT)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

        assert result.returncode == 0, result.stderr
        assert (fake_home / ".local" / "bin" / "controlloop").is_file()
