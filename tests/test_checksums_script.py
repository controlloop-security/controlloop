"""Tests for `release-scripts/checksums.py`.

Mirrors `test_release_scripts.py`/`test_assemble_schema_site.py`'s own
precedent: this script lives outside the `controlloop` package (invoked
directly by `.github/workflows/release.yml`, never imported), so it is
exercised as a real subprocess against real file paths under `tmp_path`. It
performs no network access, so this file is unaffected by (and does not
need to participate in) `conftest.py`'s autouse offline-denial fixture, the
same reasoning `test_release_scripts.py` already documents for its own
subprocess calls.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO_ROOT / "release-scripts" / "checksums.py"


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


class TestWritePositive:
    def test_writes_one_line_per_artifact_with_real_digests(
        self, tmp_path: Path
    ) -> None:
        wheel = _write(tmp_path / "controlloop-0.2.0.whl", b"wheel-bytes")
        sdist = _write(tmp_path / "controlloop-0.2.0.tar.gz", b"sdist-bytes")
        output = tmp_path / "SHA256SUMS"

        result = _run(["write", "--output", str(output), str(wheel), str(sdist)])

        assert result.returncode == 0, result.stderr
        lines = output.read_text(encoding="utf-8").splitlines()
        assert lines == [
            f"{_sha256(b'sdist-bytes')}  controlloop-0.2.0.tar.gz",
            f"{_sha256(b'wheel-bytes')}  controlloop-0.2.0.whl",
        ]

    def test_output_is_sorted_by_filename_regardless_of_argument_order(
        self, tmp_path: Path
    ) -> None:
        a = _write(tmp_path / "zzz.bin", b"z")
        b = _write(tmp_path / "aaa.bin", b"a")
        output = tmp_path / "SHA256SUMS"

        result = _run(["write", "--output", str(output), str(a), str(b)])

        assert result.returncode == 0, result.stderr
        names = [
            line.split("  ", 1)[1]
            for line in output.read_text(encoding="utf-8").splitlines()
        ]
        assert names == ["aaa.bin", "zzz.bin"]


class TestWriteMalformedAndBoundary:
    def test_missing_file_fails_loudly(self, tmp_path: Path) -> None:
        output = tmp_path / "SHA256SUMS"

        result = _run(["write", "--output", str(output), str(tmp_path / "nonexistent")])

        assert result.returncode == 1
        assert "missing" in result.stderr
        assert not output.exists()

    def test_duplicate_filename_across_different_directories_fails(
        self, tmp_path: Path
    ) -> None:
        first_dir = tmp_path / "a"
        second_dir = tmp_path / "b"
        first_dir.mkdir()
        second_dir.mkdir()
        first = _write(first_dir / "same-name.bin", b"one")
        second = _write(second_dir / "same-name.bin", b"two")
        output = tmp_path / "SHA256SUMS"

        result = _run(["write", "--output", str(output), str(first), str(second)])

        assert result.returncode == 1
        assert "duplicate filename" in result.stderr

    def test_empty_artifact_list_writes_an_empty_file(self, tmp_path: Path) -> None:
        output = tmp_path / "SHA256SUMS"

        result = _run(["write", "--output", str(output)])

        assert result.returncode != 0  # argparse: `paths` is `nargs="+"`


class TestVerifyPositive:
    def test_real_unmodified_artifacts_verify_clean(self, tmp_path: Path) -> None:
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        _write(artifacts_dir / "one.bin", b"one-bytes")
        _write(artifacts_dir / "two.bin", b"two-bytes")
        checksums_file = tmp_path / "SHA256SUMS"
        checksums_file.write_text(
            f"{_sha256(b'one-bytes')}  one.bin\n{_sha256(b'two-bytes')}  two.bin\n",
            encoding="utf-8",
        )

        result = _run(
            [
                "verify",
                "--checksums-file",
                str(checksums_file),
                "--dir",
                str(artifacts_dir),
            ]
        )

        assert result.returncode == 0, result.stderr
        assert "verified" in result.stdout


class TestVerifyNegativeTamper:
    """A tampered artifact fails verification."""

    def test_a_single_byte_changed_in_the_artifact_fails_verification(
        self, tmp_path: Path
    ) -> None:
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        original = b"the exact bytes this release actually published"
        _write(artifacts_dir / "controlloop-0.2.0.whl", original)
        checksums_file = tmp_path / "SHA256SUMS"
        checksums_file.write_text(
            f"{_sha256(original)}  controlloop-0.2.0.whl\n", encoding="utf-8"
        )

        # Tamper: flip one byte after the checksum was computed, exactly
        # the "downloaded artifact was modified in transit or at rest"
        # scenario verification exists to catch.
        tampered = bytearray(original)
        tampered[0] ^= 0xFF
        _write(artifacts_dir / "controlloop-0.2.0.whl", bytes(tampered))

        result = _run(
            [
                "verify",
                "--checksums-file",
                str(checksums_file),
                "--dir",
                str(artifacts_dir),
            ]
        )

        assert result.returncode == 1
        assert "checksum mismatch" in result.stderr
        assert "controlloop-0.2.0.whl" in result.stderr

    def test_a_missing_artifact_fails_verification(self, tmp_path: Path) -> None:
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        checksums_file = tmp_path / "SHA256SUMS"
        checksums_file.write_text(
            f"{_sha256(b'never written')}  ghost.bin\n", encoding="utf-8"
        )

        result = _run(
            [
                "verify",
                "--checksums-file",
                str(checksums_file),
                "--dir",
                str(artifacts_dir),
            ]
        )

        assert result.returncode == 1
        assert "ghost.bin: missing" in result.stderr

    def test_every_failure_is_reported_not_only_the_first(self, tmp_path: Path) -> None:
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        _write(artifacts_dir / "present-but-wrong.bin", b"actual")
        checksums_file = tmp_path / "SHA256SUMS"
        checksums_file.write_text(
            f"{_sha256(b'expected')}  present-but-wrong.bin\n"
            f"{_sha256(b'anything')}  also-missing.bin\n",
            encoding="utf-8",
        )

        result = _run(
            [
                "verify",
                "--checksums-file",
                str(checksums_file),
                "--dir",
                str(artifacts_dir),
            ]
        )

        assert result.returncode == 1
        assert "present-but-wrong.bin: checksum mismatch" in result.stderr
        assert "also-missing.bin: missing" in result.stderr


class TestVerifyMalformed:
    def test_malformed_line_fails_loudly_naming_the_line_number(
        self, tmp_path: Path
    ) -> None:
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        checksums_file = tmp_path / "SHA256SUMS"
        checksums_file.write_text("not-a-valid-checksums-line\n", encoding="utf-8")

        result = _run(
            [
                "verify",
                "--checksums-file",
                str(checksums_file),
                "--dir",
                str(artifacts_dir),
            ]
        )

        assert result.returncode == 1
        assert "malformed checksums line" in result.stderr
        assert f"{checksums_file}:1" in result.stderr

    def test_blank_lines_are_tolerated(self, tmp_path: Path) -> None:
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        _write(artifacts_dir / "one.bin", b"data")
        checksums_file = tmp_path / "SHA256SUMS"
        checksums_file.write_text(
            f"\n{_sha256(b'data')}  one.bin\n\n", encoding="utf-8"
        )

        result = _run(
            [
                "verify",
                "--checksums-file",
                str(checksums_file),
                "--dir",
                str(artifacts_dir),
            ]
        )

        assert result.returncode == 0, result.stderr


class TestDeterminism:
    def test_repeated_writes_of_the_same_inputs_are_byte_identical(
        self, tmp_path: Path
    ) -> None:
        wheel = _write(tmp_path / "controlloop.whl", b"wheel-bytes")
        first_output = tmp_path / "first-SHA256SUMS"
        second_output = tmp_path / "second-SHA256SUMS"

        first = _run(["write", "--output", str(first_output), str(wheel)])
        second = _run(["write", "--output", str(second_output), str(wheel)])

        assert first.returncode == 0
        assert second.returncode == 0
        assert first_output.read_bytes() == second_output.read_bytes()
