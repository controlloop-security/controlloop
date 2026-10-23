"""Tests for `release-scripts/homebrew_formula.py`.

Like the other release scripts, it lives outside the `controlloop` package
and is imported here dynamically. It is dependency-free, so every case runs
on every matrix leg without a Homebrew installation: what is tested is that
the formula is rendered from the release's own checksums and nothing else,
and that any gap in those inputs refuses to render rather than producing a
formula with a hole in it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO_ROOT / "release-scripts" / "homebrew_formula.py"

_SHAS = {
    "controlloop-macos-arm64": "a" * 64,
    "controlloop-linux-x86_64": "b" * 64,
    "controlloop-linux-arm64": "c" * 64,
    "controlloop-0.2.0-py3-none-any.whl": "d" * 64,
}


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("homebrew_formula", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sums_text(shas: dict[str, str] = _SHAS) -> str:
    return "".join(f"{digest}  {name}\n" for name, digest in shas.items())


class TestReadChecksums:
    def test_parses_sha256sum_lines(self) -> None:
        module = _load()
        assert module.read_checksums(_sums_text()) == _SHAS

    def test_accepts_binary_mode_marker_and_blank_lines(self) -> None:
        module = _load()
        text = f"{'a' * 64} *controlloop-macos-arm64\n\n"
        assert module.read_checksums(text) == {"controlloop-macos-arm64": "a" * 64}

    def test_rejects_a_malformed_line_instead_of_skipping_it(self) -> None:
        module = _load()
        with pytest.raises(module.FormulaError, match="line 2"):
            module.read_checksums(
                f"{'a' * 64}  ok\nnot-a-digest  controlloop-linux-arm64\n"
            )

    def test_rejects_a_duplicate_name(self) -> None:
        module = _load()
        text = f"{'a' * 64}  same\n{'b' * 64}  same\n"
        with pytest.raises(module.FormulaError, match="twice"):
            module.read_checksums(text)


class TestRenderFormula:
    def test_formula_carries_each_binary_url_and_its_checksum(self) -> None:
        module = _load()
        formula = module.render_formula(
            "0.2.0", _SHAS, "controlloop-security/controlloop"
        )

        base = "https://github.com/controlloop-security/controlloop/releases/download/v0.2.0"
        for asset in module.ASSETS.values():
            assert f'url "{base}/{asset}"' in formula
            assert f'sha256 "{_SHAS[asset]}"' in formula
        assert "/releases/download/v0.2.0/" in formula
        # Homebrew scans the version from the URL; `brew audit --strict`
        # rejects a redundant `version` line.
        assert '\n  version "' not in formula
        assert 'license "Apache-2.0"' in formula
        assert 'homepage "https://controlloop.ai"' in formula
        assert "class Controlloop < Formula" in formula

    def test_formula_never_points_at_a_moving_release(self) -> None:
        module = _load()
        formula = module.render_formula(
            "0.2.0", _SHAS, "controlloop-security/controlloop"
        )

        assert "releases/latest" not in formula
        assert "/main/" not in formula

    def test_macos_intel_is_refused_with_the_alternative_named(self) -> None:
        module = _load()
        formula = module.render_formula(
            "0.2.0", _SHAS, "controlloop-security/controlloop"
        )

        assert "Hardware::CPU.intel?" in formula
        assert "uv tool install controlloop" in formula

    def test_formula_test_block_runs_a_real_scan(self) -> None:
        module = _load()
        formula = module.render_formula(
            "0.2.0", _SHAS, "controlloop-security/controlloop"
        )

        assert "controlloop --version" in formula
        assert "scan" in formula and '"verdict"' in formula

    @pytest.mark.parametrize(
        "missing", ["controlloop-macos-arm64", "controlloop-linux-arm64"]
    )
    def test_a_missing_binary_checksum_refuses_to_render(self, missing: str) -> None:
        module = _load()
        shas = {name: digest for name, digest in _SHAS.items() if name != missing}
        with pytest.raises(module.FormulaError, match=missing):
            module.render_formula("0.2.0", shas, "controlloop-security/controlloop")

    @pytest.mark.parametrize("version", ["v0.2.0", "0.2", "latest", ""])
    def test_a_malformed_version_is_rejected(self, version: str) -> None:
        module = _load()
        with pytest.raises(module.FormulaError, match=r"MAJOR\.MINOR\.PATCH"):
            module.render_formula(version, _SHAS, "controlloop-security/controlloop")

    def test_a_malformed_repository_is_rejected(self) -> None:
        module = _load()
        with pytest.raises(module.FormulaError, match="owner/name"):
            module.render_formula("0.2.0", _SHAS, "https://github.com/x/y")

    def test_rendering_is_deterministic(self) -> None:
        module = _load()
        first = module.render_formula(
            "0.2.0", _SHAS, "controlloop-security/controlloop"
        )
        second = module.render_formula(
            "0.2.0", dict(reversed(_SHAS.items())), "controlloop-security/controlloop"
        )
        assert first == second


class TestCommandLine:
    def test_writes_the_formula_to_the_output_path(self, tmp_path: Path) -> None:
        module = _load()
        sums = tmp_path / "SHA256SUMS"
        sums.write_text(_sums_text(), encoding="utf-8")
        output = tmp_path / "Formula" / "controlloop.rb"

        code = module.main(
            [
                "--version",
                "0.2.0",
                "--checksums-file",
                str(sums),
                "--output",
                str(output),
            ]
        )

        assert code == 0
        assert 'sha256 "' + "a" * 64 + '"' in output.read_text(encoding="utf-8")

    def test_exits_nonzero_and_writes_nothing_when_a_checksum_is_missing(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        module = _load()
        sums = tmp_path / "SHA256SUMS"
        sums.write_text(f"{'a' * 64}  controlloop-macos-arm64\n", encoding="utf-8")
        output = tmp_path / "controlloop.rb"

        code = module.main(
            [
                "--version",
                "0.2.0",
                "--checksums-file",
                str(sums),
                "--output",
                str(output),
            ]
        )

        assert code == 1
        assert not output.exists()
        assert "controlloop-linux-x86_64" in capsys.readouterr().err
