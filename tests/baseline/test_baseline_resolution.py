"""Tests for `controlloop.baseline.resolution`.

Mirrors `tests/baseline/test_baseline_integrity.py`'s fixture-driven style,
extended with the conventional-path discovery, explicit-path override, and
no-baseline-yet cases resolution adds on top of the already-tested
validation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from controlloop.baseline import BaselineIntegrityError
from controlloop.baseline.resolution import (
    CONVENTIONAL_BASELINE_RELATIVE_PATH,
    BaselineResolutionError,
    BaselineSource,
    resolve_baseline,
)
from controlloop.baseline.serialization import with_baseline_digest
from controlloop.exit_codes import ExitCode
from controlloop.repository import RepositoryRoot

_CLI_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE_PATH = _CLI_ROOT / "tests/fixtures/baseline/minimal-baseline.json"


def _fixture_text() -> str:
    return _FIXTURE_PATH.read_text(encoding="utf-8")


def _write_conventional(root_path: Path, content: str) -> Path:
    target = root_path / CONVENTIONAL_BASELINE_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def _explicit_fixture_with_different_digest(tmp_path: Path) -> Path:
    """A second, independently valid baseline whose content (and
    therefore digest) differs from the real fixture, so a test can prove
    resolution actually returned *this* document rather than merely
    finding *a* document."""
    fixture = json.loads(_fixture_text())
    fixture["generator"]["version"] = "9.9.9"
    fixture["digest"] = f"sha256:{'0' * 64}"
    from controlloop.baseline.models import BaselineDocument

    # `model_validate_json`, not `model_validate` on the parsed dict, so
    # JSON-mode list -> tuple coercion applies under this model's
    # `strict=True` config -- the same reason
    # `controlloop.baseline.integrity.load_baseline_document` validates
    # raw text rather than a pre-parsed object.
    document = BaselineDocument.model_validate_json(json.dumps(fixture))
    redigested = with_baseline_digest(document)

    path = tmp_path / "explicit-baseline.json"
    path.write_text(redigested.model_dump_json(), encoding="utf-8")
    return path


class TestResolveBaselinePositiveCommitted:
    """Automatic discovery at the conventional path."""

    def test_discovers_the_conventional_baseline(self, tmp_path: Path) -> None:
        _write_conventional(tmp_path, _fixture_text())
        root = RepositoryRoot(path=tmp_path)

        resolved = resolve_baseline(root)

        assert resolved is not None
        assert resolved.source is BaselineSource.COMMITTED
        assert resolved.path == tmp_path / CONVENTIONAL_BASELINE_RELATIVE_PATH
        assert resolved.document.schema_version == "1.0.0"

    def test_conventional_path_is_relative_to_the_repository_root_not_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The conventional path is resolved against the *resolved
        repository root*, not the current working directory -- a
        different cwd must not change discovery."""
        _write_conventional(tmp_path, _fixture_text())
        elsewhere = tmp_path.parent
        monkeypatch.chdir(elsewhere)
        root = RepositoryRoot(path=tmp_path)

        resolved = resolve_baseline(root)

        assert resolved is not None
        assert resolved.source is BaselineSource.COMMITTED


class TestResolveBaselinePositiveExplicitOverride:
    """An explicit path overrides discovery."""

    def test_explicit_path_wins_even_when_a_conventional_baseline_exists(
        self, tmp_path: Path
    ) -> None:
        _write_conventional(tmp_path, _fixture_text())
        explicit_path = _explicit_fixture_with_different_digest(tmp_path)
        root = RepositoryRoot(path=tmp_path)

        resolved = resolve_baseline(root, explicit_path=explicit_path)

        assert resolved is not None
        assert resolved.source is BaselineSource.EXPLICIT
        assert resolved.path == explicit_path
        assert resolved.document.generator.version == "9.9.9"

    def test_explicit_path_works_with_no_conventional_baseline_present(
        self, tmp_path: Path
    ) -> None:
        explicit_path = tmp_path / "somewhere-else.json"
        explicit_path.write_text(_fixture_text(), encoding="utf-8")
        root = RepositoryRoot(path=tmp_path)

        resolved = resolve_baseline(root, explicit_path=explicit_path)

        assert resolved is not None
        assert resolved.source is BaselineSource.EXPLICIT


class TestResolveBaselineNoBaselineAvailable:
    """Similar negative: absence is a legitimate outcome, not an error."""

    def test_returns_none_when_neither_source_is_available(
        self, tmp_path: Path
    ) -> None:
        root = RepositoryRoot(path=tmp_path)

        resolved = resolve_baseline(root)

        assert resolved is None


class TestResolveBaselineUnreadablePath:
    """Negative: a selected path that cannot be read at all."""

    def test_explicit_path_that_does_not_exist_raises(self, tmp_path: Path) -> None:
        root = RepositoryRoot(path=tmp_path)
        missing = tmp_path / "does-not-exist.json"

        with pytest.raises(BaselineResolutionError) as excinfo:
            resolve_baseline(root, explicit_path=missing)

        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT

    def test_conventional_path_as_a_directory_raises_rather_than_treating_as_absent(
        self, tmp_path: Path
    ) -> None:
        """Boundary: something exists at the conventional path, but it is
        not a file -- this must not be silently treated as "no baseline
        committed"."""
        target = tmp_path / CONVENTIONAL_BASELINE_RELATIVE_PATH
        target.mkdir(parents=True)
        root = RepositoryRoot(path=tmp_path)

        with pytest.raises(BaselineResolutionError) as excinfo:
            resolve_baseline(root)

        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT


class TestResolveBaselineMalformedOrTampered:
    """A baseline that fails validation returns exit 2 rather than falling
    back silently to another source -- reuses `BaselineIntegrityError`
    unmodified from integrity validation."""

    def test_tampered_conventional_baseline_is_rejected_not_replaced(
        self, tmp_path: Path
    ) -> None:
        fixture = json.loads(_fixture_text())
        fixture["repository"]["commit"] = "tampered-commit-value"
        _write_conventional(tmp_path, json.dumps(fixture))
        root = RepositoryRoot(path=tmp_path)

        with pytest.raises(BaselineIntegrityError) as excinfo:
            resolve_baseline(root)

        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT

    def test_malformed_explicit_baseline_is_rejected_not_replaced_by_discovery(
        self, tmp_path: Path
    ) -> None:
        """Even though a perfectly valid conventional baseline is
        available, a failing explicit override must not silently fall
        back to it."""
        _write_conventional(tmp_path, _fixture_text())
        bad_path = tmp_path / "bad-explicit.json"
        bad_path.write_text("not json at all {{{", encoding="utf-8")
        root = RepositoryRoot(path=tmp_path)

        with pytest.raises(BaselineIntegrityError) as excinfo:
            resolve_baseline(root, explicit_path=bad_path)

        assert excinfo.value.exit_code is ExitCode.INVALID_INPUT

    def test_truncated_conventional_baseline_is_rejected(self, tmp_path: Path) -> None:
        raw = _fixture_text()
        truncated = raw[: len(raw) // 2]
        _write_conventional(tmp_path, truncated)
        root = RepositoryRoot(path=tmp_path)

        with pytest.raises(BaselineIntegrityError):
            resolve_baseline(root)


class TestResolveBaselinePrivacy:
    """Privacy canary: a planted secret-shaped value never leaks through
    a resolution failure's error text."""

    def test_canary_planted_secret_never_leaks_through_a_resolution_error(
        self, tmp_path: Path
    ) -> None:
        planted_secret = "ghp_" + "a" * 36  # synthetic GitHub-token-shaped canary
        fixture = json.loads(_fixture_text())
        fixture["generator"]["name"] = planted_secret
        # Tamper the digest so this is rejected by integrity checking
        # rather than accepted, without needing the recomputed digest.
        _write_conventional(tmp_path, json.dumps(fixture))
        root = RepositoryRoot(path=tmp_path)

        with pytest.raises(BaselineIntegrityError) as excinfo:
            resolve_baseline(root)

        assert planted_secret not in str(excinfo.value)


class TestResolveBaselineDeterminism:
    def test_resolving_the_same_fixture_twice_yields_identical_results(
        self, tmp_path: Path
    ) -> None:
        _write_conventional(tmp_path, _fixture_text())
        root = RepositoryRoot(path=tmp_path)

        first = resolve_baseline(root)
        second = resolve_baseline(root)

        assert first is not None
        assert second is not None
        assert first.document == second.document
        assert first.document.digest == second.document.digest
        assert first.source == second.source
