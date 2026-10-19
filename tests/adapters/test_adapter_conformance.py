"""The adapter conformance suite.

One shared suite, parametrized over `conformance_fixtures.ALL_FIXTURES`,
asserted against every currently registered adapter
(`controlloop.adapters.ALL_ADAPTERS`). Each fixture category is shaped
per adapter; `conformance_fixtures.py` explains why.

Running under the offline harness is not a test in this file: every
test under `tests/` already runs under `conftest.py`'s
`_deny_network_access` autouse fixture, so this file inherits it
structurally, the same as every other test file in this codebase.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conformance_fixtures import (
    ALL_FIXTURES,
    PRIVACY_REQUIRED_ADAPTERS,
    ConformanceFixture,
)

from controlloop.adapters import ALL_ADAPTERS, ScanContext
from controlloop.repository import resolve_repository_root

_VERSION_DRIFT_FIXTURES = tuple(
    fixture for fixture in ALL_FIXTURES if fixture.write_version_drift is not None
)
_VERSION_DRIFT_EXEMPT_FIXTURES = tuple(
    fixture for fixture in ALL_FIXTURES if fixture.write_version_drift is None
)
_OLDER_VERSION_DRIFT_FIXTURES = tuple(
    fixture for fixture in ALL_FIXTURES if fixture.write_older_version_drift is not None
)
_OLDER_VERSION_DRIFT_EXEMPT_FIXTURES = tuple(
    fixture for fixture in ALL_FIXTURES if fixture.write_older_version_drift is None
)


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _assert_evidence_contract(
    result: object, adapter_name: str, tmp_path: Path
) -> None:
    """Every produced node and edge carries adapter, confidence, and
    sanitized evidence."""

    for item in (*result.nodes, *result.edges):  # type: ignore[attr-defined]
        assert item.confidence is not None
        assert item.evidence, f"{item.id} has no evidence"
        for evidence in item.evidence:
            assert evidence.adapter == adapter_name
            assert evidence.path is not None
            assert not evidence.path.startswith("/")
            assert str(tmp_path) not in evidence.path


class TestPositive:
    """Positive parsing, for every registered adapter."""

    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.adapter_name)
    def test_positive_fixture_produces_the_expected_shape(
        self, fixture: ConformanceFixture, tmp_path: Path
    ) -> None:
        fixture.write_positive(tmp_path)
        context = _context(tmp_path)

        detection = fixture.make_adapter().detect(context)
        assert detection.claimed_paths, (
            f"{fixture.adapter_name} did not claim its own positive fixture"
        )

        result = fixture.run(fixture.make_adapter(), context)
        fixture.assert_positive(result)
        _assert_evidence_contract(result, fixture.adapter_name, tmp_path)


class TestSimilarNegative:
    """A similar negative case, for every registered adapter.

    The universal invariant is that a similar-but-different input never
    produces a false-positive node -- not that it is left unclaimed.
    Most adapters simply never claim it (content-sniffing or location
    matching excludes it before discover() runs); IAM's GCP/Azure-shaped
    fixture is different by design: it *is* claimed, specifically so it
    can be explicitly rejected with a diagnostic naming the real
    provider, rather than silently ignored. Both compose into the same
    assertion here.
    """

    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.adapter_name)
    def test_similar_but_different_input_never_produces_a_false_positive(
        self, fixture: ConformanceFixture, tmp_path: Path
    ) -> None:
        fixture.write_similar_negative(tmp_path)
        context = _context(tmp_path)

        result = fixture.run(fixture.make_adapter(), context)

        assert result.nodes == ()


class TestMalformed:
    """Malformed input never crashes and is never silently dropped -- it
    produces an explicit unknown."""

    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.adapter_name)
    def test_malformed_input_produces_a_diagnostic_not_a_crash(
        self, fixture: ConformanceFixture, tmp_path: Path
    ) -> None:
        fixture.write_malformed(tmp_path)
        context = _context(tmp_path)

        result = fixture.run(fixture.make_adapter(), context)

        assert result.nodes == ()
        assert len(result.diagnostics) >= 1
        assert all(
            diagnostic.code.startswith("INCOMPLETE-")
            for diagnostic in result.diagnostics
        )


class TestVersionDrift:
    """Version drift, for every adapter with an in-document version
    marker to drift. Disclosed exceptions are checked separately below
    rather than silently skipped."""

    @pytest.mark.parametrize(
        "fixture", _VERSION_DRIFT_FIXTURES, ids=lambda f: f.adapter_name
    )
    def test_unsupported_version_produces_a_diagnostic_not_a_misparse(
        self, fixture: ConformanceFixture, tmp_path: Path
    ) -> None:
        assert fixture.write_version_drift is not None
        fixture.write_version_drift(tmp_path)
        context = _context(tmp_path)

        result = fixture.run(fixture.make_adapter(), context)

        assert result.nodes == ()
        assert len(result.diagnostics) >= 1

    @pytest.mark.parametrize(
        "fixture", _VERSION_DRIFT_EXEMPT_FIXTURES, ids=lambda f: f.adapter_name
    )
    def test_version_drift_exemption_is_explicitly_disclosed(
        self, fixture: ConformanceFixture
    ) -> None:
        assert fixture.version_drift_unsupported_reason
        assert len(fixture.version_drift_unsupported_reason) > 10


class TestOlderVersionDrift:
    """Version drift's own older direction, for every adapter with a real
    historical version genuinely older than its `_SUPPORTED_VERSIONS`.
    Mirrors `TestVersionDrift` exactly -- identical assertion shape,
    identical exemption-disclosure contract -- for the direction that
    suite's own fixtures never exercised."""

    @pytest.mark.parametrize(
        "fixture", _OLDER_VERSION_DRIFT_FIXTURES, ids=lambda f: f.adapter_name
    )
    def test_older_than_supported_version_produces_a_diagnostic_not_a_misparse(
        self, fixture: ConformanceFixture, tmp_path: Path
    ) -> None:
        assert fixture.write_older_version_drift is not None
        fixture.write_older_version_drift(tmp_path)
        context = _context(tmp_path)

        result = fixture.run(fixture.make_adapter(), context)

        assert result.nodes == ()
        assert len(result.diagnostics) >= 1

    @pytest.mark.parametrize(
        "fixture", _OLDER_VERSION_DRIFT_EXEMPT_FIXTURES, ids=lambda f: f.adapter_name
    )
    def test_older_version_drift_exemption_is_explicitly_disclosed(
        self, fixture: ConformanceFixture
    ) -> None:
        assert fixture.older_version_drift_unsupported_reason
        assert len(fixture.older_version_drift_unsupported_reason) > 10


class TestBoundarySize:
    """Boundary size, for every registered adapter -- many entries in one
    otherwise-valid document complete without a crash, a hang, or a
    silently truncated result."""

    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.adapter_name)
    def test_many_entries_are_all_discovered(
        self, fixture: ConformanceFixture, tmp_path: Path
    ) -> None:
        fixture.write_boundary(tmp_path)
        context = _context(tmp_path)

        result = fixture.run(fixture.make_adapter(), context)

        fixture.assert_boundary(result)
        _assert_evidence_contract(result, fixture.adapter_name, tmp_path)


class TestDeterminism:
    """Determinism, for every registered adapter."""

    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.adapter_name)
    def test_identical_input_produces_an_identical_result(
        self, fixture: ConformanceFixture, tmp_path: Path
    ) -> None:
        fixture.write_positive(tmp_path)
        context = _context(tmp_path)

        first = fixture.run(fixture.make_adapter(), context)
        second = fixture.run(fixture.make_adapter(), context)

        assert first == second


_PRIVACY_FIXTURES = tuple(
    fixture for fixture in ALL_FIXTURES if fixture.write_privacy is not None
)


class TestPrivacy:
    """A credential-shaped value, an environment value, a header value, or
    a prompt body planted in an agent-authority configuration file never
    appears in what the adapter records -- nodes, edges, or diagnostics."""

    @pytest.mark.parametrize("fixture", _PRIVACY_FIXTURES, ids=lambda f: f.adapter_name)
    def test_planted_values_never_reach_the_result(
        self, fixture: ConformanceFixture, tmp_path: Path
    ) -> None:
        assert fixture.write_privacy is not None
        planted = fixture.write_privacy(tmp_path)

        result = fixture.run(fixture.make_adapter(), _context(tmp_path))

        assert result.nodes, "the privacy fixture must still be discovered"
        recorded = "\n".join(
            item.model_dump_json()
            for item in (*result.nodes, *result.edges, *result.diagnostics)
        )
        for value in planted:
            assert value not in recorded

    def test_every_agent_authority_adapter_has_a_privacy_case(self) -> None:
        with_privacy = {fixture.adapter_name for fixture in _PRIVACY_FIXTURES}

        assert with_privacy >= PRIVACY_REQUIRED_ADAPTERS


class TestFixtureRegistryCoversEveryAdapter:
    """A newly registered adapter with no conformance fixtures fails CI,
    checked in both directions so an orphaned fixture with no matching
    adapter is caught too."""

    def test_every_registered_adapter_has_a_conformance_fixture(self) -> None:
        registered = {adapter_cls().name for adapter_cls in ALL_ADAPTERS}
        fixtured = {fixture.adapter_name for fixture in ALL_FIXTURES}

        assert registered == fixtured
