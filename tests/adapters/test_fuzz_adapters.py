"""Hostile input fuzzing for every discovery adapter's `discover()`.

Seeds from each fixture's own `write_positive` writer
(`conformance_fixtures.ALL_FIXTURES`, already imported elsewhere in
this test suite, not duplicated) -- every fixture's positive writer
creates exactly one file, located by snapshotting the target directory
before and after the writer runs, so this suite needs no per-adapter
hardcoded path.

Every adapter's own documented contract
(`test_adapter_conformance.py::TestMalformed`) is: never raise on
malformed content, produce a diagnostic instead. That contract is
proven here for hundreds of adversarial *mutations* of each adapter's
own realistic positive fixture, not just the one hand-picked malformed
example the conformance suite already covers.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest
from conformance_fixtures import ALL_FIXTURES, ConformanceFixture
from fuzz_support import (
    FUZZ_ITERATIONS,
    FuzzOutcome,
    iter_seeds,
    load_corpus,
    mutate_bytes,
    run_bounded,
)

from controlloop.adapters import DiscoveryResult, ScanContext
from controlloop.repository import resolve_repository_root

_CORPUS_ROOT = Path(__file__).parent / "fuzz_corpus" / "adapters"


def _seed_file_for(fixture: ConformanceFixture, tmp_path: Path) -> Path:
    """The file this sweep should mutate.

    By default: the single file `fixture.write_positive` creates, found
    by snapshotting `tmp_path` before and after. Most adapters read one
    document, so an ambiguous or empty diff is a signal that assumption
    has changed and should fail loudly rather than silently fuzzing an
    arbitrary file.

    A fixture whose adapter genuinely needs a supporting document names
    its target with `fuzz_seed_relative_path` instead -- CrewAI reads the
    framework version from `pyproject.toml` before it will parse
    `config/agents.yaml` at all, so its positive writer must create both.
    The assertion below is unchanged for every fixture that does not set
    it: this widens what can be expressed, not what is accepted.
    """

    before = set(tmp_path.rglob("*"))
    fixture.write_positive(tmp_path)

    if fixture.fuzz_seed_relative_path is not None:
        target = tmp_path / fixture.fuzz_seed_relative_path
        assert target.is_file(), (
            f"{fixture.adapter_name}: declared fuzz seed "
            f"{fixture.fuzz_seed_relative_path!r} was not created by "
            "write_positive"
        )
        return target

    after = set(tmp_path.rglob("*"))
    created = [path for path in (after - before) if path.is_file()]
    assert len(created) == 1, (
        f"{fixture.adapter_name}: expected write_positive to create exactly "
        f"one file, found {created!r}"
    )
    return created[0]


def _run_discover(fixture: ConformanceFixture, tmp_path: Path) -> DiscoveryResult:
    context = ScanContext(root=resolve_repository_root(tmp_path))
    return fixture.run(fixture.make_adapter(), context)


class TestSeededSweep:
    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.adapter_name)
    @pytest.mark.parametrize("seed", list(iter_seeds(0x4155_5A31_3235_0003)))
    def test_never_raises_on_a_mutated_positive_fixture(
        self, fixture: ConformanceFixture, seed: int, tmp_path: Path
    ) -> None:
        seed_file = _seed_file_for(fixture, tmp_path)
        original = seed_file.read_bytes()
        mutated = mutate_bytes(original, random.Random(seed))
        seed_file.write_bytes(mutated)

        def _target(_: bytes) -> None:
            _run_discover(fixture, tmp_path)

        result = run_bounded(_target, mutated, seed=seed, expected_exceptions=())

        assert result.outcome == FuzzOutcome.COMPLETED, (
            f"{fixture.adapter_name} seed={seed} outcome={result.outcome} "
            f"exception={result.exception_type}: {result.exception_message} "
            f"input={result.input_bytes!r}"
        )


class TestStandingCorpus:
    """Every previously-confirmed crashing input replayed
    unconditionally, independent of the seeded sweep above."""

    @pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda f: f.adapter_name)
    def test_corpus_inputs_never_raise(
        self, fixture: ConformanceFixture, tmp_path: Path
    ) -> None:
        corpus_inputs = load_corpus(_CORPUS_ROOT / fixture.adapter_name)
        if not corpus_inputs:
            pytest.skip(f"no standing corpus for {fixture.adapter_name}")

        seed_file = _seed_file_for(fixture, tmp_path)
        for corpus_input in corpus_inputs:
            seed_file.write_bytes(corpus_input)

            def _target(_: bytes) -> None:
                _run_discover(fixture, tmp_path)

            result = run_bounded(_target, corpus_input, seed=-1, expected_exceptions=())

            assert result.outcome == FuzzOutcome.COMPLETED


def test_iteration_count_matches_story_budget() -> None:
    assert len(list(iter_seeds(0x4155_5A31_3235_0003))) == FUZZ_ITERATIONS
