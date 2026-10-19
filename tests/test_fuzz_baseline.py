"""Hostile input fuzzing for
`controlloop.baseline.integrity.load_baseline_document`.

Seeds from a real, digest-correct `BaselineDocument`, built and
serialized with the same `with_baseline_digest`/`serialize_baseline`
helpers `tests/baseline/test_baseline_serialization.py` already uses,
so the fuzzer starts from a genuinely valid document rather than a
hand-typed approximation.

`load_baseline_document`'s own documented contract is: raise
`BaselineIntegrityError` for anything malformed, truncated, tampered,
or version-incompatible -- never anything else. Any other exception, or
a hang, is a real finding.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest
from fuzz_support import (
    FUZZ_ITERATIONS,
    FuzzOutcome,
    iter_seeds,
    load_corpus,
    mutate_bytes,
    run_bounded,
)

from controlloop.acbom import Confidence, EdgeType, Evidence, Generator, Repository
from controlloop.baseline.integrity import (
    BaselineIntegrityError,
    load_baseline_document,
)
from controlloop.baseline.models import BaselineDocument
from controlloop.baseline.serialization import serialize_baseline, with_baseline_digest
from controlloop.capability.models import EffectiveAuthorityEntry

_MASTER_SEED = 0x4155_5A31_3235_0002

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ID = f"clp:tool:sha256:{'b' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'d' * 64}"
_ACBOM_DIGEST = f"sha256:{'e' * 64}"
_PLACEHOLDER_DIGEST = f"sha256:{'0' * 64}"


def _build_seed_baseline() -> bytes:
    document = BaselineDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'f' * 64}"),
        acbom_schema_version="1.0.0",
        acbom_digest=_ACBOM_DIGEST,
        effective_authority=(
            EffectiveAuthorityEntry(
                schema_version="1.0.0",
                agent_id=_AGENT_ID,
                action=EdgeType.INVOKES,
                resource_id=_RESOURCE_ID,
                permitting_identity_id=_IDENTITY_ID,
                confidence=Confidence.HIGH,
                evidence=(Evidence(adapter="mcp", path="a.json"),),
            ),
        ),
        digest=_PLACEHOLDER_DIGEST,
    )
    return serialize_baseline(with_baseline_digest(document))


_SEED_BASELINE = _build_seed_baseline()
_CORPUS_DIR = Path(__file__).parent / "fuzz_corpus" / "baseline"


def _target(raw_bytes: bytes) -> None:
    load_baseline_document(raw_bytes)


class TestSeedIsRealAndValid:
    def test_seed_baseline_loads_without_error(self) -> None:
        document = load_baseline_document(_SEED_BASELINE)

        assert document.acbom_digest == _ACBOM_DIGEST


class TestSeededSweep:
    @pytest.mark.parametrize("seed", list(iter_seeds(_MASTER_SEED)))
    def test_never_raises_outside_baseline_integrity_error(self, seed: int) -> None:
        mutated = mutate_bytes(_SEED_BASELINE, random.Random(seed))

        result = run_bounded(
            _target,
            mutated,
            seed=seed,
            expected_exceptions=(BaselineIntegrityError,),
        )

        assert result.outcome in (
            FuzzOutcome.COMPLETED,
            FuzzOutcome.EXPECTED_EXCEPTION,
        ), (
            f"seed={seed} outcome={result.outcome} "
            f"exception={result.exception_type}: {result.exception_message} "
            f"input={result.input_bytes!r}"
        )


class TestStandingCorpus:
    """Every previously-confirmed crashing input replayed unconditionally,
    independent of the seeded sweep above."""

    @pytest.mark.parametrize("corpus_input", load_corpus(_CORPUS_DIR), ids=repr)
    def test_corpus_input_never_raises_outside_baseline_integrity_error(
        self, corpus_input: bytes
    ) -> None:
        result = run_bounded(
            _target,
            corpus_input,
            seed=-1,
            expected_exceptions=(BaselineIntegrityError,),
        )

        assert result.outcome in (FuzzOutcome.COMPLETED, FuzzOutcome.EXPECTED_EXCEPTION)


def test_iteration_count_matches_story_budget() -> None:
    assert len(list(iter_seeds(_MASTER_SEED))) == FUZZ_ITERATIONS
