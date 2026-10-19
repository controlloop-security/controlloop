"""Hostile input fuzzing for `controlloop.manifest.parser.load_manifest`.

Seeds from a real, valid manifest that includes a `capability_ceiling`
block, so ceiling fields are mutated too -- `CapabilityCeiling` is a
field *within* the manifest schema
(`controlloop.manifest.models.ManifestDocument`), not a separate raw
parser, so there is nothing else to fuzz for "ceiling parsing"
specifically.

`load_manifest`'s own documented contract is: raise
`ManifestValidationError` for anything malformed, never anything else.
Any other exception, or a hang, is a real finding.
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

from controlloop.manifest import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    ManifestValidationError,
)
from controlloop.manifest.parser import load_manifest

_MASTER_SEED = 0x4155_5A31_3235  # "FUZZ125" ascii-ish, arbitrary fixed constant

_SEED_MANIFEST = f"""\
schema_version: "{CURRENT_MANIFEST_SCHEMA_VERSION}"
owner: security-team
ceilings:
  - agent: refund-agent
    prohibited_resources:
      - "tool:delete-database"
    prohibited_actions:
      - invokes
    prohibited_external_destinations:
      - "external:pastebin.com"
    prohibited_data_classes:
      - restricted
    prohibited_delegation_targets:
      - "agent:untrusted-agent"
""".encode()

_CORPUS_DIR = Path(__file__).parent / "fuzz_corpus" / "manifest"


def _target(raw_bytes: bytes) -> None:
    load_manifest(raw_bytes.decode("utf-8", errors="replace"), path="controlloop.yaml")


class TestSeededSweep:
    @pytest.mark.parametrize("seed", list(iter_seeds(_MASTER_SEED)))
    def test_never_raises_outside_manifest_validation_error(self, seed: int) -> None:
        mutated = mutate_bytes(_SEED_MANIFEST, random.Random(seed))

        result = run_bounded(
            _target, mutated, seed=seed, expected_exceptions=(ManifestValidationError,)
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
    """Every previously-confirmed crashing input replayed
    unconditionally, independent of the seeded sweep above."""

    @pytest.mark.parametrize("corpus_input", load_corpus(_CORPUS_DIR), ids=repr)
    def test_corpus_input_never_raises_outside_manifest_validation_error(
        self, corpus_input: bytes
    ) -> None:
        result = run_bounded(
            _target,
            corpus_input,
            seed=-1,
            expected_exceptions=(ManifestValidationError,),
        )

        assert result.outcome in (FuzzOutcome.COMPLETED, FuzzOutcome.EXPECTED_EXCEPTION)


def test_iteration_count_matches_story_budget() -> None:
    assert len(list(iter_seeds(_MASTER_SEED))) == FUZZ_ITERATIONS
