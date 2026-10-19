"""Tests for the determinism harness.

`determinism_support.py` is the reusable helper module under test here;
see its module docstring for the design rationale. This file supplies the
actual acceptance evidence.

Offline: `digest_in_subprocess` spawns a local child process via
`subprocess.run`, never a network call, so it is unaffected by (and does
not need to participate in) the autouse offline-denial fixture in
`conftest.py`, which monkeypatches `socket` only in the current pytest
process. `TestOffline` below is a positive control asserting a subprocess
call still succeeds while that fixture is active (it already is, for
every test in this module, since it is autouse).

Privacy: this harness handles only the existing synthetic, non-sensitive
fixture (`tests/fixtures/acbom/minimal-input.json`, already committed,
containing no real repository, credential, or customer content) and
introduces no new output, log, or artifact path. The redaction canary
(`tests/test_redaction.py`) does not apply to new surface here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import get_args

import pytest
from determinism_support import (
    DIGEST_EXCLUDED_FIELDS,
    TIMESTAMP_LIKE_FIELD_MARKERS,
    assert_stable_digest,
    build_document_from_repository_walk,
    build_golden_document,
    digest_in_subprocess,
)
from pydantic import BaseModel

from controlloop.acbom import ACBOMDocument, compute_digest, serialize_document

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def _touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("fixture content\n")


class TestGoldenDigestStableInOneProcess:
    """Repeated runs in one process."""

    def test_five_repeated_builds_produce_identical_digest(self) -> None:
        digest = assert_stable_digest(build_golden_document, runs=5)

        assert _DIGEST_PATTERN.match(digest)
        assert digest == compute_digest(build_golden_document())


class TestGoldenDigestStableAcrossProcesses:
    """Stability across separate processes."""

    def test_two_independent_subprocesses_agree_with_each_other_and_in_process(
        self,
    ) -> None:
        baseline = compute_digest(build_golden_document())

        first = digest_in_subprocess()
        second = digest_in_subprocess()

        assert first == baseline
        assert second == baseline


class TestStableAcrossPythonHashSeed:
    """Stability across a differing `PYTHONHASHSEED`.

    A hash seed can only vary at interpreter start, so this is
    necessarily subprocess-based.
    """

    def test_two_different_hash_seeds_produce_the_same_digest(self) -> None:
        baseline = compute_digest(build_golden_document())

        zero_seed = digest_in_subprocess(env={"PYTHONHASHSEED": "0"})
        other_seed = digest_in_subprocess(env={"PYTHONHASHSEED": "12345"})

        assert zero_seed == baseline
        assert other_seed == baseline


class TestStableAcrossLocale:
    """Stability across a differing locale.

    A grep of `src/controlloop/acbom/` confirms no `locale.*` call
    exists anywhere in the canonicalization path, so this test varies
    only the environment variables a locale-sensitive library would
    consult (`LC_ALL`, `LANG`) rather than calling `locale.setlocale`
    itself, which could spuriously fail on a system missing a particular
    locale definition unrelated to this test's actual claim.
    """

    def test_two_different_locale_environments_produce_the_same_digest(self) -> None:
        baseline = compute_digest(build_golden_document())

        c_locale = digest_in_subprocess(env={"LC_ALL": "C", "LANG": "C"})
        us_locale = digest_in_subprocess(
            env={"LC_ALL": "en_US.UTF-8", "LANG": "en_US.UTF-8"}
        )

        assert c_locale == baseline
        assert us_locale == baseline


class TestStableAcrossTimezone:
    """Stability across a differing timezone.

    No `datetime`/`time.*` usage exists in the canonicalization path, so
    (for the same reason as the locale test above) this varies only the
    `TZ` environment variable rather than calling `time.tzset` itself.
    """

    def test_two_different_timezones_produce_the_same_digest(self) -> None:
        baseline = compute_digest(build_golden_document())

        utc = digest_in_subprocess(env={"TZ": "UTC"})
        tokyo = digest_in_subprocess(env={"TZ": "Asia/Tokyo"})

        assert utc == baseline
        assert tokyo == baseline


class TestStableAcrossFilesystemIterationOrder:
    """Stability across differing filesystem iteration order.

    Mirrors `test_repository.py::TestWalkRepository::
    test_deterministic_regardless_of_creation_order`'s pattern -- the same
    file set created in a different order in two separate directories --
    but carries the result one layer further, through real node
    construction and canonicalization to the final ACBOM digest, which
    that walker-level test does not reach.
    """

    def test_files_created_in_different_order_produce_the_same_digest(
        self, tmp_path: Path
    ) -> None:
        first, second = tmp_path / "first", tmp_path / "second"
        for name in ("zeta.txt", "alpha.txt", "mid/file.txt"):
            _touch(first / name)
        for name in ("alpha.txt", "mid/file.txt", "zeta.txt"):
            _touch(second / name)

        first_document = build_document_from_repository_walk(first)
        second_document = build_document_from_repository_walk(second)

        assert compute_digest(first_document) == compute_digest(second_document)
        assert serialize_document(first_document) == serialize_document(second_document)
        assert len(first_document.nodes) == 3


class TestExclusionListIsExplicitAndTested:
    """The exclusion list (`DIGEST_EXCLUDED_FIELDS`) is explicit and tested
    against real `compute_digest`/`serialize_document` behavior, in both
    directions: the listed field really is excluded from the digest, and
    every other field really is not."""

    def test_digest_field_is_excluded_from_the_digest_but_not_from_serialization(
        self,
    ) -> None:
        assert frozenset({"digest"}) == DIGEST_EXCLUDED_FIELDS

        document = build_golden_document()
        placeholder_a = document.model_copy(update={"digest": f"sha256:{'a' * 64}"})
        placeholder_b = document.model_copy(update={"digest": f"sha256:{'b' * 64}"})

        assert compute_digest(placeholder_a) == compute_digest(placeholder_b)
        assert serialize_document(placeholder_a) != serialize_document(placeholder_b)

    def test_every_other_field_change_does_change_the_digest(self) -> None:
        document = build_golden_document()
        baseline = compute_digest(document)

        mutations: dict[str, ACBOMDocument] = {
            "schema_version": document.model_copy(update={"schema_version": "1.0.1"}),
            "generator.version": document.model_copy(
                update={
                    "generator": document.generator.model_copy(
                        update={"version": "0.2.0"}
                    )
                }
            ),
            "repository.commit": document.model_copy(
                update={
                    "repository": document.repository.model_copy(
                        update={"commit": "a-different-commit"}
                    )
                }
            ),
            "node.name": document.model_copy(
                update={
                    "nodes": (
                        document.nodes[0].model_copy(
                            update={"name": "A different display name"}
                        ),
                        *document.nodes[1:],
                    )
                }
            ),
        }

        for label, mutated in mutations.items():
            assert compute_digest(mutated) != baseline, (
                f"changing {label!r} did not change the digest -- it may be "
                "silently (and undocumented-ly) excluded"
            )


def _extract_nested_models(annotation: object) -> list[type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    found: list[type[BaseModel]] = []
    for arg in get_args(annotation):
        found.extend(_extract_nested_models(arg))
    return found


def _collect_timestamp_like_fields(
    model: type[BaseModel], seen: set[type[BaseModel]]
) -> set[str]:
    if model in seen:
        return set()
    seen.add(model)

    found: set[str] = set()
    for field_name, field_info in model.model_fields.items():
        normalized = re.sub(r"[^a-z0-9]", "", field_name.casefold())
        if any(marker in normalized for marker in TIMESTAMP_LIKE_FIELD_MARKERS):
            found.add(f"{model.__name__}.{field_name}")
        for nested_model in _extract_nested_models(field_info.annotation):
            found |= _collect_timestamp_like_fields(nested_model, seen)
    return found


class TestNoUndocumentedTimestampLikeField:
    """Structural guard against future silent drift.

    An empty result is correct and expected *today* -- the canonical
    schema currently carries no timestamp field at all. This test exists
    so that if a future field named e.g. `created_at` or `scanned_at` is
    ever added to any canonical model, this test fails immediately,
    forcing `DIGEST_EXCLUDED_FIELDS` (and the corresponding production
    exclusion or injection logic in `serialization.py`) to be updated
    deliberately rather than silently regressing determinism.
    """

    def test_no_timestamp_like_field_exists_in_the_canonical_schema(self) -> None:
        found = _collect_timestamp_like_fields(ACBOMDocument, set())

        assert found == set(), (
            f"found timestamp-like field(s) {sorted(found)} not covered by "
            "DIGEST_EXCLUDED_FIELDS or an injection strategy -- update "
            "DIGEST_EXCLUDED_FIELDS and the production canonicalization "
            "logic deliberately before allowing this test to pass"
        )


class TestHarnessDetectsInjectedNonDeterminism:
    """A deliberate non-determinism injected into a fixture causes the
    harness to fail, proving it detects what it claims to."""

    def test_alternating_builder_is_detected_and_raises(self) -> None:
        calls = {"count": 0}

        def flaky_build() -> ACBOMDocument:
            calls["count"] += 1
            document = build_golden_document()
            mutated_name = f"Refund agent (non-deterministic call {calls['count']})"
            return document.model_copy(
                update={
                    "nodes": (
                        document.nodes[0].model_copy(update={"name": mutated_name}),
                        *document.nodes[1:],
                    )
                }
            )

        with pytest.raises(AssertionError, match="non-determinism"):
            assert_stable_digest(flaky_build, runs=3)

        assert calls["count"] >= 2


class TestHarnessApiBoundaries:
    """Boundary/malformed cases for the harness's own API (not fixture
    data): `assert_stable_digest` requires at least two runs to have
    anything to compare."""

    @pytest.mark.parametrize("runs", [0, 1])
    def test_fewer_than_two_runs_is_rejected(self, runs: int) -> None:
        with pytest.raises(ValueError, match="at least 2 runs"):
            assert_stable_digest(build_golden_document, runs=runs)


class TestOffline:
    """Positive control: `digest_in_subprocess` (used throughout the
    stability tests above) still succeeds while this suite's autouse
    offline-denial fixture is active, because it spawns a local child
    process rather than making a network call."""

    def test_subprocess_digest_computation_succeeds_under_offline_harness(
        self,
    ) -> None:
        digest = digest_in_subprocess()

        assert _DIGEST_PATTERN.match(digest)
