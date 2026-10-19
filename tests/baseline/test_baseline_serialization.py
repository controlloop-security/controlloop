"""Focused unit tests for canonical baseline serialization and
digesting.

Mirrors `tests/acbom/test_serialization_unit.py`'s permutation-based
determinism style, applied to `BaselineDocument`.
"""

from __future__ import annotations

import pytest

from controlloop.acbom import Confidence, EdgeType, Evidence, Generator, Repository
from controlloop.baseline.models import BaselineDocument
from controlloop.baseline.serialization import (
    canonicalize_baseline,
    compute_baseline_digest,
    serialize_baseline,
    with_baseline_digest,
)
from controlloop.capability.models import EffectiveAuthorityEntry

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ONE_ID = f"clp:tool:sha256:{'b' * 64}"
_RESOURCE_TWO_ID = f"clp:resource:sha256:{'c' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'d' * 64}"
_PLACEHOLDER_DIGEST = f"sha256:{'0' * 64}"
_ACBOM_DIGEST = f"sha256:{'e' * 64}"


def _document(*, reverse: bool) -> BaselineDocument:
    first_entry = EffectiveAuthorityEntry(
        schema_version="1.0.0",
        agent_id=_AGENT_ID,
        action=EdgeType.INVOKES,
        resource_id=_RESOURCE_ONE_ID,
        permitting_identity_id=_IDENTITY_ID,
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )
    second_entry = EffectiveAuthorityEntry(
        schema_version="1.0.0",
        agent_id=_AGENT_ID,
        action=EdgeType.READS,
        resource_id=_RESOURCE_TWO_ID,
        confidence=Confidence.MEDIUM,
        evidence=(Evidence(adapter="a2a", path="b.json"),),
    )
    entries = (second_entry, first_entry) if reverse else (first_entry, second_entry)

    return BaselineDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'f' * 64}"),
        acbom_schema_version="1.0.0",
        acbom_digest=_ACBOM_DIGEST,
        effective_authority=entries,
        digest=_PLACEHOLDER_DIGEST,
    )


class TestCanonicalizeBaseline:
    def test_sorts_effective_authority_regardless_of_construction_order(self) -> None:
        forward = canonicalize_baseline(_document(reverse=False))
        reverse = canonicalize_baseline(_document(reverse=True))

        assert forward.effective_authority == reverse.effective_authority
        assert forward.effective_authority[0].resource_id == _RESOURCE_ONE_ID
        assert forward.effective_authority[1].resource_id == _RESOURCE_TWO_ID

    def test_unsupported_category_raises(self) -> None:
        from controlloop.acbom.serialization import CanonicalizationError

        with pytest.raises(CanonicalizationError):
            canonicalize_baseline(object())  # type: ignore[arg-type]


class TestComputeBaselineDigest:
    def test_digest_excludes_itself(self) -> None:
        forward = _document(reverse=False)
        changed_digest_only = forward.model_copy(
            update={"digest": f"sha256:{'9' * 64}"}
        )

        assert compute_baseline_digest(forward) == compute_baseline_digest(
            changed_digest_only
        )

    def test_permuted_construction_order_produces_identical_digest(self) -> None:
        forward_digest = compute_baseline_digest(_document(reverse=False))
        reverse_digest = compute_baseline_digest(_document(reverse=True))

        assert forward_digest == reverse_digest

    def test_changing_acbom_digest_changes_the_baseline_digest(self) -> None:
        base = _document(reverse=False)
        changed = base.model_copy(update={"acbom_digest": f"sha256:{'1' * 64}"})

        assert compute_baseline_digest(base) != compute_baseline_digest(changed)


class TestWithBaselineDigest:
    def test_round_trips_through_model_validate_json(self) -> None:
        document = with_baseline_digest(_document(reverse=False))
        serialized = serialize_baseline(document)

        round_tripped = BaselineDocument.model_validate_json(serialized)

        assert round_tripped.digest == document.digest
        assert round_tripped == document

    def test_digest_is_deterministic_across_repeated_calls(self) -> None:
        first = with_baseline_digest(_document(reverse=False))
        second = with_baseline_digest(_document(reverse=False))

        assert first.digest == second.digest

    def test_digest_changes_when_an_entry_is_added(self) -> None:
        base = with_baseline_digest(_document(reverse=False))
        extra_entry = EffectiveAuthorityEntry(
            schema_version="1.0.0",
            agent_id=_AGENT_ID,
            action=EdgeType.WRITES,
            resource_id=f"clp:resource:sha256:{'2' * 64}",
            confidence=Confidence.LOW,
            evidence=(Evidence(adapter="openapi", path="c.json"),),
        )
        expanded = base.model_copy(
            update={"effective_authority": (*base.effective_authority, extra_entry)}
        )
        expanded_with_digest = with_baseline_digest(expanded)

        assert expanded_with_digest.digest != base.digest
