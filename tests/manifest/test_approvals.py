"""Tests for controlloop.manifest.approvals.

This module is deliberately kept outside the deterministic rule engine
(see its own docstring) so both functions here take an explicit `as_of`
rather than reading the clock -- these tests exercise that explicit
parameter directly, never `datetime.now()`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from controlloop.manifest.approvals import active_approvals, is_approval_active
from controlloop.manifest.models import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    Approval,
    ManifestDocument,
)

_AS_OF = datetime(2026, 8, 20, tzinfo=UTC)


class TestIsApprovalActive:
    def test_no_expiry_is_always_active(self) -> None:
        approval = Approval(capability="refund-tool", approver="alice")

        assert is_approval_active(approval, as_of=_AS_OF) is True

    def test_future_expiry_is_active(self) -> None:
        approval = Approval(
            capability="refund-tool",
            approver="alice",
            expires_at="2026-12-31T00:00:00Z",
        )

        assert is_approval_active(approval, as_of=_AS_OF) is True

    def test_past_expiry_is_not_active(self) -> None:
        approval = Approval(
            capability="refund-tool",
            approver="alice",
            expires_at="2026-01-01T00:00:00Z",
        )

        assert is_approval_active(approval, as_of=_AS_OF) is False

    def test_exactly_at_expiry_boundary_is_not_active(self) -> None:
        """`as_of < expires_at` strictly -- the boundary instant itself
        is treated as expired, the conservative choice."""

        approval = Approval(
            capability="refund-tool",
            approver="alice",
            expires_at=_AS_OF.isoformat(),
        )

        assert is_approval_active(approval, as_of=_AS_OF) is False

    def test_unparseable_expiry_fails_closed(self) -> None:
        approval = Approval(
            capability="refund-tool", approver="alice", expires_at="not-a-timestamp"
        )

        assert is_approval_active(approval, as_of=_AS_OF) is False

    def test_naive_expiry_fails_closed(self) -> None:
        """An `expires_at` with no timezone is not safely comparable and
        is treated as unparseable, not silently assumed UTC."""

        approval = Approval(
            capability="refund-tool", approver="alice", expires_at="2026-12-31T00:00:00"
        )

        assert is_approval_active(approval, as_of=_AS_OF) is False

    def test_naive_as_of_raises(self) -> None:
        approval = Approval(capability="refund-tool", approver="alice")

        with pytest.raises(ValueError, match="timezone-aware"):
            is_approval_active(approval, as_of=datetime(2026, 8, 20))


class TestActiveApprovals:
    def test_filters_out_expired_approvals_only(self) -> None:
        active = Approval(capability="refund-tool", approver="alice")
        expired = Approval(
            capability="billing-tool",
            approver="bob",
            expires_at="2026-01-01T00:00:00Z",
        )
        manifest = ManifestDocument(
            schema_version=CURRENT_MANIFEST_SCHEMA_VERSION,
            owner="platform-team",
            approvals=(active, expired),
        )

        result = active_approvals(manifest, as_of=_AS_OF)

        assert result == (active,)

    def test_empty_approvals_returns_empty(self) -> None:
        manifest = ManifestDocument(
            schema_version=CURRENT_MANIFEST_SCHEMA_VERSION, owner="platform-team"
        )

        assert active_approvals(manifest, as_of=_AS_OF) == ()

    def test_deterministic_for_a_fixed_as_of(self) -> None:
        manifest = ManifestDocument(
            schema_version=CURRENT_MANIFEST_SCHEMA_VERSION,
            owner="platform-team",
            approvals=(
                Approval(capability="refund-tool", approver="alice"),
                Approval(
                    capability="billing-tool",
                    approver="bob",
                    expires_at="2026-12-31T00:00:00Z",
                ),
            ),
        )

        assert active_approvals(manifest, as_of=_AS_OF) == active_approvals(
            manifest, as_of=_AS_OF
        )
