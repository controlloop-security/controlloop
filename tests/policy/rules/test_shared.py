"""Tests for controlloop.policy.rules._shared -- the small helpers
shared by the concrete policy rules."""

from __future__ import annotations

from controlloop.diff.models import (
    CURRENT_DIFF_SCHEMA_VERSION,
    ChangeKind,
    DiffResult,
    NodeChange,
)
from controlloop.findings.models import FindingChangeState
from controlloop.policy.rules._shared import documentation_url, node_change_state

_NODE_ID = f"clp:tool:sha256:{'a' * 64}"
_OTHER_NODE_ID = f"clp:tool:sha256:{'b' * 64}"


def test_documentation_url_builds_a_stable_anchor_link() -> None:
    assert documentation_url("missing-action-logging") == (
        "https://docs.controlloop.ai/reference/policy-rules#missing-action-logging"
    )


class TestNodeChangeState:
    def test_no_diff_is_not_compared(self) -> None:
        assert node_change_state(None, _NODE_ID) is FindingChangeState.NOT_COMPARED

    def test_matching_node_change_maps_kind_through(self) -> None:
        diff = DiffResult(
            schema_version=CURRENT_DIFF_SCHEMA_VERSION,
            node_changes=(NodeChange(kind=ChangeKind.CHANGED, node_id=_NODE_ID),),
            edge_changes=(),
            effective_authority_changes=(),
        )
        assert node_change_state(diff, _NODE_ID) is FindingChangeState.CHANGED

    def test_diff_present_but_node_absent_falls_back_to_not_compared(self) -> None:
        """Disclosed gap: `DiffResult` never represents an unchanged
        identity, and `FindingChangeState` has no "unchanged" member --
        see this module's own docstring."""
        diff = DiffResult(
            schema_version=CURRENT_DIFF_SCHEMA_VERSION,
            node_changes=(NodeChange(kind=ChangeKind.ADDED, node_id=_OTHER_NODE_ID),),
            edge_changes=(),
            effective_authority_changes=(),
        )
        assert node_change_state(diff, _NODE_ID) is FindingChangeState.NOT_COMPARED
