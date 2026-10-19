"""Tests for entitlement decisions.

`decide` is a pure function, so both fail modes and every state are
covered without a network, a clock, or a fake service. Coverage of both
modes against a fake endpoint lives one layer up, in `test_client.py`,
which drives the real retry window through `FakeTransport`; this file
covers what the CLI concludes from the outcome.
"""

from __future__ import annotations

import pytest

from controlloop.exit_codes import ExitCode
from controlloop.team.config import TeamFailMode
from controlloop.team.entitlement import EntitlementState, decide, parse_state


class TestProceedingStates:
    def test_entitled_proceeds(self) -> None:
        decision = decide(
            state=EntitlementState.ENTITLED, fail_mode=TeamFailMode.CLOSED
        )

        assert decision.proceed is True
        assert decision.exit_code is None

    def test_grace_proceeds_and_says_why(self) -> None:
        """A past-due subscription inside its grace window proceeds:
        dunning is a billing conversation, and turning a customer's CI red
        is not how it should start."""

        decision = decide(state=EntitlementState.GRACE, fail_mode=TeamFailMode.CLOSED)

        assert decision.proceed is True
        assert decision.exit_code is None
        assert "grace" in decision.message.lower()

    @pytest.mark.parametrize("fail_mode", list(TeamFailMode))
    def test_entitled_proceeds_under_either_fail_mode(
        self, fail_mode: TeamFailMode
    ) -> None:
        """The fail mode governs unreachability, not a real answer."""

        assert decide(state=EntitlementState.ENTITLED, fail_mode=fail_mode).proceed


class TestNotEntitled:
    """Exit code 4, a clear explanation, and no partial paid behavior."""

    @pytest.mark.parametrize("fail_mode", list(TeamFailMode))
    def test_not_entitled_stops_under_either_fail_mode(
        self, fail_mode: TeamFailMode
    ) -> None:
        """`team_fail_mode` governs an *unreachable* service. A service
        that answered "not entitled" is not unreachable, and fail-open
        must not turn a definite no into a yes."""

        decision = decide(state=EntitlementState.NOT_ENTITLED, fail_mode=fail_mode)

        assert decision.proceed is False
        assert decision.exit_code is ExitCode.ENTITLEMENT

    def test_the_message_names_the_remedy(self) -> None:
        decision = decide(
            state=EntitlementState.NOT_ENTITLED, fail_mode=TeamFailMode.CLOSED
        )

        assert "subscription" in decision.message
        assert "team_enabled = false" in decision.message

    def test_the_exit_code_is_four(self) -> None:
        """Named explicitly because the documented contract is the number,
        not the enum member."""

        decision = decide(
            state=EntitlementState.NOT_ENTITLED, fail_mode=TeamFailMode.CLOSED
        )

        assert decision.exit_code is not None
        assert int(decision.exit_code) == 4


class TestUnreachableService:
    """The configured fail mode, defaulting to closed."""

    @pytest.mark.parametrize(
        "state", [EntitlementState.UNREACHABLE, EntitlementState.UNREADABLE]
    )
    def test_fail_closed_stops(self, state: EntitlementState) -> None:
        decision = decide(state=state, fail_mode=TeamFailMode.CLOSED)

        assert decision.proceed is False
        assert decision.exit_code is ExitCode.ENTITLEMENT

    @pytest.mark.parametrize(
        "state", [EntitlementState.UNREACHABLE, EntitlementState.UNREADABLE]
    )
    def test_fail_open_proceeds(self, state: EntitlementState) -> None:
        decision = decide(state=state, fail_mode=TeamFailMode.OPEN)

        assert decision.proceed is True
        assert decision.exit_code is None

    def test_fail_closed_names_the_escape_hatch(self) -> None:
        """A gate that stops must say how to make it not stop, or the next
        step is a search through documentation during an outage."""

        decision = decide(
            state=EntitlementState.UNREACHABLE, fail_mode=TeamFailMode.CLOSED
        )

        assert 'team_fail_mode = "open"' in decision.message

    def test_fail_open_says_the_entitlement_was_not_verified(self) -> None:
        """Proceeding silently would leave a build looking identically
        green whether or not the control ran."""

        decision = decide(
            state=EntitlementState.UNREACHABLE, fail_mode=TeamFailMode.OPEN
        )

        assert "without a verified entitlement" in decision.message

    def test_the_two_causes_are_described_differently(self) -> None:
        """A network the gate could not traverse and a response that did
        not match the contract need different investigation."""

        unreachable = decide(
            state=EntitlementState.UNREACHABLE, fail_mode=TeamFailMode.CLOSED
        )
        unreadable = decide(
            state=EntitlementState.UNREADABLE, fail_mode=TeamFailMode.CLOSED
        )

        assert unreachable.message != unreadable.message
        assert "reached" in unreachable.message
        assert "contract" in unreadable.message


class TestParseState:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("entitled", EntitlementState.ENTITLED),
            ("grace", EntitlementState.GRACE),
            ("not_entitled", EntitlementState.NOT_ENTITLED),
        ],
    )
    def test_every_contract_state_parses(
        self, raw: str, expected: EntitlementState
    ) -> None:
        assert parse_state(raw) is expected

    def test_an_unknown_state_is_unreadable_not_entitled(self) -> None:
        """A newer platform introducing a fourth state must not
        accidentally entitle every older client."""

        assert parse_state("provisionally_entitled") is EntitlementState.UNREADABLE

    @pytest.mark.parametrize("raw", ["unreachable", "unreadable"])
    def test_a_server_cannot_claim_a_client_side_state(self, raw: str) -> None:
        """These two exist only on this side of the wire. A server
        claiming one is saying something the contract does not allow."""

        assert parse_state(raw) is EntitlementState.UNREADABLE

    def test_an_unreadable_state_fails_closed_by_default(self) -> None:
        decision = decide(state=parse_state("nonsense"), fail_mode=TeamFailMode.CLOSED)

        assert decision.proceed is False


class TestDefaultIsFailClosed:
    def test_the_configuration_default_is_closed(self) -> None:
        """Asserted against the config registry rather than restated here,
        so this cannot pass while the actual default says otherwise."""

        from controlloop.config import _KEY_SPECS

        assert _KEY_SPECS["team_fail_mode"].default == TeamFailMode.CLOSED.value
