"""Entitlement verification.

One question, asked before any paid behavior runs: may this project be
gated as a paid project right now?

The decision logic is a pure function of an answer (or a failure) and the
repository's configured fail mode. Nothing here performs I/O; `decide`
takes what the client returned and returns what the gate should do, which
is what makes both fail modes testable without a network and without a
clock.

## Why entitlement is checked first

If a project is not entitled, it must not have fetched its organization's
policy bundle, must not have honored its exceptions, and must not have
uploaded anything. Checking first is the only ordering where "no partial
paid behavior" is structurally true rather than a property someone
has to remember to preserve.

## Fail closed by default, and why

When the service cannot be reached after the bounded retry window
(`controlloop.team.client.MAX_ATTEMPTS` attempts on the
`RETRY_BACKOFF_SECONDS` schedule), the gate applies the repository's
`team_fail_mode`. The default is `closed`.

That default is the uncomfortable one, and it is deliberate. A security
control that stops being enforced whenever the service enforcing it is
unreachable is a control that an attacker removes by making it
unreachable, and a team removes by accident during an outage. A repository
that would rather ship during an outage can set `team_fail_mode = "open"`
in its own configuration, where the decision is recorded, reviewable, and
attributable -- rather than being the silent default for everyone.

Note the asymmetry with local scanning: a fail-closed *Team* gate never
degrades Community behavior, because none of this code runs when Team is
off. An unreachable platform cannot stop a free user from scanning.

## `grace` proceeds

The contract's three states are `entitled`, `grace`, and `not_entitled`.
`grace` means a past-due subscription inside its grace window, and it
proceeds: dunning is a billing conversation, and turning a customer's CI
red is not how that conversation should start. Only `not_entitled` stops
the gate, with exit code 4.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from controlloop.exit_codes import ExitCode
from controlloop.team.config import TeamFailMode


class EntitlementState(StrEnum):
    """The platform contract's `EntitlementState`, plus the two
    states that exist only on this side of the wire.

    `UNREACHABLE` and `UNREADABLE` are not contract members: the service
    never reports them about itself. They are what the CLI concluded when
    it got no usable answer, and they are kept distinct because they have
    different causes -- a network the gate could not traverse, versus a
    response that did not match the contract -- even though both resolve
    through the same fail mode.
    """

    ENTITLED = "entitled"
    GRACE = "grace"
    NOT_ENTITLED = "not_entitled"
    UNREACHABLE = "unreachable"
    UNREADABLE = "unreadable"


@dataclass(frozen=True, slots=True)
class EntitlementDecision:
    """What the gate should do, and what to tell the developer.

    `exit_code` is `None` when the gate proceeds. When it is set, it is
    always `ExitCode.ENTITLEMENT` (4) -- this module never invents a new
    exit code, and never reuses one that means something else.
    """

    state: EntitlementState
    proceed: bool
    message: str
    exit_code: ExitCode | None = None


_PROCEED_STATES = frozenset({EntitlementState.ENTITLED, EntitlementState.GRACE})


def decide(
    *,
    state: EntitlementState,
    fail_mode: TeamFailMode,
) -> EntitlementDecision:
    """Turn an entitlement state into a gate decision.

    Brand voice: say what happened, say
    what to do, do not editorialize. A developer reading a red CI log
    wants the cause and the next step, not an apology and not a sales
    pitch.
    """

    if state in _PROCEED_STATES:
        return EntitlementDecision(
            state=state,
            proceed=True,
            message=(
                "Team entitlement confirmed."
                if state is EntitlementState.ENTITLED
                else (
                    "Team entitlement is in its grace period. The gate ran "
                    "normally; update billing to avoid an interruption."
                )
            ),
        )

    if state is EntitlementState.NOT_ENTITLED:
        return EntitlementDecision(
            state=state,
            proceed=False,
            exit_code=ExitCode.ENTITLEMENT,
            message=(
                "This project is not entitled to a Team gate, so no paid "
                "verdict was produced. Check the subscription and the "
                "project's plan in your ControlLoop organization, or set "
                "team_enabled = false to run the free Community gate."
            ),
        )

    reason = (
        "could not be reached"
        if state is EntitlementState.UNREACHABLE
        else "returned a response that did not match the platform contract"
    )

    if fail_mode is TeamFailMode.OPEN:
        return EntitlementDecision(
            state=state,
            proceed=True,
            message=(
                f"The entitlement service {reason} after the bounded retry "
                "window. team_fail_mode is 'open', so the gate continued "
                "without a verified entitlement."
            ),
        )

    return EntitlementDecision(
        state=state,
        proceed=False,
        exit_code=ExitCode.ENTITLEMENT,
        message=(
            f"The entitlement service {reason} after the bounded retry "
            "window. team_fail_mode is 'closed', so the gate stopped rather "
            "than reporting an unverified paid verdict. Set "
            'team_fail_mode = "open" to continue through an outage instead.'
        ),
    )


def parse_state(raw: str) -> EntitlementState:
    """Read a contract state string, or report it as unreadable.

    A state this CLI does not recognize is `UNREADABLE`, not an
    optimistic `ENTITLED`. A newer platform introducing a fourth state
    must not accidentally entitle every older client.
    """

    try:
        state = EntitlementState(raw)
    except ValueError:
        return EntitlementState.UNREADABLE
    if state in {EntitlementState.UNREACHABLE, EntitlementState.UNREADABLE}:
        # These two exist only on this side of the wire. A server claiming
        # one is a server saying something the contract does not allow.
        return EntitlementState.UNREADABLE
    return state
