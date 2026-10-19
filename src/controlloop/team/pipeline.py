"""The Team gate pipeline -- the orchestration `controlloop gate` calls.

Everything in this package below this module is a value or a pure
function. This is where they are put in order, and the order is the
requirement:

1. **Entitlement, first.** A project that is not entitled must not have
   fetched a policy bundle, honored an exception, or uploaded anything
   ("no partial paid behavior"). Checking first makes that structural.
2. **Policy and exceptions, second.** Both feed local evaluation, so both
   have to be resolved before any rule runs.
3. **Upload, last.** After the verdict exists, and never able to change
   it.

`gate` calls `prepare` before evaluating policy and `upload` after writing
evidence. Between those two calls it does exactly what it does without
Team, with two substitutions: the merged disabled-rule set replaces the
repository's own, and severity floors are applied to the findings.

## Every effect is injected

`transport`, `sleep`, and `now` all arrive as parameters. This module
reads no clock and constructs no connection, which is why the whole Team
path is testable under a socket-denying harness and why a gate pinned to a
fixed instant produces the same verdict every run.

## Failure is a decision, not an exception

`prepare` does not raise for an unreachable platform. It returns a
`TeamPreparation` whose `decision` says whether to proceed, carrying the
message to print. `team_fail_mode` is applied in exactly one place --
`entitlement.decide` -- and the policy fetch reuses that same decision
rather than inventing a second, subtly different fail-mode rule.

## What "stale" means here

If the policy cache holds a copy past its lifetime and the service cannot
be reached, `policy_source` becomes `stale_cache` and the gate proceeds
only under `TeamFailMode.OPEN`. Under `CLOSED` it stops. Serving
indefinitely old policy silently would turn fail-closed into fail-open
with extra steps.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from controlloop.findings.models import Finding
from controlloop.team import cache
from controlloop.team.client import (
    ActiveExceptionResponse,
    EffectivePolicyResponse,
    PlatformAuthError,
    PlatformClient,
    PlatformProtocolError,
)
from controlloop.team.components import DeltaJudgment
from controlloop.team.config import TeamConfig, TeamFailMode
from controlloop.team.entitlement import (
    EntitlementDecision,
    EntitlementState,
    decide,
    parse_state,
)
from controlloop.team.envelope import (
    RepositoryPolicyDelta,
    RuleOverride,
    ScanEnvelope,
    serialize_envelope,
)
from controlloop.team.evidence import TeamEvidence
from controlloop.team.exceptions import (
    ActiveException,
    ExceptionOutcome,
    apply_exceptions,
)
from controlloop.team.policy import (
    MERGE_SEMANTICS_VERSION,
    ApprovedComponentSpec,
    MergeResult,
    RuleSpec,
    merge_policy,
)
from controlloop.team.transport import TransportError

#: Cache entry names. Two entries, because they have different lifetimes
#: in practice: a bundle changes rarely, an exception list changes
#: whenever someone approves or revokes one.
_POLICY_CACHE: Final = "policy"
_EXCEPTIONS_CACHE: Final = "exceptions"

#: `TeamEvidence.policy_source` values.
SOURCE_FETCHED: Final = "fetched"
SOURCE_CACHE: Final = "cache"
SOURCE_STALE_CACHE: Final = "stale_cache"
SOURCE_NONE: Final = "none"


@dataclass(frozen=True, slots=True)
class TeamPreparation:
    """Everything the Team path contributes before policy evaluation.

    `decision.proceed` is the only field a caller must branch on. When it
    is false, the caller prints `decision.message` and exits with
    `decision.exit_code`; nothing else here is meaningful.
    """

    decision: EntitlementDecision
    merge: MergeResult | None = None
    organization_bundle_version: str = ""
    policy_source: str = SOURCE_NONE
    exceptions: tuple[ActiveException, ...] = ()
    repository_delta: tuple[RuleSpec, ...] = ()
    notes: tuple[str, ...] = field(default=())

    def disabled_rule_ids(self) -> frozenset[str] | None:
        """The effective disabled set, or `None` when no merge happened.

        `None` means the caller keeps its own repository-configured set --
        which is what a Community gate, and a fail-open gate that could
        not reach the platform, both do.
        """

        return self.merge.disabled_rule_ids() if self.merge is not None else None

    def severity_floors(self) -> dict[str, str]:
        return self.merge.severity_floors() if self.merge is not None else {}


def repository_delta_from(disabled_rule_ids: frozenset[str]) -> tuple[RuleSpec, ...]:
    """The repository's policy as a delta the server can re-merge.

    Today this is exactly the repository's disabled rules. The CLI's other
    policy settings -- `severity_threshold`, `low_confidence_action`,
    `completeness_enforcement` -- are gate-wide thresholds, not per-rule
    configuration, and the contract's `RuleOverrideRequest` has no field
    for them. Sending them coerced into a shape that does not fit would
    make the server compute an effective policy that misdescribes what the
    repository asked for; sending only what maps cleanly is the honest
    option, and it is stated in `docs/reference/team-envelope.md` rather
    than left for someone to discover.
    """

    return tuple(
        RuleSpec(rule_id=rule_id, enabled=False)
        for rule_id in sorted(disabled_rule_ids)
    )


def delta_for_envelope(delta: tuple[RuleSpec, ...]) -> RepositoryPolicyDelta | None:
    """The delta in the contract's request shape, or `None` when empty."""

    if not delta:
        return None
    return RepositoryPolicyDelta(
        rules=tuple(
            RuleOverride(rule_id=spec.rule_id, enabled=spec.enabled) for spec in delta
        )
    )


def prepare(
    *,
    config: TeamConfig,
    client: PlatformClient,
    repository_root: Path,
    repository_disabled_rules: frozenset[str],
    now: datetime,
) -> TeamPreparation:
    """Verify entitlement, then resolve the effective policy and
    exceptions."""

    notes: list[str] = []
    decision = _check_entitlement(client, config)
    if not decision.proceed:
        return TeamPreparation(decision=decision)
    notes.append(decision.message)

    policy, source, policy_note = _resolve_policy(
        client=client, config=config, repository_root=repository_root, now=now
    )
    if policy_note:
        notes.append(policy_note)

    if policy is None:
        # No bundle, live or cached. Under fail-open the gate continues on
        # repository policy alone, which is a materially different run and
        # is said so rather than passed over.
        if config.fail_mode is TeamFailMode.OPEN:
            return TeamPreparation(
                decision=decision,
                policy_source=SOURCE_NONE,
                notes=tuple(notes),
            )
        return TeamPreparation(
            decision=EntitlementDecision(
                state=decision.state,
                proceed=False,
                exit_code=decide(
                    state=EntitlementState.UNREACHABLE,
                    fail_mode=TeamFailMode.CLOSED,
                ).exit_code,
                message=(
                    "The organization policy bundle could not be fetched and "
                    "no cached copy is available. team_fail_mode is 'closed', "
                    "so the gate stopped rather than enforcing an unknown "
                    "policy."
                ),
            ),
        )

    delta = repository_delta_from(repository_disabled_rules)
    merge = merge_policy(
        organization_rules=_organization_rules(policy),
        organization_components=_organization_components(policy),
        repository_rules=delta,
        organization_bundle_version=policy.organization_bundle_version,
    )

    exceptions, exceptions_note = _resolve_exceptions(
        client=client, config=config, repository_root=repository_root, now=now
    )
    if exceptions_note:
        notes.append(exceptions_note)

    return TeamPreparation(
        decision=decision,
        merge=merge,
        organization_bundle_version=policy.organization_bundle_version,
        policy_source=source,
        exceptions=exceptions,
        repository_delta=delta,
        notes=tuple(notes),
    )


def build_evidence(
    preparation: TeamPreparation,
    exception_outcome: ExceptionOutcome,
    judgments: tuple[DeltaJudgment, ...] = (),
) -> TeamEvidence | None:
    """The evidence block for this run, or `None` when no merge happened.
    `judgments` are the sanction judgments of the authority delta."""

    if preparation.merge is None:
        return None
    return TeamEvidence.from_merge(
        merge=preparation.merge,
        organization_bundle_version=preparation.organization_bundle_version,
        merge_semantics_version=MERGE_SEMANTICS_VERSION,
        policy_source=preparation.policy_source,
        entitlement_state=preparation.decision.state.value,
        repository_delta=preparation.repository_delta,
        exception_records=exception_outcome.records,
        judgments=judgments,
    )


def apply_team_exceptions(
    findings: tuple[Finding, ...],
    preparation: TeamPreparation,
    *,
    now: datetime,
) -> ExceptionOutcome:
    """Honor the organization's exceptions against this run's findings."""

    return apply_exceptions(findings, preparation.exceptions, evaluated_at=now)


def upload(
    *,
    client: PlatformClient,
    envelope: ScanEnvelope,
) -> str:
    """Submit one envelope and return the line to report.

    Never raises: upload success or failure must be reported distinctly
    *without altering the gate verdict*, so every failure becomes a
    message rather than an exception the caller has to decide how to
    swallow.
    """

    try:
        accepted = client.ingest_envelope(serialize_envelope(envelope))
    except PlatformAuthError as error:
        return f"Team upload failed: {error}"
    except PlatformProtocolError as error:
        return f"Team upload failed: {error}"
    except TransportError:
        return (
            "Team upload failed: the platform endpoint could not be reached "
            "after the bounded retry window. The gate verdict is unaffected."
        )

    if accepted.duplicate:
        return (
            f"Team upload accepted as a replay of scan {accepted.scan_id}; "
            "this commit and ACBOM digest were already ingested."
        )
    return f"Team upload accepted as scan {accepted.scan_id}."


# -- internals ------------------------------------------------------------


def _check_entitlement(
    client: PlatformClient, config: TeamConfig
) -> EntitlementDecision:
    try:
        answer = client.check_entitlement()
    except TransportError:
        return decide(state=EntitlementState.UNREACHABLE, fail_mode=config.fail_mode)
    except PlatformAuthError as error:
        return EntitlementDecision(
            state=EntitlementState.NOT_ENTITLED,
            proceed=False,
            exit_code=decide(
                state=EntitlementState.NOT_ENTITLED, fail_mode=config.fail_mode
            ).exit_code,
            message=str(error),
        )
    except PlatformProtocolError:
        return decide(state=EntitlementState.UNREADABLE, fail_mode=config.fail_mode)

    return decide(state=parse_state(answer.state), fail_mode=config.fail_mode)


def _resolve_policy(
    *,
    client: PlatformClient,
    config: TeamConfig,
    repository_root: Path,
    now: datetime,
) -> tuple[EffectivePolicyResponse | None, str, str | None]:
    """Return the effective policy, where it came from, and any note.

    Order: a fresh cache entry short-circuits entirely; otherwise the
    stored ETag revalidates; otherwise a full fetch. A failure falls back
    to a stale entry, which the caller resolves through the fail mode.
    """

    entry = cache.read(
        repository_root,
        _POLICY_CACHE,
        now=now,
        lifetime_seconds=config.policy_cache_seconds,
    )
    if entry is not None and entry.fresh:
        parsed = _parse_cached_policy(entry.payload)
        if parsed is not None:
            return parsed, SOURCE_CACHE, None

    try:
        fetch = client.fetch_effective_policy(
            etag=entry.etag if entry is not None else None
        )
    except (TransportError, PlatformProtocolError, PlatformAuthError):
        if entry is None:
            return None, SOURCE_NONE, None
        parsed = _parse_cached_policy(entry.payload)
        if parsed is None:
            return None, SOURCE_NONE, None
        return (
            parsed,
            SOURCE_STALE_CACHE,
            (
                "The organization policy bundle could not be refreshed; "
                f"using the cached copy stored at {entry.stored_at.isoformat()}."
            ),
        )

    if fetch.not_modified:
        assert entry is not None
        parsed = _parse_cached_policy(entry.payload)
        if parsed is not None:
            cache.write(
                repository_root,
                _POLICY_CACHE,
                payload=entry.payload,
                etag=entry.etag,
                now=now,
            )
            return parsed, SOURCE_CACHE, None
        return None, SOURCE_NONE, None

    assert fetch.policy is not None
    cache.write(
        repository_root,
        _POLICY_CACHE,
        payload=fetch.policy.model_dump(mode="json"),
        etag=fetch.etag,
        now=now,
    )
    return fetch.policy, SOURCE_FETCHED, None


def _parse_cached_policy(payload: object) -> EffectivePolicyResponse | None:
    """A cached payload is hostile input like any other."""

    try:
        return EffectivePolicyResponse.model_validate(payload)
    except Exception:
        return None


def _resolve_exceptions(
    *,
    client: PlatformClient,
    config: TeamConfig,
    repository_root: Path,
    now: datetime,
) -> tuple[tuple[ActiveException, ...], str | None]:
    # Deliberately *not* short-circuited on a fresh cache, unlike the
    # policy bundle. A published bundle version is immutable -- version 7
    # means the same thing an hour from now -- so serving it from cache
    # changes nothing. An exception list is the opposite: it is a live
    # record of who has approved what, and a *revoked* approval that kept
    # suppressing a finding for the rest of a cache lifetime would be a
    # security control silently continuing to not apply.
    #
    # So exceptions are fetched every run, and the cache below exists only
    # as fail-open continuity when the service cannot be reached.
    entry = cache.read(
        repository_root,
        _EXCEPTIONS_CACHE,
        now=now,
        lifetime_seconds=config.policy_cache_seconds,
    )

    try:
        published = client.fetch_active_exceptions()
    except (TransportError, PlatformProtocolError, PlatformAuthError):
        if entry is None:
            return (), None
        parsed = _parse_cached_exceptions(entry.payload)
        if parsed is None:
            return (), None
        return parsed, (
            "Active exceptions could not be refreshed; using the cached list "
            f"stored at {entry.stored_at.isoformat()}."
        )

    cache.write(
        repository_root,
        _EXCEPTIONS_CACHE,
        payload=[item.model_dump(mode="json") for item in published],
        etag=None,
        now=now,
    )
    return _to_active_exceptions(published), None


def _parse_cached_exceptions(payload: object) -> tuple[ActiveException, ...] | None:
    if not isinstance(payload, list):
        return None
    try:
        return _to_active_exceptions(
            tuple(ActiveExceptionResponse.model_validate(item) for item in payload)
        )
    except Exception:
        return None


def _to_active_exceptions(
    published: tuple[ActiveExceptionResponse, ...],
) -> tuple[ActiveException, ...]:
    """Parse expiry timestamps, dropping any the CLI cannot read.

    A malformed timestamp is dropped rather than treated as unexpired: an
    exception whose expiry cannot be established is an exception that
    cannot be shown to be live, and honoring it would suppress a finding
    on the strength of an unparseable date.
    """

    resolved: list[ActiveException] = []
    for item in published:
        expires_at = _parse_timestamp(item.expires_at)
        if expires_at is None:
            continue
        resolved.append(
            ActiveException(
                finding_fingerprint=item.finding_fingerprint,
                expires_at=expires_at,
            )
        )
    return tuple(resolved)


def _parse_timestamp(raw: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    # A naive timestamp is read as UTC rather than as local time: the
    # comparison instant is UTC, and mixing the two would make an
    # exception expire at a different moment depending on the runner's
    # timezone.
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _organization_rules(policy: EffectivePolicyResponse) -> tuple[RuleSpec, ...]:
    return tuple(
        RuleSpec(
            rule_id=rule.rule_id or "",
            enabled=rule.enabled,
            severity_floor=rule.severity_floor,
            mandatory=bool(rule.mandatory),
        )
        for rule in policy.rules
        if rule.rule_id
    )


def _organization_components(
    policy: EffectivePolicyResponse,
) -> tuple[ApprovedComponentSpec, ...]:
    return tuple(
        ApprovedComponentSpec(
            type=component.type,
            name_pattern=component.name_pattern,
            package=component.package,
            version_range=component.version_range,
            digest=component.digest,
            command_pattern=component.command_pattern,
            pin_required=component.pin_required,
        )
        for component in policy.approved_components
    )


def make_sleeper() -> Callable[[float], None]:
    """The real sleep, constructed here so `controlloop.cli` does not need
    to import `time` for one call."""

    import time

    return time.sleep
