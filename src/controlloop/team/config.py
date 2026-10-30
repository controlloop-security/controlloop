"""Team configuration resolution.

`controlloop.config` resolves the eight `team_*` keys through the same
four ordered tiers as every other key and validates their *shape*. This
module turns that raw, shape-valid material into a `TeamConfig`: a frozen
value object whose every field is semantically valid, or a
`TeamConfigError` naming the one key that is not.

## Enablement is explicit, never inferred

`resolve_team_config` returns `None` when `team_enabled` is false, and it
returns it before reading the token, the endpoint, or anything else. The
alternative -- inferring "Team is on" from the presence of a token in the
environment -- was rejected deliberately: a stray `CONTROLLOOP_TEAM_TOKEN`
inherited from another job in the same CI runner would silently change
what a repository's gate enforces. Enablement is a decision a repository
records in its own configuration file, in its own commit history.

`None` is what every caller in `controlloop.cli` checks to skip the Team
path entirely, so this early return is the "no network attempt when Team
is not configured" guarantee in one line.

## The token never passes through `controlloop.config`

Every key in that module's registry is printed verbatim by
`controlloop --show-config`. The project token is therefore read here,
directly from the injected environment mapping, under its own variable
name, and is never registered, never rendered, and never included in
`TeamConfig.__repr__` -- see `_Redacted` below, which is what that field
actually holds.

## Errors name the key and never the value

Every failure is a `TeamConfigError` carrying
`exit_code = ExitCode.INVALID_INPUT`, matching `ConfigError` and
`PolicyConfigError` exactly so `controlloop.cli` translates all three
into the documented exit-2 contract the same way: a misconfiguration
produces exit code 2 with a message naming the specific key, never a
stack trace. No message contains a resolved value: not the endpoint,
not an identifier, and above all not the token.

## The branch comes from the CI when it is not configured

`team_branch` wins whenever it is set. Otherwise the branch is read from
the CI's own variables (`detect_branch`), then from the checked-out
branch in git, so a plain `controlloop gate` upload still names its
branch. A detached `HEAD` with no CI variable sends no branch rather than
a guess. Like the token, the variables come from the injected
environment mapping; git is consulted through a callable the caller
supplies, so this module still runs no process of its own.

## Why `http` is allowed for loopback only

An endpoint must be `https`, with one documented exception: a loopback
host (`localhost`, `127.0.0.1`, `::1`) may use `http`, so a developer can
run a gate against a local platform stack without terminating TLS. Any
other `http` endpoint is refused rather than downgraded silently -- a
project token sent in clear text over a network is a credential
compromise, and "it was only a test endpoint" is not a property this
module can verify.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final
from urllib.parse import urlsplit
from uuid import UUID

from controlloop.config import ResolvedConfig
from controlloop.exit_codes import ExitCode

#: The environment variable carrying the project-scoped CI token.
#: Deliberately not a `controlloop.config` key -- see the module
#: docstring. The platform contract's `projectToken` security scheme
#: defines how it is sent: `Authorization: Bearer <token>`.
TOKEN_ENVIRONMENT_VARIABLE: Final = "CONTROLLOOP_TEAM_TOKEN"

#: An upper bound on the accepted token length. Not a claim about the
#: platform's token format -- the CLI does not get to decide that -- only
#: a bound, so a pathological environment value is refused at the
#: boundary rather than carried into a request.
_MAX_TOKEN_LENGTH: Final = 4096

#: Hosts permitted to use `http` rather than `https`; see the module
#: docstring.
_LOOPBACK_HOSTNAMES: Final = frozenset({"localhost"})

#: The CI variables a branch is read from when `team_branch` is unset, in
#: order. A pull request's source branch comes before the ref the build
#: ran on: GitHub sets `GITHUB_REF_NAME` to `<number>/merge` for a pull
#: request, and Azure DevOps sets `BUILD_SOURCEBRANCH` to `refs/pull/...`.
BRANCH_ENVIRONMENT_VARIABLES: Final = (
    "GITHUB_HEAD_REF",
    "GITHUB_REF_NAME",
    "CI_COMMIT_REF_NAME",
    "BITBUCKET_BRANCH",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH",
    "BUILD_SOURCEBRANCH",
)

#: A variable that, when set, means the paired branch variable holds a
#: tag rather than a branch, so it is skipped.
_TAG_MARKERS: Final = {
    "GITHUB_REF_NAME": ("GITHUB_REF_TYPE", "tag"),
    "CI_COMMIT_REF_NAME": ("CI_COMMIT_TAG", None),
}

#: The platform stores at most this many characters of a branch name. A
#: longer detected name is dropped rather than failing the upload; a
#: configured `team_branch` is sent as written.
_MAX_DETECTED_BRANCH_LENGTH: Final = 255


class TeamFailMode(StrEnum):
    """What a gate does when the platform cannot be reached after the
    bounded retry window.

    `CLOSED` is the default, and the default is deliberate: a security
    control that stops being enforced whenever the service enforcing it is
    unreachable is a control an attacker can remove by making it
    unreachable. A repository that would rather ship than block may opt
    into `OPEN`, in its own configuration, as a recorded decision.
    """

    CLOSED = "closed"
    OPEN = "open"


@dataclass(frozen=True, slots=True)
class _Redacted:
    """A secret that does not reproduce itself in a traceback.

    `TeamConfig` is a frozen dataclass, and a dataclass renders every
    field in its generated `__repr__`. An unhandled exception anywhere in
    a call that has a `TeamConfig` in scope would therefore print the
    project token into CI logs. This wrapper makes that structurally
    impossible: `repr` is overridden, the value is reachable only through
    an explicitly named accessor, and the accessor is called in exactly
    one place -- `controlloop.team.client`, when it builds the
    `Authorization` header.
    """

    _value: str = field(repr=False)

    def __repr__(self) -> str:
        return "<redacted>"

    def __str__(self) -> str:
        return "<redacted>"

    def reveal(self) -> str:
        """Return the wrapped secret. One caller only; see the class
        docstring."""

        return self._value


class TeamConfigError(ValueError):
    """Team configuration is enabled but unusable.

    Carries `exit_code = ExitCode.INVALID_INPUT`, mirroring
    `controlloop.config.ConfigError` and
    `controlloop.policy.thresholds.PolicyConfigError` exactly. The message
    always names the configuration key or environment variable at fault
    and never contains its value.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INVALID_INPUT


@dataclass(frozen=True, slots=True)
class TeamConfig:
    """A fully validated Team configuration.

    Constructed only by `resolve_team_config`. Every field here is already
    semantically valid: `endpoint` is a normalized origin with no trailing
    slash, the two identifiers are canonical UUID strings, and
    `pull_request` is a positive integer or `None`.
    """

    endpoint: str
    organization_id: str
    project_id: str
    token: _Redacted
    fail_mode: TeamFailMode
    policy_cache_seconds: int
    branch: str | None = None
    pull_request: int | None = None


def _require_string(resolved: ResolvedConfig, key: str) -> str:
    value = resolved.team_value(key)
    assert isinstance(value, str)
    return value


def _validate_endpoint(raw: str) -> str:
    """Return the normalized endpoint origin, or raise naming the key.

    Normalization is deliberate and narrow: strip surrounding whitespace
    and one trailing slash, so `https://api.example/` and
    `https://api.example` produce byte-identical request URLs and
    therefore byte-identical idempotency behavior at the ingestion
    endpoint. Nothing else about the URL is rewritten.
    """

    candidate = raw.strip()
    if not candidate:
        raise TeamConfigError(
            "team_endpoint is required when team_enabled is true; set it in "
            "controlloop.toml or CONTROLLOOP_TEAM_ENDPOINT"
        )

    try:
        parts = urlsplit(candidate)
    except ValueError:
        raise TeamConfigError("team_endpoint is not a valid URL") from None

    if parts.scheme not in {"http", "https"}:
        raise TeamConfigError("team_endpoint must use https")
    if not parts.hostname:
        raise TeamConfigError("team_endpoint must include a host")
    if parts.query or parts.fragment:
        raise TeamConfigError("team_endpoint must not carry a query or fragment")
    if parts.scheme == "http" and not _is_loopback(parts.hostname):
        raise TeamConfigError(
            "team_endpoint must use https; http is permitted only for a "
            "loopback host, because a project token sent in clear text is a "
            "compromised token"
        )

    return candidate.rstrip("/")


def _is_loopback(hostname: str) -> bool:
    if hostname in _LOOPBACK_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_uuid(raw: str, *, key: str) -> str:
    candidate = raw.strip()
    if not candidate:
        raise TeamConfigError(
            f"{key} is required when team_enabled is true; find it in your "
            "ControlLoop project settings"
        )
    try:
        return str(UUID(candidate))
    except ValueError:
        raise TeamConfigError(f"{key} must be a UUID") from None


def _validate_token(environ: dict[str, str]) -> _Redacted:
    raw = environ.get(TOKEN_ENVIRONMENT_VARIABLE)
    if raw is None:
        raise TeamConfigError(
            f"{TOKEN_ENVIRONMENT_VARIABLE} is required when team_enabled is "
            "true; set it as a secret in your CI environment, never in "
            "controlloop.toml"
        )

    candidate = raw.strip()
    if not candidate:
        raise TeamConfigError(f"{TOKEN_ENVIRONMENT_VARIABLE} is empty")
    if len(candidate) > _MAX_TOKEN_LENGTH:
        raise TeamConfigError(
            f"{TOKEN_ENVIRONMENT_VARIABLE} is longer than "
            f"{_MAX_TOKEN_LENGTH} characters"
        )
    if any(character.isspace() or ord(character) < 0x20 for character in candidate):
        # A token is sent as an HTTP header value. Whitespace and control
        # characters are refused here rather than at the transport, so the
        # error names the variable a user can fix instead of surfacing as
        # a header-encoding failure.
        raise TeamConfigError(
            f"{TOKEN_ENVIRONMENT_VARIABLE} must not contain whitespace or "
            "control characters"
        )
    return _Redacted(candidate)


def _validate_pull_request(raw: str) -> int | None:
    candidate = raw.strip()
    if not candidate:
        return None
    if not candidate.isdigit():
        raise TeamConfigError("team_pull_request must be a positive integer")
    number = int(candidate)
    if number < 1:
        raise TeamConfigError("team_pull_request must be a positive integer")
    return number


def _branch_from_variable(name: str, environ: Mapping[str, str]) -> str | None:
    value = environ.get(name, "").strip()
    if not value:
        return None
    marker = _TAG_MARKERS.get(name)
    if marker is not None:
        marker_name, marker_value = marker
        marked = environ.get(marker_name, "").strip()
        if marked and (marker_value is None or marked == marker_value):
            return None
    if name in ("BUILD_SOURCEBRANCH", "SYSTEM_PULLREQUEST_SOURCEBRANCH"):
        # Azure DevOps gives the full ref. Only `refs/heads/` names a
        # branch; `BUILD_SOURCEBRANCHNAME` is not used because it keeps
        # only the last path segment (`feature/login` becomes `login`).
        if not value.startswith("refs/heads/"):
            return None
        value = value.removeprefix("refs/heads/")
    return value or None


def detect_branch(
    environ: Mapping[str, str],
    *,
    git_branch: Callable[[], str | None],
) -> str | None:
    """The branch a scan ran on, when `team_branch` is not set.

    Reads the CI's branch variables in `BRANCH_ENVIRONMENT_VARIABLES` order, then
    asks `git_branch` for the checked-out branch, which returns `None` on
    a detached `HEAD`. A name longer than the platform stores is dropped.
    """

    for name in BRANCH_ENVIRONMENT_VARIABLES:
        branch = _branch_from_variable(name, environ)
        if branch is not None:
            break
    else:
        branch = git_branch()
        branch = branch.strip() if branch else None
    if not branch or len(branch) > _MAX_DETECTED_BRANCH_LENGTH:
        return None
    return branch


def _no_git_branch() -> str | None:
    return None


def resolve_team_config(
    resolved: ResolvedConfig,
    *,
    environ: dict[str, str],
    git_branch: Callable[[], str | None] = _no_git_branch,
) -> TeamConfig | None:
    """Return the validated Team configuration, or `None` when Team is off.

    `None` is the entire Community path: the caller does no Team work at
    all, attempts no network call, and produces byte-identical output to
    a build of this CLI that had never heard of the paid tier.

    `environ` is injected rather than read from `os.environ` here, for the
    same reason `controlloop.config.load_config` takes it as a parameter:
    deterministic logic in this codebase does not depend on ambient
    process state, and every test supplies its own mapping. `git_branch`
    is the checked-out branch, consulted only when neither `team_branch`
    nor a CI variable names one.
    """

    enabled = resolved.team_value("team_enabled")
    assert isinstance(enabled, bool)
    if not enabled:
        return None

    cache_seconds = resolved.team_value("team_policy_cache_seconds")
    assert isinstance(cache_seconds, int)

    fail_mode_value = resolved.team_value("team_fail_mode")
    assert isinstance(fail_mode_value, str)

    branch = _require_string(resolved, "team_branch").strip() or detect_branch(
        environ, git_branch=git_branch
    )

    return TeamConfig(
        endpoint=_validate_endpoint(_require_string(resolved, "team_endpoint")),
        organization_id=_validate_uuid(
            _require_string(resolved, "team_organization_id"),
            key="team_organization_id",
        ),
        project_id=_validate_uuid(
            _require_string(resolved, "team_project_id"),
            key="team_project_id",
        ),
        token=_validate_token(environ),
        fail_mode=TeamFailMode(fail_mode_value),
        policy_cache_seconds=cache_seconds,
        branch=branch or None,
        pull_request=_validate_pull_request(
            _require_string(resolved, "team_pull_request")
        ),
    )
