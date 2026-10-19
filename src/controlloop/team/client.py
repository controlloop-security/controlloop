"""The platform client.

Four operations from the platform's contract, and nothing else:

| Method | Contract operation |
| --- | --- |
| `check_entitlement` | `project_entitlement_read` |
| `fetch_effective_policy` | `project_effective_policy_read` |
| `fetch_active_exceptions` | `project_active_exceptions_list` |
| `ingest_envelope` | `scans_ingest` |

## The retry window is fixed, not adaptive

Three attempts, with a fixed `RETRY_BACKOFF_SECONDS` schedule between
them. No jitter, no exponential growth computed from a clock, no
randomness: two runs against the same failing endpoint wait the same
amount of time and give up at the same point. That matters because the
*consequence* of giving up is a verdict -- `TeamFailMode.CLOSED` blocks --
and a verdict that depends on a random number is not a verdict anyone can
re-derive.

`sleep` is injected for the same reason it is fixed. Tests pass a
recorder and assert the exact schedule; nothing in the suite waits.

## What is retried, and what is not

Retried: a `TransportError` (no answer at all), `429` (rate limited), and
any `5xx` (the service is unwell). Not retried: every other `4xx`. A
`401` means the token is wrong, and a wrong token is still wrong three
seconds later -- retrying it wastes CI time and looks like credential
stuffing to whatever is counting.

## Responses are hostile input

Every response body is parsed by a strict, `extra="forbid"` Pydantic model
before any field is read. A body that is not JSON, is JSON of the wrong
shape, or carries a field the contract does not declare raises
`PlatformProtocolError` rather than being partially trusted. The CLI is a
security tool; "the server said so" is not a reason to skip validation.

## Nothing here logs

Not the URL, not the request body, and above all not the `Authorization`
header. `TeamConfig.token` is a `_Redacted`, and `reveal()` is called in
exactly one place in this file, inline, at the point the header is built.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, ValidationError

from controlloop.team.config import TeamConfig
from controlloop.team.transport import HttpResponse, HttpTransport, TransportError

#: Total attempts per operation, including the first. Three is the
#: documented bounded retry window.
MAX_ATTEMPTS: Final = 3

#: Seconds to wait before attempt 2 and attempt 3 respectively. Fixed and
#: ordered; `len(RETRY_BACKOFF_SECONDS) == MAX_ATTEMPTS - 1` is asserted
#: by this module's tests so the two constants cannot drift apart.
RETRY_BACKOFF_SECONDS: Final = (0.5, 2.0)

#: Per-request timeout. The whole point of a gate is that CI finishes, so
#: a slow platform must not hold a pipeline open indefinitely.
REQUEST_TIMEOUT_SECONDS: Final = 10.0

#: The envelope schema version this CLI emits. Sent in the payload and
#: recorded on the scan, so a server can tell which renderer produced it.
ENVELOPE_VERSION: Final = "1.0.0"

_RETRYABLE_STATUSES: Final = frozenset({429})

_USER_AGENT: Final = "controlloop-cli"


class PlatformProtocolError(Exception):
    """The platform answered, but not in the shape the contract declares.

    Carries no server-supplied text. A message field controlled by
    whatever answered the endpoint is exactly the kind of value this
    codebase refuses to echo into CI output.
    """


class PlatformAuthError(Exception):
    """The project token was rejected (`401`), or is not scoped to this
    project. Distinct from `PlatformProtocolError` because the remedy is
    different and the caller reports it differently."""


class _ResponseModel(BaseModel):
    """Strict by default, like every other external-boundary model in this
    codebase: unknown fields are refused rather than ignored, so a
    response cannot smuggle content past validation in a field the
    contract never declared."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=False)


class EntitlementResponse(_ResponseModel):
    """The platform contract's `Entitlement`."""

    state: str
    project_id: str
    checked_at: str
    cache_seconds: int


class RuleConfigurationResponse(_ResponseModel):
    """The platform contract's `RuleConfiguration`.

    Only `enabled` is required by the contract; `rule_id`,
    `severity_floor`, and `mandatory` are optional there and stay optional
    here rather than being invented with defaults the server never sent.
    """

    rule_id: str | None = None
    enabled: bool
    severity_floor: str | None = None
    mandatory: bool | None = None


class ApprovedComponentResponse(_ResponseModel):
    """The platform contract's `ApprovedComponent`, with the optional
    package, version-range, digest, command-pattern, and pin constraints.
    The model accepts them so that a published bundle with a constrained
    entry parses."""

    type: str
    name_pattern: str
    package: str | None = None
    version_range: str | None = None
    digest: str | None = None
    command_pattern: str | None = None
    pin_required: bool | None = None
    note: str | None = None


class EffectivePolicyResponse(_ResponseModel):
    """The platform contract's `EffectivePolicy`."""

    project_id: str
    organization_bundle_version: str
    merge_semantics_version: str
    rules: tuple[RuleConfigurationResponse, ...]
    approved_components: tuple[ApprovedComponentResponse, ...]
    computed_at: str


class ActiveExceptionResponse(_ResponseModel):
    """The platform contract's `ActiveException`."""

    finding_fingerprint: str
    expires_at: str


class ScanAcceptedResponse(_ResponseModel):
    """The platform contract's `ScanAccepted`."""

    scan_id: str
    duplicate: bool


@dataclass(frozen=True, slots=True)
class PolicyFetch:
    """The result of a conditional policy read.

    `policy` is `None` exactly when `not_modified` is true: the server
    answered `304` and the caller's cached copy is current. Modelled as
    two fields rather than an `Optional` alone so a caller cannot confuse
    "unchanged" with "absent".
    """

    policy: EffectivePolicyResponse | None
    etag: str | None
    not_modified: bool


@dataclass(frozen=True, slots=True)
class PlatformClient:
    """A thin, typed wrapper over the four contract operations.

    Holds no connection and no mutable state, so one instance is safe to
    reuse across the calls a single gate makes.
    """

    config: TeamConfig
    transport: HttpTransport
    sleep: Callable[[float], None]

    # -- public operations ------------------------------------------------

    def check_entitlement(self) -> EntitlementResponse:
        response = self._send("GET", self._project_path("entitlement"))
        return self._parse(response, EntitlementResponse)

    def fetch_effective_policy(self, *, etag: str | None = None) -> PolicyFetch:
        headers = {"If-None-Match": etag} if etag else {}
        response = self._send(
            "GET", self._project_path("effective-policy"), extra_headers=headers
        )
        if response.status == 304:
            return PolicyFetch(policy=None, etag=etag, not_modified=True)
        return PolicyFetch(
            policy=self._parse(response, EffectivePolicyResponse),
            etag=response.header("etag"),
            not_modified=False,
        )

    def fetch_active_exceptions(self) -> tuple[ActiveExceptionResponse, ...]:
        response = self._send("GET", self._project_path("active-exceptions"))
        payload = self._decode(response)
        if not isinstance(payload, list):
            raise PlatformProtocolError("the active-exceptions response was not a list")
        try:
            return tuple(
                ActiveExceptionResponse.model_validate(item) for item in payload
            )
        except ValidationError:
            raise PlatformProtocolError(
                "the active-exceptions response did not match the contract"
            ) from None

    def ingest_envelope(self, payload: bytes) -> ScanAcceptedResponse:
        """Submit one rendered envelope.

        Idempotency is the server's guarantee, not this client's: the
        contract makes ingestion idempotent on (project, commit, ACBOM
        digest) and answers a replay with the original scan and
        `duplicate: true`. This client's part is to send the same
        bytes for the same scan -- which `controlloop.team.envelope`
        guarantees -- and to surface `duplicate` rather than hide it.
        """

        response = self._send(
            "POST",
            self._project_path("scans"),
            body=payload,
            extra_headers={"Content-Type": "application/json"},
        )
        return self._parse(response, ScanAcceptedResponse)

    # -- internals --------------------------------------------------------

    def _project_path(self, suffix: str) -> str:
        return (
            f"{self.config.endpoint}/api/v1/organizations/"
            f"{self.config.organization_id}/projects/"
            f"{self.config.project_id}/{suffix}"
        )

    def _headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        headers = {
            # The one place `reveal()` is called. See
            # `controlloop.team.config._Redacted`.
            "Authorization": f"Bearer {self.config.token.reveal()}",
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        }
        headers.update(extra or {})
        return headers

    def _send(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Issue one request, retrying the retryable, and return the
        response that ended the window.

        Raises `TransportError` if every attempt failed to produce a
        response at all -- the caller turns that into the configured fail
        mode. Raises `PlatformAuthError` immediately on `401`.
        """

        headers = self._headers(extra_headers)
        last_error: TransportError | None = None
        last_response: HttpResponse | None = None

        for attempt in range(MAX_ATTEMPTS):
            if attempt:
                self.sleep(RETRY_BACKOFF_SECONDS[attempt - 1])
            try:
                response = self.transport.request(
                    method=method,
                    url=url,
                    headers=headers,
                    body=body,
                    timeout_seconds=REQUEST_TIMEOUT_SECONDS,
                )
            except TransportError as error:
                last_error = error
                continue

            if response.status == 401:
                raise PlatformAuthError(
                    "the platform rejected the project token; check "
                    "CONTROLLOOP_TEAM_TOKEN and that it belongs to this project"
                )
            if _is_retryable(response.status):
                last_response = response
                last_error = None
                continue
            return response

        if last_response is not None:
            return last_response
        assert last_error is not None
        raise last_error

    def _decode(self, response: HttpResponse) -> Any:
        if response.status >= 400:
            # An error envelope is not parsed for its message: that
            # message is server-controlled text, and this codebase does
            # not reproduce server-controlled text in CI output.
            raise PlatformProtocolError(f"the platform answered {response.status}")
        try:
            return json.loads(response.body)
        except (ValueError, UnicodeDecodeError):
            raise PlatformProtocolError(
                "the platform response was not valid JSON"
            ) from None

    def _parse[ModelT: _ResponseModel](
        self, response: HttpResponse, model: type[ModelT]
    ) -> ModelT:
        payload = self._decode(response)
        try:
            return model.model_validate(payload)
        except ValidationError:
            raise PlatformProtocolError(
                f"the platform response did not match the contract's "
                f"{model.__name__.removesuffix('Response')} schema"
            ) from None


def _is_retryable(status: int) -> bool:
    return status in _RETRYABLE_STATUSES or 500 <= status < 600
