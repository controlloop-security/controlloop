"""The one network boundary in this codebase.

Everything above this module works on values. This module is where a value
becomes a socket, and it is deliberately the only place that happens, so
that "does the CLI touch the network here?" is answerable by reading one
file rather than auditing a call graph.

## Why a protocol and a separate implementation

Network effects sit behind explicit interfaces by design, and
`tests/conftest.py` denies socket construction for the entire test
suite. Those two facts together mean a network client that constructs
its own connection cannot be tested at all. So `HttpTransport` is a
protocol, `UrllibTransport` is its one real implementation, and
`controlloop.cli` is the one caller that constructs the real one. Tests
inject a fake and exercise every status path; the offline harness stays
genuinely offline rather than being weakened to accommodate a test.

## Why the standard library

A new production dependency needs a deliberate decision. `urllib.request` is
already available, already audited as part of the interpreter, and
sufficient for four JSON requests with a bearer token. Adding an HTTP client
library would have been a new production dependency and a new supply-chain
surface for a security scanner.

## What this module guarantees to its callers

- **A timeout always applies.** There is no code path that issues a
  request without one.
- **A response is a value, not a stream.** The body is read once, bounded,
  and returned as bytes; nothing downstream holds a live connection.
- **Every failure is one exception type.** Connection refused, DNS
  failure, timeout, TLS failure, and an oversized body all surface as
  `TransportError`, so retry logic in `controlloop.team.client` has one
  thing to catch. An HTTP error status is *not* a `TransportError`: it is
  an ordinary `HttpResponse` with that status, because "the service
  answered 401" is an answer, not a transport failure.
- **Nothing is logged here.** Not the URL, not the headers, not the body.
  The `Authorization` header passes through this module and must not be
  reproduced anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Protocol

#: An upper bound on a response body, applied before the body is
#: materialized. The platform's own responses are small -- an entitlement
#: answer, a policy bundle, a page of exception fingerprints -- and a
#: scanner that can be made to allocate without limit by whatever answers
#: its endpoint is a scanner with a denial-of-service bug in it.
MAX_RESPONSE_BYTES: Final = 4 * 1024 * 1024


class TransportError(Exception):
    """A request did not produce an HTTP response at all.

    Deliberately carries no cause detail beyond a short, static reason
    string. A network exception's own message can contain the resolved
    URL, and the resolved URL is derived from configuration this CLI
    treats as hostile input; reproducing it in an error that lands in
    CI output is exactly the habit this codebase forbids.
    """


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """One completed HTTP exchange, as a value.

    `headers` is lower-cased on construction by `UrllibTransport` so
    callers can look up `etag` without worrying about the casing a server
    chose.
    """

    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class HttpTransport(Protocol):
    """The seam every Team network call passes through."""

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout_seconds: float,
    ) -> HttpResponse:
        """Perform one request and return its response.

        Raises `TransportError` when no HTTP response was produced. An
        HTTP error status is returned, not raised.
        """
        ...


@dataclass(frozen=True, slots=True)
class UrllibTransport:
    """The one real `HttpTransport`, built on the standard library.

    Constructed only by `controlloop.cli`. Importing this module opens
    nothing; instantiating this class opens nothing; only `request` does.
    """

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout_seconds: float,
    ) -> HttpResponse:
        # `urllib.request` is imported here rather than at module scope,
        # and the reason is not style. Importing it pulls in `ssl`, and
        # `ssl` builds `SSLSocket` by subclassing `socket.socket` at
        # import time. `tests/conftest.py` replaces `socket.socket`
        # with a function for the whole suite, so an `ssl` import that
        # happens after that fixture is active raises `TypeError` from
        # deep inside the standard library. Deferring the import to the
        # one method that actually needs it means importing
        # `controlloop.team` -- which `controlloop.cli` does
        # unconditionally, Team on or off -- pulls in no TLS machinery at
        # all, which is a stronger version of the claim this module's
        # docstring makes than module-scope imports could support.
        import urllib.error
        import urllib.request

        # The scheme is not attacker-chosen here: `team_endpoint` is
        # validated to https (or loopback http) by
        # `controlloop.team.config` before any URL reaches this method.
        request = urllib.request.Request(
            url,
            data=body,
            method=method,
        )
        for name, value in headers.items():
            request.add_header(name, value)

        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                return _read(response.status, response, dict(response.headers))
        except urllib.error.HTTPError as error:
            # An error status is an answer. Read it the same way and let
            # the caller decide what 401 or 429 means -- retrying a 401
            # forever would be worse than reporting it once.
            with error:
                return _read(error.code, error, dict(error.headers))
        except urllib.error.URLError:
            raise TransportError("the platform endpoint could not be reached") from None
        except TimeoutError:
            raise TransportError("the platform endpoint timed out") from None
        except OSError:
            raise TransportError("the platform endpoint could not be reached") from None


class _Readable(Protocol):
    def read(self, amount: int, /) -> bytes: ...


def _read(status: int, stream: _Readable, raw_headers: dict[str, str]) -> HttpResponse:
    """Materialize a bounded body and normalize header casing.

    Reads `MAX_RESPONSE_BYTES + 1` and refuses at the boundary rather than
    trusting a `Content-Length` a server supplied.
    """

    payload = stream.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise TransportError(
            f"the platform response exceeded {MAX_RESPONSE_BYTES} bytes"
        )
    headers = {name.lower(): value for name, value in raw_headers.items()}
    return HttpResponse(status=status, body=payload, headers=headers)
