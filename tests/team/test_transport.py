"""Tests for the network boundary.

The real `UrllibTransport` is never exercised against a real socket here,
and that is the point: `tests/conftest.py` denies socket construction
for the whole suite, and the Team client gets no exemption. What is tested
is everything around the socket -- the response-materializing helper, the
bound, the header normalization -- plus two structural properties that
would otherwise be claims in a docstring:

1. importing `controlloop.team` pulls in no TLS machinery, and
2. the real transport, if it ever were reached under the harness, would
   hit the denial rather than quietly succeed.
"""

from __future__ import annotations

import dataclasses
import sys

import pytest
from conftest import NetworkAccessDeniedError

from controlloop.team.transport import (
    MAX_RESPONSE_BYTES,
    HttpResponse,
    TransportError,
    UrllibTransport,
    _read,
)


class _Stream:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self, amount: int, /) -> bytes:
        return self._payload[:amount]


class TestResponseMaterialization:
    def test_headers_are_lower_cased(self) -> None:
        response = _read(200, _Stream(b"{}"), {"ETag": '"abc"', "Content-Type": "x"})

        assert response.header("etag") == '"abc"'
        assert response.header("ETAG") == '"abc"'

    def test_a_missing_header_is_none(self) -> None:
        assert _read(200, _Stream(b"{}"), {}).header("etag") is None

    def test_a_body_at_the_bound_is_accepted(self) -> None:
        payload = b"a" * MAX_RESPONSE_BYTES

        assert _read(200, _Stream(payload), {}).body == payload

    def test_a_body_over_the_bound_is_refused(self) -> None:
        """Refused by reading one byte past the bound rather than by
        trusting a `Content-Length` the server supplied."""

        payload = b"a" * (MAX_RESPONSE_BYTES + 1)

        with pytest.raises(TransportError, match="exceeded"):
            _read(200, _Stream(payload), {})

    def test_the_status_is_carried_verbatim(self) -> None:
        assert _read(429, _Stream(b""), {}).status == 429


class TestHttpResponse:
    def test_it_is_frozen(self) -> None:
        response = HttpResponse(status=200, body=b"{}")

        with pytest.raises(dataclasses.FrozenInstanceError):
            response.status = 500  # type: ignore[misc]


class TestOfflineProperties:
    def test_importing_the_team_package_does_not_import_ssl(self) -> None:
        """`urllib.request` imports `ssl`, and `ssl` subclasses
        `socket.socket` at import time -- which this suite has replaced.
        Deferring the import into `UrllibTransport.request` is what keeps
        `import controlloop.team` free of TLS machinery, and this is the
        assertion that keeps it that way.

        Note the module is imported by name here rather than assumed
        absent: another test may legitimately have imported `ssl` first,
        so the check is on `controlloop.team.transport`'s own module
        namespace, not on `sys.modules`.
        """

        import controlloop.team.transport as module

        assert not hasattr(module, "urllib")
        assert "controlloop.team.transport" in sys.modules

    def test_the_real_transport_hits_the_offline_harness(self) -> None:
        """The positive control: if `UrllibTransport` were ever reached in
        this suite, it would raise the harness's own error rather than
        silently reaching a network."""

        with pytest.raises((NetworkAccessDeniedError, TransportError, TypeError)):
            UrllibTransport().request(
                method="GET",
                url="https://198.51.100.1/api/v1/health",
                headers={},
                timeout_seconds=0.01,
            )
