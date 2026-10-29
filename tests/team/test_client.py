"""Tests for the platform client.

Every test drives `FakeTransport`, so the retry window is exercised
without waiting and the offline harness stays intact. The injected sleeper
records rather than sleeps, which is what makes asserting the exact
backoff schedule cheap enough to be worth doing.
"""

from __future__ import annotations

import json

import pytest
from factories import (
    ORGANIZATION_ID,
    PROJECT_ID,
    TOKEN,
    FakeTransport,
    json_response,
    make_team_config,
    recording_sleeper,
)

from controlloop.team.client import (
    MAX_ATTEMPTS,
    RETRY_BACKOFF_SECONDS,
    PlatformAuthError,
    PlatformClient,
    PlatformProtocolError,
)
from controlloop.team.transport import HttpResponse, TransportError

_ENTITLEMENT = {
    "state": "entitled",
    "project_id": PROJECT_ID,
    "checked_at": "2026-09-02T12:00:00Z",
    "cache_seconds": 300,
}

_POLICY = {
    "project_id": PROJECT_ID,
    "organization_bundle_version": "7",
    "merge_semantics_version": "1.0.0",
    "rules": [{"rule_id": "a.rule", "enabled": True}],
    "approved_components": [],
    "computed_at": "2026-09-02T12:00:00Z",
}


def _client(transport: FakeTransport) -> tuple[PlatformClient, list[float]]:
    sleep, recorded = recording_sleeper()
    return (
        PlatformClient(config=make_team_config(), transport=transport, sleep=sleep),
        recorded,
    )


class TestRequestShape:
    def test_the_token_is_sent_as_a_bearer_header(self) -> None:
        transport = FakeTransport([json_response(_ENTITLEMENT)])
        client, _ = _client(transport)

        client.check_entitlement()

        assert transport.calls[0]["headers"]["Authorization"] == f"Bearer {TOKEN}"

    def test_the_token_never_appears_in_the_url(self) -> None:
        """A credential in a URL lands in access logs, proxy logs, and
        referrer headers."""

        transport = FakeTransport([json_response(_ENTITLEMENT)])
        client, _ = _client(transport)

        client.check_entitlement()

        assert TOKEN not in transport.calls[0]["url"]

    def test_the_url_follows_the_contract_path(self) -> None:
        transport = FakeTransport([json_response(_ENTITLEMENT)])
        client, _ = _client(transport)

        client.check_entitlement()

        assert transport.calls[0]["url"] == (
            f"https://platform.example/api/v1/organizations/{ORGANIZATION_ID}"
            f"/projects/{PROJECT_ID}/entitlement"
        )

    def test_every_request_carries_a_timeout(self) -> None:
        transport = FakeTransport([json_response(_ENTITLEMENT)])
        client, _ = _client(transport)

        client.check_entitlement()

        assert transport.calls[0]["timeout_seconds"] > 0


class TestRetryWindow:
    """The bounded retry window."""

    def test_the_backoff_schedule_matches_the_attempt_count(self) -> None:
        assert len(RETRY_BACKOFF_SECONDS) == MAX_ATTEMPTS - 1

    def test_a_transport_failure_is_retried_to_exhaustion(self) -> None:
        transport = FakeTransport([TransportError("down") for _ in range(MAX_ATTEMPTS)])
        client, slept = _client(transport)

        with pytest.raises(TransportError):
            client.check_entitlement()

        assert len(transport.calls) == MAX_ATTEMPTS
        assert slept == list(RETRY_BACKOFF_SECONDS)

    def test_a_recovered_request_stops_retrying(self) -> None:
        transport = FakeTransport([TransportError("down"), json_response(_ENTITLEMENT)])
        client, slept = _client(transport)

        assert client.check_entitlement().state == "entitled"
        assert len(transport.calls) == 2
        assert slept == [RETRY_BACKOFF_SECONDS[0]]

    def test_a_first_attempt_success_never_sleeps(self) -> None:
        transport = FakeTransport([json_response(_ENTITLEMENT)])
        client, slept = _client(transport)

        client.check_entitlement()

        assert slept == []

    def test_a_rate_limit_is_retried(self) -> None:
        transport = FakeTransport(
            [json_response({}, status=429), json_response(_ENTITLEMENT)]
        )
        client, _ = _client(transport)

        assert client.check_entitlement().state == "entitled"

    def test_a_server_error_is_retried(self) -> None:
        transport = FakeTransport(
            [json_response({}, status=503), json_response(_ENTITLEMENT)]
        )
        client, _ = _client(transport)

        assert client.check_entitlement().state == "entitled"

    def test_an_exhausted_retryable_status_is_returned_not_raised(self) -> None:
        """After the window, a `429` is a protocol error naming the
        status, not a `TransportError` -- the service answered, it just
        kept saying no."""

        transport = FakeTransport([json_response({}, status=429) for _ in range(3)])
        client, _ = _client(transport)

        with pytest.raises(PlatformProtocolError, match="429"):
            client.check_entitlement()

    def test_a_bad_request_is_not_retried(self) -> None:
        """A `400` is still a `400` three seconds later. Retrying it wastes
        CI time and looks like abuse to whatever is counting."""

        transport = FakeTransport([json_response({}, status=400)])
        client, slept = _client(transport)

        with pytest.raises(PlatformProtocolError):
            client.check_entitlement()

        assert len(transport.calls) == 1
        assert slept == []

    def test_an_unauthorized_response_is_raised_immediately(self) -> None:
        transport = FakeTransport([json_response({}, status=401)])
        client, _ = _client(transport)

        with pytest.raises(PlatformAuthError, match="CONTROLLOOP_TEAM_TOKEN"):
            client.check_entitlement()

        assert len(transport.calls) == 1

    def test_an_auth_error_never_repeats_the_token(self) -> None:
        transport = FakeTransport([json_response({}, status=401)])
        client, _ = _client(transport)

        with pytest.raises(PlatformAuthError) as error:
            client.check_entitlement()

        assert TOKEN not in str(error.value)


class TestResponseValidation:
    """Responses are hostile input."""

    def test_a_non_json_body_is_a_protocol_error(self) -> None:
        transport = FakeTransport([HttpResponse(status=200, body=b"<html>")])
        client, _ = _client(transport)

        with pytest.raises(PlatformProtocolError, match="JSON"):
            client.check_entitlement()

    def test_a_missing_required_field_is_a_protocol_error(self) -> None:
        transport = FakeTransport([json_response({"state": "entitled"})])
        client, _ = _client(transport)

        with pytest.raises(PlatformProtocolError, match="Entitlement"):
            client.check_entitlement()

    def test_an_undeclared_field_is_refused_not_ignored(self) -> None:
        """`extra="forbid"`: a field the contract never declared is how a
        payload would smuggle content past every per-field check."""

        transport = FakeTransport(
            [json_response({**_ENTITLEMENT, "surprise": "value"})]
        )
        client, _ = _client(transport)

        with pytest.raises(PlatformProtocolError):
            client.check_entitlement()

    def test_a_server_error_message_is_never_echoed(self) -> None:
        """The failure this prevents: an endpoint returning attacker-chosen
        text that the CLI faithfully prints into a CI log."""

        canary = "ghp_" + "z" * 36
        transport = FakeTransport(
            [
                json_response(
                    {"error": {"code": "boom", "message": canary}}, status=500
                )
                for _ in range(3)
            ]
        )
        client, _ = _client(transport)

        with pytest.raises(PlatformProtocolError) as error:
            client.check_entitlement()

        assert canary not in str(error.value)

    def test_a_list_response_of_the_wrong_shape_is_refused(self) -> None:
        transport = FakeTransport([json_response({"not": "a list"})])
        client, _ = _client(transport)

        with pytest.raises(PlatformProtocolError, match="list"):
            client.fetch_active_exceptions()

    def test_a_list_element_of_the_wrong_shape_is_refused(self) -> None:
        transport = FakeTransport([json_response([{"finding_fingerprint": "f"}])])
        client, _ = _client(transport)

        with pytest.raises(PlatformProtocolError):
            client.fetch_active_exceptions()


class TestEffectivePolicy:
    def test_a_policy_is_parsed_with_its_etag(self) -> None:
        transport = FakeTransport([json_response(_POLICY, headers={"ETag": '"v7"'})])
        client, _ = _client(transport)

        fetch = client.fetch_effective_policy()

        assert fetch.not_modified is False
        assert fetch.etag == '"v7"'
        assert fetch.policy is not None
        assert fetch.policy.organization_bundle_version == "7"

    def test_a_rule_action_is_parsed(self) -> None:
        policy = {
            **_POLICY,
            "rules": [
                {
                    "rule_id": "policy.undeclared-tools",
                    "enabled": True,
                    "severity_floor": "medium",
                    "action": "warn",
                    "mandatory": False,
                }
            ],
        }
        transport = FakeTransport([json_response(policy)])
        client, _ = _client(transport)

        fetch = client.fetch_effective_policy()

        assert fetch.policy is not None
        assert fetch.policy.rules[0].action == "warn"

    def test_an_etag_is_sent_as_if_none_match(self) -> None:
        transport = FakeTransport([HttpResponse(status=304, body=b"")])
        client, _ = _client(transport)

        client.fetch_effective_policy(etag='"v7"')

        assert transport.calls[0]["headers"]["If-None-Match"] == '"v7"'

    def test_not_modified_returns_no_body_and_keeps_the_etag(self) -> None:
        transport = FakeTransport([HttpResponse(status=304, body=b"")])
        client, _ = _client(transport)

        fetch = client.fetch_effective_policy(etag='"v7"')

        assert fetch.not_modified is True
        assert fetch.policy is None
        assert fetch.etag == '"v7"'

    def test_no_etag_sends_no_conditional_header(self) -> None:
        transport = FakeTransport([json_response(_POLICY)])
        client, _ = _client(transport)

        client.fetch_effective_policy()

        assert "If-None-Match" not in transport.calls[0]["headers"]


class TestActiveExceptions:
    def test_exceptions_are_parsed(self) -> None:
        transport = FakeTransport(
            [
                json_response(
                    [
                        {
                            "finding_fingerprint": "clp:finding:1",
                            "expires_at": "2026-12-01T00:00:00Z",
                        }
                    ]
                )
            ]
        )
        client, _ = _client(transport)

        exceptions = client.fetch_active_exceptions()

        assert len(exceptions) == 1
        assert exceptions[0].finding_fingerprint == "clp:finding:1"

    def test_an_empty_list_is_valid(self) -> None:
        transport = FakeTransport([json_response([])])
        client, _ = _client(transport)

        assert client.fetch_active_exceptions() == ()


class TestIngestion:
    def test_an_envelope_is_posted_as_json(self) -> None:
        transport = FakeTransport(
            [json_response({"scan_id": PROJECT_ID, "duplicate": False}, status=202)]
        )
        client, _ = _client(transport)
        payload = json.dumps({"envelope_version": "1.0.0"}).encode()

        accepted = client.ingest_envelope(payload)

        assert transport.calls[0]["method"] == "POST"
        assert transport.calls[0]["body"] == payload
        assert transport.calls[0]["headers"]["Content-Type"] == "application/json"
        assert accepted.duplicate is False

    def test_a_replay_surfaces_duplicate_rather_than_hiding_it(self) -> None:
        """Resubmitting the same envelope is idempotent end to end, and the
        client reports that rather than presenting a replay as a fresh
        scan."""

        transport = FakeTransport(
            [json_response({"scan_id": PROJECT_ID, "duplicate": True}, status=202)]
        )
        client, _ = _client(transport)

        assert client.ingest_envelope(b"{}").duplicate is True

    def test_the_same_bytes_are_sent_for_a_replay(self) -> None:
        transport = FakeTransport(
            [
                json_response({"scan_id": PROJECT_ID, "duplicate": False}, status=202),
                json_response({"scan_id": PROJECT_ID, "duplicate": True}, status=202),
            ]
        )
        client, _ = _client(transport)

        client.ingest_envelope(b'{"a":1}')
        client.ingest_envelope(b'{"a":1}')

        assert transport.calls[0]["body"] == transport.calls[1]["body"]
