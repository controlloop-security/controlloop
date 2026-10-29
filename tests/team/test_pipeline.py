"""Tests for the Team gate pipeline.

The modules below this one are pure and were tested in isolation. This
file tests the thing that actually decides what happens: the order the
steps run in, and what each failure does to the run.

Three properties get the most attention, because each is a requirement
whose failure mode is silent:

- **Entitlement is checked first.** A not-entitled
  project must make no policy request at all, which is asserted by
  counting requests, not by reading the code.
- **The fail mode is honored**, in both directions, for an unreachable
  service and for a stale cache.
- **Upload never changes the verdict.** Every upload
  failure returns a message rather than raising.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from factories import (
    PROJECT_ID,
    FakeTransport,
    json_response,
    make_team_config,
    recording_sleeper,
)

from controlloop.team import cache, pipeline
from controlloop.team.client import PlatformClient
from controlloop.team.config import TeamFailMode
from controlloop.team.entitlement import EntitlementState
from controlloop.team.envelope import RuleOverride, ScanEnvelope
from controlloop.team.exceptions import ExceptionRecord, ExceptionState
from controlloop.team.policy import RuleSpec
from controlloop.team.transport import HttpResponse, TransportError

_NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=UTC)

_ENTITLED = {
    "state": "entitled",
    "project_id": PROJECT_ID,
    "checked_at": "2026-09-02T12:00:00Z",
    "cache_seconds": 300,
}
_NOT_ENTITLED = {**_ENTITLED, "state": "not_entitled"}

_POLICY = {
    "project_id": PROJECT_ID,
    "organization_bundle_version": "7",
    "merge_semantics_version": "1.0.0",
    "rules": [
        {"rule_id": "org.mandatory", "enabled": True, "mandatory": True},
        {"rule_id": "org.optional", "enabled": True, "mandatory": False},
    ],
    "approved_components": [],
    "computed_at": "2026-09-02T12:00:00Z",
}


def _client(transport: FakeTransport) -> PlatformClient:
    sleep, _ = recording_sleeper()
    return PlatformClient(config=make_team_config(), transport=transport, sleep=sleep)


def _prepare(
    transport: FakeTransport,
    root: Path,
    *,
    fail_mode: TeamFailMode = TeamFailMode.CLOSED,
    disabled: frozenset[str] = frozenset(),
    now: datetime = _NOW,
) -> pipeline.TeamPreparation:
    config = make_team_config(fail_mode=fail_mode)
    sleep, _ = recording_sleeper()
    return pipeline.prepare(
        config=config,
        client=PlatformClient(config=config, transport=transport, sleep=sleep),
        repository_root=root,
        repository_disabled_rules=disabled,
        now=now,
    )


class TestEntitlementIsFirst:
    """No partial paid behavior."""

    def test_a_not_entitled_project_makes_no_further_request(
        self, tmp_path: Path
    ) -> None:
        """Counted, not inferred: exactly one request leaves the machine,
        and it is the entitlement check."""

        transport = FakeTransport([json_response(_NOT_ENTITLED)])

        preparation = _prepare(transport, tmp_path)

        assert preparation.decision.proceed is False
        assert preparation.decision.exit_code is not None
        assert int(preparation.decision.exit_code) == 4
        assert len(transport.calls) == 1
        assert transport.calls[0]["url"].endswith("/entitlement")

    def test_a_not_entitled_project_fetches_no_policy_and_no_exceptions(
        self, tmp_path: Path
    ) -> None:
        transport = FakeTransport([json_response(_NOT_ENTITLED)])

        preparation = _prepare(transport, tmp_path)

        assert preparation.merge is None
        assert preparation.exceptions == ()
        assert not (tmp_path / cache.CACHE_DIRECTORY).exists()

    def test_a_rejected_token_stops_the_run(self, tmp_path: Path) -> None:
        transport = FakeTransport([json_response({}, status=401)])

        preparation = _prepare(transport, tmp_path)

        assert preparation.decision.proceed is False
        assert len(transport.calls) == 1

    def test_an_entitled_project_continues(self, tmp_path: Path) -> None:
        transport = FakeTransport(
            [json_response(_ENTITLED), json_response(_POLICY), json_response([])]
        )

        preparation = _prepare(transport, tmp_path)

        assert preparation.decision.proceed is True
        assert preparation.decision.state is EntitlementState.ENTITLED
        assert preparation.merge is not None
        assert preparation.organization_bundle_version == "7"


class TestFailMode:
    """The configured fail mode, in both directions."""

    def test_an_unreachable_service_stops_a_fail_closed_gate(
        self, tmp_path: Path
    ) -> None:
        transport = FakeTransport([TransportError("down") for _ in range(3)])

        preparation = _prepare(transport, tmp_path, fail_mode=TeamFailMode.CLOSED)

        assert preparation.decision.proceed is False
        assert preparation.decision.state is EntitlementState.UNREACHABLE

    def test_an_unreachable_service_continues_a_fail_open_gate(
        self, tmp_path: Path
    ) -> None:
        transport = FakeTransport(
            [TransportError("down") for _ in range(3)]
            + [TransportError("down") for _ in range(3)]
            + [TransportError("down") for _ in range(3)]
        )

        preparation = _prepare(transport, tmp_path, fail_mode=TeamFailMode.OPEN)

        assert preparation.decision.proceed is True
        assert preparation.merge is None
        assert preparation.policy_source == pipeline.SOURCE_NONE

    def test_a_missing_bundle_stops_a_fail_closed_gate(self, tmp_path: Path) -> None:
        """Entitlement answered, but the policy bundle did not. A gate that
        cannot learn its policy must not report a verdict about it."""

        transport = FakeTransport(
            [json_response(_ENTITLED)] + [TransportError("down") for _ in range(3)]
        )

        preparation = _prepare(transport, tmp_path, fail_mode=TeamFailMode.CLOSED)

        assert preparation.decision.proceed is False
        assert "policy bundle" in preparation.decision.message

    def test_a_missing_bundle_continues_a_fail_open_gate_on_repository_policy(
        self, tmp_path: Path
    ) -> None:
        transport = FakeTransport(
            [json_response(_ENTITLED)]
            + [TransportError("down") for _ in range(3)]
            + [TransportError("down") for _ in range(3)]
        )

        preparation = _prepare(transport, tmp_path, fail_mode=TeamFailMode.OPEN)

        assert preparation.decision.proceed is True
        assert preparation.disabled_rule_ids() is None
        assert preparation.severity_floors() == {}


class TestPolicyCaching:
    """Policy responses are cached, revalidated, and degrade safely."""

    def test_a_first_fetch_populates_the_cache(self, tmp_path: Path) -> None:
        transport = FakeTransport(
            [
                json_response(_ENTITLED),
                json_response(_POLICY, headers={"ETag": '"v7"'}),
                json_response([]),
            ]
        )

        preparation = _prepare(transport, tmp_path)

        assert preparation.policy_source == pipeline.SOURCE_FETCHED
        entry = cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300)
        assert entry is not None
        assert entry.etag == '"v7"'

    def test_a_fresh_cache_makes_no_policy_request(self, tmp_path: Path) -> None:
        """The point of the cache: a gate on every push must not refetch a
        bundle that changes a few times a month.

        Note what is *not* skipped. The exception list is fetched anyway,
        because a published bundle version is immutable while an approval
        list is live -- a revoked exception that kept suppressing a
        finding for the rest of a cache lifetime would be a security
        control silently continuing to not apply. So a fully cached run
        still makes two requests, and neither of them is the policy read.
        """

        cache.write(tmp_path, "policy", payload=_POLICY, etag='"v7"', now=_NOW)
        cache.write(tmp_path, "exceptions", payload=[], etag=None, now=_NOW)
        transport = FakeTransport([json_response(_ENTITLED), json_response([])])

        preparation = _prepare(transport, tmp_path)

        assert preparation.policy_source == pipeline.SOURCE_CACHE
        assert [call["url"].rsplit("/", 1)[-1] for call in transport.calls] == [
            "entitlement",
            "active-exceptions",
        ]

    def test_a_revoked_exception_stops_applying_on_the_next_run(
        self, tmp_path: Path
    ) -> None:
        """The reason the exception list is never served from a fresh
        cache. An organization that revokes an approval must have that
        take effect on the next gate, not up to `team_policy_cache_seconds`
        later."""

        cache.write(
            tmp_path,
            "exceptions",
            payload=[
                {
                    "finding_fingerprint": "clp:finding:1",
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            ],
            etag=None,
            now=_NOW,
        )
        cache.write(tmp_path, "policy", payload=_POLICY, etag='"v7"', now=_NOW)
        transport = FakeTransport([json_response(_ENTITLED), json_response([])])

        preparation = _prepare(transport, tmp_path)

        assert preparation.exceptions == ()

    def test_a_stale_cache_revalidates_with_its_etag(self, tmp_path: Path) -> None:
        cache.write(tmp_path, "policy", payload=_POLICY, etag='"v7"', now=_NOW)
        later = _NOW + timedelta(hours=1)
        transport = FakeTransport(
            [
                json_response(_ENTITLED),
                HttpResponse(status=304, body=b""),
                json_response([]),
            ]
        )

        preparation = _prepare(transport, tmp_path, now=later)

        assert preparation.policy_source == pipeline.SOURCE_CACHE
        assert transport.calls[1]["headers"]["If-None-Match"] == '"v7"'

    def test_a_stale_cache_is_used_when_the_service_is_unreachable(
        self, tmp_path: Path
    ) -> None:
        cache.write(tmp_path, "policy", payload=_POLICY, etag='"v7"', now=_NOW)
        later = _NOW + timedelta(days=3)
        transport = FakeTransport(
            [json_response(_ENTITLED)]
            + [TransportError("down") for _ in range(3)]
            + [TransportError("down") for _ in range(3)]
        )

        preparation = _prepare(
            transport, tmp_path, fail_mode=TeamFailMode.OPEN, now=later
        )

        assert preparation.policy_source == pipeline.SOURCE_STALE_CACHE
        assert preparation.merge is not None
        assert any("cached copy" in note for note in preparation.notes)

    def test_a_corrupt_cache_is_a_miss_not_a_failure(self, tmp_path: Path) -> None:
        path = tmp_path / cache.CACHE_DIRECTORY / "policy.json"
        path.parent.mkdir(parents=True)
        path.write_text("{ not json")
        transport = FakeTransport(
            [json_response(_ENTITLED), json_response(_POLICY), json_response([])]
        )

        preparation = _prepare(transport, tmp_path)

        assert preparation.policy_source == pipeline.SOURCE_FETCHED


class TestExceptions:
    def test_exceptions_are_fetched_and_parsed(self, tmp_path: Path) -> None:
        transport = FakeTransport(
            [
                json_response(_ENTITLED),
                json_response(_POLICY),
                json_response(
                    [
                        {
                            "finding_fingerprint": "clp:finding:1",
                            "expires_at": "2026-12-01T00:00:00Z",
                        }
                    ]
                ),
            ]
        )

        preparation = _prepare(transport, tmp_path)

        assert len(preparation.exceptions) == 1
        assert preparation.exceptions[0].expires_at.tzinfo is not None

    def test_a_naive_timestamp_is_read_as_utc(self, tmp_path: Path) -> None:
        """Not as local time: the comparison instant is UTC, and mixing the
        two would make an exception expire at a different moment depending
        on the runner's timezone."""

        transport = FakeTransport(
            [
                json_response(_ENTITLED),
                json_response(_POLICY),
                json_response(
                    [
                        {
                            "finding_fingerprint": "clp:finding:1",
                            "expires_at": "2026-12-01T00:00:00",
                        }
                    ]
                ),
            ]
        )

        preparation = _prepare(transport, tmp_path)

        assert preparation.exceptions[0].expires_at.tzinfo is UTC

    def test_an_unparseable_expiry_drops_the_exception(self, tmp_path: Path) -> None:
        """An exception whose expiry cannot be established cannot be shown
        to be live, and honoring it would suppress a finding on the
        strength of an unreadable date."""

        transport = FakeTransport(
            [
                json_response(_ENTITLED),
                json_response(_POLICY),
                json_response(
                    [
                        {
                            "finding_fingerprint": "clp:finding:1",
                            "expires_at": "whenever",
                        }
                    ]
                ),
            ]
        )

        preparation = _prepare(transport, tmp_path)

        assert preparation.exceptions == ()


class TestRepositoryDelta:
    def test_disabled_rules_become_the_delta(self) -> None:
        delta = pipeline.repository_delta_from(frozenset({"b.rule", "a.rule"}))

        assert [spec.rule_id for spec in delta] == ["a.rule", "b.rule"]
        assert all(spec.enabled is False for spec in delta)

    def test_an_empty_delta_is_omitted_from_the_envelope(self) -> None:
        assert pipeline.delta_for_envelope(()) is None

    def test_a_delta_renders_as_rule_overrides(self) -> None:
        rendered = pipeline.delta_for_envelope((RuleSpec("a.rule", enabled=False),))

        assert rendered is not None
        assert rendered.rules == (RuleOverride(rule_id="a.rule", enabled=False),)

    def test_the_merge_refuses_a_disable_of_a_mandatory_rule(
        self, tmp_path: Path
    ) -> None:
        """End to end through the pipeline: a repository disabling a
        mandatory organization rule does not get that rule disabled."""

        transport = FakeTransport(
            [json_response(_ENTITLED), json_response(_POLICY), json_response([])]
        )

        preparation = _prepare(
            transport, tmp_path, disabled=frozenset({"org.mandatory"})
        )

        assert preparation.merge is not None
        assert preparation.merge.rejections
        assert preparation.disabled_rule_ids() == frozenset()

    def test_the_merge_accepts_a_disable_of_a_non_mandatory_rule(
        self, tmp_path: Path
    ) -> None:
        transport = FakeTransport(
            [json_response(_ENTITLED), json_response(_POLICY), json_response([])]
        )

        preparation = _prepare(
            transport, tmp_path, disabled=frozenset({"org.optional"})
        )

        assert preparation.merge is not None
        assert not preparation.merge.rejections
        assert preparation.disabled_rule_ids() == frozenset({"org.optional"})


class TestEvidence:
    def test_evidence_records_the_platform_contribution(self, tmp_path: Path) -> None:
        transport = FakeTransport(
            [json_response(_ENTITLED), json_response(_POLICY), json_response([])]
        )
        preparation = _prepare(
            transport, tmp_path, disabled=frozenset({"org.optional"})
        )
        outcome = pipeline.apply_team_exceptions((), preparation, now=_NOW)

        evidence = pipeline.build_evidence(preparation, outcome)

        assert evidence is not None
        assert evidence.organization_bundle_version == "7"
        assert evidence.merge_semantics_version == "1.2.0"
        assert evidence.policy_source == pipeline.SOURCE_FETCHED
        assert evidence.entitlement_state == "entitled"
        assert [rule.rule_id for rule in evidence.repository_delta] == ["org.optional"]
        assert {rule.rule_id for rule in evidence.effective_policy} == {
            "org.mandatory",
            "org.optional",
        }

    def test_no_merge_means_no_evidence_block(self, tmp_path: Path) -> None:
        transport = FakeTransport(
            [json_response(_ENTITLED)]
            + [TransportError("down") for _ in range(3)]
            + [TransportError("down") for _ in range(3)]
        )
        preparation = _prepare(transport, tmp_path, fail_mode=TeamFailMode.OPEN)
        outcome = pipeline.apply_team_exceptions((), preparation, now=_NOW)

        assert pipeline.build_evidence(preparation, outcome) is None

    def test_evidence_carries_exception_records(self, tmp_path: Path) -> None:
        transport = FakeTransport(
            [json_response(_ENTITLED), json_response(_POLICY), json_response([])]
        )
        preparation = _prepare(transport, tmp_path)
        outcome = pipeline.apply_team_exceptions((), preparation, now=_NOW)
        record = ExceptionRecord(
            finding_fingerprint="clp:finding:1",
            expires_at=_NOW,
            state=ExceptionState.EXPIRED,
        )

        evidence = pipeline.build_evidence(
            preparation,
            type(outcome)(records=(record,), effective_findings=()),
        )

        assert evidence is not None
        assert evidence.applied_exceptions == (record,)

    def test_evidence_records_no_tenant_identifiers(self, tmp_path: Path) -> None:
        """The bundle version makes a verdict re-derivable; the tenant's
        identifiers do not, and an evidence file is something people
        attach to tickets."""

        transport = FakeTransport(
            [json_response(_ENTITLED), json_response(_POLICY), json_response([])]
        )
        preparation = _prepare(transport, tmp_path)
        outcome = pipeline.apply_team_exceptions((), preparation, now=_NOW)

        evidence = pipeline.build_evidence(preparation, outcome)

        assert evidence is not None
        serialized = evidence.model_dump_json()
        assert PROJECT_ID not in serialized


class TestUpload:
    """Upload failures are reported distinctly, never altering the verdict."""

    def _envelope(self) -> ScanEnvelope:
        from factories import make_document, make_finding

        from controlloop.reporting.terminal import Verdict
        from controlloop.team.envelope import render_envelope

        return render_envelope(
            document=make_document(),
            findings=(make_finding(),),
            verdict=Verdict.PASSED,
            scanner_version="0.1.0",
            policy_version="1.0.0",
        )

    def test_a_successful_upload_reports_the_scan_id(self) -> None:
        transport = FakeTransport(
            [json_response({"scan_id": PROJECT_ID, "duplicate": False}, status=202)]
        )

        message = pipeline.upload(client=_client(transport), envelope=self._envelope())

        assert "accepted as scan" in message
        assert PROJECT_ID in message

    def test_a_replay_is_reported_as_a_replay(self) -> None:
        transport = FakeTransport(
            [json_response({"scan_id": PROJECT_ID, "duplicate": True}, status=202)]
        )

        message = pipeline.upload(client=_client(transport), envelope=self._envelope())

        assert "replay" in message

    @pytest.mark.parametrize(
        "scripted",
        [
            [TransportError("down") for _ in range(3)],
            [json_response({}, status=401)],
            [json_response({}, status=400)],
        ],
        ids=["unreachable", "rejected-token", "bad-request"],
    )
    def test_every_upload_failure_returns_a_message_and_never_raises(
        self, scripted: list[HttpResponse | TransportError]
    ) -> None:
        transport = FakeTransport(list(scripted))

        message = pipeline.upload(client=_client(transport), envelope=self._envelope())

        assert "failed" in message

    def test_an_unreachable_upload_says_the_verdict_is_unaffected(self) -> None:
        transport = FakeTransport([TransportError("down") for _ in range(3)])

        message = pipeline.upload(client=_client(transport), envelope=self._envelope())

        assert "verdict is unaffected" in message

    def test_the_same_scan_produces_the_same_bytes_twice(self) -> None:
        """The client-side half of ingestion idempotency: the server can
        only recognize a replay if the CLI sends the same thing."""

        transport = FakeTransport(
            [
                json_response({"scan_id": PROJECT_ID, "duplicate": False}, status=202),
                json_response({"scan_id": PROJECT_ID, "duplicate": True}, status=202),
            ]
        )
        client = _client(transport)

        pipeline.upload(client=client, envelope=self._envelope())
        pipeline.upload(client=client, envelope=self._envelope())

        assert transport.calls[0]["body"] == transport.calls[1]["body"]
