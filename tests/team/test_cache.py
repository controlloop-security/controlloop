"""Tests for the Team response cache.

The behavior that matters most here is the failure behavior. A cache is a
convenience; a cache that can fail a build is a liability. Every corrupt,
truncated, oversized, or unreadable state has to degrade to a miss, and
each of those states gets its own test rather than being covered by one
"malformed" case.

The freshness tests inject `now` rather than reading a clock -- the same
discipline as `apply_exceptions`, for the same reason.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from controlloop.team import cache

_NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=UTC)
_PAYLOAD = {"organization_bundle_version": "7", "rules": []}


class TestRoundTrip:
    def test_a_written_entry_reads_back(self, tmp_path: Path) -> None:
        assert cache.write(tmp_path, "policy", payload=_PAYLOAD, etag='"v7"', now=_NOW)

        entry = cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300)

        assert entry is not None
        assert entry.payload == _PAYLOAD
        assert entry.etag == '"v7"'
        assert entry.fresh is True

    def test_a_missing_entry_is_a_miss(self, tmp_path: Path) -> None:
        assert cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300) is None

    def test_entries_are_namespaced_by_name(self, tmp_path: Path) -> None:
        cache.write(tmp_path, "policy", payload=_PAYLOAD, etag=None, now=_NOW)

        assert (
            cache.read(tmp_path, "exceptions", now=_NOW, lifetime_seconds=300) is None
        )

    def test_the_cache_lives_under_the_repository(self, tmp_path: Path) -> None:
        cache.write(tmp_path, "policy", payload=_PAYLOAD, etag=None, now=_NOW)

        assert (tmp_path / cache.CACHE_DIRECTORY / "policy.json").is_file()


class TestFreshness:
    def test_an_entry_inside_its_lifetime_is_fresh(self, tmp_path: Path) -> None:
        cache.write(tmp_path, "policy", payload=_PAYLOAD, etag=None, now=_NOW)

        entry = cache.read(
            tmp_path,
            "policy",
            now=_NOW + timedelta(seconds=299),
            lifetime_seconds=300,
        )

        assert entry is not None
        assert entry.fresh is True

    def test_an_entry_at_its_lifetime_is_stale(self, tmp_path: Path) -> None:
        cache.write(tmp_path, "policy", payload=_PAYLOAD, etag=None, now=_NOW)

        entry = cache.read(
            tmp_path,
            "policy",
            now=_NOW + timedelta(seconds=300),
            lifetime_seconds=300,
        )

        assert entry is not None
        assert entry.fresh is False

    def test_a_stale_entry_is_still_returned(self, tmp_path: Path) -> None:
        """Stale-but-present is what the fail-open path uses. The cache
        reports staleness; it does not decide what to do about it."""

        cache.write(tmp_path, "policy", payload=_PAYLOAD, etag='"v7"', now=_NOW)

        entry = cache.read(
            tmp_path, "policy", now=_NOW + timedelta(days=30), lifetime_seconds=300
        )

        assert entry is not None
        assert entry.payload == _PAYLOAD
        assert entry.etag == '"v7"'

    def test_a_zero_lifetime_makes_everything_stale(self, tmp_path: Path) -> None:
        cache.write(tmp_path, "policy", payload=_PAYLOAD, etag=None, now=_NOW)

        entry = cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=0)

        assert entry is not None
        assert entry.fresh is False

    def test_an_entry_from_the_future_is_stale_not_fresh(self, tmp_path: Path) -> None:
        """A clock change or a checkout copied between machines must not
        open an unbounded "fresh" window."""

        cache.write(
            tmp_path,
            "policy",
            payload=_PAYLOAD,
            etag=None,
            now=_NOW + timedelta(days=1),
        )

        entry = cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300)

        assert entry is not None
        assert entry.fresh is False


class TestCorruptionDegradesToAMiss:
    """Every one of these must be a miss, never an exception that fails a
    build."""

    def _path(self, root: Path) -> Path:
        path = root / cache.CACHE_DIRECTORY / "policy.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def test_non_json_content(self, tmp_path: Path) -> None:
        self._path(tmp_path).write_text("not json at all")

        assert cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300) is None

    def test_json_that_is_not_an_object(self, tmp_path: Path) -> None:
        self._path(tmp_path).write_text("[1, 2, 3]")

        assert cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300) is None

    def test_a_wrong_format_version(self, tmp_path: Path) -> None:
        """A future change to the cache's shape is a miss, not a
        misparse."""

        self._path(tmp_path).write_text(
            json.dumps(
                {
                    "format_version": "99.0.0",
                    "stored_at": _NOW.isoformat(),
                    "payload": {},
                }
            )
        )

        assert cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300) is None

    def test_a_missing_payload(self, tmp_path: Path) -> None:
        self._path(tmp_path).write_text(
            json.dumps(
                {
                    "format_version": cache.CACHE_FORMAT_VERSION,
                    "stored_at": _NOW.isoformat(),
                }
            )
        )

        assert cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300) is None

    def test_an_unparseable_timestamp(self, tmp_path: Path) -> None:
        self._path(tmp_path).write_text(
            json.dumps(
                {
                    "format_version": cache.CACHE_FORMAT_VERSION,
                    "stored_at": "not a date",
                    "payload": {},
                }
            )
        )

        assert cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300) is None

    def test_a_non_string_timestamp(self, tmp_path: Path) -> None:
        self._path(tmp_path).write_text(
            json.dumps(
                {
                    "format_version": cache.CACHE_FORMAT_VERSION,
                    "stored_at": 12345,
                    "payload": {},
                }
            )
        )

        assert cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300) is None

    def test_a_non_string_etag(self, tmp_path: Path) -> None:
        self._path(tmp_path).write_text(
            json.dumps(
                {
                    "format_version": cache.CACHE_FORMAT_VERSION,
                    "stored_at": _NOW.isoformat(),
                    "etag": {"not": "a string"},
                    "payload": {},
                }
            )
        )

        assert cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300) is None

    def test_an_oversized_file(self, tmp_path: Path) -> None:
        self._path(tmp_path).write_text("x" * (cache.MAX_CACHE_BYTES + 1))

        assert cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300) is None

    def test_a_directory_where_the_file_should_be(self, tmp_path: Path) -> None:
        path = tmp_path / cache.CACHE_DIRECTORY / "policy.json"
        path.mkdir(parents=True)

        assert cache.read(tmp_path, "policy", now=_NOW, lifetime_seconds=300) is None


class TestWriteFailuresAreNotErrors:
    def test_an_unserializable_payload_returns_false(self, tmp_path: Path) -> None:
        assert not cache.write(
            tmp_path, "policy", payload={"bad": object()}, etag=None, now=_NOW
        )

    def test_an_unwritable_location_returns_false(self, tmp_path: Path) -> None:
        """A read-only checkout or a sandboxed runner should refetch next
        time, not fail a build."""

        blocker = tmp_path / cache.CACHE_DIRECTORY.parts[0]
        blocker.write_text("this is a file, not a directory")

        assert not cache.write(
            tmp_path, "policy", payload=_PAYLOAD, etag=None, now=_NOW
        )


class TestWhatIsNotCached:
    def test_the_cache_never_holds_a_token(self, tmp_path: Path) -> None:
        """A structural assertion on the module rather than on one write:
        nothing here has a parameter for a credential."""

        import inspect

        for function in (cache.read, cache.write):
            parameters = inspect.signature(function).parameters
            assert not any("token" in name or "secret" in name for name in parameters)
