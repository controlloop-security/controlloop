"""The Team response cache.

A gate runs on every push. Refetching an organization policy bundle that
changes a few times a month, on every one of them, is a cost with no
benefit -- and it makes the platform a hard dependency of every build
rather than a soft one.

So policy reads are cached on disk, under the repository's own
`.controlloop/` directory, with two independent freshness mechanisms:

- **A documented lifetime.** `team_policy_cache_seconds` (default 300).
  Inside it, the cached bundle is used with no request at all.
- **Cache validation.** Past the lifetime, the stored `ETag` is sent as
  `If-None-Match`; a `304` refreshes the entry's timestamp without
  transferring or re-parsing anything.

## Stale-but-present is a fail-mode decision, not a cache decision

When the lifetime has passed and the service cannot be reached, this
module does not decide what happens. It reports that what it holds is
stale, and `controlloop.cli` applies `team_fail_mode`: `open` proceeds on
the stale bundle and says so; `closed` stops. That separation is
deliberate -- a cache that silently served indefinitely old policy would
turn "fail closed" into "fail open with extra steps," which is the failure
mode this whole design exists to avoid.

## Time is injected

`read` and `write` take the instant to compare against. This module reads
no clock, so the determinism harness can pin a gate to a fixed instant.

## What is stored, and what is not

Only what the platform published: the effective policy document and the
active exceptions, both already free of source code, prompts, and secret
values by the contract's own construction. **The project token is never
written to disk.** Neither is the entitlement answer -- it carries its own
short `cache_seconds` from the server and is re-asked each run, because a
subscription that lapsed an hour ago should not be honored from a file.

Every read treats the file as hostile input: unreadable, non-JSON,
wrong-shaped, or oversized content is a cache miss, never an exception
that fails a build. A corrupted cache must degrade to a refetch, not to a
broken gate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

#: Where a repository's Team cache lives. Inside the repository so it is
#: naturally scoped to the checkout and naturally discarded with it, and
#: under the existing `.controlloop/` directory rather than a new one.
CACHE_DIRECTORY: Final = Path(".controlloop") / "team-cache"

#: The stored document's own schema version, so a future change to the
#: cache's shape is a miss rather than a misparse.
CACHE_FORMAT_VERSION: Final = "1.0.0"

#: An upper bound on a cache file. A cache is a convenience; one that can
#: be made arbitrarily large by whatever wrote it is a liability.
MAX_CACHE_BYTES: Final = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CacheEntry:
    """One cached platform response.

    `fresh` is the only field a caller normally branches on: `True` means
    "use this and make no request," `False` means "revalidate, and if that
    fails, this is what stale looks like."
    """

    payload: Any
    etag: str | None
    stored_at: datetime
    fresh: bool


def _path(repository_root: Path, name: str) -> Path:
    return repository_root / CACHE_DIRECTORY / f"{name}.json"


def read(
    repository_root: Path,
    name: str,
    *,
    now: datetime,
    lifetime_seconds: int,
) -> CacheEntry | None:
    """Return the cached entry, or `None` for a miss.

    Every failure mode is a miss: no file, an unreadable file, a file
    larger than `MAX_CACHE_BYTES`, content that is not JSON, content whose
    shape or format version this module does not recognize, or a
    timestamp that cannot be parsed. None of them raise -- see the module
    docstring.
    """

    path = _path(repository_root, name)
    try:
        if path.stat().st_size > MAX_CACHE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None

    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None

    if not isinstance(document, dict):
        return None
    if document.get("format_version") != CACHE_FORMAT_VERSION:
        return None
    if "payload" not in document:
        return None

    stored_at_raw = document.get("stored_at")
    if not isinstance(stored_at_raw, str):
        return None
    try:
        stored_at = datetime.fromisoformat(stored_at_raw)
    except ValueError:
        return None

    etag = document.get("etag")
    if etag is not None and not isinstance(etag, str):
        return None

    age = (now - stored_at).total_seconds()
    # A negative age means the entry was written in this repository's
    # future -- a clock change, or a checkout copied between machines.
    # Treated as stale rather than fresh: the one thing that must not
    # happen is an unbounded "fresh" window opened by a bad timestamp.
    fresh = 0 <= age < lifetime_seconds

    return CacheEntry(
        payload=document["payload"],
        etag=etag,
        stored_at=stored_at,
        fresh=fresh,
    )


def write(
    repository_root: Path,
    name: str,
    *,
    payload: Any,
    etag: str | None,
    now: datetime,
) -> bool:
    """Store one response. Returns whether it was actually written.

    A cache that cannot be written is not an error: a read-only checkout,
    a full disk, or a sandboxed CI runner should refetch next time, not
    fail a build. The boolean lets a caller mention it at debug level
    without anything depending on it.
    """

    path = _path(repository_root, name)
    document = {
        "format_version": CACHE_FORMAT_VERSION,
        "stored_at": now.isoformat(),
        "etag": etag,
        "payload": payload,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    except (OSError, TypeError, ValueError):
        return False
    return True
