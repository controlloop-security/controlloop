"""Team-tier platform integration for `controlloop gate`.

This package is the CLI's entire paid-tier surface: everything that talks
to the ControlLoop platform lives here, and nothing outside it makes a
network call. It has four module sets:

- `envelope`: render the sanitized scan
  envelope and submit it to the ingestion endpoint.
- `entitlement`: verify a project may be gated
  as paid before any paid behavior runs.
- `policy`, `exceptions`, `cache`: fetch the
  organization bundle and active exceptions, merge strengthen-only with
  repository policy, and honor unexpired exceptions by fingerprint.
- `config`: the one documented configuration
  surface all three read.

## The three invariants this package exists to preserve

**Community is never degraded.** `resolve_team_config` returns `None`
whenever `team_enabled` is false, and every caller in
`controlloop.cli` is written so that `None` means the entire Team code
path is skipped -- not attempted and swallowed, not attempted with a
short timeout, but never entered. `tests/conftest.py`'s autouse
fixture denies socket access for the whole test suite, so a Team code
path accidentally reached with Team off does not produce a subtly
different result; it raises immediately and fails the test.

**Every network effect is injected.** No module here constructs a real
transport. `transport.HttpTransport` is a protocol; `UrllibTransport` is
its one real implementation, and only `controlloop.cli` builds one. This
is the same discipline `controlloop.config` already follows for the
process environment, and it is what lets the offline harness stay honest
while these modules are still fully tested.

**Verdict-affecting logic is pure.** The merge (`policy.merge_policy`),
exception application (`exceptions.apply_exceptions`), and envelope
rendering (`envelope.render_envelope`) read no clock, no environment, and
no network. Time enters only as an explicitly passed evaluation instant,
and the retry schedule is fixed rather than jittered, so two runs on the
same inputs produce the same verdict and the same bytes.

## What this package deliberately does not do

It does not decide *whether* a verdict blocks -- `controlloop.policy` and
`controlloop.cli` still own that. It contributes inputs (an effective
policy, a set of honored exceptions) and one hard stop (a not-entitled
project exits 4). It also never persists, logs, or transmits anything the
envelope schema does not declare; see `docs/reference/team-envelope.md`
for the enumerated contents and `envelope.py` for the enforcement.
"""

from __future__ import annotations

from controlloop.team.config import (
    TeamConfig,
    TeamConfigError,
    TeamFailMode,
    resolve_team_config,
)

__all__ = [
    "TeamConfig",
    "TeamConfigError",
    "TeamFailMode",
    "resolve_team_config",
]
