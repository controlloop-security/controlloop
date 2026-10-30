"""`controlloop gate`-level determinism regression suite.

`determinism_support.py` already proves `compute_digest`
over a raw `ACBOMDocument` is stable across repeated runs, separate
processes, `PYTHONHASHSEED`, locale, timezone, and filesystem iteration
order. This module proves the same guarantee one layer higher, through
the real CLI end to end (`main()`, the real redaction-wrapped entry
point) -- the guarantee users rely on is about "verdicts," not only
digests, and `gate` is the command that computes one.

Every subprocess invocation here runs `controlloop gate` via
`[sys.executable, "-c", "from controlloop.cli import main; main()",
"gate", ...]`, mirroring `determinism_support.digest_in_subprocess`'s own
`shell=False`, bounded-`timeout` construction -- never a network call,
so unaffected by (and does not need to participate in) `conftest.py`'s
autouse offline-denial fixture, the same reasoning that module's own
docstring already gives.

"Both supported architectures" is addressed by
`TestGoldenDigestIsArchitectureIndependent`: a literal, hardcoded
expected digest (computed once, real, recorded below) that this test
asserts on every run. That single assertion passes on two real,
different environments -- macOS on arm64 and, independently, `ci.yml`'s
`ubuntu-latest` runner -- which is what the cross-architecture claim
needs proven, achieved honestly without a purpose-built multi-arch
matrix.

Privacy: every fixture here is synthetic (a fabricated agent card and
manifest, no real repository, credential, or customer content), and the
new surface exercised is `gate`'s own already-canaried real `main()`
boundary -- no new output path, so no new redaction canary entry is
needed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

_GATE_ENTRY = "from controlloop.cli import main; main()"

#: Computed once against a fixed, synthetic fixture and recorded here as
#: a literal value -- the same "golden, hardcoded expected digest"
#: pattern the golden baselines already established. Verified stable
#: across 4 repeated local runs before being hardcoded.
_GOLDEN_VERDICT = "passed"
# Updated when ACBOMDocument.schema_url was added (1.0.0 -> 1.1.0): it
# changes every ACBOM's own canonical bytes, and therefore this digest,
# even though nothing about this fixture's own findings changed.
# Updated again for 1.1.0 -> 1.2.0, for the same reason: the schema version
# and URL are part of the canonical bytes.
# Updated for the 0.1.0 -> 0.1.1 release: the scanner version is part of
# the canonical bytes too, so every version bump changes this digest.
# Updated again for 0.1.1 -> 0.2.0, for the same reason.
# And for 0.2.0 -> 0.3.0.
# And for 0.3.0 -> 0.4.0.
# And for 0.4.0 -> 0.5.0.
# And for 0.5.0 -> 0.6.0.
# Stable across 3 repeated local runs before being recorded.
_GOLDEN_DIGEST = (
    "sha256:24c18130fb85ae3e36e391401ff9d620e842a9ac25b3999b72be318cc2f32c63"
)


def _write_golden_fixture(root: Path) -> None:
    """A fixed, single-file fixture with no ceiling and no git history --
    deliberately minimal, so its digest depends only on the fixture's own
    fixed bytes, never on git state or timing."""

    (root / "agent-card.json").write_text(
        '{"name": "report-agent", "skills": '
        '[{"id": "read-quarterly-metrics", "name": "read-quarterly-metrics"}]}'
    )


def _write_ceiling_breach_fixture(root: Path) -> None:
    """The `refund-agent`/`delete-database` shape already established across
    the existing tests -- reused here, not reinvented, for the repeated-run
    and cross-dimension tests below that do not need a literal golden
    digest, only self-consistency."""

    (root / "agent-card.json").write_text(
        json.dumps(
            {
                "name": "refund-agent",
                "skills": [{"id": "delete-database", "name": "delete-database"}],
            }
        )
    )
    (root / "controlloop.yaml").write_text(
        "schema_version: '1.0.0'\n"
        "owner: security-team\n"
        "ceilings:\n"
        "  - agent: refund-agent\n"
        "    prohibited_resources: [delete-database]\n"
    )


def _run_gate(
    repo: Path, evidence_path: Path, *, env: Mapping[str, str] | None = None
) -> tuple[str, str]:
    """Run `controlloop gate` against `repo` in a fresh child process
    (per-call, not memoized -- the whole point is proving independent
    invocations agree). Returns `(verdict, acbom_digest)` read back from
    the written evidence artifact. `env`, when given, is merged over
    (never replaces) a copy of the current process environment, so only
    the caller-specified keys actually vary between invocations --
    identical contract to `determinism_support.digest_in_subprocess`."""

    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _GATE_ENTRY,
            "gate",
            str(repo),
            "--evidence-path",
            str(evidence_path),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        env=merged_env,
        timeout=30,
        check=False,
        shell=False,
    )
    if not evidence_path.exists():
        raise RuntimeError(
            f"gate subprocess wrote no evidence artifact (exit {result.returncode}): "
            f"{result.stderr}"
        )
    artifact = json.loads(evidence_path.read_text())
    return artifact["verdict"], artifact["acbom_digest"]


class TestGoldenDigestIsArchitectureIndependent:
    """The literal golden digest is asserted directly, not merely compared
    to itself -- this is what makes the assertion meaningful across two
    genuinely different environments (a local development machine and CI)
    in a way a self-referential "matches run 1" comparison could not be."""

    def test_matches_the_recorded_golden_digest(self, tmp_path: Path) -> None:
        _write_golden_fixture(tmp_path)
        evidence_path = tmp_path / "evidence.json"

        verdict, digest = _run_gate(tmp_path, evidence_path)

        assert verdict == _GOLDEN_VERDICT
        assert digest == _GOLDEN_DIGEST


class TestRepeatedRunsInSeparateProcesses:
    """Repeated runs, each a genuinely separate process (`gate`
    has no meaningful "same process, repeated call" mode of its own --
    every real invocation is a fresh process), agree with each other."""

    def test_five_separate_processes_produce_identical_verdict_and_digest(
        self, tmp_path: Path
    ) -> None:
        # A disclosed interaction (`docs/reference/cli.md`'s `gate`
        # section): writing `--evidence-path` *inside*
        # the directory being scanned makes a later run see the earlier
        # run's own artifact as part of the repository, changing
        # `root_digest` between runs -- a real, already-documented
        # effect, not a determinism bug. Every multi-run test below
        # keeps the scanned `repo/` and its evidence files as siblings,
        # never nested, to avoid exercising it by accident.
        repo = tmp_path / "repo"
        repo.mkdir()
        _write_ceiling_breach_fixture(repo)

        results = [_run_gate(repo, tmp_path / f"e{i}.json") for i in range(5)]

        assert len(set(results)) == 1, (
            f"expected all 5 runs to agree, got distinct results: {set(results)}"
        )
        verdict, _ = results[0]
        assert verdict == "deployment_blocked"


class TestStableAcrossPythonHashSeed:
    """Stability under a differing `PYTHONHASHSEED`."""

    def test_hash_seed_zero_and_one_agree(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        _write_ceiling_breach_fixture(repo)

        seed_zero = _run_gate(repo, tmp_path / "e0.json", env={"PYTHONHASHSEED": "0"})
        seed_one = _run_gate(repo, tmp_path / "e1.json", env={"PYTHONHASHSEED": "1"})

        assert seed_zero == seed_one


class TestStableAcrossLocale:
    """Stability under a differing locale."""

    def test_c_and_posix_locale_agree(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        _write_ceiling_breach_fixture(repo)

        first = _run_gate(repo, tmp_path / "e0.json", env={"LC_ALL": "C", "LANG": "C"})
        second = _run_gate(
            repo, tmp_path / "e1.json", env={"LC_ALL": "POSIX", "LANG": "POSIX"}
        )

        assert first == second


class TestStableAcrossTimezone:
    """Stability under a differing timezone."""

    def test_utc_and_a_far_offset_timezone_agree(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        _write_ceiling_breach_fixture(repo)

        utc = _run_gate(repo, tmp_path / "e0.json", env={"TZ": "UTC"})
        offset = _run_gate(repo, tmp_path / "e1.json", env={"TZ": "Pacific/Kiritimati"})

        assert utc == offset


class TestStableAcrossFilesystemIterationOrder:
    """Stability under differing filesystem iteration order --
    grounded in the real repository walker (`walk_repository`) via a
    real `gate` invocation, one layer beyond
    `determinism_support.build_document_from_repository_walk`'s own
    library-level proof of the identical claim."""

    def test_creation_order_does_not_affect_the_result(self, tmp_path: Path) -> None:
        forward = tmp_path / "forward"
        forward.mkdir()
        (forward / "a-agent-card.json").write_text(
            json.dumps({"name": "a", "skills": []})
        )
        (forward / "z-agent-card.json").write_text(
            json.dumps({"name": "z", "skills": []})
        )

        reverse = tmp_path / "reverse"
        reverse.mkdir()
        (reverse / "z-agent-card.json").write_text(
            json.dumps({"name": "z", "skills": []})
        )
        (reverse / "a-agent-card.json").write_text(
            json.dumps({"name": "a", "skills": []})
        )

        forward_result = _run_gate(forward, tmp_path / "forward-evidence.json")
        reverse_result = _run_gate(reverse, tmp_path / "reverse-evidence.json")

        assert forward_result == reverse_result


def _write_undeclared_tool_fixture(root: Path) -> None:
    """A tool reachable but named in no ceiling and no declared-tools
    list -- produces exactly one MEDIUM `policy.undeclared-tools`
    finding and nothing else, verified directly to behave differently at
    `CONTROLLOOP_SEVERITY_THRESHOLD=medium` than at the product
    default (`high`): MEDIUM is below the default threshold (passes)
    but at or above an explicit `medium` threshold (blocks)."""

    (root / "agent-card.json").write_text(
        json.dumps(
            {
                "name": "refund-agent",
                "skills": [{"id": "delete-database", "name": "delete-database"}],
            }
        )
    )
    (root / "controlloop.yaml").write_text(
        "schema_version: '1.0.0'\nowner: security-team\n"
    )


class TestHarnessDetectsInjectedNonDeterminism:
    """A deliberately non-deterministic `gate` invocation is
    caught by this harness's own comparison -- proving the assertions
    above are a real, discriminating check, not one that would pass
    anything. Injected via `CONTROLLOOP_SEVERITY_THRESHOLD`, an
    existing, real configuration input (not a code patch), so this test
    exercises exactly the same subprocess path as every test above it,
    only with one run's own input deliberately varied."""

    def test_deliberately_varying_input_produces_a_detectable_mismatch(
        self, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        _write_undeclared_tool_fixture(repo)

        default_threshold = _run_gate(repo, tmp_path / "e0.json")
        medium_threshold = _run_gate(
            repo,
            tmp_path / "e1.json",
            env={"CONTROLLOOP_SEVERITY_THRESHOLD": "medium"},
        )

        assert default_threshold == ("passed", default_threshold[1])
        assert medium_threshold == ("deployment_blocked", default_threshold[1])
        # Both real, valid outcomes over the identical ACBOM digest --
        # the point is that the *verdict* differs, proving a harness
        # that only ever compared a run to itself would have caught
        # this, exactly the way the repeated-run tests above would have
        # caught a genuine non-determinism bug.
        assert default_threshold != medium_threshold


class TestOffline:
    """Positive control: `_run_gate`'s subprocess call still succeeds
    while this suite's autouse offline-denial fixture is active (it
    already is, for every test in this module, since it is autouse) --
    identical reasoning to `determinism_support.py`'s own `TestOffline`."""

    def test_subprocess_gate_call_succeeds_under_the_offline_harness(
        self, tmp_path: Path
    ) -> None:
        _write_golden_fixture(tmp_path)

        verdict, digest = _run_gate(tmp_path, tmp_path / "evidence.json")

        assert verdict == _GOLDEN_VERDICT
        assert digest == _GOLDEN_DIGEST


@pytest.mark.parametrize("dimension", ["hash_seed", "locale", "timezone"])
def test_module_documents_every_req2_dimension_with_a_real_test(
    dimension: str,
) -> None:
    """Structural guard: fails loudly if an environment dimension named in
    this module's own docstring is ever silently dropped from the test
    classes above, rather than the gap going unnoticed."""

    covering_class = {
        "hash_seed": TestStableAcrossPythonHashSeed,
        "locale": TestStableAcrossLocale,
        "timezone": TestStableAcrossTimezone,
    }[dimension]
    assert any(name.startswith("test_") for name in vars(covering_class))
