"""Performance benchmark for `controlloop scan`.

The absolute SLA (p50 < 30s, p95 < 90s) and the regression check (a
regression beyond a defined margin fails CI) are two distinct
assertions, not one: the SLA targets are roughly 25-78x looser than the
measured performance (~1.2s on the development machine that produced
`baseline.json`), so an SLA-only check would never catch a real
regression until performance degraded by orders of magnitude. The
regression check runs separately against a small, git-committed
baseline (`baseline.json`), never auto-updated by CI -- only a human,
in a reviewed change, may revise it deliberately.

Methodology, disclosed rather than oversold: 15 timed invocations of
`controlloop scan`, each a genuinely separate subprocess (mirroring
`test_gate_determinism_regression.py`'s own pattern -- not an
in-process call). p50 is the median of the 15 durations; "p95"
is the empirical value at the ceil(0.95 * 15) = 14th position among
the sorted durations -- a coarse estimate over a small sample, not a
claim of statistical rigor.

The reference machine specification is queried live (CPU count, total
memory) rather than assumed, and printed alongside the raw durations
and computed percentiles on every run. `uv run pytest`'s default
invocation only surfaces this captured stdout for a *failing* test; a
human wanting to see it on a passing run can add `-s`.

History of the committed baseline and the margin, so the next person
reading a red run knows what was already tried:

- 2026-08-20: `baseline.json` measured on a 10-CPU
  arm64 development machine, p50 0.5086 s, p95 0.5785 s;
  `_REGRESSION_MARGIN` 2.0.
- Margin 2.0 -> 4.0 after five transient failures on the weaker
  GitHub-hosted legs. Baseline unchanged.
- `_SAMPLE_COUNT` 15 -> 20 so the p95 stops being the maximum sample.
  Baseline and margin unchanged; the evidence named re-measuring the
  baseline as the honest next step if the symptom returned in CI.
- 2026-10-18: it returned. The 2-vCPU `linux-x86_64` leg measured p50
  2.04-2.07 s against the 2.034 s limit (0.5086 s x 4.0) on `main` and
  on pull requests that changed no CLI code, while the other two legs
  passed. The question was whether the drift was expected work or an
  accidental regression, measured on one machine. Interleaved against
  the same generated repository on the same 10-CPU machine that produced
  the 2026-08-20 baseline, the August revision scanned at p50 0.84 s and
  `main` at p50 2.00 s (20 runs each), a 2.4x gap, with
  `controlloop.cli` import time unchanged (0.80 s vs 0.71 s under
  `-X importtime`). `cProfile` attributes the in-process gap
  (0.51 s -> 2.05 s): about +0.93 s from the adapters registered since, because every
  adapter walks the repository once through `walk_repository` (19 walks
  of ~455 entries now, 8 then, about 70 ms each on that machine: the
  seven agent-host adapters account for roughly 0.56 s of it and the
  three framework adapters of 2026-09-01 for roughly 0.21 s); about
  +0.61 s from the discovery-time secret scan (added 2026-08-21, the day
  after the baseline: it reads every text file and runs the
  credential-shape patterns over it); about +0.09 s from rule-pack
  safety validation and evaluation (18 rules vs 9). The Team sanction
  judgment costs nothing in a Community scan: with Team disabled that
  code path is never reached. No quadratic path, repeated file read, or
  per-call regex compile was found; the cost is linear in the adapter
  count, and one bounded walk per adapter is a design property older
  than the baseline, not a regression (sharing one walk across adapters
  is a follow-up optimization, not a fix). Verdict: expected work, so
  the baseline was re-measured rather than the scanner changed.
  `baseline.json` now holds a run of this module's own 20-sample method
  on the same 10-CPU arm64 machine (16 GiB), p50 1.9434 s, p95 2.2711 s,
  taken while the machine carried a load average of 4.8-5.9 from
  other concurrent work; that load inflates it relative to an idle
  machine (the August revision re-measured at 0.84 s under the same load against
  0.51 s idle in August), and is disclosed rather than corrected for,
  because a scaled number would not be a measurement.
  `_REGRESSION_MARGIN` stays at 4.0: the resulting p50 limit is 7.77 s,
  which the 2-vCPU leg's observed 2.05 s reaches at 26%, so the check
  now fails that leg when its scan becomes roughly 3.8x slower than
  today and fails the baseline machine at 4.0x, and an injected 5x
  slowdown fails it everywhere. Lowering the margin to 3.0 would tighten
  CI detection to about 2.6x at the cost of re-coupling the check to the
  load the baseline was measured under; that trade was considered and
  not taken.
"""

from __future__ import annotations

import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from bench_repo import build_benchmark_repository

_SCAN_ENTRY = "from controlloop.cli import main; main()"
_SAMPLE_COUNT = 20
"""How many real `controlloop scan` subprocesses each benchmark run
times.

Raised from 15 to 20, and the reason is arithmetic, not taste.
`_percentile` picks index `ceil(fraction * n) - 1`. At `n = 15` that is
`ceil(0.95 * 15) - 1 = 14` -- the **last** index of `0..14`, so "p95"
was literally the maximum of the samples. No sample sat above it, which
meant one transient stall (a GC pause, a busy machine, disk contention)
decided
`TestRegressionMargin::test_p95_within_margin_of_committed_baseline`
on its own.

At `n = 20` the index is `ceil(0.95 * 20) - 1 = 18` of `0..19`, so one
sample may exceed the reported p95 without failing the check. That is
what makes it a percentile rather than a worst-of-N check.

This is deliberately **not** another margin increase.
`_REGRESSION_MARGIN` stays at `4.0` and `baseline.json` is unchanged:
the check detects exactly what it detected before, and merely stops
being decided by a single outlier. An earlier change had already raised
the margin `2.0 -> 4.0` against this same symptom; the margin was never
the root cause, so the flakiness returned at the new threshold.

Do not lower this below the point where `ceil(0.95 * _SAMPLE_COUNT) - 1`
equals `_SAMPLE_COUNT - 1`.
`TestPercentile::test_p95_is_not_the_maximum_sample` fails if you do.
Each added sample is one more real subprocess scan on every CI leg, so
raise it further only with a reason.
"""
_P50_TARGET_SECONDS = 30.0
_P95_TARGET_SECONDS = 90.0
_REGRESSION_MARGIN = 4.0
"""How far measured performance may drift above `baseline.json` before
the regression check treats it as a regression -- generous enough to
absorb ordinary CI-runner hardware variance, tight enough to catch an
accidental algorithmic regression.

Raised from 2.0 to 4.0 as a disclosed follow-up to the "baseline
measured on one dev machine, CI hardware varies" limitation above.
`baseline.json` was measured on a 10-`cpu_count` development machine
(re-measured later on the same machine, see the module docstring). A
2.0x margin failed this check five times across three unrelated pull
requests in real CI, always on the weaker GitHub-hosted legs --
`linux-x86_64` (2 vCPU) and `macos-arm64` (3 vCPU), never `linux-arm64`
(4+ vCPU) -- with a worst observed ratio of 3.15x (p95, macos-arm64).
Every failure was confirmed transient by re-running the benchmark in
isolation immediately after, which passed cleanly each time; none of
those five PRs touched scanning or performance-relevant code. 4.0x sits
with real headroom above that 3.15x worst case (real CI load is itself
variable run to run) while staying far tighter than the absolute SLA
targets (p50 < 30s, p95 < 90s, roughly 25-78x looser than measured
performance), so this still fails on anything resembling a genuine
algorithmic regression. The alternatives considered and rejected were
scaling by CPU count, per-CI-leg baselines, and an advisory-only check
on weak legs."""

_BASELINE_PATH = Path(__file__).parent / "baseline.json"


def _reference_machine_spec() -> dict[str, Any]:
    """The real machine that produced this run's measurement,
    queried live rather than assumed."""

    total_memory_bytes: int | None
    system = platform.system()
    if system == "Linux":
        total_memory_bytes = None
        try:
            with open("/proc/meminfo") as handle:
                for line in handle:
                    if line.startswith("MemTotal:"):
                        total_memory_bytes = int(line.split()[1]) * 1024
                        break
        except OSError:
            total_memory_bytes = None
    elif system == "Darwin":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            total_memory_bytes = int(result.stdout.strip())
        except (OSError, subprocess.SubprocessError, ValueError):
            total_memory_bytes = None
    else:
        total_memory_bytes = None

    return {
        "platform": system,
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "total_memory_bytes": total_memory_bytes,
    }


def _time_one_scan(repo: Path) -> float:
    start = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-c", _SCAN_ENTRY, "scan", str(repo), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed = time.monotonic() - start
    assert result.returncode in (0, 1), (
        f"benchmark scan exited unexpectedly: {result.returncode}\n"
        f"stderr: {result.stderr}"
    )
    return elapsed


def _percentile(sorted_durations: list[float], fraction: float) -> float:
    index = math.ceil(fraction * len(sorted_durations)) - 1
    return sorted_durations[max(0, min(index, len(sorted_durations) - 1))]


@pytest.fixture(scope="module")
def benchmark_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("controlloop-benchmark-repo")
    line_count = build_benchmark_repository(root)
    assert line_count >= 100_000
    return root


@pytest.fixture(scope="module")
def benchmark_result(benchmark_repo: Path) -> dict[str, Any]:
    durations = [_time_one_scan(benchmark_repo) for _ in range(_SAMPLE_COUNT)]
    sorted_durations = sorted(durations)
    result = {
        "durations_seconds": durations,
        "p50_seconds": statistics.median(sorted_durations),
        "p95_seconds": _percentile(sorted_durations, 0.95),
        "reference_machine": _reference_machine_spec(),
    }
    print(f"\ncontrolloop scan benchmark result: {json.dumps(result, indent=2)}")
    return result


class TestPercentile:
    """These are pure arithmetic -- they time nothing, so
    they run in microseconds and can never themselves be flaky."""

    def test_p95_is_not_the_maximum_sample(self) -> None:
        """The whole defect in one assertion.

        At `_SAMPLE_COUNT = 15`, `ceil(0.95 * 15) - 1 = 14` -- the last
        index -- so the reported "p95" was the worst sample, and a single
        transient stall failed the regression check on its own. At least
        one sample must be able to sit above the p95, or the statistic is
        a worst-of-N check wearing a percentile's name.

        If this fails, someone lowered `_SAMPLE_COUNT`. Raise it back rather
        than widening `_REGRESSION_MARGIN` -- an earlier change already
        widened the margin against this same symptom and the flakiness
        returned, because the margin was never the cause.
        """
        samples = [float(index) for index in range(_SAMPLE_COUNT)]

        index = math.ceil(0.95 * _SAMPLE_COUNT) - 1

        assert index < _SAMPLE_COUNT - 1, (
            f"_SAMPLE_COUNT={_SAMPLE_COUNT} makes the p95 index {index}, "
            f"the last of 0..{_SAMPLE_COUNT - 1} -- the maximum. Raise "
            "_SAMPLE_COUNT so at least one sample can exceed the p95."
        )
        assert _percentile(samples, 0.95) < max(samples)

    def test_one_outlier_does_not_move_the_p95(self) -> None:
        """The behavior that matters: a single stalled sample must not
        decide the check."""
        steady = [1.0] * _SAMPLE_COUNT
        with_outlier = sorted([*steady[:-1], 99.0])

        assert _percentile(with_outlier, 0.95) == 1.0

    def test_p50_is_unaffected_by_this_change(self) -> None:
        """`statistics.median` was always robust; the p50 check never
        had this defect and must keep behaving identically."""
        steady = [1.0] * _SAMPLE_COUNT
        with_outlier = sorted([*steady[:-1], 99.0])

        assert statistics.median(with_outlier) == 1.0

    @pytest.mark.parametrize(
        ("sorted_durations", "fraction", "expected"),
        [
            ([1.0], 0.95, 1.0),
            ([1.0, 2.0], 0.5, 1.0),
            ([1.0, 2.0, 3.0, 4.0], 0.5, 2.0),
            ([1.0, 2.0, 3.0, 4.0], 1.0, 4.0),
            ([1.0, 2.0, 3.0, 4.0], 0.0, 1.0),
        ],
    )
    def test_percentile_arithmetic(
        self, sorted_durations: list[float], fraction: float, expected: float
    ) -> None:
        """Boundary cases, including a single sample and both extremes,
        so the index clamping stays correct if `_percentile` is ever
        touched."""
        assert _percentile(sorted_durations, fraction) == expected


class TestAbsoluteServiceLevelTargets:
    """p50 under 30 seconds and p95 under 90 seconds."""

    def test_p50_under_target(self, benchmark_result: dict[str, Any]) -> None:
        assert benchmark_result["p50_seconds"] < _P50_TARGET_SECONDS, benchmark_result

    def test_p95_under_target(self, benchmark_result: dict[str, Any]) -> None:
        assert benchmark_result["p95_seconds"] < _P95_TARGET_SECONDS, benchmark_result


class TestRegressionMargin:
    """A regression beyond a defined margin fails CI."""

    def test_p50_within_margin_of_committed_baseline(
        self, benchmark_result: dict[str, Any]
    ) -> None:
        baseline = json.loads(_BASELINE_PATH.read_text())
        limit = baseline["p50_seconds"] * _REGRESSION_MARGIN
        assert benchmark_result["p50_seconds"] < limit, {
            **benchmark_result,
            "baseline_p50_seconds": baseline["p50_seconds"],
            "regression_margin": _REGRESSION_MARGIN,
            "limit_seconds": limit,
        }

    def test_p95_within_margin_of_committed_baseline(
        self, benchmark_result: dict[str, Any]
    ) -> None:
        baseline = json.loads(_BASELINE_PATH.read_text())
        limit = baseline["p95_seconds"] * _REGRESSION_MARGIN
        assert benchmark_result["p95_seconds"] < limit, {
            **benchmark_result,
            "baseline_p95_seconds": baseline["p95_seconds"],
            "regression_margin": _REGRESSION_MARGIN,
            "limit_seconds": limit,
        }


def test_benchmark_repository_meets_the_representative_line_count(
    benchmark_repo: Path,
) -> None:
    """The generated repository is at least 100,000 lines and
    plants real, adapter-detectable declaration files."""

    assert (benchmark_repo / ".mcp.json").is_file()
    assert (benchmark_repo / "openapi.json").is_file()

    total_lines = sum(
        len(path.read_text().splitlines())
        for path in (benchmark_repo / "src").glob("*.py")
    )
    assert total_lines >= 100_000
