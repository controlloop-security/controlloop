"""Dependency-free, deterministic, seeded fuzzing infrastructure.

No fuzzing library (`hypothesis`, `atheris`) is added as a dependency.
This module is a small, stdlib-only, byte-level structured-mutation
fuzzer instead, reusing `random.Random(seed)` for full reproducibility --
the same discipline `test_gate_determinism_regression.py` already
established: every failure is reproducible locally from its seed.

`mutate_bytes` is format-agnostic (works identically against JSON,
YAML, or adapter-specific text/binary seeds), so the same harness
drives every target here without a bespoke mutator per format.

`run_bounded` isolates every fuzz call in a forked child process,
killed at the OS level if it outlives the bound -- not an in-process
`signal.alarm`-based timeout. `signal.alarm` only fires between Python
bytecode instructions; a genuinely stuck operation (a tight C-level
loop, a blocked syscall, anything that never yields back to the
interpreter) can defeat it silently, turning a bounded fuzz call into
an unbounded hang. `multiprocessing`'s `fork` start method (POSIX-only,
matching this module's other POSIX-only assumptions) makes this cheap:
the child is a copy-on-write clone of the parent, so no target function
or argument needs to be picklable, unlike the `spawn` start method.
"""

from __future__ import annotations

import multiprocessing
import random
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import Enum, auto
from multiprocessing.connection import Connection
from pathlib import Path

FUZZ_ITERATIONS = 40
"""Fixed iteration count per target. 300 was the original figure but
proved wrong in practice: CI hung at GitHub's own 10-minute job timeout
(`.github/workflows/ci.yml`), then took the platform's further ~5-minute
force-kill grace period before the job actually stopped -- a ~15-minute
total that looked like a true deadlock but was not one (confirmed by
direct local testing: `run_bounded` reliably kills a genuinely infinite
loop within its 2-second bound). The real cause was aggregate runtime:
forking ~2,100 child processes (300 x 2 for manifest/baseline, 300 x 15
for the fifteen adapters) under `pytest-cov`'s tracing overhead, on
GitHub's shared/slower runner, pushed the whole suite well past 10
minutes even though it completed in ~103s on a development machine. 40
cuts total fuzz-related test count roughly 7x (about 291 vs. about
2,100) while still giving every mutation strategy, and every fixed
adversarial sequence (tried with fixed 15% probability per call), many
chances to fire per target."""

_TIMEOUT_SECONDS = 10
"""Every target here is a pure, offline parse with no I/O or network, so
a genuinely bounded call should complete in milliseconds -- but this
bound now also has to absorb `run_bounded`'s own fork-and-IPC overhead
under real CI load, not just the target's own work. 2 seconds proved too
tight in practice: CI failed a `TestSeededSweep` case with
`FuzzOutcome.TIMEOUT` on an input that already raises `RecursionError`
almost instantly once inside the child (the same nested-brace input the
manifest parser already handles), because fork-plus-pipe overhead alone
-- inherited `pytest-cov` tracing included -- exceeded 2 seconds on
GitHub's shared runner. 10 seconds gives real margin for that overhead
while still catching a call that is actually unbounded, not merely slow
to schedule."""

_FIXED_ADVERSARIAL_SEQUENCES: tuple[bytes, ...] = (
    b"\xef\xbb\xbf",  # UTF-8 BOM
    "‮".encode(),  # right-to-left override
    "‍".encode(),  # zero-width joiner
    b"\xed\xa0\x80",  # lone unpaired UTF-16 surrogate, encoded as raw bytes
    b"\x00" * 64,  # embedded nulls
    b"A" * (2 * 1024 * 1024),  # one very long line
    b"{" * 10_000,  # unbalanced structural blow-up
    b"[" * 10_000 + b"]" * 10_000,
)
"""Classic hostile byte sequences tried on every target regardless of
RNG draw, so a run always covers these even with few iterations."""


def mutate_bytes(seed_bytes: bytes, rng: random.Random) -> bytes:
    """Return one adversarial mutation of `seed_bytes`, chosen
    deterministically from `rng`.

    A fixed menu of format-agnostic transforms: truncation (including
    mid-multibyte-UTF-8), random byte flips, random control/null byte
    insertion, large-scale slice duplication, and (with fixed
    probability) substitution of one of `_FIXED_ADVERSARIAL_SEQUENCES`.
    """

    if not seed_bytes:
        return rng.choice(_FIXED_ADVERSARIAL_SEQUENCES)

    if rng.random() < 0.15:
        return rng.choice(_FIXED_ADVERSARIAL_SEQUENCES)

    strategy = rng.choice(["truncate", "flip", "insert", "duplicate", "delete"])
    data = bytearray(seed_bytes)

    if strategy == "truncate":
        cut = rng.randint(0, len(data))
        return bytes(data[:cut])

    if strategy == "flip":
        count = rng.randint(1, max(1, len(data) // 10))
        for _ in range(count):
            index = rng.randrange(len(data))
            data[index] = rng.randint(0, 255)
        return bytes(data)

    if strategy == "insert":
        count = rng.randint(1, 32)
        for _ in range(count):
            index = rng.randrange(len(data) + 1)
            byte = rng.choice([0x00, 0x0B, 0x0C, 0x7F, 0xFF])
            data.insert(index, byte)
        return bytes(data)

    if strategy == "duplicate":
        start = rng.randrange(len(data))
        end = rng.randint(start, len(data))
        chunk = data[start:end] or data[:1]
        repeats = rng.randint(2, 500)
        return bytes(data + chunk * repeats)

    # delete
    start = rng.randrange(len(data))
    end = rng.randint(start, len(data))
    del data[start:end]
    return bytes(data)


def iter_seeds(master_seed: int, count: int = FUZZ_ITERATIONS) -> Iterator[int]:
    """A deterministic stream of per-call seeds derived from
    `master_seed`, so every fuzz call gets its own reproducible RNG."""

    rng = random.Random(master_seed)
    for _ in range(count):
        yield rng.randrange(2**32)


class FuzzOutcome(Enum):
    COMPLETED = auto()
    """The target ran to completion without raising."""

    EXPECTED_EXCEPTION = auto()
    """The target raised exactly the exception type its own contract
    documents for malformed input -- not a finding."""

    UNEXPECTED_EXCEPTION = auto()
    """The target raised something outside its documented contract --
    a real finding."""

    TIMEOUT = auto()
    """The target did not return within `_TIMEOUT_SECONDS` -- a real
    finding (unbounded recursion or backtracking)."""


@dataclass(frozen=True, slots=True)
class FuzzResult:
    outcome: FuzzOutcome
    seed: int
    input_bytes: bytes
    exception_type: str | None = None
    exception_message: str | None = None


def _worker(
    target: Callable[[bytes], object], input_bytes: bytes, conn: Connection
) -> None:
    try:
        target(input_bytes)
    except BaseException as error:  # classifying every exception, not swallowing one
        conn.send(("exception", type(error).__name__, str(error)[:200]))
    else:
        conn.send(("completed", None, None))
    finally:
        conn.close()


def run_bounded(
    target: Callable[[bytes], object],
    input_bytes: bytes,
    *,
    seed: int,
    expected_exceptions: tuple[type[BaseException], ...] = (),
) -> FuzzResult:
    """Invoke `target(input_bytes)` in a forked child process under a
    wall-clock bound, classifying the outcome against
    `expected_exceptions` -- any other exception, or a timeout, is a
    finding. A child that outlives the bound is terminated, then killed
    outright if it does not exit promptly -- an OS-level guarantee, not
    dependent on the child ever yielding back to the interpreter."""

    ctx = multiprocessing.get_context("fork")
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_worker, args=(target, input_bytes, child_conn))
    process.start()
    child_conn.close()

    process.join(_TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(1)
        if process.is_alive():
            process.kill()
            process.join()
        parent_conn.close()
        return FuzzResult(
            outcome=FuzzOutcome.TIMEOUT, seed=seed, input_bytes=input_bytes
        )

    if parent_conn.poll():
        status, exception_type, exception_message = parent_conn.recv()
    else:
        # The child exited without reporting anything -- killed by the OS
        # (e.g. OOM) or crashed at the C level (e.g. a segfault). Real
        # findings either way, not swallowed as a silent pass.
        status = "exception"
        exception_type = "ChildProcessExitedWithoutResult"
        exception_message = f"exit code {process.exitcode}"
    parent_conn.close()

    if status == "completed":
        return FuzzResult(
            outcome=FuzzOutcome.COMPLETED, seed=seed, input_bytes=input_bytes
        )

    expected_names = {exception.__name__ for exception in expected_exceptions}
    outcome = (
        FuzzOutcome.EXPECTED_EXCEPTION
        if exception_type in expected_names
        else FuzzOutcome.UNEXPECTED_EXCEPTION
    )
    return FuzzResult(
        outcome=outcome,
        seed=seed,
        input_bytes=input_bytes,
        exception_type=exception_type,
        exception_message=exception_message,
    )


def load_corpus(corpus_dir: Path) -> tuple[bytes, ...]:
    """Every standing regression input under `corpus_dir`, sorted for a
    stable replay order. An empty or missing directory yields no
    entries -- a target with no confirmed crash has an empty corpus."""

    if not corpus_dir.is_dir():
        return ()
    return tuple(path.read_bytes() for path in sorted(corpus_dir.glob("*.bin")))
