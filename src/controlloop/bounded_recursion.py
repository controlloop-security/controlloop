"""A recursion-depth bound for parsing untrusted, pathologically nested
input.

PyYAML's pure-Python parser and the stdlib's pure-Python JSON decoder
both recurse once per nesting level with no bound of their own.
Pathologically deep nesting (e.g. a long run of "{" or "[") eventually
raises `RecursionError` against Python's own interpreter-wide
recursion limit -- but how much CPU work that takes before raising
depends on how much overhead each frame carries (coverage
instrumentation, profilers, or anything else that adds per-call cost
multiplies it), so relying on the ambient limit alone does not bound
*work done*, only frame count under whatever overhead happens to be
active. Temporarily lowering the limit to a small, fixed budget
*relative to the caller's own current depth* bounds the number of
recursive calls PyYAML or `json` can make before raising, independent
of per-frame overhead -- the same fixed number of frames is walked
whether or not anything is tracing them.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from types import FrameType


@contextmanager
def bounded_recursion(margin: int) -> Iterator[None]:
    """Temporarily cap the recursion limit to the caller's current
    stack depth plus `margin`, restoring the previous limit afterward.

    `margin` should comfortably exceed the deepest *legitimate* nesting
    the wrapped call will ever see (verified against real fixtures at
    each call site), so this only ever rejects pathological input, not
    a valid document.
    """

    depth = 0
    frame: FrameType | None = sys._getframe()
    while frame is not None:
        depth += 1
        frame = frame.f_back

    previous_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(depth + margin)
    try:
        yield
    finally:
        sys.setrecursionlimit(previous_limit)
