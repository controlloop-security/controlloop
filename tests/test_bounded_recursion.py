"""Tests for controlloop.bounded_recursion."""

from __future__ import annotations

import sys

from controlloop.bounded_recursion import bounded_recursion


def _recurse(n: int) -> int:
    if n <= 0:
        return 0
    return 1 + _recurse(n - 1)


class TestBoundedRecursion:
    def test_allows_recursion_within_the_margin(self) -> None:
        with bounded_recursion(margin=200):
            assert _recurse(50) == 50

    def test_rejects_recursion_beyond_the_margin(self) -> None:
        with bounded_recursion(margin=50):
            try:
                _recurse(10_000)
            except RecursionError:
                pass
            else:
                raise AssertionError("expected RecursionError")

    def test_restores_the_previous_limit_on_success(self) -> None:
        previous = sys.getrecursionlimit()

        with bounded_recursion(margin=200):
            pass

        assert sys.getrecursionlimit() == previous

    def test_restores_the_previous_limit_after_an_error(self) -> None:
        previous = sys.getrecursionlimit()

        try:
            with bounded_recursion(margin=50):
                _recurse(10_000)
        except RecursionError:
            pass

        assert sys.getrecursionlimit() == previous

    def test_is_relative_to_the_caller_own_current_depth(self) -> None:
        """A large ambient call depth must not make a generous margin
        insufficient -- the bound is relative, not absolute."""

        def _nested(n: int) -> None:
            if n <= 0:
                with bounded_recursion(margin=200):
                    assert _recurse(50) == 50
                return
            _nested(n - 1)

        _nested(300)
