"""Tests for `action-scripts/pr_comment.py`.

The script is loaded from its file, the way `action.yml` runs it, and driven
with a fake transport so no test opens a socket. Each test is one of the
comment's designed behaviors: one comment, edited in place, change-only,
skipped cleanly where it cannot apply, and never able to change the verdict.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "action-scripts" / "pr_comment.py"
_STATEMENT = (
    "This change gives Claude Code the power to run `node .github/setup.js` on "
    "every session start (`.claude/settings.json`, hook `SessionStart`). No "
    "approval is recorded."
)
SECRET = "ghp_" + "C" * 36


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pr_comment", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr_comment"] = module
    spec.loader.exec_module(module)
    return module


pr_comment = _load()


class FakeGitHub:
    """An in-memory issue-comments API."""

    def __init__(self, comments: list[dict[str, Any]] | None = None, fail: int = 0):
        self.comments = comments or []
        self.calls: list[tuple[str, str, Mapping[str, object] | None]] = []
        self.fail = fail

    def __call__(
        self, method: str, url: str, payload: Mapping[str, object] | None
    ) -> Any:
        self.calls.append((method, url, payload))
        if self.fail:
            return pr_comment.Response(self.fail, None)
        if method == "GET":
            return pr_comment.Response(200, list(self.comments))
        if method == "POST":
            comment = {"id": 100 + len(self.comments), "body": payload["body"]}  # type: ignore[index]
            self.comments.append(comment)
            return pr_comment.Response(201, comment)
        if method == "PATCH":
            identifier = int(url.rsplit("/", 1)[1])
            for comment in self.comments:
                if comment["id"] == identifier:
                    comment["body"] = payload["body"]  # type: ignore[index]
            return pr_comment.Response(200, {})
        raise AssertionError(method)


def _sarif(tmp_path: Path, statements: list[str]) -> str:
    namespace: dict[str, object] = {"blastRadius": ["x"]}
    if statements:
        namespace["authorityDelta"] = [
            {"statement": text, "host_name": "Claude Code"} for text in statements
        ]
    path = tmp_path / "out.sarif"
    path.write_text(json.dumps({"runs": [{"properties": {"controlloop": namespace}}]}))
    return str(path)


def _environ(
    tmp_path: Path, *, event: str = "pull_request", fork: bool = False
) -> dict[str, str]:
    payload = {
        "pull_request": {
            "number": 7,
            "head": {"repo": {"full_name": "someone/fork" if fork else "o/r"}},
            "base": {"repo": {"full_name": "o/r"}},
        }
    }
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload))
    return {
        "GITHUB_EVENT_NAME": event,
        "GITHUB_EVENT_PATH": str(path),
        "GITHUB_API_URL": "https://api.example",
        "CONTROLLOOP_GITHUB_TOKEN": "test-token",
    }


def _run(tmp_path: Path, api: FakeGitHub, statements: list[str], **environ: Any) -> str:
    outcome: str = pr_comment.run(
        sarif_path=_sarif(tmp_path, statements),
        verdict="deployment_blocked",
        environ=_environ(tmp_path, **environ),
        transport=api,
    )
    return outcome


class TestOneCommentKeptCurrent:
    def test_a_grant_creates_one_marked_comment(self, tmp_path: Path) -> None:
        api = FakeGitHub()

        assert _run(tmp_path, api, [_STATEMENT]) == "created"

        (comment,) = api.comments
        assert comment["body"].startswith(pr_comment.MARKER)
        assert "gives **Claude Code** the power to run" in comment["body"]
        assert "`deployment_blocked`" in comment["body"]
        assert api.calls[-1][1] == "https://api.example/repos/o/r/issues/7/comments"

    def test_a_later_push_edits_the_same_comment(self, tmp_path: Path) -> None:
        api = FakeGitHub()
        _run(tmp_path, api, [_STATEMENT])

        assert _run(tmp_path, api, [_STATEMENT, _STATEMENT.replace("node", "bun")]) == (
            "updated"
        )

        (comment,) = api.comments
        assert "bun .github/setup.js" in comment["body"]
        assert [method for method, _, _ in api.calls].count("POST") == 1

    def test_an_emptied_delta_updates_the_comment_rather_than_leaving_it(
        self, tmp_path: Path
    ) -> None:
        api = FakeGitHub()
        _run(tmp_path, api, [_STATEMENT])

        assert _run(tmp_path, api, []) == "cleared"

        (comment,) = api.comments
        assert "no longer changes agent authority" in comment["body"]
        assert "setup.js" not in comment["body"]

    def test_no_grant_and_no_comment_posts_nothing(self, tmp_path: Path) -> None:
        api = FakeGitHub()

        assert _run(tmp_path, api, []) == "nothing"

        assert api.comments == []
        assert {method for method, _, _ in api.calls} == {"GET"}

    def test_someone_elses_comment_is_never_edited(self, tmp_path: Path) -> None:
        api = FakeGitHub([{"id": 1, "body": "LGTM"}])

        _run(tmp_path, api, [_STATEMENT])

        assert api.comments[0] == {"id": 1, "body": "LGTM"}
        assert len(api.comments) == 2

    def test_statements_are_bounded(self, tmp_path: Path) -> None:
        api = FakeGitHub()

        _run(tmp_path, api, [_STATEMENT] * (pr_comment.MAX_STATEMENTS + 5))

        body = api.comments[0]["body"]
        assert body.count("- This change gives") == pr_comment.MAX_STATEMENTS
        assert "...and 5 more" in body


class TestSkippedCleanly:
    @pytest.mark.parametrize("event", ["push", "workflow_dispatch", "schedule"])
    def test_not_a_pull_request(
        self, tmp_path: Path, event: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        api = FakeGitHub()

        assert _run(tmp_path, api, [_STATEMENT], event=event) == "skipped"

        assert api.calls == []
        assert "::notice::" in capsys.readouterr().out

    def test_a_fork(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        api = FakeGitHub()

        assert _run(tmp_path, api, [_STATEMENT], fork=True) == "skipped"

        assert api.calls == []
        assert "fork" in capsys.readouterr().out

    def test_no_write_permission(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert _run(tmp_path, FakeGitHub(fail=403), [_STATEMENT]) == "skipped"

        out = capsys.readouterr().out
        assert "::notice::" in out
        assert "pull-requests: write" in out

    def test_a_server_error_is_a_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert _run(tmp_path, FakeGitHub(fail=500), [_STATEMENT]) == "failed"

        assert "::warning::" in capsys.readouterr().out

    def test_the_script_always_exits_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No token and no event: the real entry point still exits 0, so
        the step can never change the gate's exit code."""

        monkeypatch.delenv("CONTROLLOOP_GITHUB_TOKEN", raising=False)
        assert pr_comment.main([str(tmp_path / "missing.sarif"), "passed"]) == 0


class TestRedaction:
    def test_no_secret_reaches_the_comment(self, tmp_path: Path) -> None:
        api = FakeGitHub()

        _run(tmp_path, api, [f"This change gives Claude Code ... --token={SECRET}."])

        assert SECRET not in json.dumps(api.calls)
        assert SECRET not in api.comments[0]["body"]
