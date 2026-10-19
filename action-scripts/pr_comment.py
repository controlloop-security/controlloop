"""Post or update the one change-only pull-request comment carrying the
authority statement.

Run by `action.yml` after `gate` exits. The CLI never posts anything and
makes no network call; this step reads only what `gate` already wrote
(the SARIF document's `runs[0].properties.controlloop.authorityDelta`),
the verdict, and the runner's own environment.

At most one comment exists per pull request, found by `MARKER`:

- the delta is non-empty and there is no comment: create one;
- there is a comment: edit it in place (to the new statements, or, when
  the delta is now empty, to say the pull request no longer changes
  agent authority);
- the delta is empty and there is no comment: post nothing.

Skipped with a workflow notice when the event is not a pull request, the
pull request comes from a fork, there is no token, or the token cannot
write (HTTP 403). Any other failure is a workflow warning. This script
always exits 0: a comment can never change the gate's verdict.

The body is built only from the authority statements and the verdict,
bounded, and passed through the redaction primitive as a whole.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

MARKER = "<!-- controlloop:authority-statement -->"
MAX_STATEMENTS = 50
MAX_PAGES = 10
_PULL_REQUEST_EVENTS = frozenset({"pull_request", "pull_request_target"})
_NO_LONGER = (
    "This pull request no longer changes agent authority. An earlier push "
    "did; this comment is kept so the history of the conversation stays "
    "readable."
)


@dataclass(frozen=True)
class Response:
    status: int
    body: Any


#: `(method, url, payload) -> Response`. Injected so tests never open a
#: socket; `_urllib_transport` is the real one.
Transport = Callable[[str, str, Mapping[str, object] | None], Response]


class _Skip(Exception):
    """The comment does not apply here; say why in a notice."""


def _redact(text: str) -> str:
    try:
        from controlloop.redaction import redact_text
    except ImportError:  # pragma: no cover - the Action always has the CLI
        return text
    return redact_text(text)


def statements_from_sarif(path: str) -> list[dict[str, str]]:
    """The authority entries `gate` embedded, or an empty list when the
    file is missing, unreadable, or carries none."""

    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
        namespace = document["runs"][0].get("properties", {}).get("controlloop", {})
        entries = namespace.get("authorityDelta", [])
    except (OSError, KeyError, IndexError, AttributeError, TypeError, ValueError):
        return []
    return [
        {"statement": entry["statement"], "host_name": str(entry.get("host_name", ""))}
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("statement"), str)
    ]


def build_body(entries: list[dict[str, str]], verdict: str) -> str:
    """The comment text: the marker, the verdict, and one bullet per
    statement with the agent's name in bold."""

    lines = [MARKER, "### ControlLoop: agent authority", ""]
    if not entries:
        lines.append(_NO_LONGER)
    else:
        lines.append(f"**Verdict:** `{verdict or 'unknown'}`")
        lines.append("")
        lines.append("This pull request gives agents new power:")
        lines.append("")
        for entry in entries[:MAX_STATEMENTS]:
            statement = entry["statement"]
            host = entry.get("host_name") or ""
            if host:
                statement = statement.replace(f"gives {host} ", f"gives **{host}** ", 1)
            lines.append(f"- {statement}")
        if len(entries) > MAX_STATEMENTS:
            lines.append(
                f"- ...and {len(entries) - MAX_STATEMENTS} more; see the check "
                "summary and the evidence artifact."
            )
    lines.extend(
        [
            "",
            (
                "<sub>Posted by the ControlLoop GitHub Action. It edits this "
                "one comment on later pushes. See the check for findings.</sub>"
            ),
        ]
    )
    return _redact("\n".join(lines))


def _pull_request(environ: Mapping[str, str]) -> tuple[int, str]:
    event_name = environ.get("GITHUB_EVENT_NAME", "")
    if event_name not in _PULL_REQUEST_EVENTS:
        raise _Skip(f"the event is {event_name or 'unknown'}, not a pull request")
    try:
        with open(environ["GITHUB_EVENT_PATH"], encoding="utf-8") as handle:
            event = json.load(handle)
        pull = event["pull_request"]
        number = int(pull["number"])
        head_repository = pull["head"]["repo"]["full_name"]
        base_repository = pull["base"]["repo"]["full_name"]
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise _Skip(f"the pull request event could not be read ({error})") from None
    if head_repository != base_repository and event_name == "pull_request":
        raise _Skip(
            "the pull request comes from a fork, whose token cannot write comments"
        )
    return number, base_repository


def _find_comment(
    transport: Transport, api: str, repository: str, number: int
) -> int | None:
    for page in range(1, MAX_PAGES + 1):
        response = transport(
            "GET",
            f"{api}/repos/{repository}/issues/{number}/comments?per_page=100&page={page}",
            None,
        )
        _raise_for(response)
        comments = response.body if isinstance(response.body, list) else []
        for comment in comments:
            if isinstance(comment, dict) and MARKER in str(comment.get("body", "")):
                return int(comment["id"])
        if len(comments) < 100:
            return None
    return None


class _ApiError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


def _raise_for(response: Response) -> None:
    if response.status >= 400:
        raise _ApiError(response.status)


def run(
    *,
    sarif_path: str,
    verdict: str,
    environ: Mapping[str, str],
    transport: Transport,
) -> str:
    """Do whatever this pull request needs and return what happened:
    `created`, `updated`, `cleared`, `nothing`, or `skipped`. Prints the
    workflow notice or warning itself."""

    try:
        if not environ.get("CONTROLLOOP_GITHUB_TOKEN"):
            raise _Skip("no token was given to the step")
        number, repository = _pull_request(environ)
        # `CONTROLLOOP_GITHUB_API_URL` exists for the action-e2e workflow's
        # intercepting server: a workflow cannot override `GITHUB_API_URL`.
        api = (
            environ.get("CONTROLLOOP_GITHUB_API_URL")
            or environ.get("GITHUB_API_URL")
            or "https://api.github.com"
        ).rstrip("/")
        entries = statements_from_sarif(sarif_path)
        existing = _find_comment(transport, api, repository, number)
        if existing is None and not entries:
            return "nothing"
        body = build_body(entries, verdict)
        if existing is None:
            response = transport(
                "POST",
                f"{api}/repos/{repository}/issues/{number}/comments",
                {"body": body},
            )
            outcome = "created"
        else:
            response = transport(
                "PATCH",
                f"{api}/repos/{repository}/issues/comments/{existing}",
                {"body": body},
            )
            outcome = "updated" if entries else "cleared"
        _raise_for(response)
        return outcome
    except _Skip as skip:
        print(f"::notice::ControlLoop pull-request comment skipped: {skip}.")
        return "skipped"
    except _ApiError as error:
        if error.status in (401, 403):
            print(
                "::notice::ControlLoop pull-request comment skipped: the token "
                "cannot write comments here. Grant `pull-requests: write` to "
                "the calling workflow to enable it."
            )
            return "skipped"
        print(
            "::warning::ControlLoop could not post or edit its pull-request "
            f"comment (HTTP {error.status}). The gate's verdict is unaffected."
        )
        return "failed"
    except (OSError, ValueError) as error:
        print(
            "::warning::ControlLoop could not post or edit its pull-request "
            f"comment ({type(error).__name__}). The gate's verdict is unaffected."
        )
        return "failed"


def _urllib_transport(token: str) -> Transport:
    def send(method: str, url: str, payload: Mapping[str, object] | None) -> Response:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as reply:
                text = reply.read().decode("utf-8")
                return Response(reply.status, json.loads(text) if text else None)
        except urllib.error.HTTPError as error:
            return Response(error.code, None)

    return send


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    sarif_path = args[0] if args else ""
    verdict = args[1] if len(args) > 1 else ""
    environ = dict(os.environ)
    outcome = run(
        sarif_path=sarif_path,
        verdict=verdict,
        environ=environ,
        transport=_urllib_transport(environ.get("CONTROLLOOP_GITHUB_TOKEN", "")),
    )
    print(f"ControlLoop pull-request comment: {outcome}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
