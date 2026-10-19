"""An intercepting stand-in for GitHub's issue-comments API, used only by
`.github/workflows/action-e2e.yml` to exercise `pr_comment.py` end to end
without touching a real pull request.

Serves `GET /repos/<o>/<r>/issues/<n>/comments`, `POST` to the same path,
and `PATCH /repos/<o>/<r>/issues/comments/<id>` from memory, and writes
every request and the current comments to the JSON file named on the
command line after each one, so a later step can assert on them.

    python fake_github_api.py <port> <state.json>
"""

from __future__ import annotations

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_LIST = re.compile(r"^/repos/[^/]+/[^/]+/issues/(\d+)/comments(?:\?.*)?$")
_EDIT = re.compile(r"^/repos/[^/]+/[^/]+/issues/comments/(\d+)$")


def main() -> None:
    port, state_path = int(sys.argv[1]), sys.argv[2]
    comments: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []

    def save() -> None:
        with open(state_path, "w", encoding="utf-8") as handle:
            json.dump({"comments": comments, "requests": requests}, handle)

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, body: object) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _payload(self) -> dict[str, object]:
            length = int(self.headers.get("Content-Length") or 0)
            loaded = json.loads(self.rfile.read(length) or b"{}")
            return loaded if isinstance(loaded, dict) else {}

        def do_GET(self) -> None:
            requests.append({"method": "GET", "path": self.path})
            save()
            if _LIST.match(self.path):
                self._reply(200, comments)
            else:
                self._reply(404, {})

        def do_POST(self) -> None:
            payload = self._payload()
            requests.append({"method": "POST", "path": self.path})
            if _LIST.match(self.path):
                comment = {"id": 1000 + len(comments), "body": payload.get("body", "")}
                comments.append(comment)
                save()
                self._reply(201, comment)
            else:
                save()
                self._reply(404, {})

        def do_PATCH(self) -> None:
            payload = self._payload()
            requests.append({"method": "PATCH", "path": self.path})
            match = _EDIT.match(self.path)
            for comment in comments:
                if match and comment["id"] == int(match.group(1)):
                    comment["body"] = payload.get("body", "")
            save()
            self._reply(200 if match else 404, {})

        def log_message(self, format: str, *args: object) -> None:
            return

    save()
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
