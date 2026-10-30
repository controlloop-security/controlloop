"""`controlloop mcp`: the local, read-only MCP server.

Serves four of the CLI's own commands -- `bom`, `diff`, `gate` and
`rules` -- as Model Context Protocol tools over stdio, so an agent host
can call ControlLoop as tools instead of through shell instructions.
Each tool runs the existing command in this process with `--format json`
and returns exactly the JSON that command prints, plus its exit code and
its standard-error diagnostic lines.

## What this server will not do

- **No network.** Every tool call runs with Team forced off
  (`CONTROLLOOP_TEAM_ENABLED=false`, `CONTROLLOOP_TEAM_TOKEN` removed for
  the call), so even a repository whose `controlloop.toml` enables Team
  takes the Community path, which constructs no transport and opens no
  connection (see `controlloop.team.config.resolve_team_config`). The
  hosted Team MCP server is a separate product surface and is never
  contacted from here.
- **No repository writes.** No tool accepts an output path. `gate`'s
  evidence artifact -- which its JSON output already is, byte for byte --
  goes to a private temporary directory outside the workspace that is
  deleted before the tool returns.
- **No path outside the workspace.** The workspace is fixed when the
  server starts. Every `path` argument, and a `baseline` that names a
  file, must resolve (after symlinks) inside it; a git revision argument
  must match `_REVISION_PATTERN` and may not begin with `-`.
- **No secrets, prompts, or file contents** beyond what the CLI itself
  prints: tool output is captured inside the CLI's redaction boundary
  (`controlloop.redaction`), the same one `main()` installs.

## Protocol

Newline-delimited JSON-RPC 2.0 on stdin/stdout, as the MCP stdio
transport defines it. Implemented: `initialize`, `notifications/initialized`,
`ping`, `tools/list`, `tools/call`. Anything else that expects a reply
gets `-32601`; notifications get no reply. Only the standard library is
used -- the official SDK would bring an HTTP stack into a command whose
point is that it has none.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import IO, Any, Final, TextIO

from controlloop import __version__, redaction
from controlloop.exit_codes import ExitCode

#: Newest first. `initialize` answers with the client's version when it
#: is one of these, and with the newest otherwise, as the lifecycle
#: section of the specification asks.
SUPPORTED_PROTOCOL_VERSIONS: Final = ("2025-06-18", "2025-03-26", "2024-11-05")

#: A single JSON-RPC message larger than this is refused as a parse error
#: rather than read into memory.
MAX_MESSAGE_BYTES: Final = 1024 * 1024

#: A git revision as `gate --default-branch` and `diff --baseline` accept
#: one: a branch, tag, commit, or `rev~n`/`rev^`. Deliberately narrower
#: than git's own grammar; never begins with `-`, so it cannot become an
#: option.
_REVISION_PATTERN: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/@^~-]{0,199}")

_TEAM_ENABLED_VARIABLE: Final = "CONTROLLOOP_TEAM_ENABLED"
_TEAM_TOKEN_VARIABLE: Final = "CONTROLLOOP_TEAM_TOKEN"

_PARSE_ERROR: Final = -32700
_INVALID_REQUEST: Final = -32600
_METHOD_NOT_FOUND: Final = -32601
_INVALID_PARAMS: Final = -32602

_EXIT_MEANINGS: Final[dict[int, str]] = {
    ExitCode.PASS: "passed",
    ExitCode.POLICY_FAIL: "blocked or review required",
    ExitCode.INVALID_INPUT: "invalid input",
    ExitCode.INCOMPLETE_ANALYSIS: "incomplete analysis with enforcement",
    ExitCode.ENTITLEMENT: "not entitled",
    ExitCode.INTERNAL_ERROR: "internal error",
}

SERVER_INSTRUCTIONS: Final = (
    "ControlLoop's local, read-only server. It answers 'what does this "
    "change let my agents do?' from the repository on disk: `gate` compares "
    "the working tree with the default branch and returns the verdict, the "
    "authority each change grants (authority_delta.entries[].statement), and "
    "findings with rule ids; `rules` gives each rule's documentation_url. "
    "Nothing is sent anywhere and nothing is written. Organization policy, "
    "approved-component checks, fleet queries and evidence reports are "
    "ControlLoop Team features (controlloop.ai) and are not available here."
)

#: Every tool only reads; none reaches outside the machine.
_READ_ONLY: Final = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

_PATH_PROPERTY: Final = {
    "type": "string",
    "description": "Directory to analyse, relative to the workspace. Default: "
    "the workspace root.",
}

TOOLS: Final[tuple[dict[str, Any], ...]] = (
    {
        "name": "gate",
        "title": "Gate this change",
        "description": "Run `controlloop gate`: compare the working tree with "
        "the default branch's merge base and return the verdict "
        "(passed, passed_with_warnings, review_required, deployment_blocked), "
        "the authority each change grants, and the findings. Writes no "
        "evidence file. Community rules only; Team policy is not evaluated.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": _PATH_PROPERTY,
                "default_branch": {
                    "type": "string",
                    "description": "Branch the merge base is taken against, "
                    "for example main. Default: resolved automatically.",
                },
            },
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY,
    },
    {
        "name": "diff",
        "title": "Diff agent authority",
        "description": "Run `controlloop diff`: what changed in agent "
        "capabilities between a baseline and the working tree, without "
        "evaluating policy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": _PATH_PROPERTY,
                "baseline": {
                    "type": "string",
                    "description": "A git revision (main, HEAD~1, a commit) or "
                    "a baseline ACBOM file inside the workspace. Default: the "
                    "repository's conventional baseline or merge base.",
                },
            },
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY,
    },
    {
        "name": "bom",
        "title": "Agent capability bill of materials",
        "description": "Run `controlloop bom`: the Agent Capability Bill of "
        "Materials (agents, tools, MCP servers, hooks, permissions and how "
        "they connect) for the working tree, as canonical ACBOM JSON.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": _PATH_PROPERTY},
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY,
    },
    {
        "name": "rules",
        "title": "List policy rules",
        "description": "Run `controlloop rules`: the rule pack, whether each "
        "rule is active for this repository, what it looks for, and its "
        "documentation_url with remediation guidance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": _PATH_PROPERTY,
                "all": {
                    "type": "boolean",
                    "description": "List every rule, ignoring the repository's "
                    "disabled_rules.",
                },
            },
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY,
    },
)


class InvalidToolArgumentsError(ValueError):
    """A tool argument failed validation. Its message names the argument,
    never echoes the value."""


@dataclass(frozen=True, slots=True)
class CliOutcome:
    """What one in-process CLI invocation produced."""

    exit_code: int
    stdout: str
    stderr: str


CliRunner = Callable[[list[str], Path], CliOutcome]


@contextlib.contextmanager
def _community_environment() -> Iterator[None]:
    """Force the Community path for the duration of one tool call.

    `CONTROLLOOP_TEAM_ENABLED` outranks the repository configuration file
    in `controlloop.config`'s precedence, so `false` here wins over a
    `team_enabled = true` in `controlloop.toml`. The token is removed as
    well, so nothing downstream can read it. Both are restored afterwards.
    """

    saved = {
        name: os.environ.get(name)
        for name in (_TEAM_ENABLED_VARIABLE, _TEAM_TOKEN_VARIABLE)
    }
    os.environ[_TEAM_ENABLED_VARIABLE] = "false"
    os.environ.pop(_TEAM_TOKEN_VARIABLE, None)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def run_cli_in_process(args: list[str], cwd: Path) -> CliOutcome:
    """Run one `controlloop` command in this process and capture it.

    Standard streams are swapped for the call only, inside the redaction
    boundary, so what the command prints is redacted exactly as it would
    be on a terminal. An unexpected exception becomes the same generic
    exit-5 diagnostic `controlloop.cli.main` prints, never a traceback.
    """

    import typer.main

    from controlloop.cli import app

    command = typer.main.get_command(app)
    stdout, stderr = StringIO(), StringIO()
    with (
        _community_environment(),
        contextlib.chdir(cwd),
        redaction.redirected_streams(target_stdout=stdout, target_stderr=stderr),
    ):
        try:
            command.main(args=args, prog_name="controlloop", standalone_mode=True)
            exit_code = int(ExitCode.PASS)
        except SystemExit as error:
            exit_code = error.code if isinstance(error.code, int) else 1
        except Exception as error:
            print(
                "error[CLI-INTERNAL-ERROR]: controlloop encountered an unexpected "
                f"internal error and stopped ({type(error).__name__}).",
                file=stderr,
            )
            exit_code = int(ExitCode.INTERNAL_ERROR)
    return CliOutcome(
        exit_code=exit_code, stdout=stdout.getvalue(), stderr=stderr.getvalue()
    )


class Server:
    """One MCP session over a pair of text streams."""

    def __init__(
        self, workspace: Path, *, run_cli: CliRunner = run_cli_in_process
    ) -> None:
        self._workspace = workspace.resolve(strict=True)
        if not self._workspace.is_dir():
            raise NotADirectoryError(str(workspace))
        self._run_cli = run_cli

    @property
    def workspace(self) -> Path:
        return self._workspace

    # -- transport ---------------------------------------------------------

    def serve(self, reader: IO[bytes], writer: TextIO) -> int:
        """Answer messages until the client closes stdin. Returns the exit
        code for `controlloop mcp` itself, which is 0 on a clean close."""

        while True:
            line = reader.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                return int(ExitCode.PASS)
            if len(line) > MAX_MESSAGE_BYTES and not line.endswith(b"\n"):
                # Discard the rest of the oversized line before replying.
                while (
                    rest := reader.readline(MAX_MESSAGE_BYTES)
                ) and not rest.endswith(b"\n"):
                    pass
                self._send(writer, _error(None, _PARSE_ERROR, "message too large"))
                continue
            if not line.strip():
                continue
            reply = self.handle_line(line)
            if reply is not None:
                self._send(writer, reply)

    @staticmethod
    def _send(writer: TextIO, message: Mapping[str, Any]) -> None:
        writer.write(
            json.dumps(message, ensure_ascii=True, separators=(",", ":")) + "\n"
        )
        writer.flush()

    def handle_line(self, line: bytes) -> dict[str, Any] | None:
        try:
            message = json.loads(line)
        except (UnicodeDecodeError, ValueError):
            return _error(None, _PARSE_ERROR, "parse error")
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, _INVALID_REQUEST, "invalid request")
        method = message.get("method")
        if not isinstance(method, str):
            # A response or an unrecognisable message; this server sends no
            # requests, so there is nothing to match a response to.
            return None
        if "id" not in message:
            return None  # notifications: initialized, cancelled, ...
        request_id = message["id"]
        if not isinstance(request_id, str | int) or isinstance(request_id, bool):
            return _error(None, _INVALID_REQUEST, "invalid request id")
        params = message.get("params", {})
        if not isinstance(params, dict):
            return _error(request_id, _INVALID_PARAMS, "params must be an object")
        return self.handle_request(request_id, method, params)

    # -- methods -------------------------------------------------------------

    def handle_request(
        self, request_id: str | int, method: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        if method == "initialize":
            requested = params.get("protocolVersion")
            version = (
                requested
                if requested in SUPPORTED_PROTOCOL_VERSIONS
                else SUPPORTED_PROTOCOL_VERSIONS[0]
            )
            return _result(
                request_id,
                {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "controlloop",
                        "title": "ControlLoop CLI (local)",
                        "version": __version__,
                    },
                    "instructions": SERVER_INSTRUCTIONS,
                },
            )
        if method == "ping":
            return _result(request_id, {})
        if method == "tools/list":
            return _result(request_id, {"tools": list(TOOLS)})
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                return _error(
                    request_id, _INVALID_PARAMS, "arguments must be an object"
                )
            try:
                args = self.command_for(name, arguments)
            except InvalidToolArgumentsError as error:
                return _error(request_id, _INVALID_PARAMS, str(error))
            return _result(request_id, self._call(args))
        return _error(request_id, _METHOD_NOT_FOUND, "method not found")

    def _call(self, args: list[str]) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="controlloop-mcp-") as scratch:
            if args[0] == "gate":
                args = [*args, "--evidence-path", str(Path(scratch) / "evidence.json")]
            outcome = self._run_cli(args, self._workspace)
        try:
            parsed: Any = json.loads(outcome.stdout) if outcome.stdout.strip() else None
        except ValueError:
            parsed = None
        structured = {
            "command": "controlloop " + " ".join(_display_args(args, self._workspace)),
            "exit_code": outcome.exit_code,
            "exit_meaning": _EXIT_MEANINGS.get(outcome.exit_code, "unknown"),
            "result": parsed,
            "stderr": [line for line in outcome.stderr.splitlines() if line.strip()],
        }
        is_error = outcome.exit_code in (
            ExitCode.INVALID_INPUT,
            ExitCode.INTERNAL_ERROR,
        ) or (parsed is None)
        return {
            "content": [{"type": "text", "text": json.dumps(structured, indent=2)}],
            "structuredContent": structured,
            "isError": is_error,
        }

    # -- argument validation ------------------------------------------------

    def command_for(self, name: object, arguments: dict[str, Any]) -> list[str]:
        """Translate one tool call into `controlloop` arguments, refusing
        anything outside the tool's schema or the workspace."""

        tool = next((tool for tool in TOOLS if tool["name"] == name), None)
        if tool is None:
            raise InvalidToolArgumentsError("unknown tool")
        allowed = tool["inputSchema"]["properties"]
        for key in arguments:
            if key not in allowed:
                raise InvalidToolArgumentsError(f"unexpected argument: {key[:64]}")

        target = str(self._inside_workspace(arguments.get("path"), argument="path"))
        if name == "gate":
            args = ["gate", target, "--format", "json"]
            if (branch := arguments.get("default_branch")) is not None:
                args += [
                    "--default-branch",
                    _revision(branch, argument="default_branch"),
                ]
            return args
        if name == "diff":
            args = ["diff", target, "--format", "json"]
            if (baseline := arguments.get("baseline")) is not None:
                args += ["--baseline", self._baseline(baseline)]
            return args
        if name == "bom":
            return ["bom", target]
        show_all = arguments.get("all", False)
        if not isinstance(show_all, bool):
            raise InvalidToolArgumentsError("all must be a boolean")
        return ["rules", target, "--format", "json", *(["--all"] if show_all else [])]

    def _inside_workspace(self, value: object, *, argument: str) -> Path:
        if value is None:
            return self._workspace
        if (
            not isinstance(value, str)
            or not value
            or "\x00" in value
            or len(value) > 4096
        ):
            raise InvalidToolArgumentsError(
                f"{argument} must be a non-empty path string"
            )
        try:
            resolved = (self._workspace / value).resolve()
        except (OSError, RuntimeError):
            raise InvalidToolArgumentsError(f"{argument} cannot be resolved") from None
        if not resolved.is_relative_to(self._workspace):
            raise InvalidToolArgumentsError(f"{argument} is outside the workspace")
        return resolved

    def _baseline(self, value: object) -> str:
        if not isinstance(value, str) or not value:
            raise InvalidToolArgumentsError("baseline must be a non-empty string")
        if (
            _REVISION_PATTERN.fullmatch(value)
            and ".." not in Path(value).parts
            and not _is_file(self._workspace / value)
        ):
            return value
        # Not a revision, so it must be an existing file inside the workspace.
        resolved = self._inside_workspace(value, argument="baseline")
        if not _is_file(resolved):
            raise InvalidToolArgumentsError(
                "baseline is neither a git revision nor a file in the workspace"
            )
        return str(resolved)


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:  # a name too long for the filesystem, for one
        return False


def _revision(value: object, *, argument: str) -> str:
    if not isinstance(value, str) or not _REVISION_PATTERN.fullmatch(value):
        raise InvalidToolArgumentsError(f"{argument} is not a valid git revision")
    return value


def _display_args(args: list[str], workspace: Path) -> list[str]:
    """The command as a user could rerun it from the workspace: paths
    relative to it, and gate's throwaway evidence path left out."""

    shown: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg == "--evidence-path":
            skip = True
            continue
        path = Path(arg)
        if path.is_absolute() and path.is_relative_to(workspace):
            arg = str(path.relative_to(workspace)) or "."
        shown.append(arg)
    return shown


def _result(request_id: str | int, result: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: str | int | None, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
