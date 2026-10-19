#!/usr/bin/env python3
"""A minimal, stdlib-only stdio MCP server test double.

Never used in production -- exists only so tests can spawn a real
subprocess and exercise `normalize_live_mcp_server`'s actual JSON-RPC
client code, rather than mocking the transport away. Takes one
argument: a path to a JSON config file describing its behavior.

Config shape:
    {
        "mode": "normal" | "malformed" | "oversized" | "hang" | "crash",
        "tools": [{"name": ..., "description": ..., "inputSchema": {...}}],
        "resources": [{"uri": ..., "name": ..., "description": ..., "mimeType": ...}]
    }
"""

from __future__ import annotations

import json
import sys
import time


def _write(message: object) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main() -> None:
    config_path = sys.argv[1]
    with open(config_path, encoding="utf-8") as handle:
        config = json.load(handle)
    mode = config.get("mode", "normal")

    if mode == "crash":
        sys.exit(1)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = request.get("method")
        request_id = request.get("id")

        if method == "notifications/initialized":
            continue

        if method == "initialize":
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "serverInfo": {"name": "stub-server", "version": "0.0.0"},
                    },
                }
            )
            continue

        if method == "tools/list":
            if mode == "hang":
                time.sleep(config.get("hang_seconds", 30))
                continue
            if mode == "malformed":
                sys.stdout.write("not valid json at all\n")
                sys.stdout.flush()
                continue
            if mode == "oversized":
                padding = "x" * config.get("oversized_bytes", 11 * 1024 * 1024)
                _write(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {"tools": [{"name": "t", "description": padding}]},
                    }
                )
                continue
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"tools": config.get("tools", [])},
                }
            )
            continue

        if method == "resources/list":
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"resources": config.get("resources", [])},
                }
            )
            continue

        _write(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            }
        )


if __name__ == "__main__":
    main()
