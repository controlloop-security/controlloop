"""Print the blast-radius statement embedded in a SARIF log document's
`runs[0].properties.controlloop.blastRadius`.

Used by `action.yml`'s "Write the check summary" step -- kept as a real
script file rather than an inline `python -c` one-liner in the YAML,
which cannot hold a multi-line, indented Python block (a YAML block
scalar's own indentation rules and Python's own top-level-statement
indentation rule conflict).

It also prints the authority statement from
`runs[0].properties.controlloop.authorityDelta`: one bullet per grant the
change hands an agent, the agent's name in bold. A change that grants
nothing prints nothing more.

A missing, unreadable, or malformed SARIF file, or one written by a
version that did not yet emit the property, prints nothing and exits `0` -- this is
a best-effort summary line, never something that should fail the
action's own step over a formatting surprise in a file the action
itself just wrote moments earlier.
"""

from __future__ import annotations

import json
import sys


def main() -> None:
    sarif_path = sys.argv[1]
    try:
        with open(sarif_path, encoding="utf-8") as handle:
            document = json.load(handle)
        namespace = document["runs"][0].get("properties", {}).get("controlloop", {})
        lines = namespace.get("blastRadius", [])
        entries = namespace.get("authorityDelta", [])
    except (OSError, KeyError, IndexError, AttributeError, json.JSONDecodeError):
        lines, entries = [], []

    for line in lines:
        print(line)
    statements = [
        _bold_host(entry)
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("statement"), str)
    ]
    if statements:
        print()
        print("**Authority**")
        print()
        for statement in statements:
            print(f"- {statement}")


def _bold_host(entry: dict[str, object]) -> str:
    statement = str(entry["statement"])
    host = entry.get("host_name")
    if isinstance(host, str) and host:
        return statement.replace(f"gives {host} ", f"gives **{host}** ", 1)
    return statement


if __name__ == "__main__":
    main()
