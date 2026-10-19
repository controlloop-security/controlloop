"""Generated fragments for `docs/reference/cli.md` and
`docs/reference/configuration.md`.

Mirrors `tests/concepts/reference_fixture.py`'s established
`<!-- BEGIN GENERATED: <name> -->`/`<!-- END GENERATED: <name> -->` marker
convention exactly: each function below renders one fragment directly from
real implementation state (`controlloop.exit_codes.EXIT_CODE_INFO`,
`controlloop.config._KEY_SPECS`), never from a second, hand-maintained copy
of the same facts. `tests/reference/test_cli_reference_doc.py` extracts the
committed doc's own marked regions and asserts they equal a fresh call to
these functions -- byte for byte, so the doc cannot silently drift from the
implementation.

Run as a script (`python cli_doc_fixtures.py`) to print every current
fragment for pasting into the docs by hand when regenerating after a
real implementation change, the same regeneration workflow
`reference_fixture.py` already established.
"""

from __future__ import annotations

import re

from controlloop.config import _ENV_PREFIX, _KEY_SPECS
from controlloop.exit_codes import EXIT_CODE_INFO, ExitCode

#: Which CLI flag (if any) each configuration key is also settable through,
#: so every configuration key is documented with its default and precedence.
#: Deliberately a local, explicit mapping here rather than a new field on
#: `controlloop.config._KeySpec` -- `config.py`'s own module docstring
#: establishes this codebase's precedent of keeping that module a
#: dependency-light leaf with locally declared literal sets
#: (`_SEVERITY_THRESHOLD_VALUES` and siblings) that a drift test guards
#: rather than importing a heavier shared type.
#: `tests/reference/test_cli_reference_doc.py`'s
#: `TestEveryConfigKeyDocumented.
#: test_flag_mapping_covers_exactly_the_real_key_registry` asserts this
#: dict's key set is exactly `set(_KEY_SPECS)`, so a new configuration
#: key without an entry here fails immediately rather than silently
#: rendering "none yet" by omission.
CLI_FLAG_BY_KEY: dict[str, str] = {
    "max_file_size_bytes": "--max-file-size-bytes",
    "max_total_bytes": "--max-total-bytes",
    "max_file_count": "--max-file-count",
    "max_depth": "--max-depth",
    "severity_threshold": "none yet",
    "low_confidence_action": "none yet",
    "disabled_rules": "none yet",
    "completeness_enforcement": "none yet",
    # None of the Team keys has a flag: they configure a repository's
    # relationship with its organization, which is a property of the
    # repository and its CI environment, not of one invocation.
    # `--team-endpoint` on a command line would put a per-run override on a
    # setting whose whole point is being recorded in a commit.
    "team_enabled": "none yet",
    "team_fail_mode": "none yet",
    "team_endpoint": "none yet",
    "team_organization_id": "none yet",
    "team_project_id": "none yet",
    "team_branch": "none yet",
    "team_pull_request": "none yet",
    "team_policy_cache_seconds": "none yet",
}


def render_exit_code_table() -> str:
    """`docs/reference/cli.md`'s "Exit codes" table, generated directly from
    `ExitCode` and `EXIT_CODE_INFO`, so every exit code is documented with
    when it occurs and what to do about it."""

    lines = [
        "| Code | Meaning | When it occurs | Remediation |",
        "| ---: | --- | --- | --- |",
    ]
    for code in ExitCode:
        info = EXIT_CODE_INFO[code]
        lines.append(
            f"| {int(code)} | {info.meaning} | {info.when_it_occurs} | "
            f"{info.remediation} |"
        )
    return "\n".join(lines)


def render_config_key_table() -> str:
    """`docs/reference/configuration.md`'s configuration-key table,
    generated directly from `controlloop.config._KEY_SPECS`, so every
    configuration key is documented with its default and precedence --
    "precedence" is the shared four-tier order the surrounding prose in
    `configuration.md` already documents once, identically, for every key;
    this table's own job is naming each key's repository-file/environment
    name, flag (if any), and default)."""

    lines = [
        "| Key | Repository file / environment name | Flag | Default |",
        "| --- | --- | --- | ---: |",
    ]
    for key, spec in _KEY_SPECS.items():
        env_name = _ENV_PREFIX + key.upper()
        default = spec.default
        if isinstance(default, tuple):
            default_str = "(empty)" if not default else ",".join(default)
        elif isinstance(default, bool):
            # TOML spelling, not Python's: this table is meant to be
            # copied into a `controlloop.toml`, and `team_enabled = False`
            # is not valid TOML.
            default_str = "`true`" if default else "`false`"
        elif default == "":
            default_str = "(none)"
        else:
            default_str = f"`{default}`"
        flag = CLI_FLAG_BY_KEY[key]
        flag_str = flag if flag == "none yet" else f"`{flag}`"
        lines.append(
            f"| `{key}` | `{key}` / `{env_name}` | {flag_str} | {default_str} |"
        )
    return "\n".join(lines)


#: Every generated fragment, keyed by the marker name used in the two
#: docs above -- the single source of truth both the doc-sync test and
#: the `__main__` regeneration helper below iterate over, mirroring
#: `reference_fixture.py`'s own `GENERATED_FRAGMENTS`.
GENERATED_FRAGMENTS: dict[str, str] = {
    "exit-codes": render_exit_code_table(),
    "configuration-keys": render_config_key_table(),
}


_MARKER_PATTERN = re.compile(
    r"<!-- BEGIN GENERATED: (?P<name>[a-z-]+) -->\n"
    r"(?P<body>.*?)"
    r"\n<!-- END GENERATED: (?P=name) -->",
    re.DOTALL,
)


def extract_generated_fragments(doc_text: str) -> dict[str, str]:
    """Every `<!-- BEGIN GENERATED: name -->`/`<!-- END GENERATED: name -->`
    region in `doc_text`, keyed by marker name, body exactly as written
    between the two marker lines. Raises `ValueError` on a marker name
    repeated in the same document. Identical in shape to
    `reference_fixture.py`'s own function of the same name, duplicated
    rather than imported across the two unrelated doc-sync helpers to keep
    each one independently readable and independently owned."""

    fragments: dict[str, str] = {}
    for match in _MARKER_PATTERN.finditer(doc_text):
        name = match.group("name")
        if name in fragments:
            raise ValueError(f"duplicate generated marker {name!r} in document")
        fragments[name] = match.group("body")
    return fragments


if __name__ == "__main__":
    for _name, _text in GENERATED_FRAGMENTS.items():
        print(f"--- {_name} ---")
        print(_text)
        print()
