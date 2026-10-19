#!/usr/bin/env python3
"""Enforce and extract a release's `CHANGELOG.md` entry: `CHANGELOG.md` is
updated as part of a release, and a release without changelog entries
fails.

Invoked by `.github/workflows/release.yml` as:

    python3 release-scripts/changelog_release_notes.py 0.2.0

Exits `1` (with a specific stderr message) if `CHANGELOG.md` has no
`## [0.2.0]` heading, or that section has no non-empty content under it.
On success, prints the section's own body to stdout -- reused verbatim as
the GitHub Release's notes, so release notes are always real changelog
content, never hand-written at release time.

Deliberately dependency-free (stdlib only). Never mutates `CHANGELOG.md`;
converting `## [Unreleased]` into a dated `## [X.Y.Z]` section is a human
step that happens in the pull request that prepares a release, before the
tag is pushed -- this script only verifies that happened.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

#: Matches a whole `## [X.Y.Z] - <anything, e.g. a date>` heading line,
#: including its own trailing date suffix and line ending, so that suffix
#: is never mistaken for the section's own body content.
_HEADING_PATTERN = re.compile(r"^##\s*\[(?P<version>[^\]]+)\][^\n]*\n?", re.MULTILINE)


class ChangelogGateError(RuntimeError):
    """Raised when `CHANGELOG.md` has no real entry for the requested
    version."""


def extract_section(changelog_text: str, version: str) -> str:
    """Return the body text between the `## [version]` heading and the
    next `##` heading (or end of file), stripped. Raises
    `ChangelogGateError` if the heading is missing or its body is empty."""
    headings = list(_HEADING_PATTERN.finditer(changelog_text))
    start_index = None
    for index, match in enumerate(headings):
        if match.group("version") == version:
            start_index = index
            break
    if start_index is None:
        raise ChangelogGateError(
            f"CHANGELOG.md has no '## [{version}]' heading -- add the "
            "release's changelog entries (moving them out of "
            "'## [Unreleased]') before tagging"
        )
    section_start = headings[start_index].end()
    section_end = (
        headings[start_index + 1].start()
        if start_index + 1 < len(headings)
        else len(changelog_text)
    )
    body = changelog_text[section_start:section_end].strip()
    if not body:
        raise ChangelogGateError(
            f"CHANGELOG.md's '## [{version}]' section has no entries -- a "
            "release without changelog entries fails"
        )
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="The release version, e.g. 0.2.0")
    parser.add_argument(
        "--changelog",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "CHANGELOG.md",
        help="Path to CHANGELOG.md (default: repository root CHANGELOG.md)",
    )
    args = parser.parse_args(argv)

    try:
        text = args.changelog.read_text(encoding="utf-8")
    except OSError as error:
        print(
            f"changelog_release_notes: could not read {args.changelog}: {error}",
            file=sys.stderr,
        )
        return 1

    try:
        body = extract_section(text, args.version)
    except ChangelogGateError as error:
        print(f"changelog_release_notes: {error}", file=sys.stderr)
        return 1

    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
