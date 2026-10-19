#!/usr/bin/env python3
"""Assemble the static site published to `schemas.controlloop.ai`.

Invoked by `.github/workflows/release.yml` as:

    python3 release-scripts/assemble_schema_site.py \\
        --schemas-root src/controlloop/schemas \\
        --output _schema-site

Copies every packaged schema file -- every version of every family,
including frozen historical ones -- into a directory tree matching the
exact URL shape each file's own `$id` already declares:
`<family>/<version>/<family>.schema.json`. Published schemas are never
modified in place, which is why every historical version is copied here
too, not only the current one -- a URL that has ever
resolved must keep resolving. Writes a `CNAME` file naming the custom
domain (GitHub Pages' own mechanism for associating a Pages deployment
with a domain a maintainer points DNS at separately -- this
script and the workflow that runs it do not, and cannot, configure DNS
themselves).

Deliberately dependency-free (stdlib only), mirroring
`derive_release_metadata.py`'s own precedent.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

SCHEMA_DOMAIN = "schemas.controlloop.ai"


def assemble(schemas_root: Path, output: Path) -> list[Path]:
    """Copy every `<family>/<version>/<family>.schema.json` file under
    `schemas_root` into the identical relative path under `output`.
    Returns the list of files copied, for the caller to report."""

    output.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []

    for family_dir in sorted(p for p in schemas_root.iterdir() if p.is_dir()):
        for version_dir in sorted(p for p in family_dir.iterdir() if p.is_dir()):
            schema_files = sorted(version_dir.glob("*.schema.json"))
            for schema_file in schema_files:
                relative = schema_file.relative_to(schemas_root)
                destination = output / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(schema_file, destination)
                copied.append(relative)

    (output / "CNAME").write_text(f"{SCHEMA_DOMAIN}\n", encoding="utf-8")

    return copied


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schemas-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if not args.schemas_root.is_dir():
        print(f"schemas root does not exist: {args.schemas_root}", file=sys.stderr)
        return 2

    copied = assemble(args.schemas_root, args.output)
    if not copied:
        print(
            "no schema files found -- refusing to publish an empty site",
            file=sys.stderr,
        )
        return 2

    for relative in copied:
        print(f"copied {relative}")
    print(f"wrote {args.output / 'CNAME'} ({SCHEMA_DOMAIN})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
