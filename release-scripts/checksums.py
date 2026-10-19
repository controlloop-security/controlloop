#!/usr/bin/env python3
"""Write and verify a combined `SHA256SUMS` checksum file for every
published release artifact.

Invoked by `.github/workflows/release.yml`'s `attest-artifacts` job as:

    python3 release-scripts/checksums.py write \\
        --output SHA256SUMS file1 file2 ...

    python3 release-scripts/checksums.py verify \\
        --checksums-file SHA256SUMS --dir .

Extends `build_binary.py::write_checksum` (one
`<binary>.sha256` file per standalone binary) with one combined file
covering every artifact a release publishes -- the wheel, the sdist,
`release-manifest.json`, and every standalone binary -- so
`docs/reference/release-verification.md` documents a single command a
downloader runs, not one per artifact. The existing per-binary `.sha256`
files are untouched; this is additive.

Deliberately dependency-free (stdlib only: `hashlib`, `re`, `argparse`,
`pathlib`), the same precedent `derive_release_metadata.py` and
`assemble_schema_site.py` already established.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

#: A `sha256sum`-compatible line: a 64-character lowercase hex digest,
#: two spaces (the "text mode" separator `sha256sum`/`shasum -a 256`
#: itself writes), then the filename. Deliberately strict -- a line that
#: doesn't match this shape is treated as malformed input, never silently
#: skipped, since a checksums file a caller cannot fully parse must never
#: be treated as "verified clean" by omission.
_LINE_PATTERN = re.compile(r"^(?P<digest>[0-9a-f]{64})  (?P<filename>.+)$")


class ChecksumError(RuntimeError):
    """Raised for any condition this script must fail loudly on: a
    missing file to checksum, a duplicate filename, a malformed
    checksums-file line, a missing artifact at verify time, or a digest
    mismatch."""


def write_checksums_file(paths: list[Path], output: Path) -> Path:
    """Write one combined checksums file covering every path in `paths`,
    sorted by filename so the output is deterministic regardless of the
    order `paths` was given in (the workflow step and a local, manual
    invocation may list artifacts in different orders). Raises
    `ChecksumError` if any path does not exist, or if two paths share a
    filename -- ambiguous once verified against one flat directory,
    per `verify_checksums_file` below."""

    entries: list[tuple[str, str]] = []
    seen_names: set[str] = set()
    for path in paths:
        if not path.is_file():
            raise ChecksumError(f"cannot checksum missing file: {path}")
        if path.name in seen_names:
            raise ChecksumError(
                f"duplicate filename across checksummed artifacts: {path.name}"
            )
        seen_names.add(path.name)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append((path.name, digest))

    entries.sort(key=lambda entry: entry[0])
    output.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in entries),
        encoding="utf-8",
    )
    return output


def parse_checksums_file(checksums_path: Path) -> dict[str, str]:
    """Return `{filename: expected_digest}` from a checksums file. Raises
    `ChecksumError` naming the exact line if any non-blank line does not
    match `_LINE_PATTERN`."""

    entries: dict[str, str] = {}
    text = checksums_path.read_text(encoding="utf-8")
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        match = _LINE_PATTERN.match(line)
        if match is None:
            raise ChecksumError(
                f"{checksums_path}:{line_number}: malformed checksums line: {line!r}"
            )
        entries[match.group("filename")] = match.group("digest")
    return entries


def verify_checksums_file(checksums_path: Path, artifacts_dir: Path) -> None:
    """Verify every artifact named in `checksums_path` exists directly
    inside `artifacts_dir` and its real SHA-256 digest matches. Raises
    `ChecksumError` listing every failure at once -- a missing file and a
    mismatched file elsewhere in the same run are both reported, never
    only the first encountered (a tampered artifact must be reported,
    not silently skipped past)."""

    expected = parse_checksums_file(checksums_path)
    failures: list[str] = []
    for filename, expected_digest in expected.items():
        artifact_path = artifacts_dir / filename
        if not artifact_path.is_file():
            failures.append(f"{filename}: missing")
            continue
        actual_digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        if actual_digest != expected_digest:
            failures.append(
                f"{filename}: checksum mismatch "
                f"(expected {expected_digest}, got {actual_digest})"
            )

    if failures:
        raise ChecksumError("checksum verification failed:\n" + "\n".join(failures))


def _write_command(args: argparse.Namespace) -> None:
    paths = [Path(raw) for raw in args.paths]
    output = write_checksums_file(paths, Path(args.output))
    print(f"wrote {output} covering {len(paths)} artifact(s)")


def _verify_command(args: argparse.Namespace) -> None:
    verify_checksums_file(Path(args.checksums_file), Path(args.dir))
    print(f"{args.checksums_file}: every listed artifact verified")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    write_parser = subparsers.add_parser(
        "write", help="write a combined SHA256SUMS file"
    )
    write_parser.add_argument("paths", nargs="+", help="files to checksum")
    write_parser.add_argument("--output", required=True, help="output path")

    verify_parser = subparsers.add_parser(
        "verify", help="verify a directory of artifacts against a checksums file"
    )
    verify_parser.add_argument("--checksums-file", required=True)
    verify_parser.add_argument(
        "--dir", required=True, help="directory the listed artifacts live in"
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "write":
            _write_command(args)
        else:
            _verify_command(args)
    except ChecksumError as error:
        print(f"checksums: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
