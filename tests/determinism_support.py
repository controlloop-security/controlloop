"""Reusable determinism-harness test infrastructure.

This module is test-only infrastructure -- it lives under `tests/`,
never `src/`, because nothing here is shipped or imported by the product.
It builds directly on the existing canonical primitives in
`controlloop.acbom.serialization` (`compute_digest`, `serialize_document`,
`canonicalize_document`) rather than reimplementing canonicalization: the
whole point of a determinism harness is to prove those primitives behave
as claimed, not to duplicate them.

`golden_fixture_bytes` / `build_golden_document` reuse the existing
`tests/fixtures/acbom/minimal-input.json` synthetic fixture rather than
adding a parallel one.

`assert_stable_digest` is the harness's one core primitive: it both proves
determinism (called with a genuinely deterministic ``build``) and proves
detection (called with a deliberately non-deterministic ``build`` in a test
that expects it to raise).

`digest_in_subprocess` exists because three of the four environment
dimensions -- `PYTHONHASHSEED`, locale, and timezone -- can only actually
vary at interpreter start. There is no way to change a running process's
hash seed, and changing `LC_ALL`/`TZ` mid-process does not reliably change
already-imported behavior. Each of those dimensions therefore requires a
fresh child process with the relevant environment variable set before
interpreter start.

`build_document_from_repository_walk` grounds the fourth dimension,
"differing filesystem iteration order," in the real
`controlloop.repository.walk_repository` production code path plus real
node construction and canonicalization -- one layer beyond what
`tests/test_repository.py` already proves about the walker itself in
isolation.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from controlloop.acbom import (
    ACBOMDocument,
    Confidence,
    Evidence,
    Generator,
    Node,
    NodeIdentityMaterial,
    NodeType,
    Repository,
    SecurityAttributes,
    SemanticIdentity,
    compute_digest,
    node_id,
    serialize_document,
    with_digest,
)
from controlloop.repository import resolve_repository_root, walk_repository

GOLDEN_FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "acbom" / "minimal-input.json"
)
"""The reusable golden fixture: the existing synthetic minimal ACBOM
document already committed for other tests, not a new one."""

DIGEST_EXCLUDED_FIELDS: frozenset[str] = frozenset({"digest"})
"""The explicit, named list of fields excluded from the digest.

Today this contains exactly one field: `ACBOMDocument.digest` itself --
the document's own self-referential digest, which `compute_digest`
excludes from its own input (see `serialization.py::_document_data`,
`exclude_digest=True`). No other field of the canonical schema is
excluded, and no field anywhere in the canonical model tree is currently
timestamp-shaped or otherwise inherently variable -- `test_determinism_
harness.py` proves both halves of that claim against real behavior:
that every field *in* this set really is excluded from the digest, and
that every field *not* in this set really does change the digest, plus a
structural guard that fails loudly if a future timestamp-shaped field is
ever added to the canonical schema without updating this list (and the
corresponding production exclusion or injection logic) at the same time.
"""

TIMESTAMP_LIKE_FIELD_MARKERS: tuple[str, ...] = (
    "timestamp",
    "createdat",
    "updatedat",
    "generatedat",
    "scannedat",
    "modifiedat",
    "builtat",
    "capturedat",
)
"""Substrings (matched against a casefolded, non-alphanumeric-stripped
field name) that would indicate a newly added inherently variable field.
Used only by the structural guard test, never by production code."""


def golden_fixture_bytes() -> bytes:
    """Read the golden fixture fresh from disk on every call.

    Never memoized: the harness's entire claim is that repeated,
    independent construction from the same source produces byte-identical
    output, so a cached document would prove nothing.
    """

    return GOLDEN_FIXTURE_PATH.read_bytes()


def build_golden_document() -> ACBOMDocument:
    """Parse the golden fixture into a fresh `ACBOMDocument` on every call.

    The fixture is canonicalization input with a placeholder `digest`, so
    it is parsed directly rather than through `load_acbom_document`, which
    rejects a document whose digest does not match its content. Every
    caller computes the digest itself.
    """

    return ACBOMDocument.model_validate_json(golden_fixture_bytes())


def assert_stable_digest(build: Callable[[], ACBOMDocument], *, runs: int = 5) -> str:
    """Call `build` `runs` times and assert every run's canonical bytes
    and digest are identical to the first run's. Returns the common
    digest on success.

    Raises `ValueError` if `runs < 2` (there is nothing to compare a
    single run against). Raises `AssertionError`, naming the first
    mismatching run and both digests, on the first detected divergence --
    this is the harness's detection engine: a `build` that is not actually
    deterministic makes this raise rather than silently passing.
    """

    if runs < 2:
        raise ValueError("assert_stable_digest requires at least 2 runs")

    first_document = build()
    first_digest = compute_digest(first_document)
    first_bytes = serialize_document(first_document)

    for attempt in range(2, runs + 1):
        document = build()
        digest = compute_digest(document)
        serialized = serialize_document(document)
        if digest != first_digest or serialized != first_bytes:
            raise AssertionError(
                "determinism harness detected non-determinism: run "
                f"{attempt} of {runs} produced digest {digest!r}, "
                f"expected {first_digest!r} (from run 1)"
            )

    return first_digest


def _subprocess_digest_script(tests_dir: str) -> str:
    return (
        "import sys\n"
        f"sys.path.insert(0, {tests_dir!r})\n"
        "from determinism_support import build_golden_document\n"
        "from controlloop.acbom import compute_digest\n"
        "sys.stdout.write(compute_digest(build_golden_document()))\n"
    )


def digest_in_subprocess(*, env: Mapping[str, str] | None = None) -> str:
    """Compute the golden fixture's canonical digest in a fresh child
    process, with `env` merged over (never replacing) a copy of the
    current process environment -- so only the caller-specified keys
    actually vary between invocations.

    Spawns a local child process via `subprocess.run` (`shell=False`,
    bounded `timeout`). This is never a network call, so it is unaffected
    by the autouse offline-denial fixture in `conftest.py`, which
    monkeypatches `socket` only in the current pytest process.

    Used for digest stability across separate processes and for
    stability under a differing `PYTHONHASHSEED`, locale, and timezone --
    each of which can only actually vary at process start.
    """

    tests_dir = str(Path(__file__).parent)
    script = _subprocess_digest_script(tests_dir)
    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=merged_env,
        timeout=30,
        check=False,
        shell=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "subprocess digest computation failed "
            f"(exit {result.returncode}): {result.stderr}"
        )
    return result.stdout


def build_document_from_repository_walk(root: Path) -> ACBOMDocument:
    """Build a minimal `ACBOMDocument` from a real `walk_repository` pass
    over `root`, one `resource` node per discovered file.

    Grounds the "differing filesystem iteration order" guarantee in
    the real production repository walker and real node construction,
    not only in an abstract model-level permutation (already covered by
    `tests/acbom/test_serialization_unit.py`'s permutation tests).
    """

    resolved_root = resolve_repository_root(root)
    nodes: list[Node] = []
    for entry in walk_repository(resolved_root):
        if not isinstance(entry, Path):
            continue
        relative = entry.relative_to(resolved_root.path).as_posix()
        material = NodeIdentityMaterial(
            node_type=NodeType.RESOURCE,
            namespace="determinism-harness.fixture-file",
            semantic_identity=SemanticIdentity(
                source_path=relative, in_document_key="file"
            ),
        )
        nodes.append(
            Node(
                id=node_id(material),
                type=NodeType.RESOURCE,
                name=f"Fixture file {relative}",
                security_attributes=SecurityAttributes(),
                confidence=Confidence.HIGH,
                evidence=(Evidence(adapter="determinism-harness", path=relative),),
            )
        )

    document = ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
        nodes=tuple(nodes),
        edges=(),
        diagnostics=(),
        digest=f"sha256:{'0' * 64}",
    )
    return with_digest(document)
