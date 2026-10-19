"""Generate a canonical ACBOM from a repository.

`build_acbom_document` is the one function `controlloop bom` calls to go
from a resolved repository root to a complete, digested `ACBOMDocument`:
walk the repository, run every registered discovery adapter, run the
discovery-time secret-shaped-content scan (`controlloop.secret_scan`),
and wrap the result in the canonical envelope (`schema_version`,
`generator`, `repository`, `digest`). No policy evaluation and no rule
configuration are involved anywhere in this path -- that is
`scan`/`gate`'s job, not this one's; the
secret scan's own output (`Diagnostic`s on `ACBOMDocument.diagnostics`)
is evidence a later rule (`controlloop.policy.rules.hardcoded_secrets`)
reads, not itself a policy verdict.

Repository identity (`ACBOMDocument.repository`) is deliberately
minimal. `commit` is the output of `git rev-parse HEAD` when `root` is a
git checkout with at least one commit, or the literal `"unknown"`
otherwise (a fresh repository, a detached export, or `git` unavailable
-- never a crash, since generation must still succeed offline and
outside a git checkout). `root_digest` is a SHA-256 over the sorted,
repository-relative paths this scan actually walked -- it names *what
was scanned*, not each file's content; detecting content-only drift
between two scans of the same path set is diff/baseline work, not this
module's, and is disclosed as a known limitation rather than silently
assumed.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from controlloop import __version__
from controlloop.acbom import (
    ACBOMDocument,
    Diagnostic,
    Evidence,
    Generator,
    Node,
    Repository,
    incomplete_diagnostic,
    with_digest,
)
from controlloop.acbom.models import CommitIdentifier, Sha256Digest
from controlloop.acbom.versioning import CURRENT_SCHEMA_URL, CURRENT_SCHEMA_VERSION
from controlloop.adapters import ALL_ADAPTERS, ScanContext, run_adapters
from controlloop.adapters.sandbox import adapter_sandbox
from controlloop.manifest import ManifestValidationError, load_manifest
from controlloop.manifest.annotation import annotate_tool_capabilities
from controlloop.manifest.reconciliation import (
    manifest_evidence,
    unverified_diagnostic,
)
from controlloop.repository import RepositoryRoot, TraversalBounds, walk_repository
from controlloop.secret_scan import scan_repository_for_secrets

_GENERATOR_NAME = "controlloop"
_UNKNOWN_COMMIT: CommitIdentifier = "unknown"
_PLACEHOLDER_DIGEST: Sha256Digest = f"sha256:{'0' * 64}"
_MANIFEST_FILENAME = "controlloop.yaml"


def _resolve_commit(root_path: Path) -> CommitIdentifier:
    """Return `root_path`'s current commit via `git rev-parse HEAD`, or
    `"unknown"` if it is not a git checkout with at least one commit, or
    `git` is not installed. Local and read-only; never touches the
    network."""

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root_path,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return _UNKNOWN_COMMIT

    commit = result.stdout.strip()
    if result.returncode != 0 or not commit:
        return _UNKNOWN_COMMIT
    return commit


def _compute_root_digest(root_path: Path, files: list[Path]) -> Sha256Digest:
    """Hash the sorted, repository-relative paths of every file in
    `files` -- deterministic regardless of filesystem iteration order."""

    relative_paths = sorted(path.relative_to(root_path).as_posix() for path in files)
    digest_input = "\n".join(relative_paths).encode("utf-8")
    return f"sha256:{hashlib.sha256(digest_input).hexdigest()}"


def _run_secret_scan(root: RepositoryRoot, files: list[Path]) -> tuple[Diagnostic, ...]:
    """Run `controlloop.secret_scan.scan_repository_for_secrets`, isolated
    the same way `controlloop.adapters.runner` isolates a real adapter's
    own failure -- inside `adapter_sandbox()` (deny write/subprocess/
    socket, the same defense-in-depth every real adapter already runs
    under, even though this pass is not itself registered as a
    `DiscoveryAdapter`; see `controlloop.secret_scan`'s own module
    docstring for why) and with a broad `except Exception` converting a
    raised error into one `INCOMPLETE-ADAPTER-FAILURE` diagnostic rather
    than crashing the whole `bom` generation (the adapter-isolation
    approach, reused here for consistency)."""

    try:
        with adapter_sandbox():
            return scan_repository_for_secrets(root, files)
    except Exception as error:
        return (
            incomplete_diagnostic(
                code="INCOMPLETE-ADAPTER-FAILURE",
                message=(
                    "secret-shaped-content scanning failed "
                    f"({type(error).__name__}) and was isolated; no "
                    "detections from this pass are included"
                ),
                evidence=(
                    Evidence(adapter="secret-scan", path="<secret-scan-evaluation>"),
                ),
            ),
        )


def _annotate_from_manifest(
    root: RepositoryRoot, nodes: tuple[Node, ...]
) -> tuple[tuple[Node, ...], tuple[Diagnostic, ...]]:
    """Supplement discovered tool nodes with the repository's own
    `tool_capabilities` declarations.

    Deliberately lenient about the manifest itself. `bom` has never
    required a `controlloop.yaml`, and a repository with a broken one
    must still be able to produce an ACBOM -- `scan`/`gate` load the
    same file through `_scan_load_manifest`, which reports a parse
    failure properly and exits `2`. So an absent manifest is silent, and
    an unreadable or invalid one degrades to an explicit diagnostic
    rather than either raising here or silently pretending the file said
    nothing.
    """

    manifest_path = root.path / _MANIFEST_FILENAME
    if not manifest_path.exists():
        return nodes, ()

    evidence = manifest_evidence(_MANIFEST_FILENAME)
    try:
        raw = manifest_path.read_text(encoding="utf-8")
    except OSError:
        return nodes, (
            unverified_diagnostic(
                evidence, "the manifest could not be read, so no tool was annotated"
            ),
        )
    try:
        manifest = load_manifest(raw, path=_MANIFEST_FILENAME)
    except ManifestValidationError:
        return nodes, (
            unverified_diagnostic(
                evidence,
                "the manifest could not be parsed, so no tool was annotated",
            ),
        )
    return annotate_tool_capabilities(nodes, manifest, evidence)


def build_acbom_document(
    root: RepositoryRoot,
    *,
    bounds: TraversalBounds | None = None,
    commit_override: CommitIdentifier | None = None,
) -> ACBOMDocument:
    """Generate a complete, digested `ACBOMDocument` for `root`.

    Requires no policy configuration and evaluates no rules:
    every diagnostic in the result comes from repository traversal or
    adapter discovery, never from a rule engine. Repeated calls over an
    unchanged repository produce an identical digest, since
    `walk_repository`, `run_adapters`, and `with_digest` are each
    already independently deterministic.

    `commit_override`, when given, is recorded as `repository.commit`
    directly instead of calling `_resolve_commit(root.path)` -- added for
    `controlloop.baseline.merge_base.build_merge_base_acbom`, which scans
    a materialized copy of a historical revision that is a plain
    directory, not itself a git checkout, so `_resolve_commit` would
    otherwise report `"unknown"` for a commit the caller already knows
    precisely. `None` (the default) preserves this function's original
    behavior for every existing caller.
    """

    walked = list(walk_repository(root, bounds=bounds))
    files = [entry for entry in walked if isinstance(entry, Path)]
    walk_diagnostics = tuple(entry for entry in walked if isinstance(entry, Diagnostic))

    discovery = run_adapters(
        [adapter_cls() for adapter_cls in ALL_ADAPTERS], ScanContext(root=root)
    )
    secret_scan_diagnostics = _run_secret_scan(root, files)
    nodes, annotation_diagnostics = _annotate_from_manifest(root, discovery.nodes)

    document = ACBOMDocument(
        schema_version=CURRENT_SCHEMA_VERSION,
        schema_url=CURRENT_SCHEMA_URL,
        generator=Generator(name=_GENERATOR_NAME, version=__version__),
        repository=Repository(
            commit=commit_override
            if commit_override is not None
            else _resolve_commit(root.path),
            root_digest=_compute_root_digest(root.path, files),
        ),
        nodes=nodes,
        edges=discovery.edges,
        diagnostics=(
            walk_diagnostics
            + discovery.diagnostics
            + secret_scan_diagnostics
            + annotation_diagnostics
        ),
        digest=_PLACEHOLDER_DIGEST,
    )
    return with_digest(document)
