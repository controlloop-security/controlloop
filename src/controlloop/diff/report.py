"""The `controlloop diff` command's report envelope.

`DiffResult` (`controlloop.diff.models`) classifies nodes, edges, and
effective-capability facts against a baseline graph, but says nothing
about *where* that baseline graph came from or *whether* a node and edge
comparison was even attempted. Both are structural facts about this
command's own three usage forms, not properties of the classification
itself, so they are not added to `DiffResult` -- that model, and every
field on `NodeChange`/`EdgeChange`/`EffectiveAuthorityChange`, stays
unchanged.

`DiffReport` wraps an unmodified `DiffResult` with that missing context
instead:

- `baseline_origin` names which of this command's five resolution paths
  supplied the comparison ("diff output never silently switches to the
  merge-base baseline; the user is told which was used" -- this is the
  structural place that disclosure lives).
- `comparison_scope` distinguishes `FULL` (both sides are real ACBOM
  graphs: two ACBOM files, a merge-base scan, or an explicit-revision
  scan) from `EFFECTIVE_AUTHORITY_ONLY` (the baseline side is a resolved
  `BaselineDocument`, which carries no `nodes`/`edges` at all --
  `controlloop.baseline.models` -- so `node_changes`/`edge_changes` on
  the wrapped `DiffResult` are empty because they were never evaluated,
  not because nothing changed).

`comparison_scope` living in the same payload as the changes themselves
-- not only a stderr diagnostic -- is deliberate: a caller parsing only
`--format json` stdout must not be able to mistake "not evaluated" for
"confirmed zero," which is exactly the "Unknown, never omitted"
invariant applied to this command's own biggest honesty risk. See
docs/reference/diff-output-format.md's "CLI report envelope" section.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from controlloop.acbom.models import SafeText, SemanticVersion
from controlloop.diff.authority import AuthorityDelta
from controlloop.diff.models import DiffResult, _DiffModel

#: 1.1.0 adds the optional `authority_delta`, left out of the serialized
#: report when there is none -- a MINOR bump.
CURRENT_DIFF_REPORT_SCHEMA_VERSION = "1.1.0"


class BaselineOrigin(StrEnum):
    """Which of `diff`'s five resolution paths supplied the comparison's
    baseline side."""

    TWO_ACBOMS = "two_acboms"
    """`diff FIRST SECOND`: two ACBOM files compared directly. `FIRST` is
    the baseline side, `SECOND` is the current side."""

    EXPLICIT_BASELINE_FILE = "explicit_baseline_file"
    """`diff REPOSITORY --baseline PATH`, where `PATH` exists as a
    readable file: an explicit committed-baseline-document override
    (`controlloop.baseline.resolve_baseline`, `explicit_path=PATH`)."""

    COMMITTED_BASELINE = "committed_baseline"
    """`diff REPOSITORY` with no `--baseline`: a baseline committed at
    the conventional path (`.controlloop/baseline.json`) was found."""

    MERGE_BASE = "merge_base"
    """`diff REPOSITORY` with no `--baseline` and no committed baseline:
    the merge-base of the default branch was resolved and scanned
    (`controlloop.baseline.resolve_merge_base`/`build_merge_base_acbom`)."""

    EXPLICIT_REVISION = "explicit_revision"
    """`diff REPOSITORY --baseline VALUE`, where `VALUE` does not exist
    as a file: resolved locally as a git revision and scanned."""


class ComparisonScope(StrEnum):
    """Whether the wrapped `DiffResult`'s `node_changes`/`edge_changes`
    were actually evaluated (an honesty requirement -- see this module's
    own docstring)."""

    FULL = "full"
    """Both sides are real ACBOM graphs: `node_changes`, `edge_changes`,
    and `effective_authority_changes` were all computed."""

    EFFECTIVE_AUTHORITY_ONLY = "effective_authority_only"
    """The baseline side is a resolved `BaselineDocument`, which carries
    no `nodes`/`edges` at all. `node_changes`/`edge_changes` on the
    wrapped `DiffResult` are empty tuples because they were never
    evaluated -- not because nothing changed."""


class DiffReport(_DiffModel):
    """Complete, self-describing output of the `controlloop diff`
    command: an unmodified `DiffResult` plus the resolution context a
    bare `DiffResult` cannot express on its own. Follows the same model
    discipline as every other canonical model in this codebase
    (`extra="forbid", frozen=True, strict=True`, inherited from
    `_DiffModel`). No packaged JSON schema file exists for this
    contract, matching `DiffResult`'s own precedent: this is a computed
    CLI report, not a persisted artifact like the ACBOM or a baseline.
    """

    schema_version: SemanticVersion
    baseline_origin: BaselineOrigin
    baseline_description: SafeText
    """Human-readable identification of the resolved baseline: a file
    path, a resolved commit and the ref it came from, or a description
    of the two compared ACBOM files. Never repository content, secret
    values, or anything the redaction boundary would need to scrub --
    only paths and git-local identifiers already safe to display
    elsewhere in this codebase (for example `ResolvedBaseline.path`,
    `MergeBaseResolution.merge_base_commit`)."""

    comparison_scope: ComparisonScope
    result: DiffResult
    #: Every grant the change hands an agent, one statement each. Left
    #: out of the serialized report when `None`.
    authority_delta: AuthorityDelta | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
