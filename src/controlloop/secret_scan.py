"""Discovery-time secret-shaped-content scanning.

## Why this module exists, and why it is not a `Rule`

`controlloop.policy.engine` structurally forbids a `Rule.evaluate` from
touching the filesystem (an AST import check and a runtime import
guard). Detection needs to scan real file content for secret-shaped
strings and high-entropy values -- content a `Rule` has no way to reach.
This module is the upstream discovery pass that does that reading, once,
during ACBOM construction (`controlloop.bom.build_acbom_document`,
alongside `walk_repository` and `run_adapters`), producing `Diagnostic`s
a `Rule` (`controlloop.policy.rules.hardcoded_secrets`) then only reads.

## Why a `Diagnostic`, not a `DiscoveryAdapter`

Seriously considered and disclosed as a real, human-reviewable
architectural choice: registering this as a
`controlloop.adapters.framework.DiscoveryAdapter` in `ALL_ADAPTERS`
would pull it into `tests/adapters/test_adapter_conformance.py`'s
shared conformance suite, built for adapters that parse *one structured
document format* with an in-document version marker (MCP configs,
OpenAPI, A2A cards, OASF, IAM policy). A whole-repository,
format-agnostic content scanner has no document version to drift, and
forcing it through that suite would mean fabricating a meaningless
"version" concept. This module is instead a directly-invoked, bounded
discovery pass -- the same category
`controlloop.repository.walk_repository` itself already is, also
outside `ALL_ADAPTERS`, also containment- and bounds-safe, also with
its own dedicated test module rather than the shared adapter
conformance suite.

## What is detected, and at what confidence

- **Known credential shapes** (`SECRET-CREDENTIAL-SHAPE-DETECTED`):
  reuses `controlloop.redaction.scan_credential_shapes` -- the same
  signature-based pattern set `redact_text` already uses -- rather than
  a second copy of it. Baseline confidence: `HIGH`.
- **High-entropy values** (`SECRET-HIGH-ENTROPY-VALUE-DETECTED`): a
  value with no fixed signature, so this tier is disclosed as genuinely
  less certain than a shape match. Requires *both* a credential-
  suggestive assignment context on the same line (a keyword such as
  `secret`, `token`, `password`, `api_key`, `credential`, or `auth`
  immediately followed by `=`/`:` ) *and* a candidate value of at least
  20 base64/hex/URL-safe characters whose Shannon entropy is at or above
  4.0 bits/character -- a widely used practical threshold for this class
  of heuristic, never claimed as a proven statistical guarantee.
  Baseline confidence: `MEDIUM`, one tier below a known-shape match.
- **Test fixtures and documented example values**: confidence is
  downgraded one tier -- never treated as certain -- when either the
  file's own repository-relative path looks like a test/fixture location
  (a path segment such as `tests`, `fixtures`, `examples`, `samples`,
  `mocks`, `specs`, or `demos`), or the matched value itself is a
  documented, well-known placeholder (AWS's own published documentation
  example key, Stripe's own documented `sk_test_` prefix, a small set of
  generic filler markers, a run of four or more identical characters, or
  a four-or-more-digit ascending/descending run). A known-shape match
  downgraded this way lands at `MEDIUM`; an entropy match downgraded
  this way lands at `LOW`. Neither ever reaches `HIGH`, and neither is
  ever silently dropped.

## Privacy

Every `Diagnostic` this module produces carries a pattern/heuristic name
and a location (`Evidence.path`/`line_start`/`line_end`) -- never the
matched value, and never any surrounding line content. The matched
substring exists only transiently, inside this module's own local
variables, for exactly as long as it takes to classify its confidence
(fixture/placeholder check, entropy calculation); it is never passed to
`Diagnostic`, logged, or returned. `tests/test_secret_scan.py`
proves this both structurally and with a planted-secret runtime canary,
mirroring `tests/test_redaction.py`'s own established canary
pattern.

## Bounds and isolation

`SecretScanBounds.max_detections` is a global, cumulative cap (default
200 -- generous, disclosed, not a tuned production threshold) on
retained diagnostics, mirroring `controlloop.repository.TraversalBounds`
and `controlloop.policy.models.EvaluationBounds`'s own role: exceeding
it appends one `INCOMPLETE-BOUND-EXCEEDED` diagnostic and stops, rather
than silently truncating. A single file's decode failure is isolated (a
per-file try/except producing one `INCOMPLETE-UNPARSED-REGION`
diagnostic) so it cannot discard detections in unrelated files. Only
files `controlloop.repository.walk_repository` itself already yielded
are read -- containment, `.gitignore`, and size/count/depth bounds are
inherited, never reimplemented here.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from controlloop import redaction
from controlloop.acbom.completeness import incomplete_diagnostic
from controlloop.acbom.models import (
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Evidence,
)
from controlloop.repository import RepositoryRoot

_ADAPTER_NAME = "secret-scan"

_SHAPE_DETECTED_CODE = "SECRET-CREDENTIAL-SHAPE-DETECTED"
_ENTROPY_DETECTED_CODE = "SECRET-HIGH-ENTROPY-VALUE-DETECTED"
_UNPARSED_REGION_CODE = "INCOMPLETE-UNPARSED-REGION"
_BOUND_EXCEEDED_CODE = "INCOMPLETE-BOUND-EXCEEDED"

#: This module's own closed, documented diagnostic code registry (the
#: same pattern `controlloop.repository.DIAGNOSTIC_REGISTRY` already
#: establishes) for the two codes it mints itself.
#: `INCOMPLETE-UNPARSED-REGION`/`INCOMPLETE-BOUND-EXCEEDED` are reused
#: from `controlloop.acbom.completeness.INCOMPLETE_DIAGNOSTIC_REGISTRY`
#: unchanged, not redefined here.
DIAGNOSTIC_REGISTRY: dict[str, str] = {
    _SHAPE_DETECTED_CODE: (
        "Content matching a known, signature-based credential shape was "
        "found. The matched value is never included; only its shape name "
        "and location."
    ),
    _ENTROPY_DETECTED_CODE: (
        "A high-entropy value assigned to a credential-like variable was "
        "found. A heuristic signal, disclosed as less certain than a known "
        "credential shape match; the matched value is never included."
    ),
}

#: Path segments (case-insensitive, delimiter-split) that mark a file
#: as a test fixture or documented example location for the confidence
#: downgrade.
_FIXTURE_SEGMENT_KEYWORDS: frozenset[str] = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "fixture",
        "fixtures",
        "testdata",
        "example",
        "examples",
        "sample",
        "samples",
        "mock",
        "mocks",
        "spec",
        "specs",
        "demo",
        "demos",
    }
)
_PATH_SPLIT_PATTERN = re.compile(r"[/_.\-]")

#: A small set of documented, well-known placeholder credential values --
#: not exhaustive, disclosed as an initial baseline the same way
#: `controlloop.redaction._CREDENTIAL_SHAPES` is.
_KNOWN_PLACEHOLDER_VALUES: frozenset[str] = frozenset({"AKIAIOSFODNN7EXAMPLE"})
_PLACEHOLDER_MARKER_PATTERN = re.compile(
    r"(?i)(example|placeholder|changeme|replace[-_]?me|your[-_]|dummy|fake)"
)
_REPEATED_CHARACTER_RUN_PATTERN = re.compile(r"(.)\1{3,}")
_STRIPE_TEST_PREFIX = "sk_test_"

#: A credential-suggestive assignment on one line: a keyword, `=`/`:`,
#: then a candidate value of base64/hex/URL-safe characters, 20-256
#: long (the high-entropy tier). Group 1 is the candidate value itself
#: -- offsets are taken from that group, never the keyword, so
#: evidence locates the value, not the variable name.
_ENTROPY_ASSIGNMENT_PATTERN = re.compile(
    # A name prefix is allowed (`MAIL_API_KEY`, `githubToken`).
    r"(?i)\b\w*?(?:secret|token|password|passwd|pwd|api[_-]?key|credential|auth)\w*"
    # A quoted key, as in a JSON `env` or `headers` block.
    r"['\"]?"
    r"[ \t]*[:=][ \t]*"
    r"['\"]?([A-Za-z0-9+/_=-]{20,256})"
)
_ENTROPY_THRESHOLD_BITS_PER_CHARACTER = 4.0

_DEFAULT_MAX_DETECTIONS = 200


@dataclass(frozen=True, slots=True)
class SecretScanBounds:
    """Configurable resource bound for `scan_repository_for_secrets`
    (mirrors `controlloop.repository.TraversalBounds` and
    `controlloop.policy.models.EvaluationBounds`'s own role and
    disclaimer: a generous, overridable starting point, not an approved
    production threshold)."""

    max_detections: int = _DEFAULT_MAX_DETECTIONS

    def __post_init__(self) -> None:
        if self.max_detections < 1:
            raise ValueError("max_detections must be at least 1")


def _path_tokens(relative_path: str) -> tuple[str, ...]:
    return tuple(
        token.lower() for token in _PATH_SPLIT_PATTERN.split(relative_path) if token
    )


#: Agent configuration paths. A secret here is handed to an agent at run
#: time, so these are never downgraded as test or example locations, even
#: under a directory named `examples`.
_AGENT_CONFIG_PREFIXES: tuple[str, ...] = (
    ".claude/",
    ".cursor/",
    ".codex/",
    ".gemini/",
    ".kiro/",
    ".roo/",
    ".continue/",
    ".windsurf/",
    ".claude-plugin/",
)
_AGENT_CONFIG_NAMES: frozenset[str] = frozenset(
    {".mcp.json", "cline_mcp_settings.json", "opencode.json"}
)
_AGENT_CONFIG_PATHS: frozenset[str] = frozenset({".vscode/mcp.json"})


def is_agent_config_path(relative_path: str) -> bool:
    """Whether `relative_path` is agent host configuration."""

    if relative_path in _AGENT_CONFIG_PATHS:
        return True
    if relative_path.rsplit("/", 1)[-1] in _AGENT_CONFIG_NAMES:
        return True
    return any(
        relative_path.startswith(prefix) or f"/{prefix}" in relative_path
        for prefix in _AGENT_CONFIG_PREFIXES
    )


def _looks_like_fixture_path(relative_path: str) -> bool:
    """Path-based signal: any delimiter-split path segment matches a
    known test/fixture/example keyword. Agent configuration is never a
    fixture path."""

    if is_agent_config_path(relative_path):
        return False
    return any(
        token in _FIXTURE_SEGMENT_KEYWORDS for token in _path_tokens(relative_path)
    )


def _has_sequential_digit_run(value: str, *, length: int = 4) -> bool:
    digits = [character for character in value if character.isdigit()]
    if len(digits) < length:
        return False
    numbers = [int(digit) for digit in digits]
    for start in range(len(numbers) - length + 1):
        window = numbers[start : start + length]
        ascending = all(
            window[index + 1] - window[index] == 1 for index in range(length - 1)
        )
        descending = all(
            window[index + 1] - window[index] == -1 for index in range(length - 1)
        )
        if ascending or descending:
            return True
    return False


def _looks_like_placeholder_value(value: str) -> bool:
    """Value-based signal. `value` is used only transiently here for
    classification -- never returned, stored, or logged."""

    if value in _KNOWN_PLACEHOLDER_VALUES:
        return True
    if value.startswith(_STRIPE_TEST_PREFIX):
        return True
    if _PLACEHOLDER_MARKER_PATTERN.search(value):
        return True
    if _REPEATED_CHARACTER_RUN_PATTERN.search(value):
        return True
    return _has_sequential_digit_run(value)


def _shannon_entropy_bits_per_character(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _line_bounds(text: str, *, start: int, end: int) -> tuple[int, int]:
    line_start = text.count("\n", 0, start) + 1
    end_index = max(start, end - 1)
    line_end = text.count("\n", 0, end_index) + 1
    return line_start, line_end


def _detection_diagnostic(
    *,
    code: str,
    message: str,
    confidence: Confidence,
    relative_path: str,
    start: int,
    end: int,
    text: str,
) -> Diagnostic:
    line_start, line_end = _line_bounds(text, start=start, end=end)
    severity = (
        DiagnosticSeverity.ERROR
        if confidence is Confidence.HIGH
        else (DiagnosticSeverity.WARNING)
    )
    evidence = Evidence(
        adapter=_ADAPTER_NAME,
        path=relative_path,
        line_start=line_start,
        line_end=line_end if line_end != line_start else None,
    )
    return Diagnostic(
        code=code,
        severity=severity,
        message=message,
        confidence=confidence,
        incomplete=False,
        evidence=(evidence,),
    )


def _scan_text(
    text: str, *, relative_path: str, fixture_path: bool
) -> tuple[Diagnostic, ...]:
    detections: list[Diagnostic] = []
    shape_spans: list[tuple[int, int]] = []

    for shape_match in redaction.scan_credential_shapes(text):
        shape_spans.append((shape_match.start, shape_match.end))
        value = text[shape_match.start : shape_match.end]
        confidence = (
            Confidence.MEDIUM
            if fixture_path or _looks_like_placeholder_value(value)
            else Confidence.HIGH
        )
        detections.append(
            _detection_diagnostic(
                code=_SHAPE_DETECTED_CODE,
                message=(
                    f"Content matching the {shape_match.name!r} credential "
                    "shape was detected."
                ),
                confidence=confidence,
                relative_path=relative_path,
                start=shape_match.start,
                end=shape_match.end,
                text=text,
            )
        )

    for entropy_match in _ENTROPY_ASSIGNMENT_PATTERN.finditer(text):
        candidate_start, candidate_end = entropy_match.start(1), entropy_match.end(1)
        if any(
            candidate_start < shape_end and candidate_end > shape_start
            for shape_start, shape_end in shape_spans
        ):
            continue  # already reported as a known-shape match

        value = entropy_match.group(1)
        if (
            _shannon_entropy_bits_per_character(value)
            < _ENTROPY_THRESHOLD_BITS_PER_CHARACTER
        ):
            continue

        confidence = (
            Confidence.LOW
            if fixture_path or _looks_like_placeholder_value(value)
            else Confidence.MEDIUM
        )
        detections.append(
            _detection_diagnostic(
                code=_ENTROPY_DETECTED_CODE,
                message=(
                    "A high-entropy value assigned to a credential-like "
                    "variable was detected."
                ),
                confidence=confidence,
                relative_path=relative_path,
                start=candidate_start,
                end=candidate_end,
                text=text,
            )
        )

    return tuple(detections)


def _unparsed_region_diagnostic(relative_path: str) -> Diagnostic:
    return incomplete_diagnostic(
        code=_UNPARSED_REGION_CODE,
        message=(
            "This file's content could not be decoded and was not scanned "
            "for secret-shaped values."
        ),
        evidence=(Evidence(adapter=_ADAPTER_NAME, path=relative_path),),
    )


def _bound_exceeded_diagnostic(max_detections: int) -> Diagnostic:
    return incomplete_diagnostic(
        code=_BOUND_EXCEEDED_CODE,
        message=(
            "secret-shaped-content scanning stopped after the configured "
            f"detection bound of {max_detections}; further detections were "
            "not retained"
        ),
        evidence=(Evidence(adapter=_ADAPTER_NAME, path="<secret-scan-evaluation>"),),
    )


def _sort_key(diagnostic: Diagnostic) -> tuple[str, int, str, str]:
    evidence = diagnostic.evidence[0]
    return (
        evidence.path or "",
        evidence.line_start or 0,
        diagnostic.code,
        diagnostic.message,
    )


def scan_repository_for_secrets(
    root: RepositoryRoot,
    files: Sequence[Path],
    *,
    bounds: SecretScanBounds | None = None,
) -> tuple[Diagnostic, ...]:
    """Scan every already-walked text `files` under `root` for
    secret-shaped content, returning a deterministically ordered tuple
    of `Diagnostic`s -- never a matched value.

    `files` must already be the result of
    `controlloop.repository.walk_repository(root, ...)` filtered to
    `Path` entries (as `controlloop.bom.build_acbom_document` already
    computes for its own `root_digest`), so containment, `.gitignore`,
    and size/count/depth bounds are inherited, never reimplemented
    here. A single file's decode failure is isolated to one
    `INCOMPLETE-UNPARSED-REGION` diagnostic; it does not discard
    detections from other files. Exceeding `bounds.max_detections` adds
    one `INCOMPLETE-BOUND-EXCEEDED` diagnostic and stops scanning
    further files, rather than silently truncating without saying so.
    """

    active_bounds = bounds or SecretScanBounds()
    collected: list[Diagnostic] = []

    for file in files:
        if len(collected) >= active_bounds.max_detections:
            collected.append(_bound_exceeded_diagnostic(active_bounds.max_detections))
            break

        relative_path = file.relative_to(root.path).as_posix()
        try:
            text = file.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError, ValueError):
            collected.append(_unparsed_region_diagnostic(relative_path))
            continue

        fixture_path = _looks_like_fixture_path(relative_path)
        file_detections = _scan_text(
            text, relative_path=relative_path, fixture_path=fixture_path
        )

        overflowed = False
        for detection in file_detections:
            if len(collected) >= active_bounds.max_detections:
                overflowed = True
                break
            collected.append(detection)
        if overflowed:
            collected.append(_bound_exceeded_diagnostic(active_bounds.max_detections))
            break

    return tuple(sorted(collected, key=_sort_key))
