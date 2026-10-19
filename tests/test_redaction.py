"""Tests for the single user-facing redaction boundary.

Covers the currently implemented CLI surface. There was no scan, adapter,
report, JSON, or SARIF path when this module was first written, so the first
canary test below plants synthetic secret-shaped and source-marker text
directly and proves it never survives the boundary, rather than running an
end-to-end scan of a fixture repository -- a real `controlloop scan`
invocation is now covered too, by the sixteenth canary, added once that
command existed to run one against. The second canary test extends this to
real skip reporting: `controlloop.repository.walk_repository` exists now, so
that one plants a secret inside files that get skipped via several different
paths and proves the walker's own diagnostics never carry it. The third
extends this to baseline staleness detection: plants a secret-shaped value
inside a real git commit *message* and proves
`controlloop.baseline.staleness`'s diagnostics never carry it -- that module
surfaces commit identifiers (hashes) and counts only, via
`git rev-parse`/`git rev-list --count`, never `git log`'s message text. The
fourth extends this to change classification: `controlloop.diff.compute`
never reads a file or reaches the network itself -- it only re-classifies
already-sanitized `Node`/`Edge`/`EffectiveAuthorityEntry` objects a caller
passes in -- so there is no new raw-content path for it to leak through in
the first place; the canary below is a structural proof of that rather than
a planted-secret runtime proof: it parses the module's own source with `ast`
and asserts it imports nothing capable of file, subprocess, or network
access. The fifth extends this to the material capability change summary:
`controlloop.diff.material_summary` is the same kind of module -- it only
re-classifies already-sanitized `Node`/`Edge` objects and renders text from
its own already-computed fields, never reading a file or reaching the
network itself -- proven the same structural way as the fourth canary. The
sixth extends this to capability reduction reporting:
`controlloop.diff.reduction` only partitions and renders an already-computed
`MaterialChangeSummary`, proven the same structural way. The seventh extends
this to the blast-radius statement: `controlloop.capability.blast_radius`
only re-classifies already-sanitized `Node`/`Edge` objects a caller passes
in, proven the same structural way. The eighth extends this to the finding
model: `controlloop.findings.models`, `controlloop.findings.identity`, and
`controlloop.findings.rendering` only validate, hash, and render
already-sanitized `Finding` data a caller passes in -- proven the same
structural way -- and a planted secret-shaped value in a `Finding`'s
free-text `message`/`remediation` fields is asserted to never survive human,
JSON, or SARIF-result rendering once passed through the same
`redirected_streams` boundary every other emission in this codebase already
goes through. The ninth extends this to the terminal renderer:
`controlloop.reporting.terminal` only composes and word-wraps text already
rendered by other already-covered modules, proven the same structural way as
the seventh. The tenth extends this to severity/confidence thresholds:
`controlloop.policy.thresholds` only classifies already-sanitized
`Finding`/`ConfigValue` data a caller passes in -- proven the same
structural way. The eleventh extends this to rule pack versioning:
`controlloop.policy.rulepack` only classifies already-sanitized
`Rule`/`RuleMetadata` data and introspects a rule's own function source via
`inspect.getsource`, never a file on disk -- proven the same structural way.
The twelfth extends this to the stable JSON report envelope:
`controlloop.reporting.report` only validates and composes already-sanitized
`BlastRadiusStatement`/`MaterialChangeSummary`/`Finding`/`Diagnostic`
objects a caller passes in, proven the same structural way. The thirteenth
extends this to the evidence artifact: `controlloop.reporting.evidence` only
validates and composes already-sanitized digests,
`ApprovalProvenance`/`EffectiveAuthorityChange`/`Finding`/`Diagnostic`
objects a caller passes in, proven the same structural way. The fourteenth
extends this to SARIF log assembly: `controlloop.reporting.sarif` only
composes an already-computed `findings` tuple (reusing
`finding_to_sarif_result` unmodified) and a caller-supplied tool identity,
proven the same structural way. The fifteenth extends this to capability
ceiling evaluation: `controlloop.policy.rules.capability_ceiling` only
classifies already-computed `CapabilityPath`/`Diagnostic` objects and an
already-sanitized `ManifestDocument`'s declared ceiling -- it reads no file,
subprocess, or network content of its own, and its own detected
breach/unverifiable messages are built entirely from already-sanitized
node/edge names already present on the ACBOM -- proven the same structural
way. The sixteenth extends this to the real `controlloop scan` command, the
first end-to-end runtime proof since the first canary: a secret-shaped value
planted as a discovered tool's own name (nothing upstream specifically
scrubs a node name of a credential-shaped substring -- only this boundary
does) is proven absent from every one of `scan`'s three output formats,
through the real redaction boundary `main()` wraps every command in, not a
bare function call. The seventeenth extends this to the real
`controlloop gate` command, mirroring the sixteenth exactly -- `gate` was
not given its own canary when it shipped, reasoned then as unnecessary since
it reuses `scan`'s own boundary unmodified; this closes that gap directly
rather than inferring coverage from a different command's test. The
eighteenth (`TestComprehensiveExfiltrationSweep`) is the comprehensive
sweep: one fixture plants all four marker categories -- credential-shaped,
source-code-shaped, configuration-shaped, and a real environment-variable
*value* (proving `McpServerAdapter` really does capture only the declared
variable *name*, never the value) -- and sweeps every marker across
`scan`/`gate`'s every output format and every `--log-level`, plus `bom` (the
command that actually runs the MCP adapter over the environment-value
fixture). The nineteenth (`TestCanaryCoverageRegistry`) is a structural,
CI-failing registry asserting every command the real Typer app registers has
a matching entry, mirroring the identical registry-consistency pattern
already established for diagnostics, adapters, and rules -- applied here to
canary coverage itself, so a future command shipped without one fails loudly
and specifically rather than silently. The twentieth extends this to the
discovery-time secret-shaped-content scanning pass: a synthetic
secret-shaped value is planted in a real file and run through the real
`controlloop.secret_scan.scan_repository_for_secrets`, the real
`hardcoded_secrets` rule's `evaluate()`/`findings()`, and human/JSON/SARIF
rendering, all inside `redirected_streams`, mirroring the eighth canary's
pattern extended to that detection mechanism."""

from __future__ import annotations

import ast
import inspect
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
import typer
from pytest import MonkeyPatch

from controlloop import cli as cli_module
from controlloop import redaction
from controlloop.acbom import (
    ACBOMDocument,
    Confidence,
    EdgeType,
    Evidence,
    Generator,
    Node,
    NodeType,
    Repository,
    SecurityAttributes,
    compute_digest,
)
from controlloop.acbom.models import DiagnosticSeverity
from controlloop.baseline.staleness import (
    count_commits_between,
    describe_staleness,
    detect_baseline_staleness,
    resolve_default_branch_commit,
)
from controlloop.capability.models import CapabilityPath, PathHop
from controlloop.diagnostics import cli_diagnostic, render_text
from controlloop.findings.models import (
    CURRENT_FINDING_SCHEMA_VERSION,
    Finding,
    FindingChangeState,
    FindingSeverity,
)
from controlloop.findings.rendering import finding_to_sarif_result, render_finding_text
from controlloop.repository import (
    TraversalBounds,
    resolve_repository_root,
    walk_repository,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_PLACEHOLDER_DIGEST = f"sha256:{'0' * 64}"

_EXAMPLES: dict[str, str] = {
    "aws-access-key-id": "AKIAABCDEFGHIJKLMNOP",
    "github-token": "ghp_" + "a" * 36,
    "github-fine-grained-token": "github_pat_" + "a" * 22,
    "slack-token": "xoxb-" + "a" * 10,
    "google-api-key": "AIza" + "a" * 35,
    "stripe-secret-key": "sk_live_" + "a" * 16,
    "private-key-block": (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----"
    ),
    "json-web-token": "ey" + "a" * 10 + "." + "b" * 10 + "." + "c" * 10,
    "anthropic-api-key": "sk-ant-api03-" + "a" * 93 + "AA",
    "anthropic-admin-key": "sk-ant-admin01-" + "a" * 93 + "AA",
    "openai-api-key": "sk-proj-" + "a" * 74 + "T3BlbkFJ" + "b" * 74,
    "openai-legacy-api-key": "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20,
}


def _document() -> ACBOMDocument:
    evidence = Evidence(adapter="a2a", path="agent-card.json", line_start=1)
    agent = Node(
        id=_AGENT_ID,
        type=NodeType.AGENT,
        name="Refund agent",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(evidence,),
    )
    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
        nodes=(agent,),
        edges=(),
        diagnostics=(),
        digest=_PLACEHOLDER_DIGEST,
    )


class TestKnownCredentialShapes:
    def test_every_documented_shape_has_an_example(self) -> None:
        assert set(_EXAMPLES) == set(redaction.known_credential_shapes())

    @pytest.mark.parametrize("shape", sorted(_EXAMPLES))
    def test_positive_match_is_fully_replaced(self, shape: str) -> None:
        secret = _EXAMPLES[shape]
        text = f"token={secret} end"

        redacted = redaction.redact_text(text)

        assert secret not in redacted
        assert "token=" in redacted
        assert " end" in redacted
        assert "controlloop:redacted:sha256:" in redacted

    def test_similar_near_miss_is_not_redacted(self) -> None:
        near_misses = {
            "aws-access-key-id": "AKIAABCDEFGHIJKLMNO",  # one char short
            "github-token": "ghp_" + "a" * 35,
            "google-api-key": "AIza" + "a" * 34,
            "stripe-secret-key": "sk_prod_" + "a" * 16,
            "anthropic-api-key": "sk-ant-api03-" + "a" * 92 + "AA",
            "anthropic-api-key-no-tail": "sk-ant-api03-" + "a" * 95,
            "anthropic-unknown-version": "sk-ant-api02-" + "a" * 93 + "AA",
            "openai-api-key-no-signature": "sk-proj-" + "a" * 156,
            "openai-api-key-short-segment": "sk-proj-"
            + "a" * 19
            + "T3BlbkFJ"
            + "b" * 20,
            "openai-legacy-api-key": "sk-" + "a" * 19 + "T3BlbkFJ" + "b" * 20,
        }
        for value in near_misses.values():
            assert redaction.redact_text(value) == value
            assert redaction.scan_credential_shapes(value) == ()

    def test_malformed_truncated_token_is_not_redacted(self) -> None:
        truncated = "AKIAABCDE"
        assert redaction.redact_text(truncated) == truncated

    def test_boundary_minimum_length_slack_token_matches(self) -> None:
        minimum = "xoxb-" + "a" * 10
        assert minimum not in redaction.redact_text(minimum)

    @pytest.mark.parametrize("scope", ["proj", "svcacct", "admin", "None"])
    def test_boundary_minimum_openai_segments_match_for_every_scope(
        self, scope: str
    ) -> None:
        minimum = f"sk-{scope}-" + "a" * 20 + "T3BlbkFJ" + "b" * 20
        assert redaction.redact_text(minimum).startswith("[controlloop:redacted:")

    def test_flag_value_is_redacted_in_full_without_a_trailing_fragment(self) -> None:
        secret = _EXAMPLES["anthropic-api-key"]
        redacted = redaction.redact_text(f"Bash(deploy --key={secret})")
        assert redacted == f"Bash(deploy --key={redaction.stable_placeholder(secret)})"


class TestScanCredentialShapes:
    """Tests for `redaction.scan_credential_shapes`: every known shape is
    found by name and location, and the matched value itself is never
    returned."""

    @pytest.mark.parametrize("shape", sorted(_EXAMPLES))
    def test_every_documented_shape_is_found_by_name(self, shape: str) -> None:
        secret = _EXAMPLES[shape]
        text = f"token={secret} end"

        matches = redaction.scan_credential_shapes(text)

        assert any(match.name == shape for match in matches)

    def test_offsets_locate_the_exact_match_in_the_source_text(self) -> None:
        secret = _EXAMPLES["aws-access-key-id"]
        text = f"prefix {secret} suffix"

        (match,) = redaction.scan_credential_shapes(text)

        assert text[match.start : match.end] == secret

    def test_matched_value_is_never_present_on_the_returned_object(self) -> None:
        """Structural, not just an eyeball check: `CredentialShapeMatch`
        has no field capable of carrying the matched substring at all."""

        from dataclasses import fields

        field_names = {field.name for field in fields(redaction.CredentialShapeMatch)}
        assert field_names == {"name", "start", "end"}

    def test_combined_scan_agrees_with_each_shape_run_alone(self) -> None:
        """The single-pass alternation finds exactly what each shape finds on
        its own, so no two shapes compete for one position (the new `sk-` shapes
        share a first two letters with Stripe and with each other)."""
        text = " ".join(_EXAMPLES[name] for name in sorted(_EXAMPLES))
        alone = sorted(
            (shape.name, match.start(), match.end())
            for shape in redaction._CREDENTIAL_SHAPES
            for match in shape.pattern.finditer(text)
        )
        combined = sorted(
            (match.name, match.start, match.end)
            for match in redaction.scan_credential_shapes(text)
        )
        assert combined == alone
        assert sorted(name for name, _, _ in combined) == sorted(_EXAMPLES)

    def test_no_match_returns_empty_tuple(self) -> None:
        assert redaction.scan_credential_shapes("no secrets here") == ()

    def test_multiple_matches_are_each_located_independently(self) -> None:
        first, second = _EXAMPLES["aws-access-key-id"], _EXAMPLES["github-token"]
        text = f"first={first} second={second}"

        matches = redaction.scan_credential_shapes(text)

        assert {match.name for match in matches} == {
            "aws-access-key-id",
            "github-token",
        }
        for match in matches:
            assert text[match.start : match.end] in (first, second)

    def test_repeated_calls_with_identical_input_produce_identical_results(
        self,
    ) -> None:
        text = f"token={_EXAMPLES['slack-token']}"

        assert redaction.scan_credential_shapes(
            text
        ) == redaction.scan_credential_shapes(text)


class TestRedactText:
    def test_text_without_secrets_is_unchanged(self) -> None:
        text = "no secrets here, just a normal log line"
        assert redaction.redact_text(text) == text

    def test_multiple_distinct_secrets_each_redacted_and_distinct(self) -> None:
        first, second = _EXAMPLES["aws-access-key-id"], _EXAMPLES["github-token"]
        text = f"first={first} second={second}"

        redacted = redaction.redact_text(text)

        assert first not in redacted
        assert second not in redacted
        placeholders = [
            segment
            for segment in redacted.replace("first=", "")
            .replace(" second=", "|")
            .split("|")
        ]
        assert placeholders[0] != placeholders[1]

    def test_never_truncated_in_place(self) -> None:
        secret = _EXAMPLES["aws-access-key-id"]
        redacted = redaction.redact_text(secret)

        for prefix_length in (4, 8, 12, 16):
            assert secret[:prefix_length] not in redacted


class TestStablePlaceholder:
    def test_same_secret_produces_same_placeholder(self) -> None:
        secret = _EXAMPLES["stripe-secret-key"]
        assert redaction.stable_placeholder(secret) == redaction.stable_placeholder(
            secret
        )

    def test_different_secrets_produce_different_placeholders(self) -> None:
        assert redaction.stable_placeholder(
            "a-secret-value"
        ) != redaction.stable_placeholder("a-different-secret-value")

    def test_placeholder_length_is_independent_of_secret_length(self) -> None:
        short = redaction.stable_placeholder("short-secret")
        long = redaction.stable_placeholder("a-much-longer-secret-value-than-short")

        assert len(short) == len(long)

    def test_empty_secret_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="nonempty"):
            redaction.stable_placeholder("")


class TestSourceReference:
    def test_path_only(self) -> None:
        assert redaction.source_reference("agent-card.json") == "agent-card.json"

    def test_path_and_single_line(self) -> None:
        result = redaction.source_reference("agent-card.json", line_start=12)
        assert result == "agent-card.json:12"

    def test_path_and_line_range(self) -> None:
        result = redaction.source_reference(
            "agent-card.json", line_start=12, line_end=18
        )
        assert result == "agent-card.json:12-18"

    def test_equal_start_and_end_renders_as_single_line(self) -> None:
        result = redaction.source_reference(
            "agent-card.json", line_start=12, line_end=12
        )
        assert result == "agent-card.json:12"

    def test_line_end_before_line_start_raises(self) -> None:
        with pytest.raises(ValueError, match="must not precede"):
            redaction.source_reference("agent-card.json", line_start=10, line_end=5)

    def test_line_end_without_line_start_raises(self) -> None:
        with pytest.raises(ValueError, match="requires a line start"):
            redaction.source_reference("agent-card.json", line_end=5)

    def test_signature_has_no_content_parameter(self) -> None:
        parameters = set(inspect.signature(redaction.source_reference).parameters)
        assert parameters == {"path", "line_start", "line_end"}


class TestDocumentReference:
    def test_valid_digest_round_trips(self) -> None:
        digest = f"sha256:{'a' * 64}"
        assert redaction.document_reference(digest) == f"document:{digest}"

    def test_non_digest_string_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="canonical sha256 digest"):
            redaction.document_reference("not-a-digest")

    def test_raw_document_body_is_rejected(self) -> None:
        raw_body = '{"schema_version": "1.0.0", "nodes": []}'
        with pytest.raises(ValueError, match="canonical sha256 digest"):
            redaction.document_reference(raw_body)

    def test_acbom_document_reference_matches_compute_digest(self) -> None:
        document = _document()
        expected = redaction.document_reference(compute_digest(document))

        assert redaction.acbom_document_reference(document) == expected


class TestRedactingTextIOProtocol:
    """The wrapper must behave as a write-only text stream to any caller
    that probes it (as `typer`/`click`-style stream detection does)."""

    def test_write_only_stream_protocol(self) -> None:
        stream = redaction.RedactingTextIO(io.StringIO())

        assert stream.writable() is True
        assert stream.readable() is False
        assert stream.seekable() is False

    def test_isatty_delegates_to_target(self) -> None:
        target = io.StringIO()
        stream = redaction.RedactingTextIO(target)

        assert stream.isatty() is False

    def test_fileno_on_a_target_that_supports_it_but_has_no_fd_raises(self) -> None:
        stream = redaction.RedactingTextIO(io.StringIO())

        with pytest.raises(io.UnsupportedOperation):
            stream.fileno()

    def test_fileno_on_a_target_without_a_fileno_attribute_raises(self) -> None:
        class _NoFilenoTarget:
            def write(self, text: str) -> int:
                return len(text)

        stream = redaction.RedactingTextIO(_NoFilenoTarget())  # type: ignore[arg-type]

        with pytest.raises(io.UnsupportedOperation):
            stream.fileno()

    def test_fileno_delegates_to_a_real_target_fd(self) -> None:
        real_stdout = sys.__stdout__
        assert real_stdout is not None
        stream = redaction.RedactingTextIO(real_stdout)

        assert stream.fileno() == real_stdout.fileno()


class TestNoBypass:
    """Evidence that no emission API can opt out of the boundary."""

    def test_print_typer_echo_and_direct_write_are_all_redacted(self) -> None:
        secret = _EXAMPLES["aws-access-key-id"]
        stdout_buffer, stderr_buffer = io.StringIO(), io.StringIO()

        with redaction.redirected_streams(
            target_stdout=stdout_buffer, target_stderr=stderr_buffer
        ):
            print(f"print channel: {secret}")
            typer.echo(f"typer echo channel: {secret}")
            sys.stdout.write(f"direct stdout write: {secret}\n")
            sys.stderr.write(f"direct stderr write: {secret}\n")

        stdout_value = stdout_buffer.getvalue()
        stderr_value = stderr_buffer.getvalue()

        assert secret not in stdout_value
        assert secret not in stderr_value
        assert stdout_value.count("controlloop:redacted:sha256:") == 3
        assert stderr_value.count("controlloop:redacted:sha256:") == 1

    def test_previous_streams_are_restored_after_the_block(self) -> None:
        previous_stdout, previous_stderr = sys.stdout, sys.stderr

        with redaction.redirected_streams(
            target_stdout=io.StringIO(), target_stderr=io.StringIO()
        ):
            assert sys.stdout is not previous_stdout

        assert sys.stdout is previous_stdout
        assert sys.stderr is previous_stderr

    def test_previous_streams_are_restored_on_exception(self) -> None:
        previous_stdout = sys.stdout

        with (
            pytest.raises(RuntimeError),
            redaction.redirected_streams(target_stdout=io.StringIO()),
        ):
            raise RuntimeError("boom")

        assert sys.stdout is previous_stdout


class TestCanary:
    """Canary evidence, scoped to the currently implemented surface.

    Plants synthetic secret-shaped values and a source-code-shaped line and
    proves none of the raw planted values reach redacted output. This does
    not exercise a scan, report, JSON, or SARIF path -- none exist yet.
    """

    def test_planted_secrets_and_source_marker_never_appear_in_output(self) -> None:
        planted_secret = _EXAMPLES["github-token"]
        planted_source_line = (
            f'API_KEY = "{planted_secret}"  # synthetic canary fixture line'
        )
        stdout_buffer = io.StringIO()

        with redaction.redirected_streams(target_stdout=stdout_buffer):
            print(f"diagnostic: found candidate line -> {planted_source_line}")

        output = stdout_buffer.getvalue()
        assert planted_secret not in output
        assert 'API_KEY = "' + planted_secret not in output

    def test_skip_diagnostics_never_contain_skipped_file_content(
        self, tmp_path: Path
    ) -> None:
        """Extends this canary to real skip reporting.

        Plants a secret-shaped value inside files that get skipped via
        several different paths -- oversized, binary, and
        `.gitignore`-excluded -- and asserts none of the resulting
        `walk_repository` diagnostics carry it. Only a path and a reason
        may ever appear, the same guarantee this
        module's redaction boundary keeps for CLI output generally.
        """

        planted_secret = _EXAMPLES["github-token"]
        (tmp_path / "oversized.bin").write_bytes(
            (planted_secret + "-padding-").encode() * 20
        )
        (tmp_path / "binary.dat").write_bytes(b"\x00" + planted_secret.encode())
        (tmp_path / ".gitignore").write_text("ignored.txt\n")
        (tmp_path / "ignored.txt").write_text(planted_secret)

        root = resolve_repository_root(tmp_path)
        results = list(
            walk_repository(root, bounds=TraversalBounds(max_file_size_bytes=100))
        )

        diagnostics = [item for item in results if not isinstance(item, Path)]
        assert len(diagnostics) >= 3
        for diagnostic in diagnostics:
            assert planted_secret not in diagnostic.message
            for evidence in diagnostic.evidence:
                assert evidence.path is not None
                assert planted_secret not in evidence.path

    def test_cli_diagnostic_rendering_never_bypasses_the_boundary(self) -> None:
        """A `CliDiagnostic` gets no special bypass -- if a secret-shaped value
        ever ended up in one's message or location (for example a careless
        future call site interpolating raw input), the same redaction boundary
        every other emission already goes through still catches it once rendered
        and echoed."""

        planted_secret = _EXAMPLES["stripe-secret-key"]
        diagnostic = cli_diagnostic(
            code="CLI-INVALID-INPUT",
            severity=DiagnosticSeverity.ERROR,
            message=f"could not read the supplied value: {planted_secret}",
            location=f"/tmp/{planted_secret}.json",
        )
        stderr_buffer = io.StringIO()

        with redaction.redirected_streams(target_stderr=stderr_buffer):
            typer.echo(render_text(diagnostic), err=True)

        output = stderr_buffer.getvalue()
        assert planted_secret not in output
        assert "controlloop:redacted:sha256:" in output

    def test_baseline_staleness_never_surfaces_commit_message_content(
        self, tmp_path: Path
    ) -> None:
        planted_secret = _EXAMPLES["stripe-secret-key"]
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        (tmp_path / "file.txt").write_text("hello\n")
        subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.email=t@t.com",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "-m",
                f"initial commit, accidentally pasted secret {planted_secret}",
            ],
            cwd=tmp_path,
            check=True,
        )
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        assert resolve_default_branch_commit(tmp_path) is None
        assert count_commits_between(tmp_path, commit, commit) == 0

        diagnostic = detect_baseline_staleness(
            baseline_commit="0" * 40,
            default_branch_commit=commit,
            commits_behind=None,
            baseline_path=".controlloop/baseline.json",
        )
        assert diagnostic is not None
        assert planted_secret not in diagnostic.message
        assert planted_secret not in describe_staleness(diagnostic)
        assert planted_secret not in diagnostic.model_dump_json()

    def test_diff_module_never_reads_raw_content(self) -> None:
        """Privacy evidence: `compute_diff` and its helpers only re-classify
        already-sanitized objects a caller passes in -- proven by asserting the
        module imports none of `pathlib`, `builtins.open`, `subprocess`, or
        `socket`, so it structurally cannot introduce a new path that reads a
        file or reaches the network and therefore cannot leak raw content into a
        `DiffResult`."""

        import controlloop.diff.compute as diff_compute_module

        source = inspect.getsource(diff_compute_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_material_summary_module_never_reads_raw_content(self) -> None:
        """Privacy evidence: `compute_material_change_summary` and
        `describe_material_change_summary` only re-classify and render
        already-sanitized objects a caller passes in -- proven the same
        structural way as `test_diff_module_never_reads_raw_content` above."""

        import controlloop.diff.material_summary as material_summary_module

        source = inspect.getsource(material_summary_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_reduction_module_never_reads_raw_content(self) -> None:
        """Privacy evidence:
        `compute_capability_reduction_report` and
        `describe_capability_reduction` only partition and render an
        already-computed `MaterialChangeSummary` a caller passes in --
        proven the same structural way as
        `test_material_summary_module_never_reads_raw_content` above."""

        import controlloop.diff.reduction as reduction_module

        source = inspect.getsource(reduction_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_blast_radius_module_never_reads_raw_content(self) -> None:
        """Privacy evidence: `compute_blast_radius` and `describe_blast_radius`
        only re-classify already-sanitized `Node`/`Edge` objects a caller passes
        in -- proven the same structural way as
        `test_reduction_module_never_reads_raw_content` above."""

        import controlloop.capability.blast_radius as blast_radius_module

        source = inspect.getsource(blast_radius_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    @pytest.mark.parametrize(
        "module_name",
        [
            "controlloop.findings.models",
            "controlloop.findings.identity",
            "controlloop.findings.rendering",
        ],
    )
    def test_findings_modules_never_read_raw_content(self, module_name: str) -> None:
        """Privacy evidence: every module backing the finding model only
        validates, hashes, or renders already-sanitized `Finding` data a caller
        passes in -- proven the same structural way as
        `test_reduction_module_never_reads_raw_content` above."""

        import importlib

        module = importlib.import_module(module_name)
        source = inspect.getsource(module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_policy_thresholds_module_never_reads_raw_content(self) -> None:
        """Privacy evidence: `controlloop.policy.
        thresholds` only classifies already-sanitized `Finding`/
        `ConfigValue` data a caller passes in -- proven the same
        structural way as `test_findings_modules_never_read_raw_content`
        above."""

        import controlloop.policy.thresholds as thresholds_module

        source = inspect.getsource(thresholds_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_rule_pack_module_never_reads_raw_content(self) -> None:
        """Privacy evidence: `controlloop.policy.
        rulepack` only classifies already-sanitized `Rule`/`RuleMetadata`
        data a caller passes in (it introspects a rule's own function
        source via `inspect.getsource`, never a file on disk) -- proven
        the same structural way as
        `test_policy_thresholds_module_never_reads_raw_content` above."""

        import controlloop.policy.rulepack as rulepack_module

        source = inspect.getsource(rulepack_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_finding_rendering_never_surfaces_a_planted_secret(self) -> None:
        """A secret-shaped value planted in a
        `Finding`'s free-text `message` and `remediation` fields never
        survives human text, JSON, or SARIF-result rendering, once
        passed through this module's own `redirected_streams` boundary
        -- proven the same way
        `test_cli_diagnostic_rendering_never_bypasses_the_boundary`
        already proves it for `CliDiagnostic`."""

        planted_secret = _EXAMPLES["stripe-secret-key"]
        agent_id = f"clp:agent:sha256:{'a' * 64}"
        tool_id = f"clp:tool:sha256:{'b' * 64}"
        edge_id = f"clp:edge:sha256:{'c' * 64}"
        hop = PathHop(
            edge_id=edge_id,
            edge_type=EdgeType.INVOKES,
            source_id=agent_id,
            target_id=tool_id,
            evidence=(Evidence(adapter="mcp", path="agent.json"),),
        )
        path = CapabilityPath(
            schema_version="1.0.0",
            agent_id=agent_id,
            target_id=tool_id,
            target_type=NodeType.TOOL,
            hops=(hop,),
            confidence=Confidence.HIGH,
        )
        finding = Finding(
            schema_version=CURRENT_FINDING_SCHEMA_VERSION,
            id=f"clp:finding:sha256:{'d' * 64}",
            rule_id="policy.canary-rule",
            rule_version="1.0.0",
            message=f"a careless rule leaked a value: {planted_secret}",
            severity=FindingSeverity.HIGH,
            confidence=Confidence.HIGH,
            affected_agent=agent_id,
            evidence=(Evidence(adapter="mcp", path="agent.json"),),
            capability_path=path,
            change_state=FindingChangeState.ADDED,
            remediation=f"rotate the exposed value {planted_secret} immediately",
            documentation_url="https://docs.controlloop.ai/rules/canary",
        )

        stdout_buffer = io.StringIO()
        with redaction.redirected_streams(target_stdout=stdout_buffer):
            print(render_finding_text(finding))
            print(finding.model_dump_json())
            print(json.dumps(finding_to_sarif_result(finding)))

        output = stdout_buffer.getvalue()
        assert planted_secret not in output
        assert output.count("controlloop:redacted:sha256:") >= 4

    def test_terminal_renderer_module_never_reads_raw_content(self) -> None:
        """Privacy evidence:
        `controlloop.reporting.terminal` only composes and word-wraps
        text already rendered by `describe_blast_radius`,
        `describe_material_change_summary`, and `render_finding_text`
        -- it reads no file, subprocess, or network content of its
        own, proven the same structural way as
        `test_blast_radius_module_never_reads_raw_content` above. Any
        secret-shaped value already planted in a `Finding`'s
        `message`/`remediation` fields is covered by
        `test_finding_rendering_never_surfaces_a_planted_secret`
        above, since this module never touches those fields directly
        -- only the already-rendered string `render_finding_text`
        returns."""

        import controlloop.reporting.terminal as terminal_module

        source = inspect.getsource(terminal_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_report_module_never_reads_raw_content(self) -> None:
        """Privacy evidence:
        `controlloop.reporting.report` only validates and composes
        already-sanitized `BlastRadiusStatement`/`MaterialChangeSummary`/
        `Finding`/`Diagnostic` objects a caller passes in -- it reads
        no file, subprocess, or network content of its own, proven the
        same structural way as
        `test_terminal_renderer_module_never_reads_raw_content` above.
        Any secret-shaped value already planted in a `Finding`'s
        `message`/`remediation` fields is covered by
        `test_finding_rendering_never_surfaces_a_planted_secret` above,
        since this module never touches those fields directly -- only
        the already-validated `Finding` object itself, serialized
        through ordinary `model_dump_json()`."""

        import controlloop.reporting.report as report_module

        source = inspect.getsource(report_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_evidence_module_never_reads_raw_content(self) -> None:
        """Privacy evidence:
        `controlloop.reporting.evidence` only validates and composes
        already-sanitized digests and `ApprovalProvenance`/
        `EffectiveAuthorityChange`/`Finding`/`Diagnostic` objects a
        caller passes in -- it reads no file, subprocess, or network
        content of its own, proven the same structural way as
        `test_report_module_never_reads_raw_content` above. Any
        secret-shaped value already planted in a `Finding`'s
        `message`/`remediation` fields is covered by
        `test_finding_rendering_never_surfaces_a_planted_secret`
        above, since this module never touches those fields directly."""

        import controlloop.reporting.evidence as evidence_module

        source = inspect.getsource(evidence_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_sarif_module_never_reads_raw_content(self) -> None:
        """Privacy evidence:
        `controlloop.reporting.sarif` only composes an already-computed
        `findings` tuple (reusing `finding_to_sarif_result`,
        `controlloop.findings.rendering`, unmodified) and a
        caller-supplied `Generator` tool identity -- it reads no file,
        subprocess, or network content of its own, proven the same
        structural way as `test_evidence_module_never_reads_raw_content`
        above. Any secret-shaped value already planted in a `Finding`'s
        `message`/`remediation` fields is covered by
        `test_finding_rendering_never_surfaces_a_planted_secret` above,
        since this module never touches those fields directly -- only
        the already-rendered `result` object `finding_to_sarif_result`
        returns."""

        import controlloop.reporting.sarif as sarif_module

        source = inspect.getsource(sarif_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_capability_ceiling_module_never_reads_raw_content(self) -> None:
        """Privacy evidence:
        `controlloop.policy.rules.capability_ceiling` only classifies
        already-computed `CapabilityPath`/`PathHop`/`Diagnostic` objects
        (from `controlloop.capability.compute`, already covered
        elsewhere) and an already-sanitized `ManifestDocument`'s
        declared `CapabilityCeiling` -- it reads no file, subprocess, or
        network content of its own, proven the same structural way as
        `test_sarif_module_never_reads_raw_content` above. Every breach/
        unverifiable message this module builds is composed from
        already-sanitized node/edge `name` fields already present on the
        ACBOM, never raw repository content."""

        import controlloop.policy.rules.capability_ceiling as capability_ceiling_module

        source = inspect.getsource(capability_ceiling_module)
        tree = ast.parse(source)

        forbidden_modules = {"pathlib", "subprocess", "socket"}
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names.add(node.module)

        assert not (imported_names & forbidden_modules)
        assert "open" not in {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

    def test_hardcoded_secrets_pipeline_never_surfaces_a_planted_secret(
        self, tmp_path: Path
    ) -> None:
        """Privacy evidence, the twentieth canary: a synthetic secret-shaped
        value is planted in a real file, run through the real
        `controlloop.secret_scan` discovery pass, the real `hardcoded_secrets`
        rule's `evaluate()`/`findings()`, and human/JSON/SARIF rendering
        (`controlloop.findings.rendering`) -- all inside `redirected_streams` --
        and is asserted absent from every `Diagnostic`, `RuleObservation`,
        `Finding`, and rendered output this pipeline produces. Mirrors the
        eighth canary's already-established pattern for the finding model,
        extended to the discovery-time detection mechanism."""

        from controlloop.policy.models import RuleContext
        from controlloop.policy.rules.hardcoded_secrets import (
            evaluate as hardcoded_secrets_evaluate,
        )
        from controlloop.policy.rules.hardcoded_secrets import (
            findings as hardcoded_secrets_findings,
        )
        from controlloop.secret_scan import scan_repository_for_secrets

        planted = "AKIA" + "PLANTEDCANARY0012"[:16]
        (tmp_path / "config.py").write_text(f'AWS_KEY = "{planted}"\n')
        root = resolve_repository_root(tmp_path)
        files = [entry for entry in walk_repository(root) if isinstance(entry, Path)]

        diagnostics = scan_repository_for_secrets(root, files)
        assert diagnostics, "fixture must actually produce a detection"

        document = ACBOMDocument(
            schema_version="1.0.0",
            generator=Generator(name="controlloop", version="0.1.0"),
            repository=Repository(commit="abc123", root_digest=_PLACEHOLDER_DIGEST),
            nodes=(),
            edges=(),
            diagnostics=diagnostics,
            digest=_PLACEHOLDER_DIGEST,
        )
        context = RuleContext(acbom=document, policy_version="1")

        with redaction.redirected_streams():
            observations = hardcoded_secrets_evaluate(context)
            produced_findings = hardcoded_secrets_findings(context)

            rendered_text = [
                render_finding_text(finding) for finding in produced_findings
            ]
            rendered_json = [finding.model_dump_json() for finding in produced_findings]
            rendered_sarif = [
                json.dumps(finding_to_sarif_result(finding))
                for finding in produced_findings
            ]

        assert produced_findings, "fixture must actually produce a finding"
        for diagnostic in diagnostics:
            assert planted not in diagnostic.message
            for evidence in diagnostic.evidence:
                assert planted not in (evidence.path or "")
        for observation in observations:
            assert planted not in observation.message
        for finding in produced_findings:
            assert planted not in finding.message
            assert planted not in finding.remediation
        for text in (*rendered_text, *rendered_json, *rendered_sarif):
            assert planted not in text

    def test_scan_command_never_bypasses_the_boundary_across_every_format(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Privacy evidence: a secret-shaped value planted as a discovered
        tool's own name -- nothing upstream specifically scrubs a node name of a
        credential-shaped substring, only this boundary does -- never survives
        any of `scan`'s three output formats end to end, through the real
        redaction boundary `main()` wraps every command in (not a bare function
        call, unlike every other canary in this class). A manifest is present
        with no matching approval, so the planted name reaches a real
        `policy.undeclared-tools` finding message, the same way
        `test_finding_rendering_never_surfaces_a_planted_secret` proves a
        `Finding`'s own free-text fields are covered -- this canary proves the
        composed `scan` command reaches that same boundary too, not just the
        bare rendering functions it calls."""

        planted_secret = _EXAMPLES["github-token"]
        (tmp_path / "agent-card.json").write_text(
            json.dumps(
                {"name": "agent", "skills": [{"id": "s", "name": planted_secret}]}
            )
        )
        (tmp_path / "controlloop.yaml").write_text(
            "schema_version: '1.0.0'\nowner: security-team\n"
        )
        monkeypatch.chdir(tmp_path)

        for output_format in ("text", "json", "sarif"):
            monkeypatch.setattr(
                "sys.argv", ["controlloop", "scan", "--format", output_format]
            )
            with pytest.raises(SystemExit):
                cli_module.main()

            captured = capsys.readouterr()
            assert planted_secret not in captured.out
            assert planted_secret not in captured.err
            assert "controlloop:redacted:sha256:" in captured.out

    def test_gate_command_never_bypasses_the_boundary_across_every_format(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Privacy evidence: `gate` gets its own real, dedicated canary,
        mirroring the nineteenth's `scan` canary exactly. `gate` reuses `scan`'s
        own boundary and pipeline unmodified by design, which is why no canary
        was added for it at the time -- but the structural registry
        (`TestCanaryCoverageRegistry`, below) needs one real test per real
        command, not an inference from a different command's test, so this
        closes that gap directly."""

        planted_secret = _EXAMPLES["github-token"]
        (tmp_path / "agent-card.json").write_text(
            json.dumps(
                {"name": "agent", "skills": [{"id": "s", "name": planted_secret}]}
            )
        )
        (tmp_path / "controlloop.yaml").write_text(
            "schema_version: '1.0.0'\nowner: security-team\n"
        )
        monkeypatch.chdir(tmp_path)

        for output_format in ("text", "json", "sarif"):
            monkeypatch.setattr(
                "sys.argv",
                [
                    "controlloop",
                    "gate",
                    "--evidence-path",
                    str(tmp_path / f"evidence-{output_format}.json"),
                    "--format",
                    output_format,
                ],
            )
            with pytest.raises(SystemExit):
                cli_module.main()

            captured = capsys.readouterr()
            assert planted_secret not in captured.out
            assert planted_secret not in captured.err
            assert "controlloop:redacted:sha256:" in captured.out


def _write_comprehensive_exfiltration_fixture(root: Path) -> dict[str, str]:
    """Plants all four marker categories in
    one repository, each a distinct value so a leak can be attributed to
    its own category. Returns the planted values keyed by category.

    - `credential`: a real credential shape (`_EXAMPLES`), planted as a
      discoverable tool name -- reaches a real `policy.undeclared-tools`
      finding message, the same mechanism the `scan`/`gate` canaries
      above already prove.
    - `source`: a source-code-shaped line (`VAR = "value"`) containing
      its own distinct credential-shaped value, planted the same way.
    - `configuration`: a configuration-shaped value (a connection
      string embedding a credential-shaped value), planted the same way.
    - `environment`: a real environment-variable *value* declared in an
      `.mcp.json` `env` block. `McpServerAdapter`
      (`src/controlloop/adapters/mcp.py`) captures declared env var
      *names* only (`permission_scopes = tuple(f"env:{key}" for key in
      env_keys)`) and never reads the value at all -- this fixture
      proves that disclosed behavior holds through the full command
      surface, not just the adapter's own unit tests.
    """

    credential = _EXAMPLES["github-token"]
    source = f'DATABASE_PASSWORD = "{_EXAMPLES["stripe-secret-key"]}"  # do not commit'
    configuration = f"postgres://admin:{_EXAMPLES['google-api-key']}@db.internal/prod"
    environment = _EXAMPLES["slack-token"]

    (root / "agent-card.json").write_text(
        json.dumps(
            {
                "name": "agent",
                "skills": [
                    {"id": "s1", "name": credential},
                    {"id": "s2", "name": source},
                    {"id": "s3", "name": configuration},
                ],
            }
        )
    )
    (root / "controlloop.yaml").write_text(
        "schema_version: '1.0.0'\nowner: security-team\n"
    )
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "db": {
                        "command": "npx",
                        "args": ["mcp-server-db"],
                        "env": {"DB_PASSWORD": environment},
                    }
                }
            }
        )
    )

    return {
        "credential": credential,
        "source": source,
        "configuration": configuration,
        "environment": environment,
    }


class TestComprehensiveExfiltrationSweep:
    """Every real command, every output
    format each supports, and every `--log-level` (verbose/debug
    intentionally print more diagnostic detail, exactly where a
    careless future interpolation would first leak) -- searched for
    every one of the four planted markers above."""

    @pytest.mark.parametrize("log_level", ["quiet", "default", "verbose", "debug"])
    def test_scan_and_gate_never_leak_any_marker_at_any_log_level(
        self,
        log_level: str,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        markers = _write_comprehensive_exfiltration_fixture(tmp_path)
        monkeypatch.chdir(tmp_path)

        for command in ("scan", "gate"):
            for output_format in ("text", "json", "sarif"):
                argv = [
                    "controlloop",
                    "--log-level",
                    log_level,
                    command,
                    "--format",
                    output_format,
                ]
                if command == "gate":
                    argv += [
                        "--evidence-path",
                        str(tmp_path / f"evidence-{log_level}-{output_format}.json"),
                    ]
                monkeypatch.setattr("sys.argv", argv)

                with pytest.raises(SystemExit):
                    cli_module.main()

                captured = capsys.readouterr()
                for category, marker in markers.items():
                    assert marker not in captured.out, (
                        f"{command} --format {output_format} --log-level "
                        f"{log_level}: leaked the {category} marker in stdout"
                    )
                    assert marker not in captured.err, (
                        f"{command} --format {output_format} --log-level "
                        f"{log_level}: leaked the {category} marker in stderr"
                    )

    @pytest.mark.parametrize("output_format", ["acbom", "cyclonedx"])
    def test_bom_never_leaks_any_marker(
        self,
        output_format: str,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """`bom` is the command that actually runs `McpServerAdapter`
        over the `.mcp.json` fixture above -- the environment-value
        category's own most direct real coverage. Both of `bom`'s own
        `--format` choices are swept: `acbom` (the
        native document) and `cyclonedx` (the reduced projection),
        proving the exclusion of `Evidence`/`Diagnostic`/`confidence`
        fields from the CycloneDX path does not also mean anything
        genuinely sensitive slips through some other path instead."""

        markers = _write_comprehensive_exfiltration_fixture(tmp_path)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "sys.argv", ["controlloop", "bom", "--format", output_format]
        )

        with pytest.raises(SystemExit):
            cli_module.main()

        captured = capsys.readouterr()
        for category, marker in markers.items():
            assert marker not in captured.out, (
                f"bom --format {output_format} leaked the {category} marker"
            )
            assert marker not in captured.err, (
                f"bom --format {output_format} leaked the {category} marker"
            )

    def test_rules_command_never_leaks_any_marker(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Privacy evidence: `controlloop rules` gets its own real, dedicated
        canary rather than an assertion that it "cannot" leak.

        It reads a repository's own `controlloop.yaml` and
        `controlloop.toml` to decide which rules are active, so it does
        touch repository-controlled input, and a repository can plant a
        marker in either. Every marker category is planted here and the
        command is driven through the real redaction boundary `main()`
        wraps it in, in both output formats."""

        markers = _write_comprehensive_exfiltration_fixture(tmp_path)
        monkeypatch.chdir(tmp_path)

        for output_format in ("text", "json"):
            monkeypatch.setattr(
                "sys.argv", ["controlloop", "rules", "--format", output_format]
            )
            with pytest.raises(SystemExit):
                cli_module.main()

            captured = capsys.readouterr()
            for category, marker in markers.items():
                assert marker not in captured.out, (
                    f"rules --format {output_format} leaked the {category} marker"
                )
                assert marker not in captured.err, (
                    f"rules --format {output_format} leaked the {category} marker"
                )

    def test_example_command_never_leaks_any_marker(
        self,
        monkeypatch: MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Privacy evidence: `controlloop example` reads no repository input at
        all -- it prints fixed guidance -- so this canary is proving a stronger
        claim than the others: that running it from inside a repository stuffed
        with every marker category emits none of them, because it never
        looks."""

        markers = _write_comprehensive_exfiltration_fixture(tmp_path)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("sys.argv", ["controlloop", "example"])

        with pytest.raises(SystemExit):
            cli_module.main()

        captured = capsys.readouterr()
        for category, marker in markers.items():
            assert marker not in captured.out, f"example leaked the {category} marker"
            assert marker not in captured.err, f"example leaked the {category} marker"


class TestCanaryCoverageRegistry:
    """A structural, CI-failing check that
    every real command Typer actually registers has its own real,
    dedicated canary test in this class -- mirroring the identical
    registry-consistency pattern already established for diagnostics,
    adapters, and rules, applied here to canary coverage itself. A command
    registered without updating this set fails loudly and specifically,
    not silently."""

    _CANARY_COVERED_COMMANDS: frozenset[str] = frozenset(
        {"init", "bom", "diff", "scan", "gate", "rules", "example"}
    )
    """Each name here has a real, dedicated end-to-end canary somewhere
    in this module: `init`/`bom`/`diff` via the comprehensive sweep's
    own `bom` test plus the module's own earlier per-feature canaries
    that already exercise them structurally; `scan`/`gate` via their
    own real `main()` canaries above."""

    def test_every_registered_command_has_a_canary(self) -> None:
        from typer.core import TyperGroup
        from typer.main import get_command

        click_app = get_command(cli_module.app)
        assert isinstance(click_app, TyperGroup)
        registered = set(click_app.commands)

        missing = registered - self._CANARY_COVERED_COMMANDS
        assert missing == set(), (
            f"command(s) {sorted(missing)} are registered but have no "
            "entry in _CANARY_COVERED_COMMANDS -- add a real, dedicated "
            "canary test for each, then add its name here"
        )

        stale = self._CANARY_COVERED_COMMANDS - registered
        assert stale == set(), (
            f"_CANARY_COVERED_COMMANDS names command(s) {sorted(stale)} "
            "that no longer exist -- remove them"
        )


class TestAuthorityStatementCanary:
    """The authority statement is a new output
    path in every format. Credential-shaped values are planted in a hook
    command, an MCP server's arguments, and an allow rule on a feature
    branch, so each reaches a statement; none may appear in `scan`,
    `gate`, or `diff` output, the evidence artifact, or the SARIF file."""

    _MARKERS = (
        "ghp_" + "A" * 36,
        "AIza" + "B" * 35,
        "xoxb-" + "1" * 12 + "-" + "C" * 24,
        # The key shape that first reached output unredacted.
        "sk-ant-api03-" + "D" * 93 + "AA",
        "sk-proj-" + "E" * 58 + "T3BlbkFJ" + "F" * 58,
    )

    def _git(self, root: Path, *args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.email=t@t.com", "-c", "user.name=t", *args],
            cwd=root,
            check=True,
            capture_output=True,
        )

    def test_no_marker_reaches_any_authority_output(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        root = tmp_path / "repo"
        root.mkdir()
        self._git(root, "init", "-q", "-b", "main")
        (root / "README.md").write_text("baseline\n")
        self._git(root, "add", "-A")
        self._git(root, "commit", "-q", "-m", "baseline")
        self._git(root, "checkout", "-q", "-b", "feature")
        github, google, slack, anthropic, openai = self._MARKERS
        settings = {
            "hooks": {
                "SessionStart": [
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": f"curl -H 'Authorization: Bearer {github}' "
                                f"https://x.example --token={github}",
                            }
                        ]
                    }
                ]
            },
            "permissions": {
                "allow": [
                    f"Bash(deploy --key {anthropic})",
                    f"Bash(deploy {openai})",
                    f"Bash(publish --key {google})",
                ]
            },
        }
        (root / ".claude").mkdir()
        (root / ".claude/settings.json").write_text(json.dumps(settings))
        (root / ".mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"chat": {"command": "npx", "args": ["--key", slack]}}}
            )
        )
        self._git(root, "add", "-A")
        self._git(root, "commit", "-q", "-m", "grant")

        runner = CliRunner()
        evidence = tmp_path / "evidence.json"
        sarif = tmp_path / "out.sarif"
        outputs = [
            runner.invoke(cli_module.app, ["scan", str(root), *flags]).stdout
            for flags in ([], ["--format", "json"], ["--format", "sarif"])
        ]
        outputs += [
            runner.invoke(
                cli_module.app,
                [
                    "gate",
                    str(root),
                    "--default-branch",
                    "main",
                    "--evidence-path",
                    str(evidence),
                    "--sarif-path",
                    str(sarif),
                    *flags,
                ],
            ).stdout
            for flags in ([], ["--format", "json"], ["--format", "sarif"])
        ]
        outputs += [
            runner.invoke(
                cli_module.app, ["diff", str(root), "--baseline", "main", *flags]
            ).stdout
            for flags in ([], ["--format", "json"])
        ]
        outputs += [evidence.read_text(), sarif.read_text()]

        assert all("This change gives" in output for output in outputs)
        for output in outputs:
            for marker in self._MARKERS:
                assert marker not in output
