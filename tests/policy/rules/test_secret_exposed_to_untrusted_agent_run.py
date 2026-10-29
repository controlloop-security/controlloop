"""Tests for `policy.secret-exposed-to-untrusted-agent-run`."""

from __future__ import annotations

from pathlib import Path

from _authority_rule_support import context, repos, summary, write

from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.policy.rules.secret_exposed_to_untrusted_agent_run import RULE
from controlloop.policy.rules.secret_exposed_to_untrusted_agent_run import (
    findings as secret_exposed_findings,
)

_SECRET_VALUE = "never-read-by-the-adapter"


def test_the_rule_reads_agent_authority() -> None:
    assert RULE.reads_agent_authority is True


def _workflow(
    root: Path,
    *,
    trigger: str = "pull_request_target",
    secrets: tuple[str, ...] = ("ANTHROPIC_API_KEY",),
    head_checkout: bool = False,
) -> None:
    lines = [f"on: {trigger}", "jobs:", "  review:", "    runs-on: ubuntu-latest"]
    if secrets:
        lines.append("    env:")
        lines += [f"      {name}: ${{{{ secrets.{name} }}}}" for name in secrets]
    lines.append("    steps:")
    if head_checkout:
        lines += [
            "      - uses: actions/checkout@v4",
            "        with:",
            "          ref: ${{ github.event.pull_request.head.sha }}",
        ]
    lines += [
        "      - uses: anthropics/claude-code-action@v1",
        "        with:",
        '          claude_args: "--max-turns 5"',
    ]
    write(root, ".github/workflows/agent.yml", "\n".join(lines) + "\n")


def test_an_untrusted_trigger_with_a_secret_is_high(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _workflow(head, secrets=("ANTHROPIC_API_KEY", "DEPLOY_KEY"))

    (finding,) = secret_exposed_findings(context(head, base))

    assert summary((finding,)) == [(FindingSeverity.HIGH, FindingChangeState.ADDED)]
    assert "(pull_request_target)" in finding.message
    assert "secrets ANTHROPIC_API_KEY, DEPLOY_KEY" in finding.message


def test_a_secret_added_to_an_untrusted_job_is_high(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _workflow(base, secrets=())
    _workflow(head, secrets=("DEPLOY_KEY",))

    (finding,) = secret_exposed_findings(context(head, base))

    assert summary((finding,)) == [(FindingSeverity.HIGH, FindingChangeState.CHANGED)]
    assert "secret DEPLOY_KEY." in finding.message


def test_an_untrusted_trigger_without_a_secret_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _workflow(head, trigger="issue_comment", secrets=())

    assert secret_exposed_findings(context(head, base)) == ()


def test_a_trusted_trigger_with_a_secret_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _workflow(head, trigger="pull_request")

    assert secret_exposed_findings(context(head, base)) == ()


def test_a_head_checkout_with_a_secret_is_high(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _workflow(head, trigger="pull_request", head_checkout=True)

    (finding,) = secret_exposed_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
    assert "a checkout of the pull request head" in finding.message


def test_github_token_is_not_counted(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _workflow(head, secrets=("GITHUB_TOKEN",))

    assert secret_exposed_findings(context(head, base)) == ()


def test_a_first_scan_is_medium(tmp_path: Path) -> None:
    _workflow(tmp_path)

    assert summary(secret_exposed_findings(context(tmp_path))) == [
        (FindingSeverity.MEDIUM, FindingChangeState.NOT_COMPARED)
    ]


def test_a_secret_removed_in_the_change_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _workflow(base)
    _workflow(head, secrets=())

    assert secret_exposed_findings(context(head, base)) == ()


def test_an_exposure_unchanged_since_the_baseline_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _workflow(base, secrets=("DEPLOY_KEY",))
    _workflow(head, secrets=("DEPLOY_KEY",), head_checkout=True)

    assert secret_exposed_findings(context(head, base)) == ()


def test_another_secret_on_an_exposed_job_names_only_the_new_one(
    tmp_path: Path,
) -> None:
    base, head = repos(tmp_path)
    _workflow(base, secrets=("DEPLOY_KEY",))
    _workflow(head, secrets=("DEPLOY_KEY", "NPM_TOKEN"))

    (finding,) = secret_exposed_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
    assert finding.message.endswith("is given secret NPM_TOKEN.")


def test_no_secret_value_reaches_the_finding(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _workflow(head)
    text = (head / ".github/workflows/agent.yml").read_text()
    write(
        head,
        ".github/workflows/agent.yml",
        text.replace(
            "runs-on: ubuntu-latest", f"runs-on: ubuntu-latest\n    # {_SECRET_VALUE}"
        ),
    )

    (finding,) = secret_exposed_findings(context(head, base))

    assert _SECRET_VALUE not in finding.model_dump_json()
