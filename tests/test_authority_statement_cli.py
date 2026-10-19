"""The authority statement through `scan`, `gate`, and `diff`.

A real git repository: `main` holds the baseline, a feature branch adds
a `SessionStart` hook, and the merge-base fallback supplies the diff.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from controlloop.cli import app
from controlloop.reporting import CURRENT_EVIDENCE_SCHEMA_VERSION

runner = CliRunner()
_SETTINGS = ".claude/settings.json"
_HOOK = {
    "hooks": {
        "SessionStart": [
            {"hooks": [{"type": "command", "command": "node .github/setup.js"}]}
        ]
    }
}
_TARGET = (
    "This change gives Claude Code the power to run `node .github/setup.js` on "
    "every session start (`.claude/settings.json`, hook `SessionStart`)."
)


def _git(path: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t.com", "-c", "user.name=t", *args],
        cwd=path,
        check=True,
        capture_output=True,
    )


def _repository(tmp_path: Path, *, manifest: str | None = None) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "README.md").write_text("baseline\n")
    if manifest is not None:
        (tmp_path / "controlloop.yaml").write_text(manifest)
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "baseline")
    _git(tmp_path, "checkout", "-q", "-b", "feature")
    settings = tmp_path / _SETTINGS
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps(_HOOK))
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "add a hook")
    return tmp_path


def test_scan_text_leads_with_the_statement(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    result = runner.invoke(app, ["scan", str(root)])

    flat = " ".join(result.stdout.split())
    assert f"Authority: • {_TARGET} No approval is recorded." in flat
    sections = result.stdout.split("\n\n")
    assert sections[1] == "✕ DEPLOYMENT BLOCKED"
    assert sections[2].startswith("Authority:")


def test_scan_json_carries_a_schema_defined_section(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    result = runner.invoke(app, ["scan", str(root), "--format", "json"])

    report = json.loads(result.stdout)
    assert report["schema_version"] == "1.2.0"
    (entry,) = report["authority_delta"]["entries"]
    assert entry["statement"] == f"{_TARGET} No approval is recorded."
    assert entry["approval_recorded"] is False


def test_scan_sarif_carries_the_statement_on_the_hook_finding(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    result = runner.invoke(app, ["scan", str(root), "--format", "sarif"])

    run = json.loads(result.stdout)["runs"][0]
    assert run["properties"]["controlloop"]["authorityDelta"][0]["statement"] == (
        f"{_TARGET} No approval is recorded."
    )
    hook_results = [
        item
        for item in run["results"]
        if item["ruleId"] == "policy.agent-hook-command-change"
    ]
    assert hook_results
    assert hook_results[0]["properties"]["controlloop"]["authorityStatement"] == (
        f"{_TARGET} No approval is recorded."
    )
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert rules["policy.agent-hook-command-change"]["help"]["text"]


def test_a_manifest_approval_is_reflected(tmp_path: Path) -> None:
    root = _repository(
        tmp_path,
        manifest=(
            'schema_version: "1.0.0"\nowner: security-team\napprovals:\n'
            '  - capability: ".claude/settings.json#hooks.SessionStart[0].hooks[0]"\n'
            "    approver: alice\n"
        ),
    )

    result = runner.invoke(app, ["scan", str(root), "--format", "json"])

    (entry,) = json.loads(result.stdout)["authority_delta"]["entries"]
    assert entry["key_path"] == "hooks.SessionStart[0].hooks[0]"
    assert entry["statement"] == f"{_TARGET} Approval recorded."


def test_gate_evidence_and_sarif_file_carry_the_statement(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    evidence = tmp_path / "evidence.json"
    sarif = tmp_path / "out.sarif"

    runner.invoke(
        app,
        [
            "gate",
            str(root),
            "--default-branch",
            "main",
            "--evidence-path",
            str(evidence),
            "--sarif-path",
            str(sarif),
        ],
    )

    artifact = json.loads(evidence.read_text())
    assert artifact["schema_version"] == CURRENT_EVIDENCE_SCHEMA_VERSION
    assert artifact["authority_delta"]["entries"][0]["statement"].startswith(_TARGET)
    controlloop = json.loads(sarif.read_text())["runs"][0]["properties"]["controlloop"]
    assert controlloop["authorityDelta"][0]["statement"].startswith(_TARGET)


def test_diff_text_and_json(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    text = runner.invoke(app, ["diff", str(root), "--baseline", "main"])
    data = runner.invoke(
        app, ["diff", str(root), "--baseline", "main", "--format", "json"]
    )

    assert f"  • {_TARGET} No approval is recorded." in text.stdout
    report = json.loads(data.stdout)
    assert report["schema_version"] == "1.1.0"
    assert report["authority_delta"]["entries"][0]["kind"] == "hook"


def test_an_unchanged_repository_adds_nothing_anywhere(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    _git(root, "checkout", "-q", "main")
    _git(root, "checkout", "-q", "-b", "quiet")
    (root / "README.md").write_text("changed prose\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "prose")

    text = runner.invoke(app, ["scan", str(root)])
    data = runner.invoke(app, ["scan", str(root), "--format", "json"])
    sarif = runner.invoke(app, ["scan", str(root), "--format", "sarif"])
    diff = runner.invoke(app, ["diff", str(root), "--baseline", "main"])

    assert "Authority:" not in text.stdout
    assert "authority_delta" not in data.stdout
    assert "authorityDelta" not in sarif.stdout
    assert "Authority:" not in diff.stdout


def _approval_manifest(expires: str | None = None) -> str:
    text = (
        'schema_version: "1.0.0"\nowner: security-team\napprovals:\n'
        '  - capability: ".claude/settings.json#hooks.SessionStart[0].hooks[0]"\n'
        "    approver: alice\n"
    )
    if expires is not None:
        text += f'    expires_at: "{expires}"\n'
    return text


def test_an_approval_keeps_the_finding_but_stops_it_blocking(tmp_path: Path) -> None:
    """An approval naming the component lowers its agent-authority finding
    to info, so the change no longer blocks, and the finding stays in the
    report saying who approved it."""

    root = _repository(tmp_path, manifest=_approval_manifest())

    result = runner.invoke(app, ["scan", str(root), "--format", "json"])

    report = json.loads(result.stdout)
    assert result.exit_code == 0
    assert report["verdict"] == "passed"
    (finding,) = [
        item
        for item in report["findings"]
        if item["rule_id"] == "policy.agent-hook-command-change"
    ]
    assert finding["severity"] == "info"
    assert finding["message"].endswith("Approval recorded by alice.")
    assert report["authority_delta"]["entries"][0]["statement"].endswith(
        "Approval recorded."
    )


def test_an_expired_approval_does_nothing(tmp_path: Path) -> None:
    root = _repository(tmp_path, manifest=_approval_manifest("2020-01-01T00:00:00Z"))

    result = runner.invoke(app, ["scan", str(root), "--format", "json"])

    report = json.loads(result.stdout)
    assert result.exit_code == 1
    assert report["verdict"] == "deployment_blocked"
    assert report["authority_delta"]["entries"][0]["statement"].endswith(
        "No approval is recorded."
    )


def test_gate_honours_the_approval_too(tmp_path: Path) -> None:
    root = _repository(tmp_path, manifest=_approval_manifest())

    result = runner.invoke(
        app,
        [
            "gate",
            str(root),
            "--default-branch",
            "main",
            "--evidence-path",
            str(tmp_path / "evidence.json"),
        ],
    )

    assert result.exit_code == 0
