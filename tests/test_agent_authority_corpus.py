"""The agent-authority benign corpus.

`tests/fixtures/agent-authority-corpus/` holds twenty-two cases, each a
directory with one settings, skill, subagent, command, plugin, MCP, or
workflow file shaped like common real-world usage: formatter and linter
hooks, narrow allow rules, pinned plugins, read-only workflows.

Each case is gated twice:

- `as_present`: the file as it sits in a repository, with no baseline.
  The bar here: zero *Deployment blocked*, at most two *Passed with
  warnings*.
- `as_introduced`: a pull request that adds the file to an otherwise
  empty repository, compared against its merge base. A newly added hook
  command is `high` on purpose, so these results are recorded for review
  rather than held to that bar.

`results.json` is the committed record of both. Regenerate it after a
deliberate change with:

    uv run python tests/test_agent_authority_corpus.py

and review the diff by hand.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from controlloop.cli import app
from controlloop.redaction import redact_text, scan_credential_shapes

_CORPUS = Path(__file__).resolve().parent / "fixtures" / "agent-authority-corpus"
_RESULTS = _CORPUS / "results.json"
_BLOCKED = "deployment_blocked"
_WARNINGS = "passed_with_warnings"


def _cases() -> list[Path]:
    return sorted(path for path in _CORPUS.iterdir() if path.is_dir())


def _files(case: Path) -> list[str]:
    return sorted(
        str(path.relative_to(case)) for path in case.rglob("*") if path.is_file()
    )


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def _gate(root: Path, evidence: Path, *extra: str) -> dict[str, object]:
    result = CliRunner().invoke(
        app,
        [
            "gate",
            str(root),
            "--format",
            "json",
            "--evidence-path",
            str(evidence),
            *extra,
        ],
    )
    artifact = json.loads(result.stdout)
    findings = artifact.get("findings") or []
    return {
        "verdict": artifact["verdict"],
        "findings": sorted(
            [finding["rule_id"], finding["severity"]] for finding in findings
        ),
        "incomplete": sorted(item["code"] for item in artifact["completeness"]),
    }


def evaluate(work: Path) -> dict[str, object]:
    """Gate every case both ways, in a scratch directory `work`."""

    cases: dict[str, object] = {}
    for case in _cases():
        present = work / case.name / "present"
        shutil.copytree(case, present)
        as_present = _gate(present, work / case.name / "present.json")

        repository = work / case.name / "introduced"
        repository.mkdir()
        _git(repository, "init", "-q", "-b", "main")
        (repository / "README.md").write_text("A project.\n")
        _git(repository, "add", "-A")
        _git(repository, "commit", "-q", "-m", "base")
        _git(repository, "checkout", "-q", "-b", "change")
        shutil.copytree(case, repository, dirs_exist_ok=True)
        _git(repository, "add", "-A")
        _git(repository, "commit", "-q", "-m", "add the configuration")
        as_introduced = _gate(
            repository,
            work / case.name / "introduced.json",
            "--default-branch",
            "main",
        )
        cases[case.name] = {
            "files": _files(case),
            "as_present": as_present,
            "as_introduced": as_introduced,
        }

    def count(mode: str, verdict: str) -> int:
        return sum(
            1
            for result in cases.values()
            if isinstance(result, dict) and result[mode]["verdict"] == verdict
        )

    return {
        "_about": (
            "Recorded gate results for the benign agent-configuration corpus. "
            "Regenerate with `uv run python tests/test_agent_authority_corpus.py`."
        ),
        "summary": {
            "cases": len(cases),
            "as_present": {
                _BLOCKED: count("as_present", _BLOCKED),
                _WARNINGS: count("as_present", _WARNINGS),
            },
            "as_introduced": {
                _BLOCKED: count("as_introduced", _BLOCKED),
                _WARNINGS: count("as_introduced", _WARNINGS),
            },
        },
        "cases": cases,
    }


def _recorded() -> dict[str, object]:
    document: dict[str, object] = json.loads(_RESULTS.read_text(encoding="utf-8"))
    return document


def test_the_corpus_has_at_least_twenty_files() -> None:
    files = [name for case in _cases() for name in _files(case)]

    assert len(files) >= 20


def test_recorded_results_match_a_fresh_run(tmp_path: Path) -> None:
    assert evaluate(tmp_path) == _recorded()


def test_decision_d7_holds_for_the_corpus_as_it_sits() -> None:
    summary = _recorded()["summary"]
    assert isinstance(summary, dict)

    assert summary["cases"] >= 20
    assert summary["as_present"][_BLOCKED] == 0
    assert summary["as_present"][_WARNINGS] <= 2


def test_no_corpus_file_holds_a_credential_shape() -> None:
    for case in _cases():
        for name in _files(case):
            text = (case / name).read_text(encoding="utf-8")
            assert scan_credential_shapes(text) == (), f"{case.name}/{name}"
            assert redact_text(text) == text, f"{case.name}/{name}"


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as scratch:
        document = evaluate(Path(scratch))
    _RESULTS.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document["summary"], indent=2), file=sys.stderr)
