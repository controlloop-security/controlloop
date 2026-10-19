"""The example agent configurations cannot rot.

`examples/agent-config/baseline/` is committed on a `main` branch and
`examples/agent-config/head/` on a branch from it, the way a pull request
would change them; `controlloop gate` then compares the branch with its
merge base. The verdict, every finding's rule, severity, and ID, and the
authority statements must match `examples/agent-config/expected.json`.

Regenerate the record after a deliberate change with:

    uv run python tests/test_agent_config_examples.py

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

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "agent-config"
_EXPECTED = _EXAMPLES / "expected.json"


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def _replace_tree(root: Path, source: Path) -> None:
    for child in root.iterdir():
        if child.name != ".git":
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    shutil.copytree(source, root, dirs_exist_ok=True)


def evaluate(work: Path) -> dict[str, object]:
    repository = work / "repository"
    repository.mkdir(parents=True)
    _git(repository, "init", "-q", "-b", "main")
    _replace_tree(repository, _EXAMPLES / "baseline")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "baseline")
    _git(repository, "checkout", "-q", "-b", "widen")
    _replace_tree(repository, _EXAMPLES / "head")
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "widen")

    sarif = work / "out.sarif"
    result = CliRunner().invoke(
        app,
        [
            "gate",
            str(repository),
            "--default-branch",
            "main",
            "--format",
            "json",
            "--evidence-path",
            str(work / "evidence.json"),
            "--sarif-path",
            str(sarif),
        ],
    )
    artifact = json.loads(result.stdout)
    delta = artifact.get("authority_delta") or {"entries": []}
    return {
        "_about": (
            "Recorded `controlloop gate` result for examples/agent-config: "
            "baseline/ on main, head/ on a branch. Regenerate "
            "with `uv run python tests/test_agent_config_examples.py`."
        ),
        "verdict": artifact["verdict"],
        "exit_code": result.exit_code,
        "findings": sorted(
            [finding["rule_id"], finding["severity"], finding["id"]]
            for finding in artifact["findings"]
        ),
        "authority_statements": [entry["statement"] for entry in delta["entries"]],
    }


def _expected() -> dict[str, object]:
    document: dict[str, object] = json.loads(_EXPECTED.read_text(encoding="utf-8"))
    return document


def test_the_examples_still_produce_their_recorded_result(tmp_path: Path) -> None:
    assert evaluate(tmp_path) == _expected()


def test_approved_and_unapproved_statements_sit_side_by_side() -> None:
    statements = _expected()["authority_statements"]
    assert isinstance(statements, list)

    assert any(text.endswith("Approval recorded.") for text in statements)
    assert any(text.endswith("No approval is recorded.") for text in statements)


def test_no_example_file_holds_a_credential_shape() -> None:
    for path in sorted(_EXAMPLES.rglob("*")):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert scan_credential_shapes(text) == (), path.name
            assert redact_text(text) == text, path.name


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as scratch:
        document = evaluate(Path(scratch))
    _EXPECTED.write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps(document, indent=2), file=sys.stderr)
