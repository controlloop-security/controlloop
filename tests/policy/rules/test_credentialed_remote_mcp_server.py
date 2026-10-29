"""Tests for `policy.credentialed-remote-mcp-server`."""

from __future__ import annotations

from pathlib import Path

import pytest
from _authority_rule_support import context, repos, summary, write

from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.policy.rules.credentialed_remote_mcp_server import (
    RULE,
    is_credential_name,
)
from controlloop.policy.rules.credentialed_remote_mcp_server import (
    findings as credentialed_findings,
)

_TOKEN_VALUE = "planted-header-value-7f7f"


def test_the_rule_reads_agent_authority() -> None:
    assert RULE.reads_agent_authority is True


@pytest.mark.parametrize(
    "name",
    [
        "Authorization",
        "proxy-authorization",
        "X-API-Key",
        "api-key",
        "GITHUB_TOKEN",
        "client_secret",
        "OPENAI_API_KEY",
        "DB_PASSWORD",
        "SERVICE_CREDENTIAL",
        "VENDOR_APIKEY",
    ],
)
def test_credential_shaped_names(name: str) -> None:
    assert is_credential_name(name)


@pytest.mark.parametrize(
    "name",
    ["Content-Type", "Accept", "X-Request-Id", "LOG_LEVEL", "TOKENIZER", "KEYBOARD"],
)
def test_other_names(name: str) -> None:
    assert not is_credential_name(name)


def _http(
    root: Path,
    *,
    url: str = "https://api.example.com/mcp",
    headers: dict[str, str] | None = None,
) -> None:
    server: dict[str, object] = {"type": "http", "url": url}
    if headers is not None:
        server["headers"] = headers
    write(root, ".mcp.json", {"mcpServers": {"docs": server}})


_AUTH = {"Authorization": f"Bearer {_TOKEN_VALUE}"}


def test_a_new_credentialed_server_is_medium(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _http(head, headers=_AUTH)

    (finding,) = credentialed_findings(context(head, base))

    assert summary((finding,)) == [(FindingSeverity.MEDIUM, FindingChangeState.ADDED)]
    assert finding.message == (
        "MCP server 'docs' sends Authorization to api.example.com."
    )
    assert _TOKEN_VALUE not in finding.model_dump_json()


def test_a_host_change_is_high(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _http(base, headers=_AUTH)
    _http(head, url="https://collector.example.net/mcp", headers=_AUTH)

    (finding,) = credentialed_findings(context(head, base))

    assert summary((finding,)) == [(FindingSeverity.HIGH, FindingChangeState.CHANGED)]
    assert "to collector.example.net, previously api.example.com" in finding.message


def test_a_credential_added_to_an_existing_server_is_medium(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _http(base, headers={"Accept": "application/json"})
    _http(head, headers={"Accept": "application/json", **_AUTH})

    (finding,) = credentialed_findings(context(head, base))

    assert summary((finding,)) == [(FindingSeverity.MEDIUM, FindingChangeState.CHANGED)]
    assert "now also sends Authorization" in finding.message


def test_a_server_without_credential_names_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _http(head, headers={"Accept": "application/json"})

    assert credentialed_findings(context(head, base)) == ()


def test_a_stdio_server_with_a_key_in_its_env_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    write(
        head,
        ".mcp.json",
        {"mcpServers": {"local": {"command": "npx", "env": {"API_KEY": "x"}}}},
    )

    assert credentialed_findings(context(head, base)) == ()


def test_a_first_scan_is_low(tmp_path: Path) -> None:
    _http(tmp_path, headers=_AUTH)

    assert summary(credentialed_findings(context(tmp_path))) == [
        (FindingSeverity.LOW, FindingChangeState.NOT_COMPARED)
    ]


def test_removal_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _http(base, headers=_AUTH)
    write(head, ".mcp.json", {"mcpServers": {}})

    assert credentialed_findings(context(head, base)) == ()


def test_an_unchanged_credential_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _http(base, headers=_AUTH)
    _http(head, headers={**_AUTH, "Accept": "application/json"})

    assert credentialed_findings(context(head, base)) == ()
