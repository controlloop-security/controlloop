"""Tests for Team configuration resolution.

Two properties carry most of the weight here:

- **Off means off.** `resolve_team_config` returns `None` for a repository
  that has not enabled Team, and returns it without reading the token or
  the endpoint. That single return is what makes "no network attempt when
  Team is not configured" structural rather than remembered.
- **An error names the key, never the value.** Every failure path is
  asserted both ways: the key appears, and the rejected value does not.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from factories import ENDPOINT, ORGANIZATION_ID, PROJECT_ID, TOKEN, resolved_config_with

from controlloop.config import _TEAM_FAIL_MODE_VALUES, ResolvedConfig
from controlloop.exit_codes import ExitCode
from controlloop.team.config import (
    TOKEN_ENVIRONMENT_VARIABLE,
    TeamConfigError,
    TeamFailMode,
    resolve_team_config,
)

_SECRET_SHAPED_CANARY = "ghp_" + "a" * 36


def _enabled(root: Path, **overrides: object) -> ResolvedConfig:
    settings: dict[str, object] = {
        "team_enabled": True,
        "team_endpoint": ENDPOINT,
        "team_organization_id": ORGANIZATION_ID,
        "team_project_id": PROJECT_ID,
    }
    settings.update(overrides)
    return resolved_config_with(root, settings)


class TestTeamOff:
    """A repository that has not enabled Team resolves to no configuration."""

    def test_a_repository_with_no_configuration_resolves_to_none(
        self, tmp_path: Path
    ) -> None:
        resolved = resolved_config_with(tmp_path, {})

        assert resolve_team_config(resolved, environ={}) is None

    def test_off_ignores_a_token_present_in_the_environment(
        self, tmp_path: Path
    ) -> None:
        """The inference this rules out: a `CONTROLLOOP_TEAM_TOKEN`
        inherited from another job in the same runner silently switching a
        repository onto the paid path."""

        resolved = resolved_config_with(tmp_path, {"team_enabled": False})

        assert (
            resolve_team_config(resolved, environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN})
            is None
        )

    def test_off_does_not_require_any_other_key(self, tmp_path: Path) -> None:
        """A repository that disabled Team but left a half-finished
        endpoint behind still resolves, rather than failing a build over a
        setting nothing reads."""

        resolved = resolved_config_with(
            tmp_path, {"team_enabled": False, "team_endpoint": "not-a-url"}
        )

        assert resolve_team_config(resolved, environ={}) is None


class TestResolvedConfiguration:
    def test_a_complete_configuration_resolves(self, tmp_path: Path) -> None:
        config = resolve_team_config(
            _enabled(tmp_path), environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN}
        )

        assert config is not None
        assert config.endpoint == ENDPOINT
        assert config.organization_id == ORGANIZATION_ID
        assert config.project_id == PROJECT_ID
        assert config.fail_mode is TeamFailMode.CLOSED
        assert config.branch is None
        assert config.pull_request is None
        assert config.policy_cache_seconds == 300

    def test_a_trailing_slash_is_normalized_away(self, tmp_path: Path) -> None:
        """Two spellings of the same endpoint must produce byte-identical
        request URLs, or ingestion idempotency depends on how someone
        typed a setting."""

        config = resolve_team_config(
            _enabled(tmp_path, team_endpoint=f"{ENDPOINT}/"),
            environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
        )

        assert config is not None
        assert config.endpoint == ENDPOINT

    def test_branch_and_pull_request_resolve(self, tmp_path: Path) -> None:
        config = resolve_team_config(
            _enabled(tmp_path, team_branch="main", team_pull_request="42"),
            environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
        )

        assert config is not None
        assert config.branch == "main"
        assert config.pull_request == 42

    def test_fail_mode_open_resolves(self, tmp_path: Path) -> None:
        config = resolve_team_config(
            _enabled(tmp_path, team_fail_mode="open"),
            environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
        )

        assert config is not None
        assert config.fail_mode is TeamFailMode.OPEN

    def test_fail_mode_values_match_the_config_registry(self) -> None:
        """`controlloop.config` declares the allowed values as a local
        literal set rather than importing this enum, to stay a
        dependency-light leaf. This is the drift guard that arrangement
        requires -- the same one `test_policy_thresholds.py` applies to
        the severity set."""

        assert {member.value for member in TeamFailMode} == _TEAM_FAIL_MODE_VALUES


class TestTheTokenIsNeverExposed:
    def test_the_token_does_not_appear_in_the_repr(self, tmp_path: Path) -> None:
        """A `TeamConfig` in scope during an unhandled exception must not
        print a credential into a CI log."""

        config = resolve_team_config(
            _enabled(tmp_path), environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN}
        )

        assert config is not None
        assert TOKEN not in repr(config)
        assert TOKEN not in str(config)
        assert TOKEN not in repr(config.token)
        assert "<redacted>" in repr(config)

    def test_the_token_is_reachable_only_through_reveal(self, tmp_path: Path) -> None:
        config = resolve_team_config(
            _enabled(tmp_path), environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN}
        )

        assert config is not None
        assert config.token.reveal() == TOKEN

    def test_the_token_is_not_a_configuration_key(self, tmp_path: Path) -> None:
        """`--show-config` renders every registered key. This asserts the
        token is not among them, from the rendering side rather than the
        registry side."""

        resolved = _enabled(tmp_path)

        rendered = "\n".join(resolved.render_lines())
        assert "token" not in rendered


class TestMisconfigurationNamesTheKey:
    """Exit code 2, naming the specific key, never a stack trace."""

    def test_a_missing_token_names_the_variable(self, tmp_path: Path) -> None:
        with pytest.raises(TeamConfigError) as error:
            resolve_team_config(_enabled(tmp_path), environ={})

        assert TOKEN_ENVIRONMENT_VARIABLE in str(error.value)
        assert error.value.exit_code == ExitCode.INVALID_INPUT

    def test_an_empty_token_names_the_variable(self, tmp_path: Path) -> None:
        with pytest.raises(TeamConfigError, match=TOKEN_ENVIRONMENT_VARIABLE):
            resolve_team_config(
                _enabled(tmp_path), environ={TOKEN_ENVIRONMENT_VARIABLE: "   "}
            )

    def test_an_overlong_token_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(TeamConfigError) as error:
            resolve_team_config(
                _enabled(tmp_path),
                environ={TOKEN_ENVIRONMENT_VARIABLE: "t" * 4097},
            )

        assert "t" * 4097 not in str(error.value)

    def test_a_token_with_whitespace_is_refused_before_the_transport(
        self, tmp_path: Path
    ) -> None:
        """Refused here so the error names a variable a user can fix,
        rather than surfacing later as a header-encoding failure."""

        with pytest.raises(TeamConfigError) as error:
            resolve_team_config(
                _enabled(tmp_path),
                environ={TOKEN_ENVIRONMENT_VARIABLE: "abc def"},
            )

        assert TOKEN_ENVIRONMENT_VARIABLE in str(error.value)
        assert "abc def" not in str(error.value)

    def test_a_missing_endpoint_names_the_key(self, tmp_path: Path) -> None:
        with pytest.raises(TeamConfigError, match="team_endpoint"):
            resolve_team_config(
                _enabled(tmp_path, team_endpoint=""),
                environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
            )

    def test_a_plain_http_endpoint_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(TeamConfigError) as error:
            resolve_team_config(
                _enabled(tmp_path, team_endpoint="http://platform.example"),
                environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
            )

        assert "https" in str(error.value)

    @pytest.mark.parametrize(
        "endpoint",
        [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        ],
    )
    def test_loopback_http_is_permitted(self, tmp_path: Path, endpoint: str) -> None:
        """A developer running a gate against a local platform stack should
        not have to terminate TLS to do it."""

        config = resolve_team_config(
            _enabled(tmp_path, team_endpoint=endpoint),
            environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
        )

        assert config is not None

    def test_a_scheme_that_is_not_http_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(TeamConfigError, match="https"):
            resolve_team_config(
                _enabled(tmp_path, team_endpoint="ftp://platform.example"),
                environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
            )

    def test_an_endpoint_with_no_host_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(TeamConfigError, match="host"):
            resolve_team_config(
                _enabled(tmp_path, team_endpoint="https:///path"),
                environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
            )

    def test_an_endpoint_with_a_query_is_refused(self, tmp_path: Path) -> None:
        """A query string on a base URL would be silently dropped when a
        path is appended, producing requests to an endpoint nobody
        configured."""

        with pytest.raises(TeamConfigError, match="query"):
            resolve_team_config(
                _enabled(tmp_path, team_endpoint="https://platform.example?a=1"),
                environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
            )

    def test_an_endpoint_error_never_echoes_a_secret_shaped_value(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(TeamConfigError) as error:
            resolve_team_config(
                _enabled(tmp_path, team_endpoint=f"ftp://{_SECRET_SHAPED_CANARY}"),
                environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
            )

        assert _SECRET_SHAPED_CANARY not in str(error.value)

    @pytest.mark.parametrize("key", ["team_organization_id", "team_project_id"])
    def test_a_missing_identifier_names_its_key(self, tmp_path: Path, key: str) -> None:
        with pytest.raises(TeamConfigError, match=key):
            resolve_team_config(
                _enabled(tmp_path, **{key: ""}),
                environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
            )

    @pytest.mark.parametrize("key", ["team_organization_id", "team_project_id"])
    def test_a_malformed_identifier_names_its_key(
        self, tmp_path: Path, key: str
    ) -> None:
        with pytest.raises(TeamConfigError) as error:
            resolve_team_config(
                _enabled(tmp_path, **{key: "not-a-uuid"}),
                environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
            )

        assert key in str(error.value)
        assert "not-a-uuid" not in str(error.value)

    @pytest.mark.parametrize("value", ["zero", "-1", "0", "1.5"])
    def test_a_malformed_pull_request_number_is_refused(
        self, tmp_path: Path, value: str
    ) -> None:
        with pytest.raises(TeamConfigError, match="team_pull_request"):
            resolve_team_config(
                _enabled(tmp_path, team_pull_request=value),
                environ={TOKEN_ENVIRONMENT_VARIABLE: TOKEN},
            )
