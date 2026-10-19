"""Tests for configuration loading and precedence.

Covers precedence at each of the three tier boundaries, the effective
configuration and winning source (exercised in `test_cli.py`'s
`--show-config` integration tests as well as here at the `load_config`
level), an unknown repository-file key being a hard error, a malformed
repository file being a hard error with a parse location and never
surrounding file content, and no configuration value being required to
resolve successfully.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from controlloop.config import (
    CONFIG_FILENAME,
    ConfigError,
    ConfigSource,
    load_config,
)
from controlloop.repository import RepositoryRoot, TraversalBounds

_ALL_KEYS = (
    "max_file_size_bytes",
    "max_total_bytes",
    "max_file_count",
    "max_depth",
)

# A github-token-shaped canary, matching the fixture style already used by
# `test_redaction.py`, planted in a malformed value to prove privacy: a
# `ConfigError` message must never echo a raw value from the file or the
# environment, secret-shaped or not.
_SECRET_SHAPED_CANARY = "ghp_" + "a" * 36


def _root(path: Path) -> RepositoryRoot:
    return RepositoryRoot(path=path)


class TestDefaultsRequireNoConfiguration:
    """A fully resolved configuration never requires any value."""

    def test_empty_environment_no_flags_no_file_resolves_from_defaults(
        self, tmp_path: Path
    ) -> None:
        resolved = load_config(_root(tmp_path), environ={}, flags={})

        defaults = TraversalBounds()
        for key in _ALL_KEYS:
            assert resolved[key].source is ConfigSource.DEFAULT
        assert resolved["max_file_size_bytes"].value == defaults.max_file_size_bytes
        assert resolved["max_total_bytes"].value == defaults.max_total_bytes
        assert resolved["max_file_count"].value == defaults.max_file_count
        assert resolved["max_depth"].value == defaults.max_depth

    def test_traversal_bounds_accessor_matches_default_traversal_bounds(
        self, tmp_path: Path
    ) -> None:
        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved.traversal_bounds() == TraversalBounds()


class TestPrecedenceBoundaries:
    """Defaults < repository file < environment < flags, one dedicated test
    per tier boundary."""

    def test_repository_file_overrides_default(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("max_depth = 33\n")

        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved["max_depth"].value == 33
        assert resolved["max_depth"].source is ConfigSource.REPOSITORY_FILE
        # An untouched key still resolves from defaults.
        assert resolved["max_file_count"].source is ConfigSource.DEFAULT

    def test_environment_overrides_repository_file(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("max_depth = 33\n")

        resolved = load_config(
            _root(tmp_path), environ={"CONTROLLOOP_MAX_DEPTH": "77"}, flags={}
        )

        assert resolved["max_depth"].value == 77
        assert resolved["max_depth"].source is ConfigSource.ENVIRONMENT

    def test_flag_overrides_environment(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("max_depth = 33\n")

        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_MAX_DEPTH": "77"},
            flags={"max_depth": 9},
        )

        assert resolved["max_depth"].value == 9
        assert resolved["max_depth"].source is ConfigSource.FLAG

    def test_flag_present_but_none_does_not_win(self, tmp_path: Path) -> None:
        """A flag mapped to `None` means "not supplied," never a winning
        value of `None` -- the environment tier must still win."""
        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_MAX_DEPTH": "77"},
            flags={"max_depth": None},
        )

        assert resolved["max_depth"].value == 77
        assert resolved["max_depth"].source is ConfigSource.ENVIRONMENT

    def test_each_key_resolves_independently(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text(
            "max_file_size_bytes = 1000\nmax_total_bytes = 2000\n"
        )

        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_MAX_FILE_COUNT": "5"},
            flags={"max_depth": 3},
        )

        def _as_tuple(key: str) -> tuple[int | str | tuple[str, ...], ConfigSource]:
            return (resolved[key].value, resolved[key].source)

        assert _as_tuple("max_file_size_bytes") == (1000, ConfigSource.REPOSITORY_FILE)
        assert _as_tuple("max_total_bytes") == (2000, ConfigSource.REPOSITORY_FILE)
        assert _as_tuple("max_file_count") == (5, ConfigSource.ENVIRONMENT)
        assert _as_tuple("max_depth") == (3, ConfigSource.FLAG)


class TestUnknownKey:
    """An unknown repository-file key is a hard error naming the key and the
    file, never silently ignored."""

    def test_unknown_key_raises_naming_key_and_file(self, tmp_path: Path) -> None:
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("bogus_key = 1\n")

        with pytest.raises(ConfigError) as excinfo:
            load_config(_root(tmp_path), environ={}, flags={})

        message = str(excinfo.value)
        assert "bogus_key" in message
        assert str(config_path) in message
        assert excinfo.value.exit_code == 2

    def test_unknown_key_alongside_known_keys_still_raises(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("max_depth = 10\nnot_a_key = 1\n")

        with pytest.raises(ConfigError, match="not_a_key"):
            load_config(_root(tmp_path), environ={}, flags={})


class TestMalformedFile:
    """A malformed repository file returns a parse location and never
    surrounding file content."""

    def test_malformed_toml_raises_with_parse_location(self, tmp_path: Path) -> None:
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(f"max_depth = [1,2\nfoo = {_SECRET_SHAPED_CANARY}")

        with pytest.raises(ConfigError) as excinfo:
            load_config(_root(tmp_path), environ={}, flags={})

        message = str(excinfo.value)
        assert str(config_path) in message
        assert "line" in message
        assert excinfo.value.exit_code == 2

    def test_malformed_file_error_never_echoes_planted_secret(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(f"max_depth = [1,2\nfoo = {_SECRET_SHAPED_CANARY}")

        with pytest.raises(ConfigError) as excinfo:
            load_config(_root(tmp_path), environ={}, flags={})

        assert _SECRET_SHAPED_CANARY not in str(excinfo.value)

    def test_undecodable_file_raises(self, tmp_path: Path) -> None:
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_bytes(b"max_depth = \xff\xfe not utf-8")

        with pytest.raises(ConfigError) as excinfo:
            load_config(_root(tmp_path), environ={}, flags={})

        assert excinfo.value.exit_code == 2

    @pytest.mark.skipif(
        sys.platform == "win32" or os.geteuid() == 0,
        reason="permission-denied simulation requires a non-root POSIX user",
    )
    def test_unreadable_file_raises_config_error_not_ostraceback(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("max_depth = 10\n")
        config_path.chmod(0o000)
        try:
            with pytest.raises(ConfigError) as excinfo:
                load_config(_root(tmp_path), environ={}, flags={})
            assert excinfo.value.exit_code == 2
        finally:
            config_path.chmod(0o644)

    def test_absent_file_is_not_an_error(self, tmp_path: Path) -> None:
        """An absent repository file is a normal default, not an error
        condition -- distinguishing "missing" from "malformed"."""
        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved["max_depth"].source is ConfigSource.DEFAULT


class TestValueValidation:
    """A present but invalid value is rejected with an explicit,
    value-free error rather than silently coerced or ignored."""

    def test_non_integer_file_value_raises(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text('max_depth = "fifty"\n')

        with pytest.raises(ConfigError, match="max_depth"):
            load_config(_root(tmp_path), environ={}, flags={})

    def test_boolean_file_value_is_rejected_not_coerced_to_int(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("max_depth = true\n")

        with pytest.raises(ConfigError, match="max_depth"):
            load_config(_root(tmp_path), environ={}, flags={})

    def test_non_integer_environment_value_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="CONTROLLOOP_MAX_DEPTH"):
            load_config(
                _root(tmp_path),
                environ={"CONTROLLOOP_MAX_DEPTH": "not-a-number"},
                flags={},
            )

    def test_non_integer_environment_value_error_never_echoes_value(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ConfigError) as excinfo:
            load_config(
                _root(tmp_path),
                environ={"CONTROLLOOP_MAX_DEPTH": _SECRET_SHAPED_CANARY},
                flags={},
            )

        assert _SECRET_SHAPED_CANARY not in str(excinfo.value)

    def test_out_of_range_merged_value_raises(self, tmp_path: Path) -> None:
        """A value that parses as an integer but fails `TraversalBounds`'
        own `>= 1` validation is still rejected at load time."""
        with pytest.raises(ConfigError):
            load_config(_root(tmp_path), environ={}, flags={"max_depth": 0})


class TestSeverityThresholdKey:
    """`severity_threshold` resolves through the same four-tier mechanism as
    the original integer keys."""

    def test_default_is_high(self, tmp_path: Path) -> None:
        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved.severity_threshold_value() == "high"
        assert resolved["severity_threshold"].source is ConfigSource.DEFAULT

    def test_repository_file_overrides_default(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text('severity_threshold = "low"\n')

        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved.severity_threshold_value() == "low"
        assert resolved["severity_threshold"].source is ConfigSource.REPOSITORY_FILE

    def test_environment_overrides_repository_file(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text('severity_threshold = "low"\n')

        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_SEVERITY_THRESHOLD": "critical"},
            flags={},
        )

        assert resolved.severity_threshold_value() == "critical"
        assert resolved["severity_threshold"].source is ConfigSource.ENVIRONMENT

    def test_flag_overrides_environment(self, tmp_path: Path) -> None:
        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_SEVERITY_THRESHOLD": "critical"},
            flags={"severity_threshold": "info"},
        )

        assert resolved.severity_threshold_value() == "info"
        assert resolved["severity_threshold"].source is ConfigSource.FLAG

    @pytest.mark.parametrize("value", ["info", "low", "medium", "high", "critical"])
    def test_every_finding_severity_value_is_accepted(
        self, tmp_path: Path, value: str
    ) -> None:
        (tmp_path / CONFIG_FILENAME).write_text(f'severity_threshold = "{value}"\n')

        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved.severity_threshold_value() == value

    def test_unknown_value_from_file_raises_naming_key(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text('severity_threshold = "extreme"\n')

        with pytest.raises(ConfigError, match="severity_threshold"):
            load_config(_root(tmp_path), environ={}, flags={})

    def test_non_string_value_from_file_raises(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("severity_threshold = 3\n")

        with pytest.raises(ConfigError, match="severity_threshold"):
            load_config(_root(tmp_path), environ={}, flags={})

    def test_unknown_value_from_environment_raises_naming_env_var(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ConfigError, match="CONTROLLOOP_SEVERITY_THRESHOLD"):
            load_config(
                _root(tmp_path),
                environ={"CONTROLLOOP_SEVERITY_THRESHOLD": "extreme"},
                flags={},
            )

    def test_malformed_value_error_never_echoes_planted_secret(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ConfigError) as excinfo:
            load_config(
                _root(tmp_path),
                environ={"CONTROLLOOP_SEVERITY_THRESHOLD": _SECRET_SHAPED_CANARY},
                flags={},
            )

        assert _SECRET_SHAPED_CANARY not in str(excinfo.value)
        assert excinfo.value.exit_code == 2


class TestLowConfidenceActionKey:
    """`low_confidence_action` resolves through the same four-tier
    mechanism."""

    def test_default_is_block(self, tmp_path: Path) -> None:
        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved.low_confidence_action_value() == "block"
        assert resolved["low_confidence_action"].source is ConfigSource.DEFAULT

    @pytest.mark.parametrize("value", ["block", "warn"])
    def test_both_action_values_are_accepted(self, tmp_path: Path, value: str) -> None:
        (tmp_path / CONFIG_FILENAME).write_text(f'low_confidence_action = "{value}"\n')

        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved.low_confidence_action_value() == value

    def test_environment_overrides_repository_file(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text('low_confidence_action = "warn"\n')

        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_LOW_CONFIDENCE_ACTION": "block"},
            flags={},
        )

        assert resolved.low_confidence_action_value() == "block"
        assert resolved["low_confidence_action"].source is ConfigSource.ENVIRONMENT

    def test_unknown_value_raises_naming_key(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text('low_confidence_action = "ignore"\n')

        with pytest.raises(ConfigError, match="low_confidence_action"):
            load_config(_root(tmp_path), environ={}, flags={})


class TestDisabledRulesKey:
    """`disabled_rules` resolves as an ordered rule-ID list through the same
    four-tier mechanism."""

    def test_default_is_empty(self, tmp_path: Path) -> None:
        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved.disabled_rule_ids() == frozenset()
        assert resolved["disabled_rules"].source is ConfigSource.DEFAULT

    def test_repository_file_array_resolves(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text(
            'disabled_rules = ["policy.rule-a", "policy.rule-b"]\n'
        )

        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved.disabled_rule_ids() == frozenset(
            {"policy.rule-a", "policy.rule-b"}
        )
        assert resolved["disabled_rules"].source is ConfigSource.REPOSITORY_FILE

    def test_environment_comma_separated_list_resolves(self, tmp_path: Path) -> None:
        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_DISABLED_RULES": "policy.rule-a, policy.rule-b"},
            flags={},
        )

        assert resolved.disabled_rule_ids() == frozenset(
            {"policy.rule-a", "policy.rule-b"}
        )
        assert resolved["disabled_rules"].source is ConfigSource.ENVIRONMENT

    def test_flag_overrides_environment(self, tmp_path: Path) -> None:
        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_DISABLED_RULES": "policy.rule-a"},
            flags={"disabled_rules": ("policy.rule-c",)},
        )

        assert resolved.disabled_rule_ids() == frozenset({"policy.rule-c"})
        assert resolved["disabled_rules"].source is ConfigSource.FLAG

    def test_non_array_file_value_raises(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text('disabled_rules = "policy.rule-a"\n')

        with pytest.raises(ConfigError, match="disabled_rules"):
            load_config(_root(tmp_path), environ={}, flags={})

    def test_non_string_array_element_raises(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("disabled_rules = [1, 2]\n")

        with pytest.raises(ConfigError, match="disabled_rules"):
            load_config(_root(tmp_path), environ={}, flags={})

    def test_control_character_rule_id_raises(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text('disabled_rules = ["a\\tb"]\n')

        with pytest.raises(ConfigError, match="disabled_rules"):
            load_config(_root(tmp_path), environ={}, flags={})

    def test_empty_environment_entries_are_dropped(self, tmp_path: Path) -> None:
        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_DISABLED_RULES": "policy.rule-a,,  ,policy.rule-b"},
            flags={},
        )

        assert resolved.disabled_rule_ids() == frozenset(
            {"policy.rule-a", "policy.rule-b"}
        )


class TestCompletenessEnforcementKey:
    """`completeness_enforcement` resolves through the same four-tier
    mechanism `low_confidence_action` already established."""

    def test_default_is_warn(self, tmp_path: Path) -> None:
        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved.completeness_enforcement_value() == "warn"
        assert resolved["completeness_enforcement"].source is ConfigSource.DEFAULT

    @pytest.mark.parametrize("value", ["warn", "enforce"])
    def test_both_values_are_accepted(self, tmp_path: Path, value: str) -> None:
        (tmp_path / CONFIG_FILENAME).write_text(
            f'completeness_enforcement = "{value}"\n'
        )

        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved.completeness_enforcement_value() == value

    def test_environment_overrides_repository_file(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text(
            'completeness_enforcement = "enforce"\n'
        )

        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_COMPLETENESS_ENFORCEMENT": "warn"},
            flags={},
        )

        assert resolved.completeness_enforcement_value() == "warn"
        assert resolved["completeness_enforcement"].source is ConfigSource.ENVIRONMENT

    def test_unknown_value_raises_naming_key(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text(
            'completeness_enforcement = "sometimes"\n'
        )

        with pytest.raises(ConfigError, match="completeness_enforcement"):
            load_config(_root(tmp_path), environ={}, flags={})

    def test_malformed_value_error_never_echoes_planted_secret(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ConfigError) as excinfo:
            load_config(
                _root(tmp_path),
                environ={"CONTROLLOOP_COMPLETENESS_ENFORCEMENT": _SECRET_SHAPED_CANARY},
                flags={},
            )

        assert _SECRET_SHAPED_CANARY not in str(excinfo.value)
        assert excinfo.value.exit_code == 2


class TestDeterminism:
    def test_identical_inputs_produce_identical_resolved_config(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("max_file_count = 12\n")
        environ = {"CONTROLLOOP_MAX_DEPTH": "8"}
        flags = {"max_total_bytes": 999}

        first = load_config(_root(tmp_path), environ=environ, flags=flags)
        second = load_config(_root(tmp_path), environ=environ, flags=flags)

        assert first == second
        assert first.render_lines() == second.render_lines()


class TestRenderLines:
    def test_render_lines_are_sorted_and_show_value_and_source(
        self, tmp_path: Path
    ) -> None:
        resolved = load_config(_root(tmp_path), environ={}, flags={"max_depth": 5})

        lines = resolved.render_lines()

        # The policy keys (severity_threshold, low_confidence_action,
        # disabled_rules, completeness_enforcement) and the eight Team keys
        # resolve through the same four-tier mechanism as the original
        # integer keys. This test covers all sixteen registered keys, sorted
        # by key name.
        #
        # `team_enabled = false`, not `False`: the rendered line is meant
        # to be recognizable as the TOML a user would write, and
        # `team_enabled = False` is not valid TOML. Every Team key here
        # shows `(default)`, which is this assertion's other job -- it is
        # the line-by-line proof that a repository which has never
        # configured the paid tier resolves Team off.
        assert lines == (
            "completeness_enforcement = warn  (default)",
            "disabled_rules =   (default)",
            "low_confidence_action = block  (default)",
            "max_depth = 5  (flag)",
            "max_file_count = 50000  (default)",
            "max_file_size_bytes = 10000000  (default)",
            "max_total_bytes = 500000000  (default)",
            "severity_threshold = high  (default)",
            "team_branch =   (default)",
            "team_enabled = false  (default)",
            "team_endpoint =   (default)",
            "team_fail_mode = closed  (default)",
            "team_organization_id =   (default)",
            "team_policy_cache_seconds = 300  (default)",
            "team_project_id =   (default)",
            "team_pull_request =   (default)",
        )

    def test_no_registered_key_is_named_like_a_credential(self) -> None:
        """`render_lines` prints every registered key verbatim for
        `controlloop --show-config`, so the registry itself must never carry
        a credential. This is the structural guard on that decision --
        `controlloop.team.config` reads the project token straight from the
        environment and never registers it here, and a future key called
        `team_token` would fail this immediately rather than quietly making
        `--show-config` print a secret.
        """

        from controlloop.config import _KEYS

        forbidden = ("token", "secret", "password", "credential")
        offenders = [key for key in _KEYS for word in forbidden if word in key]
        assert offenders == []

    def test_render_lines_comma_joins_a_nonempty_rule_id_list(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / CONFIG_FILENAME).write_text(
            'disabled_rules = ["rule-a", "rule-b"]\n'
        )

        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert (
            "disabled_rules = rule-a,rule-b  (repository file)"
            in resolved.render_lines()
        )


class TestTeamKeys:
    """The eight Team keys resolve through the identical four-tier mechanism
    as every key before them, and a malformed value is exit-2 `ConfigError`
    naming the key rather than a stack trace.
    """

    def test_team_defaults_leave_the_paid_tier_off(self, tmp_path: Path) -> None:
        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved["team_enabled"].value is False
        assert resolved["team_enabled"].source is ConfigSource.DEFAULT
        assert resolved["team_fail_mode"].value == "closed"
        assert resolved["team_endpoint"].value == ""
        assert resolved["team_organization_id"].value == ""
        assert resolved["team_project_id"].value == ""
        assert resolved["team_branch"].value == ""
        assert resolved["team_pull_request"].value == ""
        assert resolved["team_policy_cache_seconds"].value == 300

    def test_repository_file_enables_team(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text(
            "team_enabled = true\nteam_fail_mode = 'open'\n"
        )

        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved["team_enabled"].value is True
        assert resolved["team_enabled"].source is ConfigSource.REPOSITORY_FILE
        assert resolved["team_fail_mode"].value == "open"

    def test_environment_overrides_the_repository_file(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("team_enabled = true\n")

        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_TEAM_ENABLED": "false"},
            flags={},
        )

        assert resolved["team_enabled"].value is False
        assert resolved["team_enabled"].source is ConfigSource.ENVIRONMENT

    @pytest.mark.parametrize("spelling", ["true", "TRUE", " True "])
    def test_environment_boolean_spellings(self, tmp_path: Path, spelling: str) -> None:
        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_TEAM_ENABLED": spelling},
            flags={},
        )

        assert resolved["team_enabled"].value is True

    def test_environment_boolean_is_never_a_truthiness_test(
        self, tmp_path: Path
    ) -> None:
        """The failure this rules out: `CONTROLLOOP_TEAM_ENABLED=false`
        being a non-empty string, and therefore truthy, and therefore
        silently enabling the paid tier a repository just tried to turn
        off."""

        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_TEAM_ENABLED": "false"},
            flags={},
        )

        assert resolved["team_enabled"].value is False

    def test_environment_boolean_rejects_anything_else(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError) as error:
            load_config(
                _root(tmp_path),
                environ={"CONTROLLOOP_TEAM_ENABLED": "yes"},
                flags={},
            )

        assert "CONTROLLOOP_TEAM_ENABLED" in str(error.value)
        assert "yes" not in str(error.value)

    def test_file_boolean_rejects_an_integer(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("team_enabled = 1\n")

        with pytest.raises(ConfigError) as error:
            load_config(_root(tmp_path), environ={}, flags={})

        assert "team_enabled" in str(error.value)
        assert "must be a boolean" in str(error.value)

    def test_fail_mode_rejects_an_unknown_member(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("team_fail_mode = 'sometimes'\n")

        with pytest.raises(ConfigError) as error:
            load_config(_root(tmp_path), environ={}, flags={})

        assert "team_fail_mode" in str(error.value)
        assert "sometimes" not in str(error.value)

    def test_string_key_rejects_a_control_character(self, tmp_path: Path) -> None:
        resolved_environ = {"CONTROLLOOP_TEAM_ENDPOINT": "https://example\x00.test"}

        with pytest.raises(ConfigError) as error:
            load_config(_root(tmp_path), environ=resolved_environ, flags={})

        assert "CONTROLLOOP_TEAM_ENDPOINT" in str(error.value)
        assert "example" not in str(error.value)

    def test_string_key_rejects_an_overlong_value(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError) as error:
            load_config(
                _root(tmp_path),
                environ={"CONTROLLOOP_TEAM_ENDPOINT": "h" * 513},
                flags={},
            )

        assert "CONTROLLOOP_TEAM_ENDPOINT" in str(error.value)
        assert "512" in str(error.value)

    def test_string_key_accepts_the_boundary_length(self, tmp_path: Path) -> None:
        resolved = load_config(
            _root(tmp_path),
            environ={"CONTROLLOOP_TEAM_ENDPOINT": "h" * 512},
            flags={},
        )

        assert resolved["team_endpoint"].value == "h" * 512

    def test_string_key_never_echoes_a_secret_shaped_value(
        self, tmp_path: Path
    ) -> None:
        """The privacy property that matters most for these keys: a
        misconfiguration that puts a token-shaped value in the wrong
        variable must not reproduce it in the error."""

        with pytest.raises(ConfigError) as error:
            load_config(
                _root(tmp_path),
                environ={
                    "CONTROLLOOP_TEAM_ENDPOINT": f"{_SECRET_SHAPED_CANARY}\x01",
                },
                flags={},
            )

        assert _SECRET_SHAPED_CANARY not in str(error.value)

    def test_cache_seconds_rejects_a_negative_value(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("team_policy_cache_seconds = -1\n")

        with pytest.raises(ConfigError) as error:
            load_config(_root(tmp_path), environ={}, flags={})

        assert "team_policy_cache_seconds" in str(error.value)
        assert "at least 0" in str(error.value)

    def test_cache_seconds_accepts_zero(self, tmp_path: Path) -> None:
        (tmp_path / CONFIG_FILENAME).write_text("team_policy_cache_seconds = 0\n")

        resolved = load_config(_root(tmp_path), environ={}, flags={})

        assert resolved["team_policy_cache_seconds"].value == 0

    def test_team_value_rejects_a_non_team_key(self, tmp_path: Path) -> None:
        resolved = load_config(_root(tmp_path), environ={}, flags={})

        with pytest.raises(KeyError):
            resolved.team_value("max_depth")
