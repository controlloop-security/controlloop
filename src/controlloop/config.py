"""Configuration loading and precedence.

Configuration resolves through exactly four ordered tiers, lowest to
highest precedence: built-in defaults, the repository configuration file
(``<repository_root>/controlloop.toml``), the process environment
(``CONTROLLOOP_<KEY>``), and explicit command-line flags.
``load_config`` merges all four and returns, for every key, both the
winning value and which tier supplied it, so a caller such as
``controlloop --show-config`` can report not just the effective
configuration but its provenance.

The key set was originally the four fields of
``controlloop.repository.TraversalBounds`` (``max_file_size_bytes``,
``max_total_bytes``, ``max_file_count``, ``max_depth``). Three policy
keys (``severity_threshold``, ``low_confidence_action``,
``disabled_rules``) extend it through the identical four-tier mechanism.
Because those three keys are not integers, ``ConfigValue.value`` widened
from ``int`` to ``int | str | tuple[str, ...]`` and coercion now
dispatches on a per-key ``ConfigValueKind`` (see ``_KEY_SPECS`` below);
the four original integer keys keep byte-identical coercion, error, and
`ConfigSource` behavior. A fourth policy key,
``completeness_enforcement`` (``"warn"`` default / ``"enforce"``
opt-in), extends the same registry once more -- an ordinary
`ConfigValueKind.STRING_ENUM` entry, identical in shape to
`low_confidence_action`, requiring no new `ConfigValueKind`.
`severity_threshold`'s, `low_confidence_action`'s, and
`completeness_enforcement`'s allowed-value sets are declared here as
local, literal frozensets rather than importing
`controlloop.findings.models.FindingSeverity` or
`controlloop.policy.thresholds.LowConfidenceAction`/
`CompletenessEnforcement` -- this module stays a dependency-light leaf
(it imports only `controlloop.exit_codes` and `controlloop.repository`);
`controlloop.policy.thresholds.resolve_policy_config` is the one place
that converts a validated raw string into the real enum.
`tests/policy/test_policy_thresholds.py`'s
`TestSeverityValuesMatchFindingSeverity` and
`TestCompletenessEnforcementValuesMatchConfig` guard these literal sets
against drift.

Eight Team keys extend the registry a third time and add two
`ConfigValueKind` members (`BOOLEAN` and `STRING`) to carry them. Every
Team key defaults to "Team is off," so a repository that never
configures the paid tier resolves byte-identically to the way it
resolved before those keys existed. Two properties of that extension are
load-bearing and deliberate:

- **The project token is not a key here.** `ResolvedConfig.render_lines`
  prints every registered key verbatim for `controlloop --show-config`,
  so a credential in this registry would be a credential printed on
  demand. `controlloop.team.config` reads `CONTROLLOOP_TEAM_TOKEN`
  straight from the injected environment mapping and never puts it on a
  rendered structure.
- **This module validates shape, never Team semantics.** A `STRING` key
  is checked for bounded length and the absence of control characters and
  nothing more. Whether `team_endpoint` is a well-formed `https` URL, and
  whether `team_organization_id` is a UUID, is decided by
  `controlloop.team.config`, where the resulting error can name the Team
  concept the user actually got wrong.

``load_config`` is deliberately pure: it takes the repository root, the
environment mapping, and the flag mapping as explicit parameters rather
than reading ``os.environ`` or the current working directory itself. Only
the CLI entry point (`controlloop.cli`) is allowed to supply the real
process environment; every other caller, including every test in this
module's own test suite, injects its own mapping. This mirrors this
repository's standing rule that deterministic core logic must not depend
on ambient process state.
The one filesystem effect this module performs -- reading
``controlloop.toml`` from a known, caller-supplied path -- is read-only,
bounded to a single file, and never touches the network (this module is
covered by the same offline test harness as the rest of `tests/`).

Every error this module raises is a `ConfigError`, carrying
``exit_code = ExitCode.INVALID_INPUT`` so a caller can translate it
directly into the documented exit-2 contract without inspecting the
message. No `ConfigError` message ever includes a raw value read from the
repository file or the environment -- only key names, source labels, and
(for a malformed file) `tomllib`'s own structural parse-location
string, which names a line and column but never quotes surrounding file
content. This matches the "never echo hostile values in errors" discipline
already established for canonical ACBOM validation and the
`controlloop.yaml` manifest parser (`controlloop.manifest.parser`).
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from controlloop.exit_codes import ExitCode
from controlloop.repository import RepositoryRoot, TraversalBounds

#: The repository configuration file's fixed name. Always resolved
#: relative to a `RepositoryRoot` (`controlloop.repository`), the same
#: root-resolution algorithm every other repository-relative concern in
#: this codebase already uses -- this module does not invent a second
#: one.
CONFIG_FILENAME = "controlloop.toml"

_ENV_PREFIX = "CONTROLLOOP_"

# The only default source of truth for these four keys: an ordinary
# `TraversalBounds` instance already carries the approved defaults.
# Reading them here rather than duplicating the literal numbers means
# this module cannot silently drift from `repository.py` if its defaults
# are ever revisited.
_BOUNDS_DEFAULTS = TraversalBounds()


#: A resolved value's shape. `_coerce_file_value`/`_coerce_env_value`
#: dispatch on a key's declared kind rather than assuming every key is an
#: integer, the way this module worked before the first non-integer keys
#: were added.
class ConfigValueKind(StrEnum):
    INTEGER = "integer"
    STRING_ENUM = "string_enum"
    RULE_ID_LIST = "rule_id_list"
    #: The Team kinds. `BOOLEAN` carries `team_enabled`, the one key
    #: whose natural TOML spelling is a real boolean rather than a
    #: two-member string enum; `STRING` carries the free-form Team
    #: identifiers (endpoint, organization, project, branch, pull
    #: request) whose valid values are not a closed set this module
    #: could enumerate. `STRING` validates shape only -- bounded length,
    #: no control characters -- and never semantics: whether an endpoint
    #: is a well-formed URL and whether an organization ID is a UUID is
    #: `controlloop.team.config`'s job, which is where the resulting
    #: error can name the Team concept rather than only the key.
    BOOLEAN = "boolean"
    STRING = "string"


#: `severity_threshold`'s allowed values. Deliberately a local literal
#: set, not an import of `controlloop.findings.models.FindingSeverity`
#: -- see the module docstring. Guarded against drift by
#: `tests/policy/test_policy_thresholds.py`'s
#: `TestSeverityValuesMatchFindingSeverity`.
_SEVERITY_THRESHOLD_VALUES: frozenset[str] = frozenset(
    {"info", "low", "medium", "high", "critical"}
)

#: `low_confidence_action`'s allowed values. Deliberately a local
#: literal set, not an import of
#: `controlloop.policy.thresholds.LowConfidenceAction` -- see the module
#: docstring.
_LOW_CONFIDENCE_ACTION_VALUES: frozenset[str] = frozenset({"block", "warn"})

#: `completeness_enforcement`'s allowed values. Deliberately a local
#: literal set, not an import of
#: `controlloop.policy.thresholds.CompletenessEnforcement` -- see the
#: module docstring. Guarded against drift by
#: `tests/policy/test_policy_thresholds.py`'s
#: `TestCompletenessEnforcementValuesMatchConfig`.
_COMPLETENESS_ENFORCEMENT_VALUES: frozenset[str] = frozenset({"warn", "enforce"})

#: A rule ID's accepted shape for the `disabled_rules` key: non-empty,
#: no control characters, bounded length. Deliberately a local regex,
#: not an import of `controlloop.acbom.models.SafeIdentifier` -- see the
#: module docstring.
_RULE_ID_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")

#: A `ConfigValueKind.STRING` value's accepted shape: no control
#: characters and bounded length, the identical discipline
#: `_RULE_ID_PATTERN` already applies to rule IDs. The bound is 512
#: rather than 256 because a real endpoint URL with a path prefix can
#: exceed a rule ID's length; it is still a bound, not an absence of
#: one. An empty string is permitted here and means "not set" --
#: `controlloop.team.config` is what decides whether a given key being
#: unset is an error, and it can only decide that once it knows Team is
#: enabled.
_STRING_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{0,512}$")

#: `team_fail_mode`'s allowed values. Deliberately a local literal set,
#: not an import of `controlloop.team.config.TeamFailMode` -- this
#: module stays a dependency-light leaf, the identical reasoning
#: `_SEVERITY_THRESHOLD_VALUES` and `_LOW_CONFIDENCE_ACTION_VALUES`
#: already document. Guarded against drift by
#: `tests/team/test_team_config.py`'s `TestFailModeValuesMatchConfig`.
_TEAM_FAIL_MODE_VALUES: frozenset[str] = frozenset({"closed", "open"})

ConfigScalar = int | str | bool | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _KeySpec:
    """One configuration key's declared shape and default."""

    kind: ConfigValueKind
    default: ConfigScalar
    allowed_values: frozenset[str] | None = None  # STRING_ENUM only
    #: Inclusive lower bound for an `INTEGER` key. The four original
    #: `TraversalBounds` keys leave this `None` because
    #: `TraversalBounds.__post_init__` already enforces their `>= 1`
    #: rule at load time; `team_policy_cache_seconds` has no such
    #: downstream validator, so it declares its bound here rather than
    #: deferring an obviously invalid value to whatever later code reads
    #: it.
    minimum: int | None = None


#: The closed, ordered registry of configuration keys this module
#: understands (anything outside this set found in the repository
#: file is an unknown key, not a silently ignored one). Order here is also
#: the order `ResolvedConfig.render_lines` falls back to when two keys tie
#: alphabetically -- which they cannot, since key names are unique, but
#: iterating this mapping rather than a plain dict keeps output order tied
#: to a single explicit declaration site rather than insertion order.
#: The first four entries are the original `TraversalBounds` keys,
#: unchanged; the rest are the policy keys and the Team keys.
_KEY_SPECS: Mapping[str, _KeySpec] = {
    "max_file_size_bytes": _KeySpec(
        ConfigValueKind.INTEGER, default=_BOUNDS_DEFAULTS.max_file_size_bytes
    ),
    "max_total_bytes": _KeySpec(
        ConfigValueKind.INTEGER, default=_BOUNDS_DEFAULTS.max_total_bytes
    ),
    "max_file_count": _KeySpec(
        ConfigValueKind.INTEGER, default=_BOUNDS_DEFAULTS.max_file_count
    ),
    "max_depth": _KeySpec(ConfigValueKind.INTEGER, default=_BOUNDS_DEFAULTS.max_depth),
    # Disclosed, overridable engineering defaults -- not an approved
    # business SLA or pricing threshold. `EvaluationBounds` already
    # established this exact "generous, disclosed starting point"
    # precedent for this codebase.
    "severity_threshold": _KeySpec(
        ConfigValueKind.STRING_ENUM,
        default="high",
        allowed_values=_SEVERITY_THRESHOLD_VALUES,
    ),
    "low_confidence_action": _KeySpec(
        ConfigValueKind.STRING_ENUM,
        default="block",
        allowed_values=_LOW_CONFIDENCE_ACTION_VALUES,
    ),
    "disabled_rules": _KeySpec(ConfigValueKind.RULE_ID_LIST, default=()),
    # Honest unknowns warn by default and block only when a repository
    # opts in. "warn" is the default for the identical reason
    # `severity_threshold`/`low_confidence_action` start
    # conservative-but-non-blocking -- a first run must not be a wall.
    "completeness_enforcement": _KeySpec(
        ConfigValueKind.STRING_ENUM,
        default="warn",
        allowed_values=_COMPLETENESS_ENFORCEMENT_VALUES,
    ),
    # The Team keys. Every one of them defaults to "Team is off", so a
    # repository that has never heard of the paid tier resolves exactly
    # the configuration it resolved before these keys existed -- see
    # `controlloop.team.config` for the enablement rule and
    # `docs/reference/configuration.md` for the user documentation.
    #
    # The project token is deliberately absent from this registry. Every
    # key here is rendered verbatim by `controlloop --show-config`
    # (`ResolvedConfig.render_lines`), so putting a credential in it would
    # print that credential on demand. `controlloop.team.config` reads the
    # token straight from the injected environment mapping instead and
    # never stores it on a rendered structure.
    "team_enabled": _KeySpec(ConfigValueKind.BOOLEAN, default=False),
    "team_fail_mode": _KeySpec(
        ConfigValueKind.STRING_ENUM,
        default="closed",
        allowed_values=_TEAM_FAIL_MODE_VALUES,
    ),
    # No default endpoint. The CLI does not choose a domain, so an
    # enabled Team configuration must state its own endpoint rather than
    # inherit an invented one.
    "team_endpoint": _KeySpec(ConfigValueKind.STRING, default=""),
    "team_organization_id": _KeySpec(ConfigValueKind.STRING, default=""),
    "team_project_id": _KeySpec(ConfigValueKind.STRING, default=""),
    "team_branch": _KeySpec(ConfigValueKind.STRING, default=""),
    "team_pull_request": _KeySpec(ConfigValueKind.STRING, default=""),
    "team_policy_cache_seconds": _KeySpec(
        ConfigValueKind.INTEGER, default=300, minimum=0
    ),
}

_KEYS: tuple[str, ...] = tuple(_KEY_SPECS)


class ConfigSource(StrEnum):
    """Which of the four precedence tiers supplied a resolved value."""

    DEFAULT = "default"
    REPOSITORY_FILE = "repository file"
    ENVIRONMENT = "environment"
    FLAG = "flag"


class ConfigError(ValueError):
    """Configuration could not be resolved.

    Carries `exit_code = ExitCode.INVALID_INPUT`, mirroring
    `controlloop.manifest.parser.ManifestValidationError`'s existing
    shape. The message never contains a raw value read from the
    repository file or the environment -- see the module docstring.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INVALID_INPUT


@dataclass(frozen=True, slots=True)
class ConfigValue:
    """One resolved key's winning value and the tier that supplied it.

    `value`'s type widened from `int` to `ConfigScalar` to carry the
    three new non-integer policy keys; the four original integer keys
    are unaffected.
    """

    value: ConfigScalar
    source: ConfigSource


@dataclass(frozen=True, slots=True)
class ResolvedConfig:
    """The complete resolved configuration: every key's `ConfigValue`."""

    values: Mapping[str, ConfigValue]

    def __getitem__(self, key: str) -> ConfigValue:
        return self.values[key]

    def traversal_bounds(self) -> TraversalBounds:
        """Return the resolved values as a `TraversalBounds`.

        Construction itself re-validates every value (`>= 1`) through
        `TraversalBounds.__post_init__`; `load_config` already calls
        this once during resolution so an invalid merged value is
        reported at load time (as input validation), not deferred to
        whatever later code happens to call this accessor.
        """

        max_file_size_bytes = self.values["max_file_size_bytes"].value
        max_total_bytes = self.values["max_total_bytes"].value
        max_file_count = self.values["max_file_count"].value
        max_depth = self.values["max_depth"].value
        assert isinstance(max_file_size_bytes, int)
        assert isinstance(max_total_bytes, int)
        assert isinstance(max_file_count, int)
        assert isinstance(max_depth, int)
        return TraversalBounds(
            max_file_size_bytes=max_file_size_bytes,
            max_total_bytes=max_total_bytes,
            max_file_count=max_file_count,
            max_depth=max_depth,
        )

    def severity_threshold_value(self) -> str:
        """Return the resolved `severity_threshold` key's raw, already
        shape-and-membership-validated string. Kept as a plain string
        here, not `FindingSeverity`, so this dependency-light module
        never imports `controlloop.findings`; see the module docstring.
        `controlloop.policy.thresholds.resolve_policy_config` is the one
        place that converts it to the real enum."""

        value = self.values["severity_threshold"].value
        assert isinstance(value, str)
        return value

    def low_confidence_action_value(self) -> str:
        """Return the resolved `low_confidence_action` key's raw,
        already shape-and-membership-validated string. See
        `severity_threshold_value`'s docstring for why this stays a
        plain string rather than `LowConfidenceAction` here."""

        value = self.values["low_confidence_action"].value
        assert isinstance(value, str)
        return value

    def completeness_enforcement_value(self) -> str:
        """Return the resolved `completeness_enforcement` key's raw,
        already shape-and-membership-validated string. Kept as a plain
        string here, not `CompletenessEnforcement`, for the identical
        reason `severity_threshold_value`/`low_confidence_action_value`
        are -- see the module docstring.
        `controlloop.policy.thresholds.resolve_policy_config` is the one
        place that converts it to the real enum."""

        value = self.values["completeness_enforcement"].value
        assert isinstance(value, str)
        return value

    def disabled_rule_ids(self) -> frozenset[str]:
        """Return the resolved `disabled_rules` key as a `frozenset`.
        Order is not semantically meaningful for a set of disabled rule
        IDs, so the ordered `tuple[str, ...]` stored internally (needed
        to give TOML-array/environment/flag values one common
        ``ConfigScalar`` shape) is converted here."""

        value = self.values["disabled_rules"].value
        assert isinstance(value, tuple)
        return frozenset(value)

    def render_lines(self) -> tuple[str, ...]:
        """Return one deterministic, key-sorted line per resolved key.

        Used verbatim by `controlloop --show-config`: each line is
        ``"<key> = <value>  (<source>)"``. Sorted by key name so output
        order never depends on dict iteration order or on the order keys
        happened to be declared. A `tuple[str, ...]` value (the
        `disabled_rules` key) renders as a comma-joined list; an empty
        tuple renders as an empty string, still followed by its source,
        e.g. ``"disabled_rules =   (default)"``.
        """

        lines = []
        for key in sorted(self.values):
            resolved = self.values[key]
            lines.append(
                f"{key} = {_render_value(resolved.value)}  ({resolved.source.value})"
            )
        return tuple(lines)

    def team_value(self, key: str) -> ConfigScalar:
        """Return one already-shape-validated Team key's resolved value.

        Kept as a raw `ConfigScalar` here, not a `TeamConfig` field, for
        the identical reason `severity_threshold_value` stays a plain
        string: this module is a dependency-light leaf that never imports
        `controlloop.team`. `controlloop.team.config.resolve_team_config`
        is the one place that turns these values into a real, semantically
        validated `TeamConfig`.
        """

        if not key.startswith("team_"):
            raise KeyError(f"{key!r} is not a Team configuration key")
        return self.values[key].value


def _render_value(value: ConfigScalar) -> str:
    """Render one resolved value for `--show-config`.

    A boolean renders as TOML spells it, `true`/`false`, not as Python
    spells it, `True`/`False`: the rendered line is meant to be
    recognizable as the configuration a user would write, and
    `team_enabled = True` is not valid TOML.
    """

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, tuple):
        return ",".join(value)
    return str(value)


def _read_repository_file(path: Path) -> dict[str, object]:
    """Return the parsed repository file's top-level table, or ``{}`` if
    it does not exist (an absent file is never an error).

    Raises `ConfigError` for anything that exists but cannot be read as
    a UTF-8 TOML document -- the message is the file path plus
    `tomllib`'s own structural parse-location string (for example
    ``"Unclosed array (at line 2, column 1)"``), which describes *where*
    parsing failed without quoting *what* was there.
    """

    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise ConfigError(f"{path} could not be read: {error.strerror}") from None

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(f"{path} could not be decoded as UTF-8") from None

    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"{path}: {error}") from None

    return payload


def _reject_unknown_keys(payload: Mapping[str, object], path: Path) -> None:
    """An unknown key in the repository file is a hard error naming the
    key and the file, never silently ignored."""

    for key in payload:
        if key not in _KEYS:
            raise ConfigError(f"unknown configuration key '{key}' in {path}")


def _validate_rule_id_shape(rule_id: str, *, where: str) -> None:
    if _RULE_ID_PATTERN.fullmatch(rule_id) is None:
        raise ConfigError(f"{where} contains an invalid rule ID shape")


def _validate_string_shape(value: str, *, where: str) -> None:
    """A `ConfigValueKind.STRING` value's shape check.

    Names the key and the rejected property, never the value -- the same
    "never echo a hostile value in an error" discipline
    `_validate_rule_id_shape` already follows.
    """

    if _STRING_PATTERN.fullmatch(value) is None:
        raise ConfigError(
            f"{where} must be at most 512 characters and contain no control characters"
        )


def _validate_integer_minimum(key: str, value: int, *, where: str) -> int:
    """Enforce an `INTEGER` key's declared inclusive lower bound. Keys
    that declare no `minimum` are unaffected."""

    minimum = _KEY_SPECS[key].minimum
    if minimum is not None and value < minimum:
        raise ConfigError(f"{where} must be at least {minimum}")
    return value


def _coerce_file_value(key: str, raw: object, path: Path) -> ConfigScalar:
    spec = _KEY_SPECS[key]

    if spec.kind is ConfigValueKind.INTEGER:
        # `bool` is a subclass of `int` in Python; TOML booleans must not
        # silently pass as integers for these numeric-only keys.
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ConfigError(
                f"configuration key '{key}' in {path} must be an integer, "
                f"got {type(raw).__name__}"
            )
        return _validate_integer_minimum(
            key, raw, where=f"configuration key '{key}' in {path}"
        )

    if spec.kind is ConfigValueKind.BOOLEAN:
        # The mirror image of the integer check above: an integer must not
        # silently pass as a boolean either, so `team_enabled = 1` is an
        # error naming the key rather than a repository quietly opting
        # into the paid tier.
        if not isinstance(raw, bool):
            raise ConfigError(
                f"configuration key '{key}' in {path} must be a boolean, "
                f"got {type(raw).__name__}"
            )
        return raw

    if spec.kind is ConfigValueKind.STRING:
        if not isinstance(raw, str):
            raise ConfigError(
                f"configuration key '{key}' in {path} must be a string, "
                f"got {type(raw).__name__}"
            )
        _validate_string_shape(raw, where=f"configuration key '{key}' in {path}")
        return raw

    if spec.kind is ConfigValueKind.STRING_ENUM:
        assert spec.allowed_values is not None
        if not isinstance(raw, str):
            raise ConfigError(
                f"configuration key '{key}' in {path} must be a string, "
                f"got {type(raw).__name__}"
            )
        if raw not in spec.allowed_values:
            raise ConfigError(
                f"configuration key '{key}' in {path} must be one of "
                f"{sorted(spec.allowed_values)}"
            )
        return raw

    if spec.kind is ConfigValueKind.RULE_ID_LIST:
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise ConfigError(
                f"configuration key '{key}' in {path} must be an array of strings"
            )
        for item in raw:
            _validate_rule_id_shape(item, where=f"configuration key '{key}' in {path}")
        return tuple(raw)

    raise AssertionError(
        f"unhandled ConfigValueKind: {spec.kind!r}"
    )  # pragma: no cover


def _coerce_env_value(key: str, raw: str, env_name: str) -> ConfigScalar:
    spec = _KEY_SPECS[key]

    if spec.kind is ConfigValueKind.INTEGER:
        try:
            parsed = int(raw.strip())
        except ValueError:
            raise ConfigError(
                f"environment variable {env_name} must be an integer"
            ) from None
        return _validate_integer_minimum(
            key, parsed, where=f"environment variable {env_name}"
        )

    if spec.kind is ConfigValueKind.BOOLEAN:
        # An environment variable is always a string, so a boolean key
        # accepts exactly the two spellings TOML itself uses, matched
        # case-insensitively after stripping. Anything else is an error
        # naming the variable -- never a truthiness test, which would
        # make `CONTROLLOOP_TEAM_ENABLED=false` mean enabled.
        value = raw.strip().lower()
        if value not in {"true", "false"}:
            raise ConfigError(
                f"environment variable {env_name} must be 'true' or 'false'"
            )
        return value == "true"

    if spec.kind is ConfigValueKind.STRING:
        # Deliberately not stripped: an endpoint or identifier with
        # surrounding whitespace is a misconfiguration worth surfacing at
        # its point of use rather than silently repairing here.
        _validate_string_shape(raw, where=f"environment variable {env_name}")
        return raw

    if spec.kind is ConfigValueKind.STRING_ENUM:
        assert spec.allowed_values is not None
        value = raw.strip()
        if value not in spec.allowed_values:
            raise ConfigError(
                f"environment variable {env_name} must be one of "
                f"{sorted(spec.allowed_values)}"
            )
        return value

    if spec.kind is ConfigValueKind.RULE_ID_LIST:
        items = tuple(item.strip() for item in raw.split(",") if item.strip())
        for item in items:
            _validate_rule_id_shape(item, where=f"environment variable {env_name}")
        return items

    raise AssertionError(
        f"unhandled ConfigValueKind: {spec.kind!r}"
    )  # pragma: no cover


def load_config(
    repository_root: RepositoryRoot,
    *,
    environ: Mapping[str, str],
    flags: Mapping[str, ConfigScalar | None],
) -> ResolvedConfig:
    """Resolve every registered key (the four `TraversalBounds` keys,
    the policy keys, and the Team keys) through defaults < repository
    file < environment < flags.

    ``environ`` and ``flags`` are supplied by the caller rather than
    read from process state here -- see the module docstring. ``flags``
    may contain any subset of `_KEYS`; a key mapped to ``None`` or
    absent entirely means "no flag was supplied," not "the flag tier
    supplied `None`," so it never wins over a lower tier. ``flags``'
    type widened to `ConfigScalar | None` from `int | None`; a caller
    passing only integer flags (every command today) is unaffected.

    Raises `ConfigError` for an unknown repository-file key, a malformed
    or undecodable repository file, a value of the wrong shape (not an
    integer / not one of a string-enum key's allowed values / not a
    well-shaped rule ID list) from the file or the environment, or a
    merged value that fails `TraversalBounds`' own validation (for
    example a bound below 1).
    """

    config_path = repository_root.path / CONFIG_FILENAME
    file_payload = _read_repository_file(config_path)
    _reject_unknown_keys(file_payload, config_path)

    resolved: dict[str, ConfigValue] = {}
    for key in _KEYS:
        value: ConfigScalar = _KEY_SPECS[key].default
        source = ConfigSource.DEFAULT

        if key in file_payload:
            value = _coerce_file_value(key, file_payload[key], config_path)
            source = ConfigSource.REPOSITORY_FILE

        env_name = _ENV_PREFIX + key.upper()
        if env_name in environ:
            value = _coerce_env_value(key, environ[env_name], env_name)
            source = ConfigSource.ENVIRONMENT

        flag_value = flags.get(key)
        if flag_value is not None:
            value = flag_value
            source = ConfigSource.FLAG

        resolved[key] = ConfigValue(value=value, source=source)

    result = ResolvedConfig(values=resolved)
    try:
        result.traversal_bounds()
    except ValueError as error:
        raise ConfigError(f"resolved configuration is invalid: {error}") from None
    return result
