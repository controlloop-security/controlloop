"""Concrete deterministic policy rules, built on the rule engine
(`controlloop.policy.engine`) and the finding model
(`controlloop.findings`).

`controlloop.policy.engine`/`controlloop.policy.models` ship with **zero
concrete rules** by design (see `docs/reference/rule-engine.md`). This
package is where the rules live, one module per rule. Among them:

- `undeclared_tools`.
- `destructive_or_financial_action`.
- `sensitive_write_without_approval`.
- `broad_permission`.
- `missing_action_logging`.
- `unauthorized_delegation`.
- `unresolved_dynamic_registration`.
- `capability_ceiling`.
- `exfiltration_triangle`, following the same `evaluate()`/`findings()`
  pattern; see that module's own docstring for its disclosed design
  decisions.
- `hardcoded_secrets`. It needed two things the other rules did not: the
  `Finding` model originally required exactly one `affected_agent` and a
  real `capability_path` per finding, with no natural single-agent
  attribution for generic repository-content secret scanning; and the
  rule engine's own filesystem restriction leaves nowhere for a `Rule`
  itself to read raw file content. Both are resolved --
  `Finding.affected_agent`/`capability_path` are optional
  (repository-scoped findings, `controlloop.findings.models`), and
  `controlloop.secret_scan` is a directly-invoked discovery pass (not a
  `DiscoveryAdapter`; see that module's own docstring for why) feeding
  `Diagnostic` evidence this rule only reads.

Expiring repo-local suppressions are not a detection rule at all and are
not included here; see `controlloop.policy.suppressions`.

## One consistent, disclosed pattern

`Rule.evaluate`'s signature is fixed by the engine contract
(`Callable[[RuleContext], tuple[RuleObservation, ...]]`) and cannot itself
carry severity, confidence, the affected agent, a capability path, change
state, remediation, or a documentation URL -- none of which
`RuleObservation` holds. Every rule module in this package therefore
follows the same shape:

- a private per-rule detection helper (a `_Detection` dataclass, or
  equivalent) holding the complete picture for one finding candidate;
- a private detection function containing the actual rule logic;
- a public `evaluate(context: RuleContext) -> tuple[RuleObservation, ...]`,
  the engine-compatible function `Rule.evaluate` is set to;
- a public `findings(context: RuleContext, ...) -> tuple[Finding, ...]`,
  mapping the same detection output through
  `controlloop.findings.finding_from_observation` with the extra fields
  a `Finding` needs -- so `evaluate()` and `findings()` can never drift
  apart, since both are pure views over one shared computation;
- a module-level `RULE: Rule` pairing the rule's stable `id` with
  `evaluate`, ready to register.

`findings()` exists so each rule's "produces a finding" behavior is
proven against a real `Finding`, not only a `RuleObservation`.

## The combined registry

**`ALL_RULES`** is the one canonical name for the combined registry (an
earlier `RULES` name was unified into it; nothing outside this package's
own `__init__.py` referenced `RULES`, since tests import the specific rule
submodule directly, for example `from controlloop.policy.rules import
unauthorized_delegation`). Every rule's `RULE_ID` and `findings` are
re-exported here.

`ALL_RULES` is not itself the versioned rule pack -- it carries no
version, no enable/disable state, and is not what `controlloop --version`
reports (`controlloop.policy.rulepack.CURRENT_RULE_PACK` is). It is only a
convenient, explicit list a caller (a `scan`/`gate` command, or this
package's own tests) can pass to `controlloop.policy.engine.evaluate`
without importing every rule module by hand.

`controlloop.policy.rulepack.CURRENT_RULE_PACK` carries the rules of
`ALL_RULES`, each paired with a decided `RuleMetadata.mandatory`
governance flag and a pinned fingerprint. The capability-ceiling rule is
`mandatory=True`, so a ceiling breach cannot be silenced by disabling
pattern rules.
"""

from __future__ import annotations

from controlloop.policy.models import Rule
from controlloop.policy.rules.agent_hook_command_change import (
    RULE as AGENT_HOOK_COMMAND_CHANGE_RULE,
)
from controlloop.policy.rules.agent_hook_command_change import (
    RULE_ID as AGENT_HOOK_COMMAND_CHANGE_RULE_ID,
)
from controlloop.policy.rules.agent_hook_command_change import (
    findings as agent_hook_command_change_findings,
)

#: Every rule this package currently defines, in a fixed, explicit order
#: (not import order, which is not itself guaranteed meaningful) -- see
#: this module's own docstring for what this registry is, and is not, and
#: for why it is named `ALL_RULES` rather than the original `RULES`.
from controlloop.policy.rules.agent_sandbox_weakened import (
    RULE as AGENT_SANDBOX_WEAKENED_RULE,
)
from controlloop.policy.rules.agent_sandbox_weakened import (
    RULE_ID as AGENT_SANDBOX_WEAKENED_RULE_ID,
)
from controlloop.policy.rules.agent_sandbox_weakened import (
    findings as agent_sandbox_weakened_findings,
)
from controlloop.policy.rules.broad_permission import RULE as BROAD_PERMISSION_RULE
from controlloop.policy.rules.broad_permission import (
    RULE_ID as BROAD_PERMISSION_RULE_ID,
)
from controlloop.policy.rules.broad_permission import (
    findings as broad_permission_findings,
)
from controlloop.policy.rules.capability_ceiling import (
    RULE as CAPABILITY_CEILING_RULE,
)
from controlloop.policy.rules.capability_ceiling import (
    RULE_ID as CAPABILITY_CEILING_RULE_ID,
)
from controlloop.policy.rules.capability_ceiling import (
    findings as capability_ceiling_findings,
)
from controlloop.policy.rules.component_self_grant import (
    RULE as COMPONENT_SELF_GRANT_RULE,
)
from controlloop.policy.rules.component_self_grant import (
    RULE_ID as COMPONENT_SELF_GRANT_RULE_ID,
)
from controlloop.policy.rules.component_self_grant import (
    findings as component_self_grant_findings,
)
from controlloop.policy.rules.component_shell_execution import (
    RULE as COMPONENT_SHELL_EXECUTION_RULE,
)
from controlloop.policy.rules.component_shell_execution import (
    RULE_ID as COMPONENT_SHELL_EXECUTION_RULE_ID,
)
from controlloop.policy.rules.component_shell_execution import (
    findings as component_shell_execution_findings,
)
from controlloop.policy.rules.credentialed_remote_mcp_server import (
    RULE as CREDENTIALED_REMOTE_MCP_SERVER_RULE,
)
from controlloop.policy.rules.credentialed_remote_mcp_server import (
    RULE_ID as CREDENTIALED_REMOTE_MCP_SERVER_RULE_ID,
)
from controlloop.policy.rules.credentialed_remote_mcp_server import (
    findings as credentialed_remote_mcp_server_findings,
)
from controlloop.policy.rules.destructive_or_financial_action import (
    RULE as DESTRUCTIVE_OR_FINANCIAL_ACTION_RULE,
)
from controlloop.policy.rules.destructive_or_financial_action import (
    RULE_ID as DESTRUCTIVE_OR_FINANCIAL_ACTION_RULE_ID,
)
from controlloop.policy.rules.destructive_or_financial_action import (
    findings as destructive_or_financial_action_findings,
)
from controlloop.policy.rules.exfiltration_triangle import (
    RULE as EXFILTRATION_TRIANGLE_RULE,
)
from controlloop.policy.rules.exfiltration_triangle import (
    RULE_ID as EXFILTRATION_TRIANGLE_RULE_ID,
)
from controlloop.policy.rules.exfiltration_triangle import (
    findings as exfiltration_triangle_findings,
)
from controlloop.policy.rules.hardcoded_secrets import RULE as HARDCODED_SECRETS_RULE
from controlloop.policy.rules.hardcoded_secrets import (
    RULE_ID as HARDCODED_SECRETS_RULE_ID,
)
from controlloop.policy.rules.hardcoded_secrets import (
    findings as hardcoded_secrets_findings,
)
from controlloop.policy.rules.mcp_server_identity_change import (
    RULE as MCP_SERVER_IDENTITY_CHANGE_RULE,
)
from controlloop.policy.rules.mcp_server_identity_change import (
    RULE_ID as MCP_SERVER_IDENTITY_CHANGE_RULE_ID,
)
from controlloop.policy.rules.mcp_server_identity_change import (
    findings as mcp_server_identity_change_findings,
)
from controlloop.policy.rules.missing_action_logging import (
    RULE as MISSING_ACTION_LOGGING_RULE,
)
from controlloop.policy.rules.missing_action_logging import (
    RULE_ID as MISSING_ACTION_LOGGING_RULE_ID,
)
from controlloop.policy.rules.missing_action_logging import (
    findings as missing_action_logging_findings,
)
from controlloop.policy.rules.overprivileged_agent_workflow import (
    RULE as OVERPRIVILEGED_AGENT_WORKFLOW_RULE,
)
from controlloop.policy.rules.overprivileged_agent_workflow import (
    RULE_ID as OVERPRIVILEGED_AGENT_WORKFLOW_RULE_ID,
)
from controlloop.policy.rules.overprivileged_agent_workflow import (
    findings as overprivileged_agent_workflow_findings,
)
from controlloop.policy.rules.permission_bypass_from_project import (
    RULE as PERMISSION_BYPASS_FROM_PROJECT_RULE,
)
from controlloop.policy.rules.permission_bypass_from_project import (
    RULE_ID as PERMISSION_BYPASS_FROM_PROJECT_RULE_ID,
)
from controlloop.policy.rules.permission_bypass_from_project import (
    findings as permission_bypass_from_project_findings,
)
from controlloop.policy.rules.secret_exposed_to_untrusted_agent_run import (
    RULE as SECRET_EXPOSED_TO_UNTRUSTED_AGENT_RUN_RULE,
)
from controlloop.policy.rules.secret_exposed_to_untrusted_agent_run import (
    RULE_ID as SECRET_EXPOSED_TO_UNTRUSTED_AGENT_RUN_RULE_ID,
)
from controlloop.policy.rules.secret_exposed_to_untrusted_agent_run import (
    findings as secret_exposed_to_untrusted_agent_run_findings,
)
from controlloop.policy.rules.sensitive_write_without_approval import (
    RULE as SENSITIVE_WRITE_WITHOUT_APPROVAL_RULE,
)
from controlloop.policy.rules.sensitive_write_without_approval import (
    RULE_ID as SENSITIVE_WRITE_WITHOUT_APPROVAL_RULE_ID,
)
from controlloop.policy.rules.sensitive_write_without_approval import (
    findings as sensitive_write_without_approval_findings,
)
from controlloop.policy.rules.unauthorized_delegation import (
    RULE as UNAUTHORIZED_DELEGATION_RULE,
)
from controlloop.policy.rules.unauthorized_delegation import (
    RULE_ID as UNAUTHORIZED_DELEGATION_RULE_ID,
)
from controlloop.policy.rules.unauthorized_delegation import (
    findings as unauthorized_delegation_findings,
)
from controlloop.policy.rules.undeclared_tools import RULE as UNDECLARED_TOOLS_RULE
from controlloop.policy.rules.undeclared_tools import (
    RULE_ID as UNDECLARED_TOOLS_RULE_ID,
)
from controlloop.policy.rules.undeclared_tools import (
    findings as undeclared_tools_findings,
)
from controlloop.policy.rules.unpinned_agent_component import (
    RULE as UNPINNED_AGENT_COMPONENT_RULE,
)
from controlloop.policy.rules.unpinned_agent_component import (
    RULE_ID as UNPINNED_AGENT_COMPONENT_RULE_ID,
)
from controlloop.policy.rules.unpinned_agent_component import (
    findings as unpinned_agent_component_findings,
)
from controlloop.policy.rules.unresolved_dynamic_registration import (
    RULE as UNRESOLVED_DYNAMIC_REGISTRATION_RULE,
)
from controlloop.policy.rules.unresolved_dynamic_registration import (
    RULE_ID as UNRESOLVED_DYNAMIC_REGISTRATION_RULE_ID,
)
from controlloop.policy.rules.unresolved_dynamic_registration import (
    findings as unresolved_dynamic_registration_findings,
)
from controlloop.policy.rules.unsanctioned_agent_component import (
    RULE as UNSANCTIONED_AGENT_COMPONENT_RULE,
)
from controlloop.policy.rules.unsanctioned_agent_component import (
    RULE_ID as UNSANCTIONED_AGENT_COMPONENT_RULE_ID,
)
from controlloop.policy.rules.unsanctioned_agent_component import (
    findings as unsanctioned_agent_component_findings,
)
from controlloop.policy.rules.widened_permission_rule import (
    RULE as WIDENED_PERMISSION_RULE_RULE,
)
from controlloop.policy.rules.widened_permission_rule import (
    RULE_ID as WIDENED_PERMISSION_RULE_RULE_ID,
)
from controlloop.policy.rules.widened_permission_rule import (
    findings as widened_permission_rule_findings,
)
from controlloop.policy.rules.workspace_scope_expansion import (
    RULE as WORKSPACE_SCOPE_EXPANSION_RULE,
)
from controlloop.policy.rules.workspace_scope_expansion import (
    RULE_ID as WORKSPACE_SCOPE_EXPANSION_RULE_ID,
)
from controlloop.policy.rules.workspace_scope_expansion import (
    findings as workspace_scope_expansion_findings,
)

ALL_RULES: tuple[Rule, ...] = (
    UNDECLARED_TOOLS_RULE,
    DESTRUCTIVE_OR_FINANCIAL_ACTION_RULE,
    BROAD_PERMISSION_RULE,
    SENSITIVE_WRITE_WITHOUT_APPROVAL_RULE,
    MISSING_ACTION_LOGGING_RULE,
    UNAUTHORIZED_DELEGATION_RULE,
    UNRESOLVED_DYNAMIC_REGISTRATION_RULE,
    CAPABILITY_CEILING_RULE,
    EXFILTRATION_TRIANGLE_RULE,
    HARDCODED_SECRETS_RULE,
    UNPINNED_AGENT_COMPONENT_RULE,
    MCP_SERVER_IDENTITY_CHANGE_RULE,
    OVERPRIVILEGED_AGENT_WORKFLOW_RULE,
    COMPONENT_SELF_GRANT_RULE,
    AGENT_HOOK_COMMAND_CHANGE_RULE,
    WIDENED_PERMISSION_RULE_RULE,
    PERMISSION_BYPASS_FROM_PROJECT_RULE,
    UNSANCTIONED_AGENT_COMPONENT_RULE,
    AGENT_SANDBOX_WEAKENED_RULE,
    SECRET_EXPOSED_TO_UNTRUSTED_AGENT_RUN_RULE,
    CREDENTIALED_REMOTE_MCP_SERVER_RULE,
    WORKSPACE_SCOPE_EXPANSION_RULE,
    COMPONENT_SHELL_EXECUTION_RULE,
)

__all__ = [
    "AGENT_HOOK_COMMAND_CHANGE_RULE",
    "AGENT_HOOK_COMMAND_CHANGE_RULE_ID",
    "AGENT_SANDBOX_WEAKENED_RULE",
    "AGENT_SANDBOX_WEAKENED_RULE_ID",
    "ALL_RULES",
    "BROAD_PERMISSION_RULE",
    "BROAD_PERMISSION_RULE_ID",
    "CAPABILITY_CEILING_RULE",
    "CAPABILITY_CEILING_RULE_ID",
    "COMPONENT_SELF_GRANT_RULE",
    "COMPONENT_SELF_GRANT_RULE_ID",
    "COMPONENT_SHELL_EXECUTION_RULE",
    "COMPONENT_SHELL_EXECUTION_RULE_ID",
    "CREDENTIALED_REMOTE_MCP_SERVER_RULE",
    "CREDENTIALED_REMOTE_MCP_SERVER_RULE_ID",
    "DESTRUCTIVE_OR_FINANCIAL_ACTION_RULE",
    "DESTRUCTIVE_OR_FINANCIAL_ACTION_RULE_ID",
    "EXFILTRATION_TRIANGLE_RULE",
    "EXFILTRATION_TRIANGLE_RULE_ID",
    "HARDCODED_SECRETS_RULE",
    "HARDCODED_SECRETS_RULE_ID",
    "MCP_SERVER_IDENTITY_CHANGE_RULE",
    "MCP_SERVER_IDENTITY_CHANGE_RULE_ID",
    "MISSING_ACTION_LOGGING_RULE",
    "MISSING_ACTION_LOGGING_RULE_ID",
    "OVERPRIVILEGED_AGENT_WORKFLOW_RULE",
    "OVERPRIVILEGED_AGENT_WORKFLOW_RULE_ID",
    "PERMISSION_BYPASS_FROM_PROJECT_RULE",
    "PERMISSION_BYPASS_FROM_PROJECT_RULE_ID",
    "SECRET_EXPOSED_TO_UNTRUSTED_AGENT_RUN_RULE",
    "SECRET_EXPOSED_TO_UNTRUSTED_AGENT_RUN_RULE_ID",
    "SENSITIVE_WRITE_WITHOUT_APPROVAL_RULE",
    "SENSITIVE_WRITE_WITHOUT_APPROVAL_RULE_ID",
    "UNAUTHORIZED_DELEGATION_RULE",
    "UNAUTHORIZED_DELEGATION_RULE_ID",
    "UNDECLARED_TOOLS_RULE",
    "UNDECLARED_TOOLS_RULE_ID",
    "UNPINNED_AGENT_COMPONENT_RULE",
    "UNPINNED_AGENT_COMPONENT_RULE_ID",
    "UNRESOLVED_DYNAMIC_REGISTRATION_RULE",
    "UNRESOLVED_DYNAMIC_REGISTRATION_RULE_ID",
    "UNSANCTIONED_AGENT_COMPONENT_RULE",
    "UNSANCTIONED_AGENT_COMPONENT_RULE_ID",
    "WIDENED_PERMISSION_RULE_RULE",
    "WIDENED_PERMISSION_RULE_RULE_ID",
    "WORKSPACE_SCOPE_EXPANSION_RULE",
    "WORKSPACE_SCOPE_EXPANSION_RULE_ID",
    "Rule",
    "agent_hook_command_change_findings",
    "agent_sandbox_weakened_findings",
    "broad_permission_findings",
    "capability_ceiling_findings",
    "component_self_grant_findings",
    "component_shell_execution_findings",
    "credentialed_remote_mcp_server_findings",
    "destructive_or_financial_action_findings",
    "exfiltration_triangle_findings",
    "hardcoded_secrets_findings",
    "mcp_server_identity_change_findings",
    "missing_action_logging_findings",
    "overprivileged_agent_workflow_findings",
    "permission_bypass_from_project_findings",
    "secret_exposed_to_untrusted_agent_run_findings",
    "sensitive_write_without_approval_findings",
    "unauthorized_delegation_findings",
    "undeclared_tools_findings",
    "unpinned_agent_component_findings",
    "unresolved_dynamic_registration_findings",
    "unsanctioned_agent_component_findings",
    "widened_permission_rule_findings",
    "workspace_scope_expansion_findings",
]
