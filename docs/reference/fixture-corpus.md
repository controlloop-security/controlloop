---
type: reference
title: Synthetic fixture corpus
tags:
  - reference
  - fixtures
  - testing
created: 2026-08-20
---

# Synthetic fixture corpus

**Status: Inventory of existing coverage.** This page
does not introduce new adapter, rule, or model behavior. It indexes the
synthetic test fixtures that already exist across this repository's test
suites, built incrementally as each adapter and each policy rule
landed, so that "does a fixture exist for X" has one answer instead of
requiring a search across nine rule files and five adapter files. Every
fixture cited below already existed before this page was written; this page
adds no new fixture unless a table explicitly says otherwise.

## What this page does not do

It does not replace the cited test files as the source of truth — it is a
map to them, not a substitute for reading them. Its accuracy for *file
existence* is enforced by `tests/test_fixture_corpus_doc.py`, which
fails CI if a path cited here stops existing. Its accuracy for exact test
*function and class names* is maintained by hand and should be reviewed
whenever an adapter or rule file changes shape — a stale name here would
not fail CI, only mislead a reader, so treat this page as a starting point
for navigation, not a guarantee that a named test still asserts exactly what
its name says.

## Adapter fixtures (positive, negative, malformed, version-drift)

Two layers of coverage exist for every adapter:

1. A shared, structurally enforced conformance suite —
   `tests/adapters/conformance_fixtures.py` (`ALL_FIXTURES`) and
   `tests/adapters/test_adapter_conformance.py` — parametrized over
   every adapter registered in `controlloop.adapters.ALL_ADAPTERS`.
   `TestFixtureRegistryCoversEveryAdapter` fails CI in both directions if a
   newly registered adapter has no fixture, or a fixture is orphaned, so
   this layer cannot silently rot.
2. Each adapter's own test file, with additional format-specific cases
   beyond what the shared suite requires.

### Shared conformance suite (`tests/adapters/test_adapter_conformance.py`)

| Category | Test | What it asserts |
| --- | --- | --- |
| Positive | `TestPositive::test_positive_fixture_produces_the_expected_shape` | Every adapter's positive fixture is claimed and parses into the expected shape, with a full evidence contract (adapter name, confidence, sanitized relative path). |
| Negative | `TestSimilarNegative::test_similar_but_different_input_never_produces_a_false_positive` | A similar-but-different input never produces a node, for every adapter (IAM's GCP/Azure fixtures are claimed and explicitly rejected rather than silently ignored — see the IAM table below). |
| Malformed | `TestMalformed::test_malformed_input_produces_a_diagnostic_not_a_crash` | Malformed input never crashes and is never silently dropped; every resulting diagnostic is `INCOMPLETE-*`. |
| Version drift | `TestVersionDrift::test_unsupported_version_produces_a_diagnostic_not_a_misparse` | An unsupported in-document version produces a diagnostic, not a misparse — runs for every adapter with a real version-drift fixture. |
| Version-drift exemption | `TestVersionDrift::test_version_drift_exemption_is_explicitly_disclosed` | For the one adapter without an in-document version field (MCP — see below), asserts a real, non-trivial disclosed reason exists rather than a silent skip. |
| Boundary | `TestBoundarySize::test_many_entries_are_all_discovered` | A many-entry (200+) otherwise-valid document completes without a crash, hang, or silent truncation. |
| Determinism | `TestDeterminism::test_identical_input_produces_an_identical_result` | Identical input produces an identical result on repeated runs. |
| Registry completeness | `TestFixtureRegistryCoversEveryAdapter::test_every_registered_adapter_has_a_conformance_fixture` | Every registered adapter has exactly one fixture, and no fixture is orphaned. |

### Per-adapter own-file coverage

**MCP** (`tests/adapters/test_mcp.py`)

| Category | Test(s) |
| --- | --- |
| Positive | `test_each_known_location_is_detected`, `test_stdio_server_is_represented_with_the_right_transport`, `test_http_server_is_represented_with_the_right_transport` |
| Negative | `test_an_unrelated_location_is_not_detected` |
| Malformed | `test_malformed_input_produces_a_diagnostic_not_a_crash`, `test_a_malformed_entry_does_not_drop_a_valid_sibling` |
| Version drift | Not present — **disclosed exemption**: real `.mcp.json` client configs carry no in-document schema-version field to drift; `supported_versions` documents the MCP *protocol* version this adapter was verified against, not a per-document marker (`conformance_fixtures.py:128-133`). |

`tests/adapters/test_mcp_live.py` adds separate live-subprocess
coverage (real stub-server process, hang timeout, oversized-response
bounding, crash/malformed-response handling) for
`normalize_live_mcp_server` — valuable, but that function is not part of
`ALL_ADAPTERS`/`bom` yet, so it sits outside the adapter tables here.

**IAM** (`tests/adapters/test_iam.py`)

| Category | Test(s) |
| --- | --- |
| Positive | `test_native_aws_iam_json_becomes_permission_nodes`, `test_terraform_jsonencode_resource_parses_equivalently`, `test_terraform_policy_document_data_source_parses`, `test_condition_is_recorded_but_marked_unevaluated` |
| Negative | `test_gcp_policy_is_recognized_and_rejected_not_misparsed`, `test_azure_policy_is_recognized_and_rejected_not_misparsed` — claimed, then explicitly rejected with a diagnostic naming the real provider, not silently ignored |
| Malformed | `test_unresolved_terraform_interpolation_produces_an_unknown`, `test_hcl_parse_never_leaks_planted_content_on_failure` |
| Version drift | Covered via the shared suite's `_iam_write_version_drift` (a far-future `Version: "2099-01-01"` statement) |

**A2A** (`tests/adapters/test_a2a.py`)

| Category | Test(s) |
| --- | --- |
| Positive | `test_each_known_location_is_detected`, `test_card_becomes_agent_node_with_identity_from_security_schemes`, `test_skills_become_tool_nodes_with_invokes_edges`, `test_repo_local_delegation_target_links_to_its_agent_node` |
| Negative | `test_card_with_no_delegation_field_is_unaffected` |
| Malformed | `test_hostile_card_text_produces_a_diagnostic_not_a_crash`, `test_malformed_skill_entry_produces_diagnostic_not_a_dropped_card`, `test_unresolvable_delegation_target_produces_an_unknown`, `test_escaping_delegation_target_produces_an_unknown_not_a_read` |
| Version drift | `test_unsupported_version_produces_a_diagnostic_naming_it` |

**OASF** (`tests/adapters/test_oasf.py`)

| Category | Test(s) |
| --- | --- |
| Positive | `test_a_supported_version_normalizes_into_a_node` (patches `SUPPORTED_OASF_VERSIONS`, which is empty by design — see the adapter status page) |
| Negative | `test_non_oasf_files_are_ignored` |
| Malformed | Covered via the shared suite's `_oasf_write_malformed` fixture (a document missing `name`); this file itself covers unknown-field forward-compatibility instead (`test_unrecognized_fields_are_preserved_as_unknown_not_discarded`), not a duplicate raw-malformed-JSON case |
| Version drift | `test_unrecognized_record_produces_a_diagnostic_naming_both_versions` — this is OASF's default (unpatched) behavior today, since `SUPPORTED_OASF_VERSIONS == ()` |

**OpenAPI** (`tests/adapters/test_openapi.py`)

| Category | Test(s) |
| --- | --- |
| Positive | `test_operations_become_tool_and_resource_nodes_with_reads_writes_edges`, `test_security_schemes_become_identity_and_permission_nodes`, `test_local_ref_resolves_correctly` |
| Negative | `test_non_openapi_files_are_ignored` |
| Malformed | `test_remote_ref_is_never_fetched_and_produces_an_unknown`, `test_cyclic_local_ref_is_detected_and_does_not_hang` |
| Version drift | `test_swagger_2_is_rejected_not_misparsed` (this file); the shared suite also carries a genuine `openapi: "4.2.0"` drift fixture (`_openapi_write_version_drift`) |

## Node and edge type coverage

All 8 `NodeType` values (`agent`,
`tool`, `resource`, `identity`, `permission`, `data-class`, `trigger`,
`policy-boundary`) and all 8 `EdgeType` values (`invokes`, `reads`,
`writes`, `authenticates-as`, `permitted-by`, `delegates-to`,
`receives-from`, `constrained-by`) — both defined in
`src/controlloop/acbom/models.py` — have complete, CI-enforced
coverage:

- `tests/acbom/test_schema_and_models.py`:
  `test_every_node_type_validates`/`test_every_edge_type_validates`
  (parametrized over every enum member) and
  `test_schema_and_model_declare_the_same_node_types`/`..._edge_types`
  (diffing the JSON Schema enum against the Python enum).
- `tests/concepts/reference_fixture.py`: one connected reference ACBOM
  (the `refund-agent` scenario) covering every `NodeType` and every
  `EdgeType` at least once, asserted by `TestFixtureCoverage` in
  `tests/concepts/test_acbom_concepts_doc.py`, and used to generate
  `docs/concepts/acbom.md` directly from real code —
  `tests/concepts/test_acbom_concepts_doc.py` keeps that page
  byte-for-byte synchronized with the fixture.
- `tests/acbom/test_identity.py`: stable-identity coverage across every
  `NodeType`/`EdgeType`.
- `tests/acbom/test_node_merge.py` / `test_edge_merge.py`: the original
  node-type and edge-type coverage tests — merge, deduplication, and
  order-independence for every field.

## Rule fixtures (at least one positive and one negative per rule)

All nine implemented rules have unambiguous positive (fires) and negative
(a similar-but-safe input does not fire) coverage.
`tests/policy/rules/test_all_rules_registry.py` proves all nine are
registered under `ALL_RULES`, have unique rule IDs, and evaluate together
against a shared context without raising.
`tests/policy/rules/_helpers.py` is the shared node/edge/manifest/context
builder library every rule test file uses.

| Rule (rule ID) | File | Positive | Negative |
| --- | --- | --- | --- |
| Undeclared tools (`policy.undeclared-tools`) | `tests/policy/rules/test_undeclared_tools.py` | `TestUndeclaredToolFires` | `TestDeclaredToolProducesNoFinding` |
| Destructive or financial action (`policy.destructive-or-financial-action`) | `tests/policy/rules/test_destructive_or_financial_action.py` | `TestTaxonomyDriven::test_destructive_attribute_fires`, `test_financial_attribute_fires` | `TestTaxonomyDriven::test_a_suggestively_named_resource_with_no_attribute_does_not_fire`, `TestNewlyGainedOnly` |
| Sensitive write without approval (`policy.sensitive-write-without-approval`) | `tests/policy/rules/test_sensitive_write_without_approval.py` | `TestDataClassSources` | `TestDeclaredApprovalSuppresses::test_matching_approval_suppresses`, `TestBoundaryAndMalformed::test_read_not_write_does_not_fire` |
| Broad permission (`policy.broad-permission`) | `tests/policy/rules/test_broad_permission.py` | `TestWildcardFires`, `TestUnevaluatedConditionFires` | `TestNarrowGrantsProduceNoFinding` |
| Missing action logging (`policy.missing-action-logging`) | `tests/policy/rules/test_missing_action_logging.py` | `TestPositive` | `TestNegative` |
| Unauthorized delegation (`policy.unauthorized-delegation`) | `tests/policy/rules/test_unauthorized_delegation.py` | `TestPositive` | `TestNegative` |
| Unresolved dynamic registration (`policy.unresolved-dynamic-registration`) | `tests/policy/rules/test_unresolved_dynamic_registration.py` | `TestPositive` | `TestNegative` |
| Capability ceiling evaluation (`policy.capability-ceiling`) | `tests/policy/rules/test_capability_ceiling.py` | `TestPositive` | `TestNegative`, `TestNoDeclaredCeiling` |
| Exfiltration triangle detection (`policy.exfiltration-triangle`) | `tests/policy/rules/test_exfiltration_triangle.py` | `TestPositive` | `TestNegativePairs` |

Every file above also carries `TestDeterminism`, engine-registration
coverage, and offline coverage (a socket call raises inside the rule under
`conftest.py`'s network-denied harness).

**When this page was written, the hardcoded-secret-material rule was not
implemented.** That was not a gap in this corpus — there was no rule to
fixture. The reason was disclosed in source:
`src/controlloop/policy/rules/__init__.py` stated the merged `Finding`
model requires exactly one `affected_agent` and a real `capability_path`
per finding, and generic repository-content secret scanning has no
natural single-agent attribution without either fabricating graph
content or a separate product decision. Both the rule and the
architectural gap blocking it were open as of this page's writing.

## No real credentials; canaries clearly marked

The dominant convention, reused rather than reinvented in each file: a
GitHub-token-shaped synthetic value, `"ghp_" + "<filler>" * 36`, always
under a clearly named local (`canary`, `planted_secret`,
`_SECRET_SHAPED_CANARY`) and usually asserted by a `TestPrivacyCanary` test
class. Used in `tests/test_cli.py`, `test_config.py`,
`test_verbosity.py`, `tests/baseline/test_baseline_models.py`,
`test_baseline_provenance.py`, `test_baseline_resolution.py`,
`test_merge_base.py`, and four of the nine rule test files
(`test_broad_permission.py`, `test_destructive_or_financial_action.py`,
`test_sensitive_write_without_approval.py`, `test_undeclared_tools.py`).

Content-appropriate variants exist where the shape matters:
`tests/adapters/test_iam.py` and `tests/manifest/test_parser.py` use
an AWS-access-key shape (`"AKIA-planted-secret-shaped-value-..."`), since
both parse AWS IAM documents; `tests/adapters/test_mcp.py` uses generic
API-key/bearer-token shapes for arbitrary env-var/header values.

The five rule test files that landed as the "sibling batch"
(`test_missing_action_logging.py`, `test_unauthorized_delegation.py`,
`test_unresolved_dynamic_registration.py`, `test_capability_ceiling.py`,
`test_exfiltration_triangle.py`) use a different, equally valid proof
instead of planting a runtime canary string: each has a `TestPrivacy` class
asserting the rule module structurally cannot import
`os`/`subprocess`/`socket`/`urllib`/`http`, so there is no code path for raw
repository content — and therefore no secret — to reach the rule at all.

No real credential-shaped value was found anywhere in the codebase during
this audit.

## Documented CI time budget

Real, measured numbers — not an invented aspirational target.

**Local (`uv run pytest` from the repository root, at the time of
measurement):** 1601 passed, 3 skipped, 24.58s wall clock.

**CI (`gh run view <id> --json jobs` against four of the most recent real
runs on `controlloop-security/controlloop`, checked directly against the live
GitHub API):**

| Run | Full "CLI checks" job | `Test` step alone |
| --- | --- | --- |
| 32415047614 | 36s | 18s |
| 32414369735 | 41s | 23s |
| 32413619128 | 30s | 16s |
| 32411691742 | 67s | 23s |

The 67-second run is consistent with a cold dependency-cache instance; the
`Test` step itself stayed in the 16-23s range across all four. `.github/workflows/ci.yml`
now sets `timeout-minutes: 10` on the `cli` job — roughly 9x headroom over
the worst full-job run observed above, chosen to catch a suite that
regresses into minutes-long hangs without producing false failures from
ordinary runner variance (the project's "low false-positive burden"
principle). This is a real enforced ceiling, not
documentation alone: before this change, no `timeout-minutes` was set, so
the only limit was the platform default of 360 minutes.

The measurements above predate the cross-platform matrix: the `cli` job
now runs as a three-leg matrix (`.github/workflows/verify.yml`, see
[Supported platforms](supported-platforms.md)) rather than only on
`ubuntu-latest`. The `timeout-minutes: 10` budget above currently applies
unchanged to every leg; it has not yet been re-measured per leg, since
the arm64 and macOS legs had not run in real CI when it was set. A later
update to this page should record real per-leg numbers once several real
matrix runs exist, rather than assuming they match the `ubuntu-latest`
figures above.

## The agent-authority benign corpus

`tests/fixtures/agent-authority-corpus/` holds twenty-two cases,
each a directory with one file shaped like common real-world agent
configuration: formatter and linter hooks, a notification hook, narrow
allow rules, a plan-mode deny list, a pinned marketplace, skills,
subagents, a slash command, read-only agent workflows for Claude Code,
Codex, and Gemini CLI, and Codex, Gemini CLI, Cursor, Kiro, and MCP
settings.

`tests/test_agent_authority_corpus.py` gates every case two ways and
compares the result with the committed `results.json`:

| Mode | What it means | Deployment blocked | Passed with warnings |
| --- | --- | --- | --- |
| As present | The file as it sits in a repository, with no baseline | 0 of 22 | 0 of 22 |
| As introduced | A pull request that adds the file to an otherwise empty repository | 8 of 22 | 0 of 22 |

The corpus target — zero *Deployment blocked*, at most two *Passed with
warnings* — holds for the first mode, and the test asserts it. The
second mode is recorded for reference. Seven of its eight blocks are
hooks added, which are `high` on purpose: a formatter hook and a
credential harvester are both hook changes. The eighth is
`Bash(git diff:*)`: a shell rule stays `high` however narrow its prefix.
Read-only tool rules (bare `Read`, `Grep`, `Glob`, and Gemini CLI's
`read_file`, `glob`, `search_file_content`) were also blocking until
they were changed to report at `medium`.

The corpus also found one false "incomplete", now fixed: a Codex
`config.toml`, Gemini CLI `settings.json`, opencode, or Continue settings
file with no MCP server section was reported as an unparsed MCP file.

Every corpus file is checked by the redaction primitive's credential
scan and holds no credential shape.

The shared adapter conformance suite also gained a privacy case for
every agent-authority adapter. Credential-shaped values, environment and
header values, and prompt bodies are planted, and none may appear in the
adapter's nodes, edges, or diagnostics.
