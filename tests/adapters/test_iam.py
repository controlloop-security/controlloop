"""Tests for IamPolicyAdapter."""

from __future__ import annotations

import json
from pathlib import Path

from controlloop.acbom import NodeType
from controlloop.adapters import IamPolicyAdapter, ScanContext, run_adapters
from controlloop.repository import resolve_repository_root

_PLANTED_SECRET = "AKIA-planted-secret-shaped-value-should-never-appear"


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _write_json(tmp_path: Path, relative_path: str, payload: object) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload))


def _write_tf(tmp_path: Path, relative_path: str, content: str) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def test_native_aws_iam_json_becomes_permission_nodes(tmp_path: Path) -> None:
    """A native AWS IAM JSON policy becomes a permission node."""
    _write_json(
        tmp_path,
        "policy.json",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        },
    )

    result = run_adapters([IamPolicyAdapter()], _context(tmp_path))

    assert len(result.nodes) == 1
    assert result.nodes[0].type is NodeType.PERMISSION
    assert "s3:GetObject" in result.nodes[0].security_attributes.permission_scopes


def test_terraform_jsonencode_resource_parses_equivalently(tmp_path: Path) -> None:
    """A Terraform `jsonencode` policy parses the same as native JSON."""
    _write_tf(
        tmp_path,
        "iam.tf",
        """
resource "aws_iam_policy" "example" {
  name = "example"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "s3:GetObject", Resource = "*" }
    ]
  })
}
""",
    )

    result = run_adapters([IamPolicyAdapter()], _context(tmp_path))

    assert len(result.nodes) == 1
    assert "s3:GetObject" in result.nodes[0].security_attributes.permission_scopes


def test_terraform_policy_document_data_source_parses(tmp_path: Path) -> None:
    """The native-HCL statement-block shape parses too."""
    _write_tf(
        tmp_path,
        "iam.tf",
        """
data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
""",
    )

    result = run_adapters([IamPolicyAdapter()], _context(tmp_path))

    assert len(result.nodes) == 1


def test_wildcards_are_preserved_never_expanded(tmp_path: Path) -> None:
    """A wildcard action is kept as a wildcard, never expanded."""
    _write_json(
        tmp_path,
        "policy.json",
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        },
    )

    result = run_adapters([IamPolicyAdapter()], _context(tmp_path))

    scopes = result.nodes[0].security_attributes.permission_scopes
    assert any("WILDCARD" in scope for scope in scopes)
    assert not any(scope in ("s3:GetObject", "s3:PutObject") for scope in scopes)


def test_condition_is_recorded_but_marked_unevaluated(tmp_path: Path) -> None:
    """A condition is recorded as present but unevaluated, so the grant is
    never reported as unrestricted without saying so."""
    _write_json(
        tmp_path,
        "policy.json",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*",
                    "Condition": {
                        "StringEquals": {"aws:PrincipalTag/team": "payments"}
                    },
                }
            ],
        },
    )

    result = run_adapters([IamPolicyAdapter()], _context(tmp_path))

    assert "condition:present" in result.nodes[0].security_attributes.permission_scopes


def test_unresolved_terraform_interpolation_produces_an_unknown(tmp_path: Path) -> None:
    """An unresolved Terraform interpolation yields a diagnostic, not a node."""
    _write_tf(
        tmp_path,
        "iam.tf",
        """
variable "bucket_name" {
  type = string
}

resource "aws_iam_policy" "dynamic" {
  name = "dynamic"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "arn:aws:s3:::${var.bucket_name}/*"
      }
    ]
  })
}
""",
    )

    result = run_adapters([IamPolicyAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-UNRESOLVED-REFERENCE"


def test_gcp_policy_is_recognized_and_rejected_not_misparsed(tmp_path: Path) -> None:
    """A GCP policy is recognized and rejected rather than misparsed."""
    _write_json(
        tmp_path,
        "gcp-policy.json",
        {"bindings": [{"role": "roles/owner", "members": ["user:x@example.com"]}]},
    )

    result = run_adapters([IamPolicyAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert "GCP" in result.diagnostics[0].message


def test_azure_policy_is_recognized_and_rejected_not_misparsed(tmp_path: Path) -> None:
    """An Azure policy is recognized and rejected rather than misparsed."""
    _write_json(
        tmp_path,
        "azure-policy.json",
        {
            "properties": {
                "roleName": "Contributor",
                "assignableScopes": ["/subscriptions/x"],
            }
        },
    )

    result = run_adapters([IamPolicyAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert "Azure" in result.diagnostics[0].message


def test_hcl_parse_never_leaks_planted_content_on_failure(tmp_path: Path) -> None:
    _write_tf(
        tmp_path,
        "iam.tf",
        f"resource broken {{ this is not valid hcl {_PLANTED_SECRET}",
    )

    result = run_adapters([IamPolicyAdapter()], _context(tmp_path))

    serialized = repr(result)
    assert _PLANTED_SECRET not in serialized


def test_result_is_deterministic(tmp_path: Path) -> None:
    _write_json(
        tmp_path,
        "policy.json",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "a"},
                {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "b"},
            ],
        },
    )
    context = _context(tmp_path)

    first = run_adapters([IamPolicyAdapter()], context)
    second = run_adapters([IamPolicyAdapter()], context)

    assert first == second
