# Security Policy

ControlLoop processes attacker-controlled repositories and may block software
delivery. We appreciate responsible reports about vulnerabilities in the
scanner, schemas, policy behavior, packaging, CI integrations, or future cloud
services.

## Supported versions

ControlLoop is currently pre-release. Security fixes are applied to the active
development branch.

After the first stable release, the latest stable minor release will receive
security fixes. Backports to older releases may be provided when practical but
are not guaranteed. Published security advisories will identify the affected
and fixed versions.

| Version | Supported |
|---|---|
| Pre-release development branch | Yes |
| Unreleased historical snapshots | No |

## Reporting a vulnerability

Use the repository host's private vulnerability-reporting or security-advisory
feature. Include:

- A concise description and affected component.
- Reproduction steps using synthetic data.
- Expected and observed behavior.
- Security or privacy impact.
- A suggested mitigation, if known.

Do not include real credentials, customer data, proprietary repositories,
private prompts, or other people's personal data.

If private vulnerability reporting is unavailable, open a minimal public issue
asking the maintainers to establish a private channel. Do not include exploit
details in that issue.

Please do not use a public issue for an unpatched vulnerability.

## Response targets

This is a bootstrapped pre-release project, not a 24/7 monitored service. The
maintainers aim to:

- Acknowledge a complete report within five business days.
- Provide an initial assessment within ten business days.
- Coordinate a fix and disclosure timeline based on severity and exploitability.

These are targets rather than service-level guarantees.

## Scope priorities

High-priority reports include:

- Repository or symlink escape.
- Arbitrary code execution or unsafe deserialization.
- Network access during a declared offline scan.
- Secret, source, prompt, or customer-data disclosure.
- Nondeterministic or bypassable blocking behavior.
- Malicious schema, archive, graph, or parser denial of service.
- Cross-tenant access in future Team services.
- Signing-key or attestation compromise in future Team services.

Ordinary false positives, unsupported adapters, and feature requests should use
the normal issue tracker unless they create a concrete security boundary
failure.

## Safe research

Use only systems and data you own or have permission to test. Do not degrade
services, access other users' data, or retain sensitive data. Give maintainers
reasonable time to investigate and release a fix before public disclosure.
