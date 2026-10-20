---
type: guide
title: ControlLoop documentation
tags:
  - overview
  - user-guide
created: 2026-08-14
---

# Know what powers your AI agent

ControlLoop is being built to show developers and security teams what an AI
agent can access, explain what changed, and stop unsafe capability expansion
before deployment.

The product is local first: the approved design keeps repository contents,
prompts, credentials, and secret values on the user's machine or CI runner.
Its decisions are intended to be deterministic and backed by inspectable
evidence, not an opaque model verdict.

> **Development preview:** the repository currently provides an installable
> Python 3.12 command with `--help`, `--version`, `init`, `bom`, `diff`,
> `scan`, and `gate`. `bom` generates or validates a canonical ACBOM; `init`
> drafts a `controlloop.yaml` manifest; `diff` compares two ACBOMs or a
> repository against a resolved baseline, evaluating no policy; `scan`
> evaluates policy with every registered rule and reports the result; `gate`
> is the noninteractive CI-facing form, adding a four-state verdict and a
> retainable evidence artifact. A GitHub Action (`action.yml`) and a
> pre-commit hook both provide CI integration. Team features --
> organization policy, exceptions, and an approved-components list -- run
> through the CLI's Team client against the ControlLoop platform; see
> [Your first Team gate](guides/first-team-gate.md). To set up Team for your
> organization, [get in touch](https://controlloop.ai/#get-started).

## Who ControlLoop is for

- Agent developers who need to understand the authority their software may
  gain.
- Platform engineers who want a reviewable capability inventory before a
  deployment.
- Application-security engineers who need reproducible evidence and narrow,
  explainable policy findings.
- Engineering leads who want capability changes to be visible in normal
  repository workflows.

## What ControlLoop is designed to deliver

1. Build an Agent Capability Bill of Materials (ACBOM) from supported local
   evidence.
2. Show direct and transitive paths from an agent to tools, resources,
   identities, permissions, and data classes.
3. Compare those capabilities with an approved baseline.
4. Evaluate deterministic policies and explain every material finding.
5. Keep unsupported or dynamic behavior visible as unknown instead of calling
   it safe.

These outcomes describe the approved product direction. See
[Capability and adapter status](adapters/readme.md) before relying on any
specific workflow.

## Start here

1. [Install the development preview](getting-started/installation.md).
2. [Verify the current CLI](getting-started/quickstart.md).
3. [Learn how the ACBOM makes agent authority reviewable](concepts/acbom.md).
4. [Review privacy, security, and current limitations](reference/privacy-security.md).

## Find what you need

| Goal | Guide |
| --- | --- |
| Verify that the current package works | [Current quickstart](getting-started/quickstart.md) |
| Understand agents, capabilities, evidence, and ACBOMs | [ACBOM concepts](concepts/acbom.md) |
| Check supported discovery formats | [Adapter status](adapters/readme.md) |
| Look up current commands | [CLI reference](reference/cli.md) |
| Understand offline and data-handling boundaries | [Privacy, security, and limitations](reference/privacy-security.md) |
| Recover from setup or command errors | [Troubleshooting](troubleshooting.md) |
| Add or change a policy rule | [Writing a rule](guides/writing-a-rule.md) |

## Product boundaries

ControlLoop is not a runtime firewall, sandbox, managed monitoring service,
incident-response service, or guarantee that an agent is safe. Its initial
scope is a self-service, pre-deployment scanner and deterministic CI gate.

Internal product and engineering guidance lives under `agent/`. It governs
development but is not evidence that a feature has shipped. User instructions
in this directory remain the source for currently available workflows.
