# Contributing to ControlLoop

Thanks for helping. ControlLoop welcomes small, testable contributions that
improve a developer's ability to understand and control what an agent can do
before it ships.

## Set up

You need Python 3.12, [`uv`](https://docs.astral.sh/uv/), and Git. From the
repository root:

```bash
uv sync --locked --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
uv build
```

The package is under `src/controlloop/` and its tests under `tests/`. The
user documentation is under [`docs/`](docs/readme.md); read the pages for
the area you are changing before you start.

## How to contribute

1. Open an issue first for anything larger than a typo, so the change can
   be agreed before you write it. Bug reports and feature requests have
   issue forms.
2. Make one coherent change per pull request, on a branch of its own.
3. Add tests: a positive case and at least two similar negative cases for
   every blocking rule, and malformed and unsupported-version cases for
   every adapter.
4. Update the documentation, examples, and `CHANGELOG.md` in the same pull
   request when behavior a user can see changes.
5. Sign off every commit (see below), run the checks above, then open the
   pull request with `Closes #<number>` and a short description of what
   changed, why, and how you tested it.

Discuss new adapters, new standards, network behavior, or changes to what
blocks a build in an issue before implementing them.

## Writing a rule

A new or changed policy rule touches the rule module, its registration,
the rule pack version, its tests, and its documentation section. [Writing a
rule](docs/guides/writing-a-rule.md) walks through each step and ends with
a checklist to copy into the pull request.

## Fixtures

Fixtures are product assets, not disposable test data.

- Use only synthetic data. Never copy customer code, credentials, prompts,
  or personal data.
- Pin standard and schema versions.
- Include the expected canonical and user-visible output.
- Add privacy canaries that are obviously fake and uniquely searchable.
- Explain any golden-output change, and add assertions that prove the new
  behavior, determinism, invalid-input handling, and privacy properties.

## Privacy and security

Repository input is hostile.

- Do not execute repository code, MCP tools, or declared endpoints.
- Do not follow paths outside the repository root.
- Do not add network access to local scanning.
- Do not log source, prompts, secrets, environment values, or customer data.
- Do not hash sensitive values and then treat them as safe.
- Bound parsing, traversal, graph expansion, output, and error collection.
- Represent incomplete analysis explicitly.
- Keep machine output stable, stdout separate from stderr, and blocking
  decisions independent of any model output.

Report vulnerabilities as described in [`SECURITY.md`](SECURITY.md), never
in a public issue.

## Sign off your commits

ControlLoop uses the [Developer Certificate of Origin](https://developercertificate.org)
(DCO) instead of a contributor license agreement. By adding a
`Signed-off-by` line to a commit, you certify that you wrote the change, or
otherwise have the right to submit it under the project's license, as the
DCO describes.

Sign off with `-s`, which adds the line using your configured name and
email:

```bash
git commit -s -m "fix: describe the change"
```

The line must name the commit's author:

```text
Signed-off-by: Your Name <you@example.com>
```

A check on every pull request (`.github/workflows/dco.yml`, running
`scripts/check-dco.sh`) fails if any commit lacks a sign-off from its
author. To sign off commits you have already made on your branch:

```bash
git rebase --signoff main
git push --force-with-lease
```

Use your real name or a consistent public identity, and an email you
control.

## Commits and review

- Prefer small commits with conventional messages (`feat:`, `fix:`,
  `docs:`, `test:`, `chore:`).
- Do not mix unrelated formatting changes into a functional change.
- Do not refresh golden artifacts without assertions that explain the new
  output.

## License

ControlLoop is licensed under the Apache License, Version 2.0. See
[`LICENSE`](LICENSE) and the
[license and dependency audit](docs/reference/licensing.md). By submitting
a contribution, you agree it is licensed under the same terms (Apache
License, Version 2.0, section 5, "Submission of Contributions"), and your
sign-off certifies the Developer Certificate of Origin for it.
