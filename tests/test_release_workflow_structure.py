"""Structural verification of `.github/workflows/release.yml` -- a
"workflow-syntax / dry-run" verification, used in place of an actual
triggered release run, which a test must never perform.

These tests never execute the workflow -- they parse the real YAML file with
`yaml.safe_load` (already a project dependency, `pyyaml`) and assert its
structure matches the release pipeline's design: a tag-only trigger, a
`needs` graph that makes every publish step depend on verification and the
changelog gate, PyPI publication through trusted publishing rather than a
stored token, GHCR publication with the workflow's own token rather than a
stored registry password, exactly one stored credential (the Homebrew tap
token, scoped to that one repository), and every third-party action pinned
to an exact version.
This mirrors the existing drift-guard pattern in
`test_fixture_corpus_doc.py`: real repository content, asserted against, not
merely described in a docstring.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]
_RELEASE_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "release.yml"
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
_VERIFY_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "verify.yml"

#: Credentials this pipeline must never store: a Docker Hub login, a
#: long-lived registry token, a personal token for GHCR. GHCR is reached
#: with the workflow's own `github.token`; the Homebrew tap with the one
#: documented secret, `HOMEBREW_TAP_TOKEN`.
_FORBIDDEN_SECRET_SUBSTRINGS = (
    "DOCKERHUB",
    "DOCKER_PASSWORD",
    "DOCKER_TOKEN",
    "GHCR_TOKEN",
    "GHCR_PAT",
    "CR_PAT",
)

#: The only `secrets.*` reference the pipeline may make. Everything else
#: is GitHub's own short-lived `github.token` / OIDC.
_ALLOWED_SECRETS = frozenset({"HOMEBREW_TAP_TOKEN"})


def _load(path: Path) -> dict[Any, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _on(workflow: dict[Any, Any]) -> Any:
    # PyYAML's default (YAML 1.1) resolver reads the bare `on:` key as the
    # boolean `True`, not the string `"on"` -- a well-known GitHub Actions
    # YAML quirk this repository's own pre-existing ci.yml already exhibits.
    return workflow.get("on", workflow.get(True))


class TestReleaseWorkflowTriggers:
    def test_only_trigger_is_a_semver_tag_push(self) -> None:
        workflow = _load(_RELEASE_WORKFLOW)
        trigger = _on(workflow)

        assert set(trigger.keys()) == {"push"}
        assert set(trigger["push"].keys()) == {"tags"}
        tags = trigger["push"]["tags"]
        assert tags == ["v*.*.*"]

    def test_never_triggers_on_pull_request_or_branch_push(self) -> None:
        workflow = _load(_RELEASE_WORKFLOW)
        trigger = _on(workflow)

        assert "pull_request" not in trigger
        assert "branches" not in trigger.get("push", {})

    def test_has_a_concurrency_group_to_avoid_double_runs(self) -> None:
        workflow = _load(_RELEASE_WORKFLOW)

        assert "concurrency" in workflow
        assert "group" in workflow["concurrency"]


class TestReleaseWorkflowJobGraph:
    def test_expected_jobs_exist(self) -> None:
        workflow = _load(_RELEASE_WORKFLOW)
        jobs = workflow["jobs"]

        assert set(jobs.keys()) == {
            "derive-version",
            "verify",
            "changelog-gate",
            "package",
            "build-binaries",
            "attest-artifacts",
            "publish-github-release",
            "publish-schemas",
            "publish-pypi",
            "publish-container",
            "publish-homebrew",
        }

    def test_verify_and_changelog_gate_depend_on_derive_version(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        assert jobs["verify"]["needs"] == "derive-version"
        assert jobs["changelog-gate"]["needs"] == "derive-version"

    def test_package_depends_on_derive_version_and_verify(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        needs = jobs["package"]["needs"]
        assert set(needs) == {"derive-version", "verify"}

    def test_build_binaries_depends_on_derive_version_and_verify(self) -> None:
        """Binary builds gate on the same verification stage every other
        publish job does -- not published in isolation, the same reasoning
        `package` already follows."""
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        needs = jobs["build-binaries"]["needs"]
        assert set(needs) == {"derive-version", "verify"}

    def test_publish_depends_on_every_prior_stage(self) -> None:
        """A failed verification stops publication for
        all channels; no channel is published in isolation. Encoded as a
        `needs` list covering verify, the changelog gate, the built
        package, the built binaries, and artifact attestation
        -- GitHub Actions skips a job whose `needs` target failed, so
        `publish-github-release` cannot run if any of these did not."""
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        needs = jobs["publish-github-release"]["needs"]
        assert set(needs) == {
            "derive-version",
            "verify",
            "changelog-gate",
            "package",
            "build-binaries",
            "attest-artifacts",
        }

    def test_verify_job_calls_the_shared_reusable_workflow(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        assert jobs["verify"]["uses"] == "./.github/workflows/verify.yml"

    def test_publish_schemas_depends_on_verify_and_changelog_gate(self) -> None:
        """Schema publication is its own channel, not
        gated behind `package`/`publish-github-release` (a schema
        publication does not need a built wheel or a GitHub Release to
        exist), but it must not skip verification -- the same "no
        channel published in isolation" principle
        `test_publish_depends_on_every_prior_stage` already proves for
        `publish-github-release`."""
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        needs = jobs["publish-schemas"]["needs"]
        assert set(needs) == {"derive-version", "verify", "changelog-gate"}

    def test_publish_schemas_only_holds_pages_permissions(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        permissions = jobs["publish-schemas"]["permissions"]
        assert permissions == {"pages": "write", "id-token": "write"}
        assert "contents" not in permissions


class TestReleaseWorkflowScopeBoundary:
    def test_no_stored_registry_credential_is_referenced(self) -> None:
        """The container image is pushed with the workflow's own token and
        the Homebrew formula with one documented, single-repository
        secret. This workflow's real, executable content (jobs: steps,
        env, secrets -- never a comment, which YAML parsing already
        strips) must reference no other stored credential."""
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        jobs_text = str(jobs)
        jobs_upper = jobs_text.upper()

        for forbidden in _FORBIDDEN_SECRET_SUBSTRINGS:
            assert forbidden not in jobs_upper, (
                f"release.yml's real job content references {forbidden!r}, "
                "a stored registry credential this pipeline must not hold"
            )
        referenced = set(re.findall(r"secrets\.([A-Za-z0-9_]+)", jobs_text))
        assert referenced <= _ALLOWED_SECRETS, (
            f"release.yml references secrets {sorted(referenced - _ALLOWED_SECRETS)}; "
            f"only {sorted(_ALLOWED_SECRETS)} may be stored"
        )

    def test_never_pushes_a_tag_or_calls_uv_publish(self) -> None:
        raw = _RELEASE_WORKFLOW.read_text(encoding="utf-8")

        assert "git push" not in raw
        assert "git tag" not in raw
        assert "uv publish" not in raw
        assert "twine" not in raw

    def test_contents_write_is_scoped_to_the_publish_job_only(self) -> None:
        workflow = _load(_RELEASE_WORKFLOW)

        top_level_permissions = workflow.get("permissions", {})
        assert top_level_permissions.get("contents") == "read"

        jobs = workflow["jobs"]
        for job_name, job in jobs.items():
            job_permissions = job.get("permissions", {})
            if job_permissions.get("contents") == "write":
                assert job_name == "publish-github-release", (
                    f"job {job_name!r} unexpectedly holds contents: write"
                )

        assert jobs["publish-github-release"]["permissions"]["contents"] == "write"


class TestReleaseWorkflowActionPinning:
    def test_every_third_party_action_pins_an_exact_version(self) -> None:
        """The project's CI standard: pin or otherwise control critical
        tool and image versions. A bare major tag (`@v4`) or a
        floating ref (`@main`, `@latest`) is rejected; an exact
        `@vMAJOR.MINOR.PATCH`-shaped tag is required, matching the pattern
        `action.yml` and `ci.yml` already established in this repository."""
        for workflow_path in (_RELEASE_WORKFLOW, _VERIFY_WORKFLOW, _CI_WORKFLOW):
            workflow = _load(workflow_path)
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    uses = step.get("uses")
                    if uses is None or uses.startswith("./"):
                        continue
                    assert "@" in uses, f"{uses!r} in {workflow_path} is not pinned"
                    ref = uses.rsplit("@", 1)[1]
                    assert ref[0] == "v" and ref[1].isdigit(), (
                        f"{uses!r} in {workflow_path} is not pinned to an "
                        "exact vMAJOR.MINOR.PATCH-shaped version"
                    )
                    assert ref.count(".") >= 2, (
                        f"{uses!r} in {workflow_path} looks like a bare "
                        "major tag, not an exact version"
                    )


class TestVerifyWorkflowIsSharedBetweenCiAndRelease:
    def test_ci_and_release_both_call_the_same_reusable_workflow(self) -> None:
        ci_jobs = _load(_CI_WORKFLOW)["jobs"]
        release_jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        assert ci_jobs["cli"]["uses"] == "./.github/workflows/verify.yml"
        assert release_jobs["verify"]["uses"] == "./.github/workflows/verify.yml"


class TestVerifyWorkflowCrossPlatformMatrix:
    """The shared `verify.yml` job -- and therefore
    both `ci.yml` (every pull request) and `release.yml` (every tag push)
    -- runs across a real cross-platform matrix, not only `ubuntu-latest`.
    """

    def test_matrix_has_exactly_the_three_disclosed_legs(self) -> None:
        job = _load(_VERIFY_WORKFLOW)["jobs"]["cli"]
        legs = job["strategy"]["matrix"]["include"]

        assert {(leg["os"], leg["label"]) for leg in legs} == {
            ("ubuntu-latest", "linux-x86_64"),
            ("ubuntu-24.04-arm", "linux-arm64"),
            ("macos-26", "macos-arm64"),
        }

    def test_fail_fast_is_disabled_so_every_leg_reports(self) -> None:
        job = _load(_VERIFY_WORKFLOW)["jobs"]["cli"]

        assert job["strategy"]["fail-fast"] is False

    def test_no_windows_runner_is_referenced_anywhere(self) -> None:
        """Windows is not tested and is documented as unsupported
        rather than silently broken -- never present in the matrix, never
        present as a step condition. Checked against the job's real,
        parsed content (YAML parsing already strips comments), not the
        raw file text, since this file's own disclosure comments
        legitimately discuss Windows and macOS x86_64 in prose."""
        job = _load(_VERIFY_WORKFLOW)["jobs"]["cli"]

        assert "windows" not in str(job).lower()

    def test_no_macos_x86_64_runner_is_referenced(self) -> None:
        """The disclosed gap: no `-large`/`-intel` macOS label (paid
        larger runners) appears in the job's real, parsed content -- paid
        usage is never enabled without explicit maintainer
        authorization."""
        job = _load(_VERIFY_WORKFLOW)["jobs"]["cli"]
        job_lower = str(job).lower()

        assert "-large" not in job_lower
        assert "-intel" not in job_lower

    def test_every_leg_runs_the_identical_step_sequence(self) -> None:
        """No platform-conditional step exists -- every leg runs the exact
        same verified command surface, which is what makes the existing
        golden-digest assertion in test_gate_determinism_regression.py a
        real cross-platform proof once this matrix runs."""
        job = _load(_VERIFY_WORKFLOW)["jobs"]["cli"]
        step_names = [step["name"] for step in job["steps"]]

        assert step_names == [
            "Check out repository",
            "Install uv",
            "Install locked dependencies",
            "Check formatting",
            "Lint",
            "Type check",
            "Test",
            "Build",
        ]
        for step in job["steps"]:
            assert "if" not in step, (
                f"step {step['name']!r} has a platform-conditional 'if' -- "
                "every leg must run the identical sequence"
            )

    def test_verify_workflow_is_call_only_never_directly_triggered(self) -> None:
        workflow = _load(_VERIFY_WORKFLOW)
        trigger = _on(workflow)

        assert set(trigger.keys()) == {"workflow_call"}


class TestReleaseWorkflowBinaryBuild:
    """The `build-binaries` job's own structural
    contract -- see `docs/reference/standalone-binaries.md` for the full
    disclosure this job's shape is expected to match."""

    def test_matrix_reuses_the_identical_three_verify_legs(self) -> None:
        """The goal of "all four platform and architecture combinations" is
        satisfied for the three combinations a free-tier GitHub-hosted
        runner can actually build (see the disclosed macOS x86_64 gap);
        this asserts the binary-build matrix is not a fourth, independently
        maintained copy that could silently drift from `verify.yml`'s own
        matrix."""
        binary_job = _load(_RELEASE_WORKFLOW)["jobs"]["build-binaries"]
        verify_job = _load(_VERIFY_WORKFLOW)["jobs"]["cli"]

        binary_legs = {
            (leg["os"], leg["label"])
            for leg in binary_job["strategy"]["matrix"]["include"]
        }
        verify_legs = {
            (leg["os"], leg["label"])
            for leg in verify_job["strategy"]["matrix"]["include"]
        }
        assert binary_legs == verify_legs
        assert binary_legs == {
            ("ubuntu-latest", "linux-x86_64"),
            ("ubuntu-24.04-arm", "linux-arm64"),
            ("macos-26", "macos-arm64"),
        }

    def test_fail_fast_is_disabled(self) -> None:
        job = _load(_RELEASE_WORKFLOW)["jobs"]["build-binaries"]

        assert job["strategy"]["fail-fast"] is False

    def test_no_macos_x86_64_or_windows_runner_is_referenced(self) -> None:
        job = _load(_RELEASE_WORKFLOW)["jobs"]["build-binaries"]
        job_lower = str(job).lower()

        assert "-large" not in job_lower
        assert "-intel" not in job_lower
        assert "windows" not in job_lower

    def test_includes_a_smoke_test_and_a_reproducibility_step(self) -> None:
        """The smoke test and the reproducibility check are each their
        own named step, not folded silently into the build step, so a
        failure in either is individually attributable in a real run."""
        job = _load(_RELEASE_WORKFLOW)["jobs"]["build-binaries"]
        step_names = [step["name"] for step in job["steps"]]

        assert any("smoke test" in name.lower() for name in step_names)
        assert any("reproducib" in name.lower() for name in step_names)

    def test_uploads_the_binary_and_its_checksum(self) -> None:
        job = _load(_RELEASE_WORKFLOW)["jobs"]["build-binaries"]
        upload_steps = [
            step
            for step in job["steps"]
            if step.get("uses", "").startswith("actions/upload-artifact")
        ]
        assert len(upload_steps) == 1
        path = upload_steps[0]["with"]["path"]
        assert ".sha256" in path

    def test_publish_job_downloads_and_attaches_binaries(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        publish_steps = jobs["publish-github-release"]["steps"]

        download_binary_steps = [
            step
            for step in publish_steps
            if step.get("uses", "").startswith("actions/download-artifact")
            and step.get("with", {}).get("pattern") == "binary-*"
        ]
        assert len(download_binary_steps) == 1

        create_release_step = next(
            step for step in publish_steps if "gh release create" in step.get("run", "")
        )
        assert "release-binaries" in create_release_step["run"]


class TestReleaseWorkflowArtifactAttestation:
    """Every published artifact gets a checksum and a
    signature -- see `docs/reference/release-verification.md` for the full
    disclosure this job's shape is expected to match."""

    def test_job_depends_on_derive_version_verify_changelog_gate_package_and_binaries(
        self,
    ) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        needs = jobs["attest-artifacts"]["needs"]
        assert set(needs) == {
            "derive-version",
            "verify",
            "changelog-gate",
            "package",
            "build-binaries",
        }

    def test_job_only_holds_id_token_and_attestations_permissions(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        permissions = jobs["attest-artifacts"]["permissions"]
        assert permissions == {"id-token": "write", "attestations": "write"}
        assert "contents" not in permissions

    def test_uses_githubs_own_attest_build_provenance_action(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        steps = jobs["attest-artifacts"]["steps"]

        attest_steps = [
            step
            for step in steps
            if step.get("uses", "").startswith("actions/attest-build-provenance")
        ]
        assert len(attest_steps) == 1

    def test_no_external_signing_credential_is_referenced(self) -> None:
        """This is GitHub's own built-in, keyless (OIDC) attestation --
        never a third-party signing key, certificate, or paid service."""
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        job_upper = str(jobs["attest-artifacts"]).upper()

        for forbidden in ("GPG", "COSIGN_KEY", "PRIVATE_KEY", "SIGNING_KEY"):
            assert forbidden not in job_upper

    def test_includes_checksum_verification_and_a_tamper_negative_test(self) -> None:
        """Documented verification (verified in CI) and the tamper check (a
        tampered artifact fails verification) are each their own named
        step, mirroring `build-binaries`'s own "each disclosure gets its
        own attributable step" precedent."""
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        step_names = [step["name"] for step in jobs["attest-artifacts"]["steps"]]

        assert any("verify checksums" in name.lower() for name in step_names)
        assert any("verify attestations" in name.lower() for name in step_names)
        assert any("tampered" in name.lower() for name in step_names)

    def test_publish_job_downloads_and_attaches_the_checksums_file(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        publish_steps = jobs["publish-github-release"]["steps"]

        download_checksums_steps = [
            step
            for step in publish_steps
            if step.get("uses", "").startswith("actions/download-artifact")
            and step.get("with", {}).get("name") == "release-checksums"
        ]
        assert len(download_checksums_steps) == 1

        create_release_step = next(
            step for step in publish_steps if "gh release create" in step.get("run", "")
        )
        assert "SHA256SUMS" in create_release_step["run"]


class TestReleaseWorkflowMajorVersionTagStaysManual:
    """A floating `vMAJOR` tag policy (e.g. `v1` tracking the latest
    `vMAJOR.*.*` release) is documented in
    `docs/reference/marketplace-listing.md` as a manual,
    maintainer-performed step after each release -- deliberately NOT
    automated in this workflow, so
    `TestReleaseWorkflowScopeBoundary::test_never_pushes_a_tag_or_calls_uv_publish`'s
    existing "no workflow in this repository ever pushes a tag itself"
    invariant continues to hold unchanged. This class exists to make
    that deliberate non-automation explicit and regression-guarded,
    rather than relying solely on the pre-existing generic guard."""

    def test_no_step_moves_or_pushes_a_major_version_tag(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        publish_steps = jobs["publish-github-release"]["steps"]

        for step in publish_steps:
            run = step.get("run", "")
            assert "git tag" not in run
            assert "git push" not in run


class TestReleaseWorkflowPyPIPublish:
    """`publish-pypi` uploads the wheel and sdist with PyPI trusted
    publishing. A PyPI version can never be uploaded twice, so the job
    runs last, holds only the OIDC permission, and never reads a stored
    token."""

    def test_runs_only_after_the_github_release_is_published(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        needs = jobs["publish-pypi"]["needs"]
        assert set(needs) == {"derive-version", "publish-github-release"}

    def test_only_holds_the_id_token_permission(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        assert jobs["publish-pypi"]["permissions"] == {"id-token": "write"}

    def test_runs_in_the_pypi_environment(self) -> None:
        """PyPI's trusted publisher entry names this environment, so a
        rename here silently breaks every upload."""
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        assert jobs["publish-pypi"]["environment"]["name"] == "pypi"

    def test_uses_the_pypa_action_without_a_stored_token(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        steps = jobs["publish-pypi"]["steps"]

        publish = [
            step
            for step in steps
            if step.get("uses", "").startswith("pypa/gh-action-pypi-publish@")
        ]
        assert len(publish) == 1
        inputs = publish[0].get("with", {})
        assert "password" not in inputs
        assert "user" not in inputs
        assert "repository-url" not in inputs
        assert "secrets." not in str(jobs["publish-pypi"])

    def test_uploads_only_the_built_wheel_and_sdist(self) -> None:
        """The release manifest sits beside `dist/` in the downloaded
        artifact; PyPI must only ever see the distributions."""
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        steps = jobs["publish-pypi"]["steps"]

        download = [
            step
            for step in steps
            if step.get("uses", "").startswith("actions/download-artifact@")
        ]
        assert [step["with"]["name"] for step in download] == ["release-dist"]
        publish = next(
            step
            for step in steps
            if step.get("uses", "").startswith("pypa/gh-action-pypi-publish@")
        )
        assert publish["with"]["packages-dir"] == "release-dist/dist/"


class TestPublishContainerJob:
    def test_runs_only_after_the_github_release_and_every_gate(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        assert set(jobs["publish-container"]["needs"]) == {
            "derive-version",
            "verify",
            "changelog-gate",
            "publish-github-release",
        }

    def test_holds_packages_write_and_attestation_permissions_only(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        assert jobs["publish-container"]["permissions"] == {
            "contents": "read",
            "packages": "write",
            "id-token": "write",
            "attestations": "write",
        }

    def test_signs_in_to_ghcr_with_the_workflow_token(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        login = next(
            step
            for step in jobs["publish-container"]["steps"]
            if str(step.get("uses", "")).startswith("docker/login-action@")
        )

        assert login["with"]["registry"] == "ghcr.io"
        assert login["with"]["password"] == "${{ github.token }}"

    def test_smoke_tests_and_scans_before_pushing(self) -> None:
        """Order matters: the push step must come after both the smoke
        test and the vulnerability scan, and the scan must fail the job
        on a critical finding."""
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        steps = jobs["publish-container"]["steps"]
        names = [str(step.get("uses", step.get("run", ""))) for step in steps]

        smoke = next(i for i, name in enumerate(names) if "container-smoke.sh" in name)
        scan = next(
            i
            for i, name in enumerate(names)
            if name.startswith("aquasecurity/trivy-action@")
        )
        push = next(
            i
            for i, step in enumerate(steps)
            if str(step.get("uses", "")).startswith("docker/build-push-action@")
            and step["with"].get("push") is True
        )
        assert smoke < push and scan < push

        trivy = steps[scan]["with"]
        assert trivy["exit-code"] == "1"
        assert trivy["severity"] == "CRITICAL"

    def test_pushes_only_an_exact_version_tag_for_both_architectures(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        push = next(
            step
            for step in jobs["publish-container"]["steps"]
            if str(step.get("uses", "")).startswith("docker/build-push-action@")
            and step["with"].get("push") is True
        )

        assert push["with"]["tags"] == "${{ env.IMAGE }}:${{ env.VERSION }}"
        assert push["with"]["platforms"] == "linux/amd64,linux/arm64"
        raw = _RELEASE_WORKFLOW.read_text(encoding="utf-8")
        assert ":latest" not in raw

    def test_attests_the_pushed_digest(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        attest = next(
            step
            for step in jobs["publish-container"]["steps"]
            if str(step.get("uses", "")).startswith("actions/attest-build-provenance@")
        )

        assert attest["with"]["push-to-registry"] is True
        assert "digest" in attest["with"]["subject-digest"]


class TestPublishHomebrewJob:
    def test_runs_only_after_the_github_release(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        assert set(jobs["publish-homebrew"]["needs"]) == {
            "derive-version",
            "publish-github-release",
        }

    def test_is_skipped_until_the_tap_repository_is_configured(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]

        assert "vars.HOMEBREW_TAP_REPOSITORY" in jobs["publish-homebrew"]["if"]

    def test_renders_the_formula_from_the_release_checksums(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        runs = " ".join(
            str(step.get("run", "")) for step in jobs["publish-homebrew"]["steps"]
        )

        assert "release-scripts/homebrew_formula.py" in runs
        assert "release-checksums/SHA256SUMS" in runs

    def test_writes_through_the_api_with_the_tap_token_only(self) -> None:
        jobs = _load(_RELEASE_WORKFLOW)["jobs"]
        write = next(
            step
            for step in jobs["publish-homebrew"]["steps"]
            if "gh api --method PUT" in str(step.get("run", ""))
        )

        assert write["env"]["GH_TOKEN"] == "${{ secrets.HOMEBREW_TAP_TOKEN }}"
        assert jobs["publish-homebrew"]["permissions"] == {"contents": "read"}
