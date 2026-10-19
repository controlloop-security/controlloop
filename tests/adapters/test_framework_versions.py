"""The shared framework version registry."""

from __future__ import annotations

import pytest

from controlloop.adapters import framework_versions as fv


class TestRegistryIsProven:
    def test_the_shipped_registry_is_sound(self) -> None:
        """Fails CI if a support range is widened without a
        conformance fixture behind it."""

        assert fv.validate_registry() == ()

    def test_a_range_with_no_fixture_is_rejected(self) -> None:
        """The registry check's teeth: editing a constant is not enough."""

        unproven = {
            "ghost": fv.FrameworkSupport(
                framework="ghost",
                distribution="ghost",
                minimum=(1, 0),
                exclusive_maximum=(2, 0),
            )
        }
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(fv, "SUPPORTED_FRAMEWORKS", unproven)
            problems = fv.validate_registry()
        assert any("no conformance fixture" in problem for problem in problems)

    def test_an_inverted_range_is_rejected(self) -> None:
        inverted = {
            "ghost": fv.FrameworkSupport(
                framework="ghost",
                distribution="ghost",
                minimum=(2, 0),
                exclusive_maximum=(1, 0),
                verified_by=("x",),
            )
        }
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(fv, "SUPPORTED_FRAMEWORKS", inverted)
            problems = fv.validate_registry()
        assert any("not below" in problem for problem in problems)


class TestVersionParsing:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("0.86.0", (0, 86)),
            ("1.2", (1, 2)),
            ("0.86.0rc1", (0, 86)),
            ("  0.90.1  ", (0, 90)),
        ],
    )
    def test_release_segment(self, raw: str, expected: tuple[int, int]) -> None:
        assert fv.parse_release(raw) == expected

    @pytest.mark.parametrize("raw", ["", "latest", "v-one", "main"])
    def test_a_non_version_is_none_not_a_guess(self, raw: str) -> None:
        assert fv.parse_release(raw) is None


class TestDeclaredVersion:
    @pytest.mark.parametrize(
        ("dependency", "expected"),
        [
            ("crewai>=0.86.0", "0.86.0"),
            ("crewai==0.86.0", "0.86.0"),
            ("crewai ~= 0.86", "0.86"),
            ("crewai>=0.86.0,<0.90", "0.86.0"),
            ("crew_ai>=0.86.0", None),
        ],
    )
    def test_lower_bound_is_read(self, dependency: str, expected: str | None) -> None:
        """The lower bound is the oldest version the project claims to
        work with, and therefore the one the adapter must be able to
        parse."""

        assert fv.declared_version((dependency, "pydantic>=2"), "crewai") == expected

    def test_an_unpinned_dependency_is_undeterminable_not_current(self) -> None:
        assert fv.declared_version(("crewai",), "crewai") is None

    def test_an_absent_dependency_is_none(self) -> None:
        assert fv.declared_version(("pydantic>=2",), "crewai") is None

    def test_an_underscore_variant_still_matches(self) -> None:
        assert fv.declared_version(("crew_ai>=0.86.0",), "crew-ai") == "0.86.0"


class TestRefusal:
    def test_a_supported_version_resolves(self) -> None:
        assert fv.require_supported("crewai", "0.86.0") == (0, 86)

    @pytest.mark.parametrize("version", ["0.1.0", "2.0.0", "1.0.0"])
    def test_an_out_of_range_version_is_refused(self, version: str) -> None:
        """Refused, not parsed as if supported."""

        with pytest.raises(fv.UnsupportedFrameworkVersionError):
            fv.require_supported("crewai", version)

    def test_an_undeclared_version_is_refused_not_assumed_current(self) -> None:
        """The dangerous alternative is resolving `None` to the
        newest supported version, which turns an unknown into a
        confident parse."""

        with pytest.raises(fv.UnsupportedFrameworkVersionError) as caught:
            fv.require_supported("crewai", None)
        assert "unsupported rather than assumed current" in str(caught.value)

    def test_an_unparseable_version_takes_the_same_path(self) -> None:
        with pytest.raises(fv.UnsupportedFrameworkVersionError):
            fv.require_supported("crewai", "latest")

    def test_an_unregistered_framework_is_refused(self) -> None:
        with pytest.raises(fv.UnsupportedFrameworkVersionError):
            fv.require_supported("ghost", "1.0.0")

    def test_the_refusal_path_works_with_an_empty_registry(self) -> None:
        """The OASF precedent: the mechanism must be real and
        tested even when it governs nothing."""

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(fv, "SUPPORTED_FRAMEWORKS", {})
            assert fv.validate_registry() == ()
            with pytest.raises(fv.UnsupportedFrameworkVersionError):
                fv.require_supported("crewai", "0.86.0")

    def test_a_refusal_never_echoes_repository_content(self) -> None:
        """The message names found and supported versions only. A
        dependency string is untrusted repository content."""

        with pytest.raises(fv.UnsupportedFrameworkVersionError) as caught:
            fv.require_supported("crewai", "9.9.9; rm -rf /")
        assert "rm -rf" not in str(caught.value)
