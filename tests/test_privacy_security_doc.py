"""Tests for `docs/reference/privacy-security.md`.

These are presence/sync checks, not full-text golden equality (unlike
`tests/concepts/test_acbom_concepts_doc.py`'s doc, this page is mostly
authored prose, not content mechanically generated from a fixture).
What they guard against is a claim silently going stale: a newly
registered adapter with no matching doc entry, or a doc claim whose
named evidence (a test file, a doc section) stops existing.
"""

from __future__ import annotations

from pathlib import Path

from controlloop.adapters import ALL_ADAPTERS

_DOC_PATH = (
    Path(__file__).resolve().parents[1] / "docs" / "reference" / "privacy-security.md"
)


def _doc_text() -> str:
    return _DOC_PATH.read_text(encoding="utf-8")


class TestAdapterCoverageStaysInSync:
    """Every registered adapter's declared depth and explicit gap are
    listed."""

    def test_every_registered_adapter_class_is_named(self) -> None:
        doc_text = _doc_text()

        for adapter_class in ALL_ADAPTERS:
            assert adapter_class.__name__ in doc_text

    def test_live_mcp_normalization_is_disclosed_as_not_registered(self) -> None:
        doc_text = _doc_text()

        assert "normalize_live_mcp_server" in doc_text
        assert "not in `ALL_ADAPTERS`" in doc_text


class TestOfflineEvidenceIsNamed:
    """The document names the real offline test as evidence, not only a
    general claim."""

    def test_offline_harness_test_file_is_named(self) -> None:
        assert "test_offline_harness.py" in _doc_text()

    def test_offline_test_classes_are_named(self) -> None:
        doc_text = _doc_text()

        assert "TestNetworkDenialRaisesLoudly" in doc_text
        assert "TestCoreSurfaceCompletesOffline" in doc_text

    def test_offline_canary_test_file_and_classes_are_named(self) -> None:
        """The individually-named, per-command offline evidence, and the
        deliberate-violation proof, are both named here too -- not only
        implied by the general harness evidence above."""

        doc_text = _doc_text()

        assert "test_offline_canary.py" in doc_text
        assert "TestEveryCoreCommandCompletesOffline" in doc_text
        assert "TestDeliberateNetworkCallFailsImmediately" in doc_text


class TestOutOfScopeIsExplicit:
    """Runtime enforcement and malicious-component detection are named as
    out of scope, not only implied by omission."""

    def test_runtime_interception_named(self) -> None:
        assert "Runtime traffic interception" in _doc_text()

    def test_malicious_component_detection_named(self) -> None:
        assert "Malicious-component" in _doc_text()

    def test_windows_named(self) -> None:
        assert "Windows support" in _doc_text()

    def test_automatic_remediation_named(self) -> None:
        assert "Automatic remediation that edits customer code" in _doc_text()


class TestThreatModelIsLinked:
    """`SECURITY.md` is linked as the threat model and reporting process."""

    def test_security_md_is_linked(self) -> None:
        assert "(../../SECURITY.md)" in _doc_text()

    def test_scope_priorities_named(self) -> None:
        assert "Scope priorities" in _doc_text()

    def test_reporting_a_vulnerability_named(self) -> None:
        assert "Reporting a vulnerability" in _doc_text()


class TestBoundary:
    def test_doc_file_exists_and_is_not_empty(self) -> None:
        assert _DOC_PATH.is_file()
        assert len(_doc_text()) > 0
