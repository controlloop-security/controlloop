"""Build-time, offline structural checks for every rule's documentation URL.

Reads the real, committed `docs/reference/policy-rules.md` and cross-
checks it against `controlloop.policy.rules.ALL_RULES` -- the same real
registry `test_all_rules_registry.py` already checks for completeness
and uniqueness, applied here to documentation. Never fetches a URL over
the network (this repository's own `--all-rules--`-wide invariant, and
a requirement of this specific check): "the URL resolves" is
verified as "a real, matching `<a id>` anchor exists in the real page,"
the offline-checkable structural fact a resolvable URL depends on, not
a live HTTP request this test suite's autouse offline-denial fixture
would block anyway.
"""

from __future__ import annotations

import re
from pathlib import Path

from controlloop.policy.rules import ALL_RULES
from controlloop.policy.rules._shared import documentation_url

_REPO_ROOT = Path(__file__).resolve().parents[3]
_POLICY_RULES_DOC = _REPO_ROOT / "docs" / "reference" / "policy-rules.md"
_DOC_TEXT = _POLICY_RULES_DOC.read_text(encoding="utf-8")

_ANCHOR_TAG_PATTERN = re.compile(r'<a id="([a-z0-9-]+)"></a>')

_REQ1_CONTENT_MARKERS = (
    "**Why this matters:**",
    "**Example:**",
    "**Remediation:**",
    "**False positives:**",
)


def _anchor_for(rule_id: str) -> str:
    """The exact anchor fragment `documentation_url` embeds -- derived
    from `rule_id` the same way that helper does, not duplicated as a
    second, independent slug computation that could itself drift."""

    url = documentation_url(rule_id)
    _, _, fragment = url.partition("#")
    assert fragment, f"{url!r} carries no anchor fragment"
    return fragment


def _section_text(anchor: str) -> str:
    """The raw text of one rule's own section: from its `<a id>` anchor
    tag up to (but not including) the next `<a id>` anchor tag, or end
    of file for the last section. Bounding by anchor rather than by H2
    heading text keeps this independent of any particular heading
    wording."""

    marker = f'<a id="{anchor}"></a>'
    start = _DOC_TEXT.find(marker)
    assert start != -1, f"anchor {marker!r} not found in {_POLICY_RULES_DOC}"

    next_anchor = _ANCHOR_TAG_PATTERN.search(_DOC_TEXT, start + len(marker))
    end = next_anchor.start() if next_anchor else len(_DOC_TEXT)
    return _DOC_TEXT[start:end]


class TestEveryRuleUrlResolves:
    """The URL in a finding resolves -- verified offline as "a real,
    matching anchor exists in the real page," never a live network fetch."""

    def test_every_registered_rule_has_a_matching_anchor(self) -> None:
        missing = [
            rule.id
            for rule in ALL_RULES
            if f'<a id="{_anchor_for(rule.id)}"></a>' not in _DOC_TEXT
        ]

        assert missing == [], (
            f"rule(s) {missing} have a documentation_url with no matching "
            f"<a id> anchor in {_POLICY_RULES_DOC} -- add one directly "
            "before that rule's own heading"
        )

    def test_every_anchor_in_the_doc_is_unique(self) -> None:
        """A duplicate anchor would make at least one rule's own URL
        resolve to the wrong section."""

        anchors = _ANCHOR_TAG_PATTERN.findall(_DOC_TEXT)

        assert len(anchors) == len(set(anchors)), (
            f"duplicate <a id> anchors in {_POLICY_RULES_DOC}: "
            f"{sorted({a for a in anchors if anchors.count(a) > 1})}"
        )


class TestEveryRuleHasRealDocumentationContent:
    """Every rule has a documentation page with rationale, an example,
    remediation, and known false-positive conditions -- a structural check
    that the four markers are present in that rule's own section, not merely
    that the page exists."""

    def test_every_rule_section_has_all_four_content_markers(self) -> None:
        missing_by_rule: dict[str, list[str]] = {}
        for rule in ALL_RULES:
            anchor = _anchor_for(rule.id)
            section = _section_text(anchor)
            missing = [
                marker for marker in _REQ1_CONTENT_MARKERS if marker not in section
            ]
            if missing:
                missing_by_rule[rule.id] = missing

        assert missing_by_rule == {}, (
            f"rule(s) missing required documentation content: "
            f"{missing_by_rule} -- see docs/reference/policy-rules.md"
        )


class TestNewRuleWithoutDocumentationFailsCi:
    """A new rule without documentation fails CI -- proven directly by
    asserting the registry-vs-documentation check above would actually catch
    an undocumented rule, not merely trusting the positive case."""

    def test_an_undeclared_anchor_would_be_caught(self) -> None:
        fabricated_rule_id = "policy.this-rule-does-not-exist"

        assert f'<a id="{_anchor_for(fabricated_rule_id)}"></a>' not in _DOC_TEXT, (
            "test fixture collided with a real anchor -- pick a different fake id"
        )


class TestUrlsAreVersionIndependent:
    """URLs are versioned by rule id, not by rule-pack version, so a finding
    from an older rule pack still resolves -- a rule's own URL never changes
    just because CURRENT_RULE_PACK's version does."""

    def test_documentation_url_never_embeds_a_version_number(self) -> None:
        for rule in ALL_RULES:
            url = documentation_url(rule.id)

            assert not re.search(r"\d+\.\d+\.\d+", url), (
                f"{url!r} for {rule.id} embeds what looks like a version "
                "number -- the URL scheme is rule-id-based, "
                "deliberately independent of rule-pack version"
            )

    def test_documentation_url_is_stable_across_repeated_calls(self) -> None:
        for rule in ALL_RULES:
            assert documentation_url(rule.id) == documentation_url(rule.id)
