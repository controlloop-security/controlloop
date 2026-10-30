"""`action.yml` metadata that GitHub Marketplace checks before it lists
the Action. The publish form refuses a release whose metadata fails, so
these are held here rather than discovered there."""

from __future__ import annotations

from pathlib import Path

import yaml

_ACTION = Path(__file__).resolve().parents[1] / "action.yml"

#: Marketplace's limit: the description must be shorter than this.
_MARKETPLACE_DESCRIPTION_LIMIT = 125


def _metadata() -> dict[str, object]:
    document = yaml.safe_load(_ACTION.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_the_description_is_short_enough_for_marketplace() -> None:
    description = _metadata()["description"]
    assert isinstance(description, str)
    assert description.strip()
    assert len(description) < _MARKETPLACE_DESCRIPTION_LIMIT, len(description)


def test_the_listing_has_a_name_and_branding() -> None:
    metadata = _metadata()
    assert metadata["name"] == "ControlLoop Security"
    assert metadata["branding"] == {"icon": "shield", "color": "blue"}
