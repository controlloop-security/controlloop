"""Deterministic canonicalization, serialization, and digesting for
baseline documents.

Mirrors `controlloop.acbom.serialization`'s discipline exactly,
reusing its `canonical_json_bytes` primitive rather than
reimplementing JSON canonicalization: tamper/truncation detection
(`controlloop.baseline.integrity`) is only as trustworthy as this
module's digest, and that digest is trustworthy because it is the same
canonicalization primitive already proven deterministic for the ACBOM.
"""

from __future__ import annotations

import hashlib

from pydantic_core import PydanticSerializationError

from controlloop.acbom.models import Sha256Digest
from controlloop.acbom.serialization import CanonicalizationError, canonical_json_bytes
from controlloop.baseline.models import BaselineDocument
from controlloop.capability.models import EffectiveAuthorityEntry


def _entry_sort_key(entry: EffectiveAuthorityEntry) -> tuple[str, str, str, str]:
    return (
        entry.agent_id,
        str(entry.action),
        entry.resource_id,
        entry.permitting_identity_id or "",
    )


def canonicalize_baseline(document: BaselineDocument) -> BaselineDocument:
    """Return a new frozen document with `effective_authority` sorted
    into canonical order, regardless of construction order. Mirrors
    `controlloop.acbom.serialization.canonicalize_document`."""

    if not isinstance(document, BaselineDocument):
        raise CanonicalizationError("unsupported canonical baseline document category")

    try:
        sorted_entries = tuple(
            sorted(document.effective_authority, key=_entry_sort_key)
        )
    except (AttributeError, TypeError, ValueError):
        raise CanonicalizationError(
            "canonical baseline document contains an unsupported value category"
        ) from None

    return document.model_copy(update={"effective_authority": sorted_entries})


def _document_data(
    document: BaselineDocument,
    *,
    exclude_digest: bool,
) -> dict[str, object]:
    """Return `document`'s canonical field data as a plain dict.

    `provenance` is dropped from the result entirely when it is `None`,
    rather than serialized as an explicit `null` -- unlike every other
    field here, which this module has always dumped unconditionally,
    `null` included, matching `model_dump`'s ordinary behavior. This
    one field needs the special case because it did not exist in schema
    `1.0.0`: every baseline digested and committed under schema `1.0.0`
    (including `tests/fixtures/baseline/minimal-baseline.json`, the
    original fixture) had its digest computed over a field set that
    never included `provenance` at all. Serializing an *absent*
    `provenance` as `"provenance": null` today would add bytes to the
    canonicalization input that were never part of that original
    computation, making every pre-existing, legitimately unmodified
    baseline recompute to a *different* digest than the one already
    committed for it -- a false tamper positive on a real, unmodified,
    unrelated document, defeating the entire point of a
    backward-compatible minor version bump. Dropping the key when unset
    restores byte-for-byte identical canonical input to the `1.0.0`
    model for any document that never carried real provenance, while a
    *present* `provenance` (the case that matters -- provenance someone
    recorded) remains fully covered by the digest exactly like every
    other field.
    """
    canonical = canonicalize_baseline(document)
    try:
        data = canonical.model_dump(
            mode="json",
            exclude={"digest"} if exclude_digest else None,
            warnings="error",
        )
    except (PydanticSerializationError, TypeError, ValueError):
        raise CanonicalizationError(
            "canonical baseline document contains an unsupported value category"
        ) from None
    if canonical.provenance is None:
        data.pop("provenance", None)
    return data


def serialize_baseline(document: BaselineDocument) -> bytes:
    """Return canonical UTF-8 JSON bytes including the document digest."""

    return canonical_json_bytes(_document_data(document, exclude_digest=False))


def compute_baseline_digest(document: BaselineDocument) -> Sha256Digest:
    """Return the SHA-256 digest of canonical bytes excluding `digest`."""

    digest_input = canonical_json_bytes(_document_data(document, exclude_digest=True))
    return f"sha256:{hashlib.sha256(digest_input).hexdigest()}"


def with_baseline_digest(document: BaselineDocument) -> BaselineDocument:
    """Return a new canonical frozen document containing its computed
    digest."""

    canonical = canonicalize_baseline(document)
    return canonical.model_copy(update={"digest": compute_baseline_digest(canonical)})
