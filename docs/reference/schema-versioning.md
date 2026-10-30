---
type: reference
title: Schema versioning and compatibility policy
tags:
  - reference
  - acbom
  - schema
created: 2026-08-19
---

# Schema versioning and compatibility policy

The canonical ACBOM schema (`schema_version`) follows semantic versioning:
`MAJOR.MINOR.PATCH`. This page states what each part means for this schema
specifically, and how a reader decides whether it can read a given
document.

## What each part means

- **MAJOR** — any breaking change: removing or renaming a field, changing
  an existing field's type or meaning, tightening a validation constraint
  so previously-valid data would now be rejected, removing an enum
  member, or changing the canonical ID algorithm. A reader on a different major
  version must not attempt to read the document.
- **MINOR** — a backward-compatible addition: a new optional field, or a
  new enum member added somewhere existing consumers already tolerate an
  unrecognized value. A reader can read any document at or below its own
  minor version, within the same major.
- **PATCH** — a change that does not affect the wire format at all (for
  example, a `description` field edited for clarity in the packaged JSON
  Schema, or scanner-internal changes). Always compatible.

## Why compatibility is one-directional, not bidirectional

Every canonical model uses `extra="forbid"`: an unrecognized field is
rejected outright, not silently ignored. This means an **older** reader
given a **newer**-minor document cannot simply skip a field it does not
know about — it would reject the document with a raw, confusing
`extra_forbidden` error partway through parsing.

The compatibility rule is therefore: **a reader can read any document at
or below its own `schema_version`, within the same major.** A document
from a newer minor or a different major is rejected before any full
parse is attempted, with a clear message naming both versions — never a
raw validation error from a partial parse. `controlloop.acbom.versioning`
implements this as `check_schema_version_compatible` and
`load_acbom_document`.

## What this does not authorize

This page defines the *vocabulary* for recognizing a compatible versus a
breaking change. It does not grant authority to ship a breaking change.
The project's architecture rules already require a maintainer-approved
issue, a migration plan, golden vectors, privacy tests, and a
release-impact review before the canonical ID algorithm or ACBOM
versioning changes — that gate applies to any MAJOR bump under this
policy, unchanged.

## Enforcement

- `tests/acbom/test_versioning.py` and
  `src/controlloop/acbom/versioning.py` implement and test the
  compatibility rule above.
- A committed golden digest of the packaged JSON Schema file, checked
  against the live file on every test run, fails the build if the schema
  changes without the version-bump process this page describes going
  with it.

## Current status

`1.2.0` is current; `1.0.0` and `1.1.0` are frozen historical versions
(`src/controlloop/schemas/acbom/1.0.0/` and `1.1.0/`, never edited, each
held to a recorded digest by `tests/acbom/test_versioning.py`).

The `1.2.0` MINOR bump adds the agent authority
contract, every part of it optional:

- Four security flags, each `true`, `false`, or `unknown`:
  `bypass_mode`, `wildcard`, `pinned`, `untrusted_input`.
- `attributes` on a node: at most 32 keys, each a lowercase name such as
  `event` or `pattern`, mapped to a string of 1 to 512 characters with
  no control characters. A key that names a value category (`value`,
  `password`, `prompt`, `body`, `output`, `private_key`, `source_code`)
  is rejected. Attributes record what a file grants, never a value it
  protects.
- Nine subtypes on existing node types, each with the attributes and
  flags it must carry:

  | Subtype | Node type | Required attributes | Required flags |
  | --- | --- | --- | --- |
  | `host` | `agent` | `host` | |
  | `subagent` | `agent` | | |
  | `hook` | `tool` | `event`, `hook_type` | `code_execution` |
  | `helper-command` | `tool` | `setting` | `code_execution` |
  | `plugin` | `tool` | `source_type` | `pinned` |
  | `marketplace` | `tool` | `source_type` | `pinned` |
  | `skill` | `tool` | | |
  | `workflow-runtime` | `trigger` | `job_permissions` | |
  | `permission-rule` | `permission` | `effect`, `pattern` | `wildcard` |

  Any other subtype is free text, as before.

No node type or edge type was added. A `1.1.0` or `1.0.0` document still
reads, and an unmodified one recomputes to the digest it was written
with: the new flags and an empty `attributes` map are left out of the
canonical bytes when unset.

The `1.2.0` schema also accepts `null` wherever the model writes it for
an unset optional field (security flags, `sensitivity`, `subtype`,
evidence locations, `schema_url`). The `1.1.0` schema did not, so a
document `bom` wrote failed validation against the `1.1.0` schema file
with an external JSON Schema validator; `bom --validate` was never
affected, because it validates with the model. Every committed golden
ACBOM is now validated against the packaged schema in the test suite.

Attribute keys recorded since `1.2.0` without a version change, since
`attributes` already accepts any lowercase key and the wire format is
unchanged: `script_path` and `script_digest` on `hook` and
`helper-command` nodes (the script a command runs, by repository path
and SHA-256, or `unknown`), and `slug`, `groups`, `mode`, and
`docs_snapshot` on Roo Code mode nodes and their rules.

The `1.1.0` bump added `ACBOMDocument.schema_url`, the
permanent, versioned URL the document's schema is published at (where it is hosted is a separate, recorded decision). Every document `bom` generates populates it.
`bom --validate` (see the [CLI reference](cli.md#bom)) validates an
existing ACBOM file against this reader's own current schema version;
`bom` and `scan` are both implemented, non-stub commands.
