Vendored third-party fixture for the SARIF export.

- **File:** `sarif-schema-2.1.0.json`
- **Source:** `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json`
- **Fetched:** 2026-08-20
- **Upstream `$id`:** `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`
- **Content:** unmodified, as fetched.
- **License:** OASIS Static Analysis Results Interchange Format (SARIF)
  TC standard; GitHub reports the upstream repository's license
  metadata as `NOASSERTION` (no SPDX identifier detected), so this is
  disclosed rather than asserted. The schema is the normative,
  publicly published technical artifact of a ratified interoperability
  standard whose stated purpose is third-party implementation and
  validation -- the same schema file many public SARIF-producing tools
  vendor for the identical purpose.
- **Purpose:** `tests/reporting/test_sarif.py` validates
  `controlloop.reporting.sarif.render_sarif_log`'s output against this
  file with `jsonschema.Draft4Validator` (the SARIF 2.1.0 schema's own
  `"$schema"` field declares `http://json-schema.org/draft-04/schema#`),
  proving that the output validates against the SARIF 2.1.0 schema,
  locally and offline, without a network dependency at test time. It ships only in the source distribution
  (`tests/` is not part of the built wheel; see `pyproject.toml`'s
  `[tool.hatch.build.targets.wheel]`), never in the installed package.
