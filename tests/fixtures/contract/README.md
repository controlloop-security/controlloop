# Platform contract fixtures

The CLI's Team client talks to the ControlLoop platform, which is not part
of this repository. These files are copies of the parts of the platform's
contract the Team client must agree with, so the tests can hold the CLI to
them without depending on the platform's source.

| File | What it is | Read by |
| --- | --- | --- |
| `version_range_vectors.json` | Accepted and refused version ranges, and which versions each range contains | `tests/team/test_sanction.py` |
| `flagging_vectors.json` | Components, approved-component entries, and the sanction state each must produce | `tests/team/test_sanction.py` |
| `policy_merge_vectors.json` | Approved-component constraint merges under strengthen-only semantics | `tests/team/test_sanction.py` |
| `policy-merge-vectors.json` | Organization and repository rule merges, with the effective policy each must produce | `tests/team/test_policy_merge.py` |
| `platform-contract-subset.json` | The `ScanEnvelopeRequest` and `PolicyBundleCreateRequest` request schemas and every schema they reference | `tests/team/test_envelope_authority.py`, `tests/team/test_example_bundle.py` |
| `envelope-field-rules.json` | The platform's field rules for envelope attributes, approved-component digests, and command patterns | the same two tests |

When the platform's contract changes, these files are refreshed from it in
the same change that updates the CLI, so the two can never disagree about
an effective policy, a sanction verdict, or what an envelope may carry.
