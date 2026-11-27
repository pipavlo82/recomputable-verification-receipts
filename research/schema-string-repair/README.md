# Local schema-string repair candidate — HOLD

Canonical repository: `pipavlo82/recomputable-verification-receipts`.
Baseline: `9dd36e882dd372f264b77b179130948aa5adcbde` (v0, post-RC2 main).
This is an adapter implementation repair candidate, not a new ERC or profile.

Changes:

- Python and TypeScript enforce minLength/maxLength using Unicode code-point
  lengths, rejecting malformed bound types/values as schema errors.
- Python pattern validation uses search instead of fullmatch. The bounded
  end-anchor correction is documented in ANCHOR_ANALYSIS.md.
- Both adapters report invalid regex syntax/types through GateRejection rather
  than an uncaught regex-engine exception. No new regex engine is introduced.
- Integral JSON numeric bounds such as `1.0` are accepted, like `1`; booleans,
  negative and fractional bounds are rejected. A preserved intermediate witness
  caught Python incorrectly rejecting `1.0`; a physical mutation covers the fix.

The existing profile, schema contracts, expected.json, mutants.json and historical
receipts are unchanged. The current branch's derived distribution manifest changes
only the two adapter pins and aggregate package digest. That is a new candidate
distribution, not a replacement of the tagged RC2 or preserved checkout.

## Reproduce

Use a fresh clone containing the baseline commit and Python 3.12, Bun 1.3.14,
Node 22 and jsonschema 4.26.0. Output paths must not already exist.

```text
python -B research/schema-string-repair/harness.py --output <new-campaign-path> --baseline-too
python -B research/schema-string-repair/oracle.py --campaign <new-campaign-path>
python -B research/schema-string-repair/mutations.py --output <new-mutation-path>
python -B research/schema-string-repair/regressions.py --output <new-regression-path>
```

The harness uses `git archive` of the exact baseline, constructs explicitly
synthetic hash-pinned profile packages, and runs the documented full public CLI.
It never changes the checkout's profiles or expectations. Baseline and repaired
adapters receive the same profile/input bytes; only adapter files and their
derived distribution manifest differ. Existing historical failure evidence is
outside this repository and stays unchanged.

Cases marked known_gap are reported, not hidden or treated as conforming PASS.
Crashes are never mutation kills. KILLED requires healthy positive/restored
controls and an observed semantic acceptance/rejection change.

## Compatibility and version boundary

The profile digest stays unchanged because its contracts are unchanged and
adapters are not its normative authority. Corrected implementations can reject
an input an older implementation incorrectly accepted, or accept one it incorrectly
rejected. Historical receipts/results are not rewritten or reinterpreted.

The unchanged RC2 baseline policy requires new versions/identities for corrections.
This local candidate has a new Git/source/package identity; it does not claim an
approved release version or retroactive RC2 conformance. An agreed adapter release
and supported-pattern policy is still needed before publication. No schema-helper
wire version or new conformance-profile identity is silently assigned.

Remaining known limits include Python/ECMAScript dot and digit-class semantics on
Unicode and ignored `$ref` sibling assertions in both inherited validators.
Other unsupported JSON Schema keywords are not made supported by this patch.
Do not advertise full JSON Schema 2020-12 or full ECMA-262 conformance. No push,
Draft PR, merge, deployment or ERC PR1980 changes are performed automatically.
Production HOLD.
