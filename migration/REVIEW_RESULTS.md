# Local review record — versioned-profile migration

Publication candidate, not production approval. Independent peer review remains
pending. The local oracle and campaigns run in one Codex/Windows session, not a
third-party audit.

- Historical main: 9dd36e882dd372f264b77b179130948aa5adcbde.
- Frozen RC2: f4476754c92e0bea549474722108ec60ded1385a.
- Repaired implementation preserved: f42d356d9e6cc4df93d80573471456b647ba95b2.
- New profile: 7cf7c2c84795e941c03a24861ef1a0c4ee55dfdf20bd9d5374cc07a5173b89bf.

The new commit restores the published conformance adapters/manifest and places
the repaired algorithms unchanged in a separately pinned package. All 60 prior
files under conformance/, profiles/ and docs/spec/ match historical main bytes.
The RC2 copy and 37 registered package files match their recorded identities.

Migration: 22 declared scenarios, each normal/repeat/Python-O: 66/66 expected
results. Both implementations evaluate each selected request. Cases include
same profileId/different digest, unknown identity, substituted profile, missing
historical profile, old empty-mediaType acceptance/new-profile rejection,
Unicode input, tampered receipt/payload, missing payload, claimed adapter hint,
independent expected-pin mismatch and a legitimate DIVERGED comparison.

Six physical dispatcher removals are KILLED with healthy negative, positive
and restored controls. The synthetic conflicting-runtime control injects a
different observation in a disposable copy; it is not evidence that the
published historical profile necessarily diverges. Some removals test loss of
failure classification/integrity specificity, not necessarily false acceptance.

Repaired schema suite: 158 scenarios / 790 Python and TypeScript CLI executions,
all expected. Twenty-one existing physical repair mutants KILLED. Original
32 inherited regression command lanes pass. Frozen Rust RC2 reviewer and Clippy
pass. The new-profile native conformance CLI passes Python normal/repeat/O and
TypeScript normal/repeat. The separately implemented jsonschema/Bun oracle is
required before publication; raw evidence records its actual runs.

Initial failure retained: the migration test initially predicted different
legacy handling of a final newline. Actual Python and Bun both reject the
anchored identifier; direct native regex checks confirm this. The test was
corrected to rejection, with the failed campaign preserved. No adapter was
changed to fit that expectation. An initial oracle invocation omitted required
--ucd; it failed with usage exit2 and is not a semantic pass.

Compatibility limits: no automatic conversion of signed receipts, no new
signature, no external-profile adapter migration, and no universal claim about
all historical receipts. Unknown historical contracts remain CANNOT_RECOMPUTE.
This layer adds no ERC fields, reason codes or normative semantics. The new
profile's explicit nonempty mediaType constraint is for newly issued receipts
only. Review the trust root (source+registry), runtime pins and bridge boundary
before adopting the layer.

Reproduce using migration/README.md and the dedicated workflow. Historic
evidence and expected outputs remain unchanged. The PR is to remain Draft;
no merge, deployment or change to ethereum/ERCs is authorized by this work.
