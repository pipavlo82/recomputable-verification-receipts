# Unicode / reference repair: local compatibility proposal

Baseline candidate: ceb9bf18a7c346d4bebcca7f92dfc76fa40e4dea.
Historical source, profiles, receipts and the earlier no-flags lab are unchanged.

Normative sources: JSON Schema 2020-12 Core sections 4.2.1, 6.4, 8.2.3.1;
Validation sections 6.3.1-6.3.3. Core recommends (SHOULD, not MUST) ECMA-262
Unicode support. `$ref` is an applicator, not an instruction to ignore siblings.

https://json-schema.org/draft/2020-12/json-schema-core
https://json-schema.org/draft/2020-12/json-schema-validation
https://tc39.es/ecma262/#sec-runtime-semantics-compileassertion
https://tc39.es/ecma262/#sec-runtime-semantics-charactersetmatcher-abstract-operation

Proposed candidate policy: standard ECMA-262 RegExp with exactly the `u` flag,
search semantics, no added `i`, `m`, `s`, `g`, or implicit anchors. Dot consumes
one code point except ECMAScript line terminators. `\d` is [0-9], even in `u`
mode; Unicode decimal digits need an explicitly different pattern such as
`\p{Decimal_Number}`. Invalid Unicode-mode patterns are schema errors.
All supported siblings of a local `$ref` are conjunctively evaluated.
This does not add remote reference fetching or certify full JSON Schema support.

Do not translate Python regex syntax into a newly invented dialect. The local
candidate will use an actual ECMAScript engine for Python's schema regex
operations (Node/V8), and native RegExp in TypeScript (Bun/JavaScriptCore).
Node becomes an explicit implementation runtime dependency; it is not an
evaluation input or a substitute for a pinned Verification Profile. No fallback
to Python `re`. Runtime absence/failure must report inability to check, not
invalid evidence or a conformance PASS. Runtime identity is part of provenance.

Compatibility decision before editing adapters: publish nothing yet. Existing
profile identities stay unchanged because their bytes stay unchanged, but that
does NOT grant permission to silently apply this engine policy to historical
receipts. The candidate is opt-in by exact Git/package identity, not a release
replacement. An explicit old no-flags profile is incompatible with this proposed
Unicode policy and requires its old adapter; the preserved 61-case lab remains
an authoritative counterexample to claiming a universal drop-in replacement.

The new test packages have their own explicitly pinned Unicode-mode laboratory
specification and profile identity. Their new expected outcomes are not edits
to historical expected.json, old cases.json, or prior evidence. In particular
the old no-flags dot/emoji expectation remains REJECT, whereas the Unicode-mode
profile expects ACCEPT. This is a contract difference, not a repaired test result.

Before a release: agree an adapter version and its supported-profile binding,
including a migration rule for profiles that explicitly selected different
regex semantics. If an existing contract is ambiguous, use a new versioned
conformance profile for new receipts, not a reinterpretation of signed history.
Finite published fixtures cannot prove that every historical receipt is unchanged.
No new release tag or approved standard is asserted by this research candidate.

Reviewer question: Can the next explicitly versioned adapter/profile contract
require ECMA-262 Unicode (`u`) search semantics and conjunctive `$ref` siblings,
while old exact adapter/profile pins remain the historical verification route?
Which existing profile identities, if any, are authorized to adopt that behavior
without a new profile identity? Until settled: HOLD, no push or Draft PR.
