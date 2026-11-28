# Unicode data repair candidate: explicit compatibility boundary

Migration follow-up: this document records the f42d356 candidate boundary.
The new [exact-profile layer](../../migration/README.md) now implements separate
historical/new routes. The repaired bytes live in profiles/generic-ucd17-v1;
conformance/rvr-v0 is restored to the published baseline. The earlier publication
blocker below is retained as history; current readiness requires the migration
controls and independent Draft PR review. No old receipt acquires this policy.

This is an opt-in research candidate, not a replacement for frozen RC2 or a
retroactive interpretation of an existing signed receipt. The ERC is unchanged.

## Cause, not a choice of whichever engine passes

U+11DE0..U+11DE9 are Tolong Siki decimal digits introduced in Unicode 17.0.0.
The official UnicodeData files contain 760 Nd code points in 16.0.0 and 770 in
17.0.0. The observed Node/V8 and Bun/JavaScriptCore property sets respectively
match those two counts and differ at precisely those ten points. Bun's reported
process.versions.unicode is not authoritative for its regex property tables.

JSON Schema 2020-12 recommends ECMA-262 Unicode regex support; it does not pin
the Unicode property-data edition of this historical RVR profile. ECMA-262's
conformance language refers to the latest Unicode edition, which is not a
stable historical verification pin. Neither text authorizes inferring an old
receipt's intended Unicode edition from the verifier currently installed.

Sources:
- https://json-schema.org/draft/2020-12/json-schema-core#regex
- https://tc39.es/ecma262/2024/multipage/conformance.html
- https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-13/
- https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt

## Proposed new contract (not a claim about historical profiles)

Candidate designation: `rvr-schema-ucd17-research.1`, plus exact Git and package
digest. No release tag is created. New laboratory profile identity:
`rvr-lab-unicode-data-17-candidate`, with authenticated specification/schema/vector
bytes. Unicode 17.0.0 is selected explicitly as the first published UCD edition
containing the reported digits, not as an assertion that every old profile
already selected it. This is a reproducibility choice for a NEW contract.

Pattern is ECMA Unicode `u` search, without i/m/s/g/v or implicit anchoring.
Property escapes use Unicode 17.0.0. `\d` remains ASCII [0-9]; `\p{Nd}` and its
aliases use the pinned Nd table. Dot and string length count code points, not
UTF-16 code units. Supported local `$ref` siblings remain conjunctive.
Unassigned characters are still tested normally; they are never skipped.
Invalid patterns are schema errors; inability to run the required implementation
is not evidence invalidity or a semantic result.

Pinned compiler: regexpu-core 6.4.0, regenerate-unicode-properties 10.2.2
(Unicode 17.0.0), regjsparser 0.13.0 (Unicode 17 identifier grammar), with all
transitives locked in unicode-build/package-lock.json.
It parses the pattern and transforms Unicode atoms/properties to explicit
ranges, using the upstream compiler rather than a handwritten regex dialect.
Named captures and their backreferences are also transformed: native capture-name
validation otherwise introduces another host Unicode dependency. The resulting
expression runs separately in V8 and JavaScriptCore. The generated
self-contained ecma-unicode.cjs is part of the candidate distribution manifest.
No npm/network access occurs during verification. Python still requires Node.

This shares a compiler/data dependency, not independent implementations of the
regex grammar. The independent oracle uses jsonschema plus native Bun regex,
without importing the compiler or either adapter. For three fixed new capture-name
vectors the oracle independently checks U+11DB0 is Lo in UCD17 and alpha-renames
that capture/reference to an ASCII name; it does not implement a general parser.
A separate exhaustive scan
checks Nd/complement, ASCII digit and dot over all 1,112,064 Unicode scalars in
both engines against official UCD bytes. These checks do not certify every
ECMAScript feature, every property or full JSON Schema 2020-12 compatibility.

## Historical verification and migration

1. Keep old exact adapter/package, profile, receipt and evidence bytes available.
2. Do not rerun historical receipts under this candidate and overwrite their
   historical status. An explicit comparative result is a separate observation.
3. For new receipts selecting Unicode 17, publish a new authenticated profile
   specification with this policy and newly computed identity. A new adapter
   version alone cannot supply missing normative meaning to an old profile.
4. Profiles explicitly choosing no-flags or another UCD require their original
   route. The earlier no-flags dot/emoji REJECT remains unchanged evidence.
5. An ambiguous existing profile requires an agreed new version before migration;
   finite published corpus equality is not proof that all receipts are unaffected.

The generic profile in conformance/rvr-v0 remains byte-identical for inherited
regression only. Its unchanged digest does not bind the new Unicode policy.
The candidate currently does NOT enforce a production dispatcher selecting old
versus new adapter by authenticated profile identity. Therefore a new normative
profile/version binding and migration agreement remain a publication gate.
Until that boundary is confirmed: HOLD, no push or Draft PR. This is distinct
from the now-testable U+11DE0 implementation correction.

## Reproduce

In unicode-build: `npm ci --ignore-scripts --no-audit --no-fund`, then
`node build.cjs`. Compare the bundle SHA-256 before accepting a rebuild.
No upstream source is edited: a build plugin statically resolves the upstream
dynamic property-data imports to exactly the locked data package.
Third-party licenses are retained in THIRD_PARTY_NOTICES.md.

Run `python -B research/schema-string-repair/unicode_data_campaign.py --output OUT`.
Use a new output directory for every invocation. Python normal/repeat/-O and
TypeScript normal/repeat use the same package bytes. `--before --new-only`
replays ab476f4 against the same new contract, recording defects rather than
claiming that contract applied historically.
