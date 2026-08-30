# Recomputable Verification Receipts v0

Status: experimental thin slice.

## 1. Scope

RVR v0 defines a small receipt for independently recomputing a verification
result under a content-addressed Verification Profile. It deliberately does
not define settlement, an on-chain registry, producer authority, ReceiptOS,
TSEI, Protected Relation Fixtures, or domain-specific verification policy.

The authoritative object is the identified contract/profile. Implementations
are evidence of conformance to it.

## 2. Independent axes

Verification outcome is semantic:

| Outcome | Meaning |
| --- | --- |
| `VERIFIED` | Available committed evidence satisfies the claim under the profile. |
| `REFUTED` | Available committed evidence contradicts the claim under the profile. |
| `UNVERIFIABLE` | The committed evidence closure explicitly records that decisive evidence is unavailable. |

Recomputation status concerns whether an independent run reproduced an
existing canonical result:

| Status | Meaning |
| --- | --- |
| `REPRODUCED` | Input identities and canonical result bytes equal those committed by the receipt. |
| `DIVERGED` | All normative dependencies were available and evaluation completed, but an input identity or canonical result differed. |
| `CANNOT_RECOMPUTE` | A required profile-pinned normative dependency was unavailable or did not match its immutable identity, so evaluation could not legitimately run. |

An `UNVERIFIABLE` result can therefore be `REPRODUCED`. A missing normative
dependency is never converted into `REFUTED`, `DIVERGED`, or a default false
result.

## 3. Receipt

The v0 receipt has exactly six fields:

```text
claimDigest
evidenceSetDigest
verificationProfileDigest
outcome
reasonCode
resultDigest
```

All digests are SHA-256 lowercase hexadecimal strings without a prefix.

The receipt is accompanied by, but does not embed, the claim, evidence-set
descriptor and payloads, Verification Profile, and canonical result object.

## 4. rvr-canonical-json-v0

`rvr-canonical-json-v0` is an explicit experimental byte contract. Its input
domain consists only of JSON null, booleans, Unicode scalar-value strings,
arrays, and objects. JSON numbers are forbidden in identity-bearing objects.
Decimal quantities such as byte lengths are encoded as canonical unsigned
decimal strings matching `0|[1-9][0-9]*`: no sign and no leading zero except
for the single-character value `0`.

Canonicalization rules:

1. Reject duplicate object keys after JSON string decoding.
2. Reject lone Unicode surrogate code points. A well-formed escaped surrogate
   pair represents its single Unicode scalar value.
3. Apply no Unicode normalization.
4. Encode null as `null` and booleans as `true` or `false`.
5. Encode strings using the exact `rvr-json-string-escaping-v0` table below.
6. Preserve array order and duplicates.
7. Sort object keys by ascending Unicode scalar-value sequence.
8. Emit no insignificant whitespace.
9. Encode the resulting canonical string exactly once as UTF-8.

The conformance vectors include discrimination for array order, null presence,
Unicode normalization, scalar-value key ordering, escaping, forbidden numbers,
duplicate keys, and lone surrogates.

### 4.1 Exact string escaping

`rvr-json-string-escaping-v0` emits an opening quotation mark, processes each
Unicode scalar value in order, then emits a closing quotation mark:

| Scalar value | Exact emitted sequence |
| --- | --- |
| `U+0022` quotation mark | `\"` |
| `U+005C` reverse solidus | `\\` |
| `U+0008` | `\b` |
| `U+0009` | `\t` |
| `U+000A` | `\n` |
| `U+000C` | `\f` |
| `U+000D` | `\r` |
| Other `U+0000` through `U+001F` | `\u00xx`, with exactly two lowercase hexadecimal digits |
| Every other Unicode scalar value | Its literal UTF-8 encoding |

The solidus `U+002F` is therefore literal. `U+2028` and `U+2029` are also
literal and MUST NOT be emitted as `\u2028` or `\u2029`. No other optional
JSON escape spelling is permitted. These rules apply identically to object
keys and string values.

## 5. Identity rules

```text
claimDigest =
  SHA-256(UTF-8(rvr-canonical-json-v0(claim)))

verificationProfileDigest =
  SHA-256(UTF-8(rvr-canonical-json-v0(verificationProfile)))

resultDigest =
  SHA-256(UTF-8(rvr-canonical-json-v0(canonicalResult)))
```

For evidence members with status `PRESENT`:

```text
member.digest = SHA-256(exact raw member bytes)
member.byteLength = canonical unsigned decimal length of exact raw member bytes
```

The evidence-set descriptor contains no payload encoding. Its `members` array
is normalized by ascending member `id` under Unicode scalar ordering before
canonicalization:

```text
evidenceSetDigest =
  SHA-256(UTF-8(rvr-canonical-json-v0(normalizedEvidenceSetDescriptor)))
```

Member IDs MUST be unique. A resolved `PRESENT` member MUST have exactly one
payload whose exact bytes match its length and digest. If a committed-present
payload cannot be resolved, the descriptor remains valid but recomputation
MUST return `CANNOT_RECOMPUTE` without evaluation. An `UNAVAILABLE` member MUST
have no payload.

The conformance-vector-set digest is SHA-256 over UTF-8 rows sorted by path:

```text
<path>\t<SHA-256(exact-file-bytes)>\n
```

## 6. Verification Profile closure

Every Verification Profile is validated in two mechanically separate layers:

1. the generic `RVR Verification Profile Manifest v0` schema, which defines
   the common closure envelope without fixing a domain profile ID, paths, or
   JSON Pointers; and
2. the profile-specific constraints schema identified and pinned by that
   manifest instance.

The generic manifest schema is the RVR v0 bootstrap contract supplied to the
verifier. After strict parsing, the manifest's own generic-schema pin MUST
identify byte-for-byte the same bootstrap schema. The profile-specific schema
MUST NOT be parsed or applied until its exact bytes match its committed digest.

The Verification Profile commits to:

- this verification specification by exact file-byte digest;
- the generic manifest schema and its profile-specific constraints schema by
  exact file-byte digest;
- the pinned vector and expected-result files and their aggregate digest;
- `rvr-canonical-json-v0` directly;
- the receipt, claim, evidence-set, and canonical-result schema contracts by
  exact file identity and JSON Pointer;
- result hash and projection rules;
- the reason-code namespace;
- external-context policy;
- which pinned dependencies are required during recomputation.

The adapter implementation is not included in profile identity.

No uncommitted mutable ambient input may influence evaluation. Every
outcome-relevant input must be the claim, an exact payload committed through
the evidence set, or an immutable external-context commitment defined by the
profile. The v0 profile defines no external-context commitment and therefore
forbids all outcome-relevant external context.

### 6.1 Dependency resolution

A verifier receives an explicit profile package root together with the profile
package. Every dependency `path` is a normative package-relative locator, not
a process-CWD path, URL, Git reference, or advisory hint. It MUST use `/` as
its separator, MUST be relative, and MUST contain no empty, `.` or `..` path
segment, reverse solidus, or colon. The colon exclusion prevents host-specific
drive-letter interpretation. Resolution MUST remain within the supplied
profile package root, including after resolving filesystem links.

For each dependency the only valid order is:

```text
resolve under supplied profile package root
  -> read exact bytes
  -> verify SHA-256 against the committed lowercase hexadecimal digest
  -> use the bytes
```

Bytes MUST NOT influence validation or evaluation before their committed
digest matches. The bytes that matched the digest MUST be the bytes subsequently
used; re-reading the locator for semantic use is forbidden. RVR v0 requires no
HTTP, Git, registry, or global path namespace.

Any dependency whose bytes can affect validation, evaluation, canonical-result
derivation, or recomputation status MUST set `requiredForRecomputation` to
`true`. A dependency marked `false` is non-semantic conformance or provenance
material. Its availability and bytes MUST NOT influence an individual
recomputation. A package-level conformance audit MAY separately require and
check such material, but that audit is not semantic recomputation.

### 6.2 Meaning of committed UNAVAILABLE

Reproducing an `UNVERIFIABLE` result proves that the committed evidence-set
descriptor contained `UNAVAILABLE` and that the identified profile correctly
derived `UNVERIFIABLE` from that committed state. RVR alone does not prove the
historical fact that the evidence was objectively impossible to obtain. A
profile that requires proof of absence or unavailability MUST define and
commit that proof as outcome-relevant evidence or immutable external context.

## 7. Canonical result and projections

There is one canonical result object with:

```text
schema
outcome
reasonCode
evaluation.operation
evaluation.evidenceMember
evaluation.expectedDigest
evaluation.observedDigest
```

The profile projects receipt fields from JSON Pointers `/outcome` and
`/reasonCode`. A receipt whose stored fields contradict either projection is
invalid even when its `resultDigest` correctly identifies the canonical result.

## 8. Generic SHA256_EQUALS profile

The first profile evaluates one claim operation:

```text
SHA256_EQUALS(evidenceMember, expectedDigest)
```

- committed member `PRESENT`, observed digest equals expected: `VERIFIED`,
  `rvr.v0.digest_match`;
- committed member `PRESENT`, observed digest differs: `REFUTED`,
  `rvr.v0.digest_mismatch`;
- committed member `UNAVAILABLE`: `UNVERIFIABLE`,
  `rvr.v0.required_evidence_unavailable`;
- missing member descriptor, unmatched payload, duplicate ID, or uncommitted
  outcome-relevant input: gate rejection, not a verification outcome.

## 9. Recomputation procedure

1. Strictly parse and schema-validate the profile and supplied objects.
2. Recompute profile identity. Profile bootstrap validation uses its required
   schema pins; a separate package-level conformance audit may verify
   non-semantic package members.
3. Validate the original receipt, canonical result digest, and result
   projections.
4. Resolve all remaining required normative dependencies. An unresolved required dependency
   returns `CANNOT_RECOMPUTE` with
   `rvr.recompute.normative_dependency_unavailable`. Resolved bytes whose digest
   does not equal the dependency pin return `CANNOT_RECOMPUTE` with
   `rvr.recompute.normative_dependency_identity_mismatch`. Neither path performs
   evaluation. Dependencies marked `requiredForRecomputation=false` MUST NOT be
   read or otherwise influence this procedure.
5. Validate evidence closure. A committed `PRESENT` descriptor whose payload
   cannot be resolved returns `CANNOT_RECOMPUTE` with
   `rvr.recompute.committed_evidence_unavailable` and no evaluation. If payload
   bytes are resolved but their length or digest does not match the descriptor,
   reject at the gate with `rvr.gate.identity_mismatch`. Other closure failures
   are gate rejections and cannot report `REPRODUCED`.
6. Recompute the claim and evidence-set identities.
7. Run semantic evaluation and derive one canonical result.
8. Recompute result bytes and digest.
9. Return `REPRODUCED` only if claim, evidence-set, profile, and result
   identities match the receipt. Otherwise return `DIVERGED` and record that
   evaluation completed.

## 10. Required falsification cases

The pinned suite executes:

- exact `REPRODUCED`;
- evaluated evidence mutation producing `DIVERGED` and `REFUTED`;
- `UNVERIFIABLE` plus `REPRODUCED`;
- missing normative dependency producing `CANNOT_RECOMPUTE` without evaluation;
- wrong bytes for a required dependency producing `CANNOT_RECOMPUTE` without
  parsing or evaluation;
- unresolved committed-`PRESENT` evidence producing `CANNOT_RECOMPUTE`, while
  resolved bytes with the wrong identity are gate-rejected;
- unavailable or substituted `requiredForRecomputation=false` material leaving
  semantic recomputation byte-for-byte unchanged;
- contradictory outcome/reason projection rejection;
- outcome-relevant hidden-state rejection, plus a counterfactual demonstration
  that the forbidden input could change the semantic outcome.

## 11. Adversarial semantic mutant/witness audit

The pinned v0 conformance set includes deliberately broken semantic behaviors
and their executable falsification witnesses. It is a semantic mutant/witness
audit, not a claim that every item is a full end-to-end mutated implementation.
Every conforming adapter MUST mechanically distinguish the correct contract
from all of them:

- sorting or deduplicating arrays during canonicalization;
- applying Unicode NFC normalization;
- ignoring canonical-result projections;
- converting an unavailable normative dependency into `REFUTED`;
- allowing uncommitted ambient state to affect evaluation;
- trusting a stored result without evaluating changed evidence.

A semantic mutant/witness is killed only when the named witness demonstrates
the specific faulty behavior and the correct gate produces the frozen contrary
result. Merely observing unrelated digest drift does not kill it.
