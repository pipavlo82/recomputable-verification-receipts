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
Decimal quantities such as byte lengths are encoded as canonical decimal
strings by their governing schema.

Canonicalization rules:

1. Reject duplicate object keys after JSON string decoding.
2. Reject lone Unicode surrogate code points. A well-formed escaped surrogate
   pair represents its single Unicode scalar value.
3. Apply no Unicode normalization.
4. Encode null as `null` and booleans as `true` or `false`.
5. Encode strings with JSON string escaping, without optional solidus escaping
   or ASCII-forcing.
6. Preserve array order and duplicates.
7. Sort object keys by ascending Unicode scalar-value sequence.
8. Emit no insignificant whitespace.
9. Encode the resulting canonical string exactly once as UTF-8.

The conformance vectors include discrimination for array order, null presence,
Unicode normalization, scalar-value key ordering, escaping, forbidden numbers,
duplicate keys, and lone surrogates.

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

Member IDs MUST be unique. A `PRESENT` member MUST have exactly one supplied
payload whose exact bytes match its length and digest. An `UNAVAILABLE` member
MUST have no payload.

The conformance-vector-set digest is SHA-256 over UTF-8 rows sorted by path:

```text
<path>\t<SHA-256(exact-file-bytes)>\n
```

## 6. Verification Profile closure

The Verification Profile commits to:

- this verification specification by exact file-byte digest;
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
2. Recompute profile identity and all exact dependency pins.
3. Validate the original receipt, canonical result digest, and result
   projections.
4. Resolve required normative dependencies. If any is unavailable or has the
   wrong identity, return `CANNOT_RECOMPUTE` without evaluation.
5. Validate evidence closure and all payload identities. Closure failure is a
   gate rejection and cannot report `REPRODUCED`.
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
- contradictory outcome/reason projection rejection;
- outcome-relevant hidden-state rejection, plus a counterfactual demonstration
  that the forbidden input could change the semantic outcome.
