# RVR invinoveritas signed verdict profile v1

Status: experimental external profile.

## 1. Authority and source identity

This file is the complete verification specification for profile
`rvr-invinoveritas-signed-verdict-v1`. Its exact bytes are committed by the
Verification Profile.

The executable base case uses the exact Git blob:

```text
repository: babyblueviper1/invinoveritas
revision: 0e4f1f7b2d24924fc51c9d8c037448ffefaca4f1
path: examples/rvr-verdict-worked-example/verdict_proof_v17.json
Git blob: 2b30c729503f96f5545f8d8875e3d473d884a9eb
byte length: 14362
SHA-256: 77058e47d3fc1ac9b84e5110ae4b5b9432ea7aac99903f14c38c41de5c97a1f6
```

Those exact bytes are vendored at `upstream/verdict_proof_v17.json.base64` under
the transport contract `RFC 4648 Base64, canonical padded form, exactly one ASCII
line followed by one LF`. The decoded bytes MUST have the byte length and
SHA-256 above before they are parsed or used. This transport preserves the
CRLF-bearing upstream Git blob while every text file in this repository remains
LF-only. Evaluation does not call the producer, `/verify-proof`, a key directory,
a package registry, or any live service.

## 2. Exact proposition and judgment boundary

The proposition identifier is:

```text
rvr.invinoveritas.v1.signed_verdict_artifact_bindings
```

For `VERIFIED`, it means:

> The exact artifact bytes, policy-commitment preimage, decision-reference
> preimage, freshness-beacon commitment, NIP-01 event identity, and BIP-340
> signature all satisfy this profile's deterministic verification relation
> under the profile-pinned issuer public key.

The producer verdict is not the RVR outcome. The strings `approve`,
`approve_with_concerns`, or `reject`, confidence, issues, and free judgment
content are authenticated and bound as data but are not independently
re-derived. The canonical result states this boundary exactly as:

```text
COMMITTED_AUTHENTICATED_NOT_REDERIVED
```

`REPRODUCED` means that the profile-defined canonical result was independently
reproduced. It never means that an independent LLM reached the same judgment.

The profile reproduces the binding between the signed `freshness_beacon` object,
its `freshness_beacon_hash`, and the decision reference. It does not contact
Bitcoin explorers and does not establish that the named block was historically
canonical, sufficiently finalized, contemporaneous, or independently observed.
The canonical result records this boundary as:

```text
COMMITMENT_REPRODUCED_CANONICALITY_NOT_ESTABLISHED
```

Establishing Bitcoin canonicality would require a distinct profile that commits
the necessary headers, consensus/finality rule, and resolution evidence. A live
three-source lookup is mutable ambient context and MUST NOT influence this
profile's result.

This profile establishes neither pre-action mediation nor non-bypassability,
market truth, policy wisdom, completeness of evidence, consensus identity of
the issuer, Bitcoin canonicality, nor ML-DSA companion validity. It verifies
BIP-340 under the exact issuer key committed by this profile.

## 3. Identity and external byte contracts

RVR claim, evidence-set, receipt, and canonical-result identities use frozen
`rvr-canonical-json-v0`. JSON numbers therefore do not occur in those identity
objects.

The external signed-verdict relation uses
`invinoveritas-jcs-safe-integer-v0`, defined here as:

- UTF-8;
- null, booleans, strings, arrays, objects, and integers in
  `[-9007199254740991, 9007199254740991]`;
- floats and non-finite values forbidden;
- object keys restricted to ASCII and sorted lexicographically;
- no whitespace or trailing byte;
- JSON short escapes for quote, reverse solidus, backspace, tab, LF, form feed,
  and CR; remaining U+0000..U+001F as lowercase `\\u00xx`;
- solidus, U+2028, and U+2029 literal; Unicode is not normalized.

This restricted contract is sufficient for the policy and decision preimages
and for the NIP-01 event serialization used by the pinned artifact. It is not a
new generic RVR serializer.

NIP-01 event identity is:

```text
sha256(invinoveritas-jcs-safe-integer-v0(
  [0, pubkey, created_at, kind, tags, content]
))
```

The BIP-340 signature verifies the 32 raw event-id bytes under the 32-byte
x-only public key committed by the profile.

## 4. Evidence closure

The claim names exactly three evidence members:

```text
artifact-bytes
policy-preimage
signed-event
```

`artifact-bytes` is arbitrary exact UTF-8 data. `policy-preimage` and
`signed-event` are exact `invinoveritas-jcs-safe-integer-v0` bytes. Evidence
descriptors commit each payload's byte length and SHA-256; the evidence set is
sorted by member `id` before RVR canonical hashing.

No outcome-relevant ambient input is permitted. A hidden live key, policy,
rubric, API response, clock, model call, or external verdict is a closure gate
rejection.

A descriptor that commits a required member as `UNAVAILABLE` produces the
profile's semantic `UNVERIFIABLE` result. If a descriptor says `PRESENT` but the
recomputer cannot resolve its payload, recomputation returns
`CANNOT_RECOMPUTE / rvr.recompute.committed_evidence_unavailable` before
evaluation. These cases MUST NOT collapse.

## 5. Deterministic verification procedure

For complete, well-formed inputs:

1. Recompute SHA-256 over exact artifact bytes and compare with claim
   `artifactHash`.
2. Parse the exact policy preimage and require the four fields
   `policy_version`, `rubric_sha256`, `conformance_suite_repo`, and
   `conformance_suite_commit`. Recompute SHA-256 over its external canonical
   bytes and compare with claim `policyCommitment`.
3. Parse the signed event; require exact fields `id`, `pubkey`, `created_at`,
   `kind`, `tags`, `content`, and `sig`, with safe integer timestamps/kinds and
   lowercase hex identities.
4. Require event `pubkey` to equal the profile-pinned issuer key.
5. Recompute the NIP-01 event id and require equality with both event `id` and
   claim `eventId`.
6. Verify the BIP-340 signature over the raw event-id bytes.
7. Parse event `content` with duplicate-key rejection.
8. Require content `artifact_hash`, `policy_commitment`, and `decision_ref` to
   equal the claim bindings.
9. Require the policy fields disclosed in content to equal the committed policy
   preimage. `rubric_doc_path` is metadata and is not silently added to the
   policy-commitment preimage.
10. Require `freshness_beacon` to be the closed object `source`, `height`,
    `hash`, and `block_time`; require `source = bitcoin`, safe non-negative
    integer height/time, and a lowercase 32-byte hash. Canonicalize and hash the
    object, then require equality with both signed `freshness_beacon_hash` and
    claim `freshnessBeaconHash`.
11. Require the exact v17 `decision_ref_preimage_fields` list, including the
    four optional action-binding fields and `freshness_beacon_hash`. Construct an
    object containing every named field, using JSON null for absent fields,
    canonicalize it under the external byte contract, hash it, and compare with
    claim `decisionRef`.

The first failed semantic check selects the `REFUTED` reason. Passing every
check yields `VERIFIED / rvr.invinoveritas.v1.signed_verdict_bindings_verified`.

The freshness check proves an exact content binding only. It MUST NOT be
reported as independent reproduction of Bitcoin consensus, finality, or the
historical availability of any explorer response.

## 6. Recomputation and failure ownership

Stored receipt/result identity and outcome/reason projections are checked before
candidate evaluation. A contradictory projection is a gate rejection.

Unavailable pinned profile dependency returns `CANNOT_RECOMPUTE` without
evaluation. Missing committed-present evidence returns `CANNOT_RECOMPUTE`
without evaluation. A complete, well-formed mutation is evaluated: a different
artifact remains a real semantic negative control, produces `REFUTED`, and
returns `DIVERGED` against the fixed receipt.

The profile-specific constraints file is hash-checked before parsing or use.
Outcome-relevant hidden state is rejected and never reported as reproduced.
