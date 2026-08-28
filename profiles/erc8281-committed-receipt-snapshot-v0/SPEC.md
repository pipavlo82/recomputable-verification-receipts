# RVR ERC-8281 committed receipt snapshot profile v0

Status: experimental external profile.

## 1. Authority and upstream identity

This file is the complete verification specification for profile
`rvr-erc8281-committed-receipt-snapshot-v0`. Its exact bytes are pinned by the
Verification Profile.

The procedure normatively incorporates the exact ERC-8281 Draft bytes reviewed
at this immutable source:

```text
repository: damonzwicker/ERCs
revision: 552350e0fb59d5a929f8470b6db6141ec9d244b8
path: ERCS/erc-8281.md
byte length: 23927
SHA-256: 8036fb5e232f4f01591d58efd920defd696211b7a5f91d425d672a75890f7bb4
```

Those bytes are vendored at
`profiles/erc8281-committed-receipt-snapshot-v0/upstream/erc-8281.md`. The
upstream conformance vectors reviewed with them are:

```text
path: assets/erc-8281/test-vectors.json
byte length: 28044
SHA-256: ab50fa0dfbad2966ac998b78d34cdab05e110870ee98f3a9bbe6c944e75da31f
```

The vector bytes are vendored at
`profiles/erc8281-committed-receipt-snapshot-v0/upstream/test-vectors.json`.
Both SHA-256 identities are committed by the Verification Profile and both
files are members of the profile package. A recomputer MUST resolve and verify
these exact local bytes. Evaluation never fetches a live Git repository, RPC
endpoint, SDK, indexer, or producer.

The local specification defines the RVR composition and the deliberately
narrower snapshot assurance. Where it invokes the `erc8281/1` procedure, the
vendored upstream specification is normative. The local rules explicitly
select required `block_hash` and committed-snapshot resolution rather than the
upstream live-RPC retrieval option.

## 2. Exact proposition

The claim and canonical result MUST contain this exact proposition identifier:

```text
rvr.erc8281.v0.observation_commitment_at_committed_receipt_snapshot
```

For `VERIFIED`, the proposition means:

> Under the pinned `erc8281/1` procedure, the exact observation bytes hash to
> the authenticated proof-envelope digest, and the selected log of the exact
> committed successful receipt snapshot contains that digest and the declared
> committer at the envelope's chain, transaction, block number, and block hash.

`REPRODUCED` means that claim, evidence-set, profile, and canonical-result
identities match the original receipt. It does not independently mean that the
proposition is true; the canonical result's `outcome` carries that semantic
meaning.

This profile does not establish consensus authenticity, canonicality, or
finality of the committed receipt snapshot. It does not establish contract
behavioral conformance, authorship, identity, authority, observation meaning,
or application correctness. A stronger successor profile may authenticate a
receipt against a block header's `receiptsRoot` and separately pin a finality
policy.

## 3. Identity contracts

All JSON identity objects use `rvr-canonical-json-v0`. JSON numbers are
forbidden; numeric quantities are canonical decimal strings. Object keys use
Unicode scalar-value ascending order, array order and duplicates are
preserved, Unicode is not normalized, and the frozen RVR v0 string-escaping
rules apply.

The receipt retains exactly six fields:

```text
claimDigest
evidenceSetDigest
verificationProfileDigest
outcome
reasonCode
resultDigest
```

The profile-specific claim contains `envelopeProjection`, the closed
identity-bearing projection of the ERC-8281 envelope. A raw ERC-8281 envelope
is first validated under the vendored procedure, which ignores unknown
extension fields. The profile then copies exactly the known required fields
plus `block_hash` into `envelopeProjection`. Unknown raw fields are neither
copied nor committed and cannot change `claimDigest`. `block_hash`, optional in
ERC-8281, is REQUIRED by this profile to freeze the snapshot reference.

The receipt snapshot is exact canonical JSON matching
`#/$defs/receiptSnapshot` in `rvr.schema.json`. The evidence member digest is
SHA-256 over those exact canonical bytes. Alternate JSON spellings are rejected
even if they parse to the same object.

Evidence-set members are sorted by `id` before canonical evidence-set hashing.
Their payload bytes remain byte-exact and are not reordered or normalized.

## 4. Evidence closure

The claim names exactly two evidence members:

```text
observation-bytes
receipt-snapshot
```

`observation-bytes` contains the exact bytes hashed by the envelope's declared
hash function. `receipt-snapshot` contains the canonical snapshot object used
for extraction. The snapshot assurance is exactly:

```text
COMMITTED_RECEIPT_SNAPSHOT
```

No live RPC response or other ambient input may influence evaluation. Passing
any outcome-relevant value outside the committed claim/evidence/profile closure
is a gate rejection with `rvr.gate.evidence_closure_incomplete`.

If `observation-bytes` is committed as `UNAVAILABLE`, evaluation returns
`UNVERIFIABLE` with
`rvr.erc8281.v0.required_observation_unavailable`. Reproducing that result
proves the committed state and profile evaluation, not historical objective
unavailability.

If the receipt-snapshot descriptor is present but an independent recomputer
cannot resolve the required snapshot payload, recomputation returns
`CANNOT_RECOMPUTE` with
`rvr.recompute.committed_snapshot_unavailable` before semantic evaluation. A
malformed descriptor, wrong payload digest, or hidden payload is instead a gate
rejection.

If the observation descriptor is `PRESENT` but an independent recomputer
cannot resolve its payload, recomputation returns `CANNOT_RECOMPUTE` with
`rvr.recompute.committed_evidence_unavailable` before semantic evaluation.
This differs from a descriptor that itself commits `UNAVAILABLE`, which is an
evaluated `UNVERIFIABLE` result.

## 5. Raw-envelope projection and validation

Before claim construction, the profile validates the known fields of the raw
ERC-8281 envelope and ignores fields not named by `erc8281/1`. It then derives
the closed `envelopeProjection`. Before semantic evaluation, the profile
validates that closed projection and additionally enforces:

- `version` is exactly `erc8281/1`;
- `hash_function` is `sha2-256`, `keccak-256`, or `blake2b-256`;
- `digest`, `tx_hash`, and `block_hash` are lowercase `0x`-prefixed bytes32;
- `chain_id`, `block_number`, and `receipt_log_position` are canonical decimal
  strings;
- `contract` and `committer` have valid EIP-55 checksums. A checksum that
  happens to uppercase or lowercase every alphabetic nibble remains valid;
  equality is determined by the checksum algorithm, not visual mixedness.

Failure is a schema/gate rejection. It is not `REFUTED` because no well-formed
profile claim reached semantic evaluation.

Two raw envelopes that differ only by ignored extension fields MUST derive
byte-identical projections and the same `claimDigest`. Supplying an extension
directly inside the closed `envelopeProjection` is malformed and is rejected.

## 6. Verification procedure

For well-formed closed inputs:

1. Resolve and verify the committed snapshot payload. Parse it strictly,
   schema-validate it, reproduce its canonical bytes, and require byte equality.
2. If observation evidence is `UNAVAILABLE`, derive the canonical
   `UNVERIFIABLE` result and stop.
3. Hash exact observation bytes using the envelope's algorithm:
   SHA-256, legacy Keccak-256, or parameterized BLAKE2b with 32-byte output.
4. Compare the computed digest with envelope `digest`.
5. Require snapshot `chainId == envelope.chain_id`.
6. Require snapshot `transactionHash == envelope.tx_hash`.
7. Require snapshot status `SUCCESS`.
8. Select `snapshot.logs[int(receipt_log_position)]` by receipt-array position.
   The log's `logIndex` is block-scoped informational data and MUST NOT be used
   for selection.
9. Require selected log `address == envelope.contract` after decoded-byte
   comparison.
10. Require exactly three topics and canonical topic-0
    `0xdca60c2087041cbb12d9a57628c6cad28ecbd0437e47c7ab6c3aa6e162bf4497`.
11. Require topic 1 to equal the envelope digest.
12. Decode the rightmost 20 bytes of topic 2 and require equality with envelope
    `committer`.
13. Require snapshot block number and block hash to equal the envelope values.

The first failed semantic assertion determines the `REFUTED` reason code.
Passing every assertion produces `VERIFIED` with
`rvr.erc8281.v0.commitment_verified`.

## 7. Recomputation and failure ownership

The recomputer MUST first validate the stored receipt/result identities and
their outcome/reason projections. A contradictory top-level projection is a
gate rejection even when `resultDigest` remains correct.

Required profile dependency unavailable or wrong digest:

```text
CANNOT_RECOMPUTE / rvr.recompute.normative_dependency_unavailable
```

Required committed snapshot unavailable to the recomputer:

```text
CANNOT_RECOMPUTE / rvr.recompute.committed_snapshot_unavailable
```

Committed `PRESENT` observation unavailable to the recomputer:

```text
CANNOT_RECOMPUTE / rvr.recompute.committed_evidence_unavailable
```

Profile bootstrap follows this exact order: parse the trusted generic manifest
schema, validate the generic profile envelope, resolve each dependency once,
verify its committed SHA-256, and only then parse or apply the profile-specific
constraints schema. A digest-mismatching constraints file MUST be rejected
without being parsed or semantically applied.

After complete evaluation, matching input/result identities produce
`REPRODUCED`; any differing claim, evidence-set, or canonical-result identity
produces `DIVERGED`. A changed observation is therefore a real semantic
negative control: it remains well formed, evaluates to `REFUTED`, and diverges
from the original fixed receipt.
