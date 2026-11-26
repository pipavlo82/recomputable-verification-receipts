# Job, evidence, confirmation and exact signing rules

This is an experimental V1 format, not a modification of frozen RVR/VECA Core.
The executable public example is `evidence/ffi-issuance.json`.

## Job and evidence

ERC-8183 `Job` supplies id, client, provider, evaluator, description, budget,
expiredAt, status and hook. The submitted deliverable digest is obtained from the
unique `JobSubmitted` event, because this escrow's Job struct does not store it.
Only Submitted, unexpired jobs naming the gate, with zero hook and zero fees, can pay.

The verifier request has **exactly one member**, `evidence`. A `verified` or `result`
member supplied by the bridge is rejected. Evidence has exactly these members:

`binding`, `assessment`, `signature`, `deliverable`, `rubric`, `conditions`, `rvr`,
`rvr_case`, `claim`, `obligations`.

The external authority policy and observed state are separate verifier inputs,
not bridge claims. See the complete sample for their shapes. The experiment checks
the exact-answer rubric, Ed25519 assessor authorization, revocation/epoch, native RVR
evidence closure and recomputation, claim/consumer/action, required obligations and
exact on-chain job/token/submission context.

Binding has exactly these 21 fields:

```text
chain_id escrow_contract job_id client provider evaluator token_contract
token_parameters amount deliverable_sha256 rubric_digest assessment_id
assessment_digest assessment_issuer rvr_profile_digest rvr_receipt_digest
veca_claim_digest nonce expiry revocation_epoch settlement_conditions_digest
```

Counters/amounts/times inside canonical objects are decimal **strings**. Addresses
in the binding/state are lowercase 0x-prefixed hex; SHA-256 digests are lowercase
64-character hex without 0x. `token_parameters` is two decimal strings: prediction
and immutable round. Raw deliverable bytes are represented by lowercase hex.

## Canonical bytes and digests

Use the pinned RVR profile's `canonical_bytes`; this experiment's independent oracle
spells the same restricted contract separately: UTF-8 JSON, sorted object keys,
compact comma/colon separators, literal Unicode, no lone surrogates. Allowed value
types are string, bool, null, arrays and objects with string keys. Numeric JSON values
are not admitted in hashed objects. Do not substitute a generic JSON/JCS library
without demonstrating byte equivalence under the pinned profile.

Let `C(x)` be those exact canonical bytes and `S(x)=sha256(C(x))`.

| Value | Exact derivation |
| --- | --- |
| bindingDigest | `S(evidence.binding)` |
| evidenceDigest | `S(entire evidence object)` |
| policyDigest | `S(authority policy object)` |
| deliverableDigest | `sha256(raw deliverable bytes)` |
| assessment_digest | `S(evidence.assessment)` |
| rubric_digest | `S(evidence.rubric)` |
| settlement_conditions_digest | `S(evidence.conditions)` |
| rvr_profile_digest | Audited content-addressed profile digest returned by pinned RVR `audit_profile` |
| rvr_receipt_digest | `S(evidence.rvr.receipt)` |
| veca_claim_digest | `S(evidence.claim)` |

The assessor signs `UTF8("AI_WORK_ESCROW_ASSESSMENT_V1") || 0x00 || C(assessment)`
with Ed25519. The sample publishes only the assessor's verification key and signature.
RVR binds the exact signed assessment bytes and its expected SHA-256; a valid assessor
signature alone does not establish the judgment's truth or current authority.

## Solidity Confirmation, in ABI order

| Index | Field | ABI type |
| --- | --- | --- |
| 0 | jobId | uint256 |
| 1 | client | address |
| 2 | recipient | address |
| 3 | token | address |
| 4 | amount | uint256 |
| 5 | bindingDigest | bytes32 |
| 6 | evidenceDigest | bytes32 |
| 7 | policyDigest | bytes32 |
| 8 | deliverableDigest | bytes32 |
| 9 | rvrProfile | bytes32 |
| 10 | rvrReceipt | bytes32 |
| 11 | vecaClaim | bytes32 |
| 12 | rvrOutcome | bytes32 |
| 13 | recomputation | bytes32 |
| 14 | admission | bytes32 |
| 15 | nonce | bytes32 |
| 16 | issuedAt | uint256 |
| 17 | expiry | uint256 |
| 18 | generation | uint256 |
| 19 | prediction | uint64 |
| 20 | round | uint64 |

The exact type is:

```text
(uint256,address,address,address,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint256,uint64,uint64)
```

`nonce` is the binding's decimal nonce encoded as an unsigned 32-byte big-endian
integer. The sample issuer uses issuedAt equal to its current observed time and
expiry `min(issuedAt+600, binding.expiry)`. The contract additionally requires
`issuedAt <= now < expiry`, a positive lifetime of at most 3600 seconds, current epoch,
nonzero unused nonce, and an unexpired submitted job.

Success tags are `keccak256(UTF8("VERIFIED"))`, `keccak256(UTF8("REPRODUCED"))`,
`keccak256(UTF8("VERIFIED"))`, respectively. Any other outcome or recomputation tag
refuses payment, including REFUTED, UNVERIFIABLE, DIVERGED and CANNOT_RECOMPUTE.

## Verifier digest and signature

```text
DOMAIN = keccak256(UTF8("ERC8378_EVIDENCE_GATE_V2"))
digest = keccak256(abi.encode(DOMAIN, chainId, gateAddress, escrowAddress, confirmation))
```

The outer ABI types are `bytes32,uint256,address,address,ConfirmationTuple`.
Use `abi.encode`, not packed encoding. This is a directly signed 32-byte secp256k1
digest, **not** an EIP-191 personal-message prefix or EIP-712 typed-data envelope.
Signature wire form is 65 bytes `r || s || v`, v=27/28, low-s as required by the
pinned OpenZeppelin ECDSA recovery. V1 supports one EOA-style verifier, not ERC-1271
or an m-of-n signature aggregate. The `digest` in the sample must match independent
Python ABI encoding and `gate.digestOf(confirmation)` exactly.

The JSON `confirmation` sample is an ordered array; bytes32 values are 0x-prefixed
hex and ABI integers require arbitrary-precision handling. The complete typed tuple,
chain, gate and escrow are all signed. Recipient, token and amount are also checked
against actual escrow state. A signature cannot be reused after nonce consumption,
epoch advance, revocation, expiry or successful completion of the job.

## Independent verifier operation

Verify public sample evidence with `gate-v2/offline_checker.py evidence` before any
signing. A future independent operator must separately approve policy and authority
roots, pin the correct deployment and obtain authentic job/submission/token/epoch
observations. Never accept bridge-provided success flags or authority configuration.

`verifier_service.py` contains a laboratory RPC reader restricted to chain 31337.
Its configuration and private-key file are operator provisioning inputs; the bridge
only submits the evidence JSON. The native replay uses a test-controller FFI snapshot
instead of a validated RPC transport. Neither reader's execution establishes chain
canonicality, independent custody or judgment truth. This review does not authorize
a live deployment or enrollment of Federico's key.
