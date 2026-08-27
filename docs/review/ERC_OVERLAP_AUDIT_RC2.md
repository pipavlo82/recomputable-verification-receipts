# RVR RC2 ERC-overlap audit

Status: publication-preparation review; non-normative.

Snapshot date: 2026-08-26.

## Audit question

Does Recomputable Verification Receipts duplicate an existing Ethereum
standard, and which boundaries must an RVR proposal state so that composition
does not become semantic capture?

In the neighboring ERCs reviewed at this snapshot, no proposal was found whose
normative object combines content-addressed Verification Profile identity,
committed evidence closure, canonical result identity, and an explicit
independent recomputation status. The closest neighbors standardize verifier
calls, commitments, provenance, confidential proof-backed verdicts,
authentication, or registries. RVR standardizes a portable statement that an
independently recomputed canonical result did or did not reproduce under one
exact content-addressed Verification Profile.

This conclusion is narrower than “RVR solves verification.” RVR does not decide
which proof system, identity, policy, chain, registry, or producer should be
trusted. It makes the selected verification contract and all outcome-relevant
inputs identifiable, then reports semantic outcome separately from the status
of independent recomputation.

## Source and status discipline

The audit uses official ERC pages where a document has landed and exact GitHub
PR revisions where it has not. Open PR text can change after this snapshot and
must be re-audited before a formal ERC submission.

| Proposal | Snapshot status | Audited revision |
| --- | --- | --- |
| ERC-8274 | Open draft PR [#1771](https://github.com/ethereum/ERCs/pull/1771) | [`3f014d07`](https://github.com/JimmyShi22/ERCs/blob/3f014d07a0ceac39fe6fb6dec0efdc30640a9653/ERCS/erc-8274.md) |
| ERC-8281 | Open draft PR [#1788](https://github.com/ethereum/ERCs/pull/1788) | [`552350e0`](https://github.com/damonzwicker/ERCs/blob/552350e0fb59d5a929f8470b6db6141ec9d244b8/ERCS/erc-8281.md) |
| ERC-8299 | Open draft PR [#1810](https://github.com/ethereum/ERCs/pull/1810) | [`c0e13d17`](https://github.com/TMerlini/ERCs/blob/c0e13d17940a6eabe4d842e623fd0f871550ef7b/ERCS/erc-8299.md) |
| ERC-8354 | Landed Draft; source PR [#1919](https://github.com/ethereum/ERCs/pull/1919) merged 2026-08-25 | [ERC source](https://github.com/ethereum/ERCs/blob/master/ERCS/erc-8354.md) |
| ERC-8395 | Open draft PR [#1967](https://github.com/ethereum/ERCs/pull/1967) | [`49bfae61`](https://github.com/slice-so/ERCs/blob/49bfae61c8ef3140f46e7e51c78650f33cf3e837/ERCS/erc-8395.md) |
| ERC-8263 | Open draft PR [#1748](https://github.com/ethereum/ERCs/pull/1748) | [`c3c0a568`](https://github.com/TruthAnchor-AI/ERCs/blob/c3c0a5686e8bc9fd693f329bf0548dfb92b9b1bf/ERCS/erc-8263.md) |

## Boundary matrix

| Neighbor | What it standardizes | Relationship to RVR | Boundary RVR must preserve |
| --- | --- | --- | --- |
| ERC-8274 | Two-layer on-chain interfaces for AI inference proof verification and an event digest | An RVR profile may invoke or audit a concrete verifier configuration | RVR is not AI-specific, does not standardize a verifier address/interface, and does not reduce its outcome to ERC-8274's `bool valid` |
| ERC-8281 (OCP) | Commitment construction, inclusion, and observation identity | An OCP result can be committed evidence or external context for a profile | RVR performs semantic recomputation under a pinned verification contract; neither surface substitutes for the other |
| ERC-8299 (WYRIWE) | AI input provenance through raw-input, sanitization-pipeline, and executed-input commitments | WYRIWE commitments can close the input-provenance part of an RVR evidence set | RVR does not define sanitization, input legitimacy, or AI provenance, and WYRIWE does not define a generic canonical result/recomputation status |
| ERC-8354 | Pre-execution ZK allow/deny verdicts against a committed confidential policy | Proof verification and its pinned circuit/policy context can be evaluated by an RVR profile | Portable recomputation closure over resolvable committed dependencies is orthogonal to confidential-policy proof semantics; RVR must not claim disclosure or recomputation of a secret policy merely because a ZK proof verifies |
| ERC-8395 | Recursive attenuating delegation for ERC-8128 signed HTTP requests | A request and delegation chain can be evidence in an RVR profile | RVR neither authenticates HTTP nor grants authority; mutable revocation/time/chain state must be snapshot-committed or recomputation cannot be claimed |
| ERC-8263 | A minimal on-chain `proofHash` anchor for agent actions | An RVR receipt or result digest may be the opaque anchored object | Anchoring proves publication/existence, not RVR semantics; RVR adds no on-chain registry |
| ERC-8273 | Transaction-scoped attestation gating and a persistent audit record with optional `evidenceHash` | An RVR receipt can be off-chain evidence behind `evidenceHash` | Attestor authorization and action gating remain ERC-8273 concerns; an attestor implementation is not RVR authority |
| ERC-8004 | Agent identity, reputation, and validation registries | A validation record can point to an RVR artifact, and an identity snapshot can be profile evidence | RVR is not an identity/reputation registry and has no mandatory agent concept |
| ERC-8126 | Provider-facing verification types and risk scores for ERC-8004 agents | A particular verification type could define an RVR profile | RVR does not define agent risk scoring, provider trust, PDV, or a required ZK path |
| ERC-7007 | NFT interfaces for verifiable AI-generated content with zkML/opML verification | An RVR profile could reproduce evidence about a prompt/output/proof tuple | RVR is not an NFT or model-output ownership standard and does not prescribe zkML/opML |
| ERC-8183 | Escrowed agentic commerce and evaluator-mediated settlement | An evaluator may attach an RVR receipt to its decision | RVR does not settle payments, select an evaluator, or authorize release of funds |
| ERC-8128 | Ethereum-authenticated HTTP message signatures | Signed request bytes can be committed evidence | Authentication and request integrity do not prove semantic verification; RVR does not replace RFC 9421 or signature validation |
| EIP-712 / ERC-1271 | Typed-data signing and contract-account signature validation | They can authenticate evidence or a receipt distribution envelope | Signatures prove authorization/authenticity under their own context, not result reproducibility; mutable ERC-1271 state must be snapshot-bound when outcome-relevant |
| RFC 8785 (JCS) | A canonical JSON representation over the I-JSON/ECMAScript domain | It addresses the same general byte-identity problem | `rvr-canonical-json-v0` is deliberately not JCS: numbers are forbidden, keys use Unicode scalar order, and the exact RVR escape/domain rules govern identity |

Primary references: [ERC-8004](https://ercs.ethereum.org/ERCS/erc-8004),
[ERC-8126](https://ercs.ethereum.org/ERCS/erc-8126),
[ERC-8273](https://ercs.ethereum.org/ERCS/erc-8273),
[ERC-7007](https://ercs.ethereum.org/ERCS/erc-7007),
[ERC-8183](https://ercs.ethereum.org/ERCS/erc-8183),
[ERC-8128 discussion](https://ethereum-magicians.org/t/erc-8128-signed-http-requests-with-ethereum/27515),
[EIP-712](https://eips.ethereum.org/EIPS/eip-712),
[ERC-1271](https://eips.ethereum.org/EIPS/eip-1271), and
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).

## Detailed findings

### ERC-8274: closest verifier-interface neighbor

ERC-8274 answers how an Ethereum application calls a proof verifier and binds
an AI task, agent, input, output, backend configuration, and boolean validity
into an on-chain verification event. Its current draft explicitly treats
`proofProfile()` as address-scoped and self-reported; the consumer must assess
the deployed verifier, code, and upgrade authority.

RVR answers a different question: given an identified verification contract,
dependency package, claim, and evidence closure, did a new implementation
derive the identical canonical result? The RVR profile identity can commit to
an ERC-8274 deployment and exact state snapshot, but a deployment address must
not displace the content-addressed profile as RVR authority.

The draft should therefore avoid names such as `valid` for the top-level RVR
outcome and explicitly state that `VERIFIED` is a profile-defined semantic
result, not an alias for one on-chain verifier return value.

### ERC-8281: closest commitment-verification neighbor

OCP's `recompute -> compare -> confirm inclusion` is intentionally minimal. It
does not define a canonical encoding for observation content, data
availability, authorship, or application semantics. RVR shares the discipline
of recomputing instead of trusting a stored digest, but adds an exact profile,
evidence closure, canonical result, projections, and failure taxonomy.

The terms must not be conflated:

- OCP can verify that bytes committed by an on-chain observation are present;
- RVR can reproduce the semantic result defined by a profile over committed
  inputs;
- either can be used without the other;
- when composed, the OCP proof and chain context must be part of the RVR
  closure.

### ERC-8299: provenance is an input, not the whole result

WYRIWE defines how AI systems distinguish raw input, a sanitization pipeline,
and the actual executed input. That addresses a concrete hidden-transformation
problem which a generic RVR profile must not redefine.

If those distinctions can change an RVR outcome, their exact WYRIWE
commitments and resolution rules belong in the evidence/profile closure. RVR
then evaluates them under a domain profile. It does not prove that the source
was truthful merely because the hashes are internally consistent.

### ERC-8354: correctness and recomputability are separate properties

ERC-8354 intentionally proves an allow/deny decision against a policy that is
not publicly disclosed. A valid proof can establish that the committed program
and witness relation accepted; it does not make the secret policy publicly
recomputable and it does not establish that the policy is safe or fair.

An RVR profile can reproducibly verify the public proof and return a semantic
outcome about proof validity. It cannot honestly claim to have recomputed the
private policy decision unless the profile actually closes all inputs needed
for that computation. This is exactly why RVR keeps `UNVERIFIABLE` and
`CANNOT_RECOMPUTE` separate from `REFUTED`.

### ERC-8395: mutable authorization context is the important seam

ERC-8395 extends signed HTTP requests with recursive, attenuating delegation,
including expiry, permissions, replay posture, and revocation. The signature
and chain establish authorization properties. They do not establish the
semantic correctness of a later verification result.

If an RVR profile evaluates a delegated request, every outcome-relevant
authorization fact must be immutable evidence or an explicitly pinned state
snapshot. Fetching current revocation state, current time, an RPC response, or
an HTTP resource as uncommitted ambient input violates evidence closure. If a
required snapshot cannot be resolved, the correct recomputation status is
`CANNOT_RECOMPUTE`, not `REFUTED`.

## Publication consequences

A Magicians proposal should make these points explicit before asking for an ERC
number:

1. RVR is an off-chain interoperability envelope with optional Ethereum
   composition, not an on-chain registry or verifier interface.
2. Profile identity, not a producer, deployed address, SDK, or reference
   implementation, is authority.
3. Verification outcome and recomputation status are independent axes.
4. Commitment inclusion, signatures, provenance, ZK validity, identity,
   reputation, and settlement are inputs or adjacent guarantees, not synonyms
   for RVR reproduction.
5. Mutable external state is outcome-relevant evidence and must be snapshot
   committed.
6. `rvr-canonical-json-v0` must be named as its own narrow byte contract, not
   described as JCS compatibility.
7. The first forum question should include whether this belongs as a
   Standards-Track ERC at all, or should remain an implementation-neutral
   companion specification consumed by Ethereum ERCs.

## Re-audit triggers

Repeat this audit before a formal ERC PR if any of the following occurs:

- ERC-8274, ERC-8281, ERC-8299, ERC-8395, or ERC-8263 lands or materially
  changes;
- the RVR receipt fields, status axes, canonical bytes, resolver semantics, or
  authority model changes;
- an Ethereum-specific on-chain interface is proposed for RVR;
- a profile makes an adjacent ERC normative rather than optional composition.
