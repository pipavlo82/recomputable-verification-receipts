# Draft proposal: Recomputable Verification Receipts (RVR)

Status: pre-ERC discussion draft for Ethereum Magicians.

Implementation baseline: [RVR v0.0.1-rc.2](https://github.com/pipavlo82/recomputable-verification-receipts/releases/tag/v0.0.1-rc.2).

This post asks for design and scope feedback. It is not an assigned ERC, and no
formal ERC pull request has been opened.

## Summary

Recomputable Verification Receipts (RVR) are small verification receipts built
from content-addressed claim, evidence, profile, and result identities. They
support independent checking of a verification result without implying that
the six-field receipt is itself a self-addressed object.

The core problem is that a stored `true`, a verifier signature, or a digest of
an opaque report does not tell a later reviewer whether the same result can be
derived from the same claim, evidence, rules, byte encoding, and external
context. RVR makes that derivation contract explicit through a
content-addressed **Verification Profile** and separates two questions that are
often collapsed:

| Axis | Values | Question |
| --- | --- | --- |
| Verification outcome | `VERIFIED`, `REFUTED`, `UNVERIFIABLE` | What did the identified verification procedure conclude? |
| Recomputation status | `REPRODUCED`, `DIVERGED`, `CANNOT_RECOMPUTE` | Could an independent implementation run the procedure, and did it derive the identical canonical result? |

At the generic level, `UNVERIFIABLE` means that the identified verification
procedure completed far enough to produce its semantic result, but under that
profile the committed inputs justify neither `VERIFIED` nor `REFUTED`. A
profile may reach that result because of unavailable decisive evidence,
insufficient quorum, a profile-defined ambiguity, an undecidable relation, or
another explicitly defined indeterminate state.

An original result may therefore be `UNVERIFIABLE` and still be independently
`REPRODUCED`. Conversely, if a required pinned dependency is unavailable, the
recomputer reports `CANNOT_RECOMPUTE`; it must not silently turn absence into
`false`, `REFUTED`, or `DIVERGED`.

The frozen RC2 `SHA256_EQUALS` profile instantiates only one of those generic
possibilities: an evidence member committed as `UNAVAILABLE` produces
`UNVERIFIABLE` with reason code `rvr.v0.required_evidence_unavailable`. This
discussion-level generalization does not retroactively change RC2; adopting it
normatively would require a new identified specification version.

## Proposed receipt

The experimental v0 receipt has exactly six fields:

```text
claimDigest
evidenceSetDigest
verificationProfileDigest
outcome
reasonCode
resultDigest
```

The receipt is accompanied by the claim, evidence-set descriptor and payloads,
Verification Profile, and canonical result object. It does not redundantly
copy serializer, specification, or vector-set identifiers because those are
already committed by `verificationProfileDigest`.

## Verification Profile

A Verification Profile is the authority for one verification procedure. An
implementation is evidence of conformance to that profile; the producer is not
authoritative merely because it emitted the original receipt.

The profile commits, directly or through exact immutable identities, to:

- the verification specification;
- the conformance/vector set;
- the canonical serializer and byte contract;
- the evidence-set contract;
- the canonical-result contract;
- result hashing and receipt projection rules;
- the reason-code namespace;
- every required outcome-relevant external-context commitment.

The profile itself has exact canonical bytes, and its SHA-256 digest is the
`verificationProfileDigest`. The current implementation uses a generic profile
manifest plus a separately pinned profile-specific constraints schema. This
keeps the generic envelope reusable without pretending that one example
profile's domain rules are universal.

## Evidence closure

The central closure invariant is:

> Every input capable of changing the verification outcome must be included in
> the committed evidence closure or identified by an immutable commitment or
> snapshot defined by the Verification Profile.

No uncommitted clock, network response, RPC head, mutable registry state,
environment variable, cache, model endpoint, or producer-local fact may affect
a result reported as reproducible.

The receipt commits to an evidence-set descriptor, not a single evidence blob.
Each present member commits to the SHA-256 and byte length of its exact raw
payload. A member may be explicitly marked `UNAVAILABLE`, but this has a narrow
meaning: reproducing the result proves that the committed descriptor said the
member was unavailable and that the profile derived the stated result from
that condition. RVR alone does not prove the historical fact that the evidence
was objectively impossible to obtain. A profile needing that stronger claim
must commit evidence of absence or unavailability.

RVR does not require committed evidence or normative dependencies to be
globally public. They need only be resolvable by the recomputer under the
Verification Profile's rules; if a required dependency cannot be resolved, the
recomputation status is `CANNOT_RECOMPUTE`.

## Canonical result and projections

The profile defines one canonical result object:

```text
canonical result
  -> canonical result bytes
  -> resultDigest
```

The receipt's `outcome` and `reasonCode` are projections of that same canonical
result. A receipt with the correct `resultDigest` but contradictory top-level
fields is invalid. This prevents a consumer that reads only the summary fields
from receiving a different statement than a consumer that resolves the result.

## Recomputation procedure

At a high level, an independent recomputer:

1. strictly parses and schema-validates the profile and supplied objects;
2. recomputes the profile identity and requires it to equal the receipt's
   `verificationProfileDigest`; a substituted or malformed profile is a gate
   rejection, not `DIVERGED`;
3. validates the original canonical result digest and its receipt projections;
4. resolves every dependency under that identified profile and returns
   `CANNOT_RECOMPUTE` without evaluation if a required normative dependency is
   unavailable or does not match its committed identity;
5. validates evidence closure and exact payload identities;
6. recomputes claim and evidence-set identities;
7. evaluates the claim under the profile and derives one canonical result;
8. recomputes its exact bytes and digest;
9. after successful profile validation and completed evaluation, returns
   `REPRODUCED` only if the recomputed claim, evidence-set, and result identities
   match the receipt; otherwise returns `DIVERGED`.

`DIVERGED` therefore means that semantic recomputation completed under the
identified verification contract but produced a different committed input or
canonical result identity. It is not a catch-all for an unresolved or
substituted profile.

Malformed schema, contradictory projections, and incomplete evidence closure
are gate rejections. They are not semantic outcomes and must not be recoded as
`REFUTED` or `UNVERIFIABLE`.

## Canonical byte contract

The RC2 implementation uses the experimental `rvr-canonical-json-v0` contract:

- input is limited to JSON null, booleans, Unicode scalar strings, arrays, and
  objects;
- numbers, duplicate decoded keys, and lone surrogates are rejected;
- object keys sort by Unicode scalar-value sequence;
- array order and duplicates are preserved;
- Unicode is not normalized;
- string escaping is completely specified;
- canonical text is encoded exactly once as UTF-8 with no insignificant
  whitespace.

This is not RFC 8785/JCS. JCS is an important neighboring canonicalization
standard, but it has a different input domain and ordering/serialization rules.
Calling the RVR contract “JCS” would create false interoperability.

## What RVR does not standardize

RVR v0 does not define:

- an on-chain registry, settlement system, or verifier contract;
- agent identity, reputation, delegation, authentication, or authorization;
- a proof system, ZK circuit, TEE, oracle, or trusted producer;
- AI-specific input provenance or model semantics;
- policy correctness, data availability, or historical proof of absence;
- a requirement to use ReceiptOS, TSEI, Protected Relation Fixtures, or any
  producer implementation.

Profiles may compose with those systems, but none becomes authority for the
generic core.

## Why discuss this in the Ethereum standards community?

Ethereum already has standards and active drafts that can carry an
`evidenceHash`, `proofHash`, `verificationDigest`, validation record, or other
opaque commitment while deliberately leaving some or all off-chain
verification semantics to the integrating system. For example,
[ERC-8273](https://ercs.ethereum.org/ERCS/erc-8273) leaves attestor evaluation
and evidence format to upper layers, the
[ERC-8263 draft](https://github.com/ethereum/ERCs/pull/1748) anchors an opaque
proof hash, and the
[ERC-8274 draft](https://github.com/ethereum/ERCs/pull/1771) standardizes an
on-chain verifier-interface surface for AI inference proofs.

RVR asks whether those references can point to one portable artifact whose
semantic verification contract and outcome-relevant closure are independently
recomputable instead of producer-specific. This is the affirmative Ethereum
interoperability case for discussing RVR here; whether it is sufficient for a
Standards-Track ERC remains deliberately open.

In the neighboring ERCs reviewed so far, I have not found another proposal
whose normative object combines content-addressed Verification Profile
identity, committed evidence closure, canonical result identity, and an
explicit independent recomputation status.

## Relationship to neighboring Ethereum proposals

The short boundary from the current review is:

| Neighbor | Its role | RVR's distinct role |
| --- | --- | --- |
| [ERC-8274 draft](https://github.com/ethereum/ERCs/pull/1771) | On-chain AI inference verifier interfaces | Portable profile/evidence/result identity and independent recomputation |
| [ERC-8281 draft](https://github.com/ethereum/ERCs/pull/1788) | Commitment construction, inclusion, and observation identity | Semantic recomputation under a pinned verification contract |
| [ERC-8299 draft](https://github.com/ethereum/ERCs/pull/1810) | AI input provenance commitments | Generic evidence closure and result reproduction |
| [ERC-8354](https://github.com/ethereum/ERCs/blob/master/ERCS/erc-8354.md) | ZK verdict against a confidential policy | Portable recomputation closure over resolvable committed dependencies; orthogonal to confidential-policy proof semantics |
| [ERC-8395 draft](https://github.com/ethereum/ERCs/pull/1967) | Delegated signed HTTP authorization | Semantic recomputation over committed verification inputs; no request authentication or delegation |
| [ERC-8263 draft](https://github.com/ethereum/ERCs/pull/1748) | On-chain proof-hash anchoring | Exact semantics behind an optionally anchored digest |
| [ERC-8004](https://ercs.ethereum.org/ERCS/erc-8004) | Agent identity, reputation, and validation registries | No registry or mandatory agent identity |
| [ERC-8273](https://ercs.ethereum.org/ERCS/erc-8273) | Transaction-scoped attestation gating | No action authorization; receipts may be referenced as evidence |

The intended dependency direction is compositional. For example, an RVR
profile may commit to the exact chain snapshot and verifier configuration used
to evaluate an ERC-8274 proof, or an ERC-8263/OCP record may anchor an RVR
digest. Neither composition changes which layer proves what.

## Executable baseline

The frozen [v0.0.1-rc.2 release](https://github.com/pipavlo82/recomputable-verification-receipts/releases/tag/v0.0.1-rc.2)
contains:

- a content-addressed generic profile and profile-specific constraints;
- exact schemas, canonical-byte vectors, resolver vectors, and semantic
  falsification cases;
- independent Python and TypeScript adapters using the same normative package;
- a tag-level CI gate.

Frozen identities:

```text
tag commit                f4476754c92e0bea549474722108ec60ded1385a
verificationProfileDigest ac16ba13abe00d8b7fac14bf5c35ee3175de3dbd7d70a296be27a094a99ef29c
packageDigest             e2c7712e4ce5551628cf2d1b65b0ae4458d5d2f7aaed7ffd3c969505ee29d63c
```

The semantic cases include a real evaluated negative control: changed evidence
is allowed through the gate, evaluation completes with `REFUTED`, and the
recomputation status is `DIVERGED` because the receipt still commits to the
original claim/result identities. Separate controls reject contradictory
projections and outcome-relevant hidden state.

## Security considerations

**Reproduction does not prove profile correctness.** Multiple implementations
can agree on a flawed profile. RVR makes conformance to the identified contract
and result falsifiable; it does not guarantee that the chosen verification
policy is wise.

**Implementation count is not independence.** Ports with shared code, shared
parsers, shared libraries, or common design mistakes may share failure modes.
Conformance reports should disclose lineage and dependencies rather than treat
“N implementations” as a security level.

**Mutable external context must be frozen.** Chain state, revocation lists,
time, remote documents, model endpoints, and registry contents can change. If
they affect the outcome, the profile must identify an immutable snapshot and
its resolution rules. Failure to obtain a required pinned snapshot is
`CANNOT_RECOMPUTE`.

**A producer can commit misleading `UNAVAILABLE` state.** Reproduction confirms
the committed descriptor and profile behavior, not the producer's historical
honesty about availability. Stronger profiles need independently checkable
evidence for that claim.

**Digest equality is scoped to exact contracts.** Equal bytes under different
schemas or profiles do not imply equal semantics. Consumers must compare the
Verification Profile identity, not only the result digest.

**Canonicalization is security-sensitive.** Duplicate keys, optional escaping,
Unicode normalization, array reordering, numbers, and host-language JSON
defaults can create cross-implementation disagreement. The exact byte contract
and adversarial vectors are part of the profile closure.

**Signatures and anchors do not upgrade semantics.** Signing or anchoring an RVR
receipt authenticates or timestamps a commitment under the adjacent system's
assumptions. It does not turn a non-reproducible or incomplete result into a
reproduced one.

## Questions for Magicians

1. Is this best pursued as a Standards-Track ERC for an off-chain artifact used
   by Ethereum applications, or should it remain an implementation-neutral
   companion specification until an Ethereum-specific integration surface is
   demonstrated?
2. Is the six-field receipt the right minimal interoperability surface, or is a
   field missing that cannot be committed through the Verification Profile?
3. Are the two axes and their six terms sufficiently distinct from existing
   verifier, proof, attestation, and commitment terminology?
4. Should gate rejection remain outside both axes, or should a future transport
   envelope standardize machine-readable gate errors separately?
5. Is content-addressed profile authority sufficient, or should the standard
   additionally define an optional authenticity envelope while keeping signer
   identity non-authoritative for semantics?
6. Does the proposed boundary with ERC-8281/OCP correctly separate commitment
   inclusion from semantic recomputation?
7. Which Ethereum integration would be the most useful first external
   integration profile after the generic core: a verifier interface, an
   observation commitment, input provenance, or a confidential-verdict proof?

## Proposed next step

Collect feedback on scope, terminology, and overlap first. Do not assign RVR an
ERC number or open a formal ERC pull request until that discussion gives
reasonable confidence that the generic off-chain artifact has a clear Ethereum
interoperability need and is not materially duplicative of a neighboring
proposal.
