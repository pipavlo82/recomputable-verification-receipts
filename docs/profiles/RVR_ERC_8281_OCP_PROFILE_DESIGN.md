# RVR x ERC-8281/OCP first external profile design

Status: non-normative design note; no profile identity has been assigned.

This note starts the first external Ethereum integration lane for RVR. It does
not modify the frozen `v0.0.1-rc.2` Verification Profile, package, schemas,
vectors, adapters, or digests. It is not a formal ERC submission and does not
make ERC-8281 a dependency of the generic RVR core.

## 1. Why this profile is first

The Ethereum Magicians review produced two independent reasons to start with
the Observation Commitment Protocol:

1. the ERC-8281 author confirmed the boundary between commitment inclusion and
   RVR semantic recomputation; and
2. subsequent feedback selected observation commitment ahead of a confidential
   verdict because its closure can be made public without allowing a first
   profile to decide unresolved access-domain semantics by accident.

ERC-8281 answers whether exact observation bytes hash to a declared digest and
whether a named EVM receipt log contains that digest and committer value. RVR
answers whether an independent implementation obtained the same canonical
result under one exact content-addressed Verification Profile. Neither result
inherits guarantees from the other layer that its own procedure did not prove.

## 2. Audited ERC-8281 identity

This design pass reads the open ERC-8281 draft at the immutable PR head already
used by the RC2 overlap audit:

```text
repository: damonzwicker/ERCs
revision: 552350e0fb59d5a929f8470b6db6141ec9d244b8
specification path: ERCS/erc-8281.md
specification bytes: 23927
specification SHA-256: 8036fb5e232f4f01591d58efd920defd696211b7a5f91d425d672a75890f7bb4
vector path: assets/erc-8281/test-vectors.json
vector bytes: 28044
vector SHA-256: ab50fa0dfbad2966ac998b78d34cdab05e110870ee98f3a9bbe6c944e75da31f
reference verifier path: assets/erc-8281/verify.mjs
reference verifier bytes: 15147
reference verifier SHA-256: 623a45cf9c53c697a42df5bacb41bd07ac4da1bd3603fb425bc6e45ed0920850
```

The draft remains open and can change. An executable RVR profile must not read
these GitHub paths at evaluation time. It must carry the selected exact
normative bytes inside its own profile package, pin their package-relative
paths and SHA-256 digests, and retain the upstream coordinates as provenance.
The ERC-8281 reference verifier may be implementation evidence; it must not be
profile authority.

## 3. Profile-bound proposition

`REPRODUCED` has no universal truth meaning. It states that the recomputer
derived identical input identities and identical canonical result bytes. The
result's `outcome` states what that result says about the claim. The
Verification Profile must define the exact proposition established by each
possible canonical result.

The first profile should bind a proposition equivalent to:

> Under the identified ERC-8281 procedure and the profile's committed chain
> snapshot policy, the exact supplied observation bytes hash to the envelope's
> digest, and the selected successful transaction-receipt log contains that
> digest and the declared committer value at the referenced block.

The proposition must be represented by an exact constant in the
profile-specific claim and canonical-result contracts. A candidate identifier
is:

```text
rvr.erc8281.v0.observation_commitment_at_snapshot
```

This is a profile-specific field committed through `claimDigest` and
`resultDigest`; it is not a seventh receipt field.

Successful evaluation does not establish:

- authorship, identity, or authority of the committer;
- truth, meaning, availability, or canonical encoding of the observation;
- behavioral conformance of the emitting contract merely because it emitted
  the canonical event signature or advertises ERC-165 support;
- finality or consensus authenticity beyond the profile's exact snapshot
  assurance contract; or
- any application-layer conclusion derived from the observation bytes.

## 4. Candidate committed input closure

Every outcome-relevant input must be supplied as committed evidence or through
an immutable external-context commitment defined by the profile. The candidate
closure contains:

1. exact observation bytes;
2. the authenticated projection of the `erc8281/1` proof envelope;
3. the exact transaction-receipt material used by extraction;
4. chain ID, block number, and a REQUIRED block hash for this profile, even
   though `block_hash` is optional in the ERC-8281 envelope;
5. the selected receipt-array position, emitting contract, topics, receipt
   status, transaction hash, and declared committer;
6. the snapshot resolution and assurance contract; and
7. every serializer, schema, hash registry, verification procedure, vector set,
   result rule, and reason namespace required to evaluate those inputs.

An RPC URL is only a locator hint. A mutable live RPC response must not become
uncommitted ambient input. The exact response material used for evaluation
must be committed, or its authenticity must be established against immutable
snapshot material under rules pinned by the profile.

Additional fields which ERC-8281 instructs its verifiers to ignore must not
silently enlarge the semantic proposition. Before implementation, the profile
must choose and vector-test one exact identity rule:

- commit the whole envelope while evaluating only its authenticated fields; or
- derive and commit a closed authenticated-field projection.

The second option is preferred because it avoids semantically irrelevant
extension fields changing RVR input identity.

## 5. Chain snapshot assurance

ERC-8281 permits receipt retrieval from an RPC endpoint and explicitly states
the trust consequences of doing so. RVR must make that trust boundary part of
the profile-defined proposition instead of implying a stronger guarantee.

A block hash identifies an immutable block header, but the EVM state root does
not by itself authenticate transaction receipts. A profile claiming
consensus-authenticated receipt inclusion would additionally need the block
header and a receipt inclusion proof against its `receiptsRoot`, plus an exact
header/finality trust rule.

The first executable lane must deliberately select one assurance level:

| Candidate | What can be reproduced | What it does not prove |
| --- | --- | --- |
| Committed receipt snapshot | ERC-8281 invariant over exact committed receipt material | Consensus authenticity of that material |
| Profile-defined RPC snapshot | ERC-8281 invariant over responses accepted by an exact resolver/quorum rule | More honesty than that resolver rule provides |
| Receipt inclusion proof | Receipt membership against a committed block header's `receiptsRoot` | Canonicality/finality unless separately established |

Recommendation for the thin external profile: start with a committed receipt
snapshot and name that assurance level in the proposition and canonical result.
Add receipt-trie proof and finality as a stronger successor profile rather than
silently treating them as already established.

If snapshot material required by the identified profile cannot be resolved,
the recomputation status is `CANNOT_RECOMPUTE` and semantic evaluation does not
run. It must never become `DIVERGED`, `REFUTED`, or a default false result.

## 6. Failure-path mapping

The executable profile must distinguish at least these paths:

| Condition | RVR handling |
| --- | --- |
| Profile or profile-pinned artifact unavailable or wrong digest | `CANNOT_RECOMPUTE`; no evaluation |
| Required immutable snapshot unavailable | `CANNOT_RECOMPUTE`; no evaluation |
| Claim, envelope projection, evidence descriptor, or snapshot object malformed | gate rejection |
| Outcome-relevant input missing from closure | gate rejection |
| Committed evidence explicitly records that required observation bytes were unavailable during the original evaluation | semantic `UNVERIFIABLE`; exact result may later be `REPRODUCED` |
| Well-formed inputs complete evaluation and an ERC-8281 assertion fails | semantic `REFUTED` with an assertion-specific reason |
| Well-formed inputs complete evaluation and every ERC-8281 assertion passes | semantic `VERIFIED` |
| Independent evaluation completes but an input identity or canonical result differs from the receipt | `DIVERGED` |
| Canonical result and every input identity match | `REPRODUCED`, independently of whether outcome is `VERIFIED`, `REFUTED`, or `UNVERIFIABLE` |

Malformed-versus-refuted classification must be exhaustively pinned. In
particular, unsupported envelope versions, unrecognized hash identifiers,
invalid EIP-55 addresses, malformed decimal strings, invalid topic counts, and
failed comparison assertions need exact non-overlapping ownership and negative
vectors.

## 7. Candidate canonical result surface

The profile-specific canonical result should commit at least:

```text
schema
proposition
outcome
reasonCode
evaluation.procedure
evaluation.snapshotAssurance
evaluation.hashFunction
evaluation.observationDigest
evaluation.envelopeDigest
evaluation.receiptSnapshotDigest
evaluation.chainId
evaluation.transactionHash
evaluation.blockNumber
evaluation.blockHash
evaluation.receiptLogPosition
evaluation.emittingContract
evaluation.onChainDigest
evaluation.committer
```

All identity-bearing values require exact schemas and byte contracts. Numeric
EVM quantities remain canonical decimal strings inside RVR JSON identity
objects. The receipt continues to project only `outcome` and `reasonCode`; the
full result, including `proposition`, is committed by `resultDigest`.

## 8. Required first vectors

The profile vector set should include:

1. `VERIFIED + REPRODUCED` for a valid SHA-256 observation and receipt snapshot;
2. `REFUTED + DIVERGED` after mutating observation bytes while keeping the
   original receipt claim fixed;
3. `UNVERIFIABLE + REPRODUCED` for committed unavailable observation bytes;
4. `CANNOT_RECOMPUTE` for unavailable required snapshot material;
5. projection contradiction rejection;
6. hidden live-RPC-state rejection;
7. wrong chain ID;
8. reverted receipt;
9. wrong receipt-array position, including the JSON-RPC `logIndex`
   confusion case;
10. contract, topic count, topic-0, digest, committer, block number, and block
    hash mismatches;
11. all three ERC-8281 hash functions, including the BLAKE2b-256 versus
    truncated-BLAKE2b-512 distinction; and
12. mutation of an ignored envelope extension field proving the selected
    envelope identity rule.

The gate must recompute rather than trust the upstream reference verifier or
stored expected outputs. At least one independent implementation must not
import either the upstream verifier or the existing RVR adapters.

## 9. Open decisions before implementation

1. Freeze the exact proposition identifier and claim/result schemas.
2. Select the first snapshot assurance level from section 5.
3. Decide whether the authenticated envelope projection or whole envelope is
   the identity-bearing object.
4. Define gate rejection versus semantic `REFUTED` ownership for every
   ERC-8281 rejection condition.
5. Define whether committed `UNAVAILABLE` observation bytes are permitted by
   this profile.
6. Define the exact contract-behavior trust statement for `committer`; event
   extraction alone does not prove the contract assigned `msg.sender`.
7. Pin the complete dependency package and conformance vectors.
8. Re-audit ERC-8281 immediately before freezing because PR #1788 remains open.

Only after these decisions are reviewed should the repository add an
executable profile package. No RC3 is justified by this design note alone.
