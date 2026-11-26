# Independent review checklist

**ITERATE / Production HOLD.** The PR is review-only, with no merge or deploy request.

## Federico — evidence and independent verifier seat

1. Recompute the provided job/evidence sample using FORMAT.md, pinned RVR and the
   separate checker. Confirm all canonical bytes, profile/receipt/claim bindings,
   assessor authority, exact submission digest and the verifier signing digest.
2. Produce a fresh local run with your own ephemeral credentials and try policy,
   state, obligation, nonce, receipt and confirmation substitutions. Report exact
   review commit, dependency-manifest hash, command outputs and counterexamples.
3. Check whether the authority policy is adequate rather than accepting the bridge's
   selected policy. The public sample policy is a laboratory fixture, not a production
   authority root. A recreated stored digest alone is not an independent judgment.
4. Review an independent seat's enrollment, authenticated public-key fingerprint,
   custody, revocation and authentic state-read requirements. No private key is
   requested. V1 has one immutable verifier; a threshold/seat registry is future work.

## Jimmy — ERC-8183 job and settlement semantics

1. Is the pinned reference implementation/API the intended prototype baseline?
   It is unchanged. Review provider acceptance, job state, budget/requirements
   commitments before funding and the use of the actual JobSubmitted event.
2. Review every fund exit and whether factory role renunciation and zero hooks/fees
   adequately exclude upgrade/admin bypass for protected jobs. Old deployments and
   a client choosing another evaluator for another job are outside that claim.
3. Review expiry/refund races, exact balance accounting and nonce reuse across jobs.
   This is not a durable distributed crash-recovery or exactly-once theorem.
4. Should a future version permit any relayer? Current V1 intentionally retains its
   fixed bridge caller check; bridge authorization alone never passes the verifier gate.

## Alexander — ERC-8378 asset meaning and parameter behavior

1. Confirm the pinned Prediction implementation and units/parameter interpretation.
   A real token transfer in the test EVM establishes mechanics, not economic value.
2. Review Normal-only accounts, matching immutable round, mutable prediction merges,
   zero fees, unsolicited incoming tokens, parameter poisoning and resulting refusal.
3. Identify what collateral, mint/redeem authority, pricing and liquidity requirements
   are needed for meaningful remuneration. None is established by 100 synthetic units.
4. Which additional token states or mixed-parameter pools should be supported before
   expanding beyond this narrow profile? Current refusal is a safety behavior, not
   a liveness or arbitrary-token compatibility proof.

## Common acceptance questions

- Can the bridge pay without an independently authorized confirmation? Try empty
  signature, bridge signature, forged flag and alternate entry points.
- Are all 21 fields, domain/chain/contract identities, expiry/epoch and replay bound?
- Can a signed nonpositive RVR/VECA/recomputation result pay? It must not.
- Can retained administration bypass the gate? The excluded-topology test says yes;
  verify the supported factory truly leaves no originating escrow authority.
- Can a compromised single verifier lie and pay? The counterexample says yes. Keep
  that trust boundary explicit and do not label the prototype trustless settlement.
- Are ephemeral test credentials absent from source, history, samples and outputs?

The expected baseline is 68/68 contract tests, 48/48 checker controls, 43/43 issuer
controls, 20 KILLED/0 SURVIVED/0 INVALID physical mutations and 13/13 unchanged Core.
Check the cleaned review copy's separate fresh results; do not relabel the original
private candidate's evidence as proof of an edited review commit.
