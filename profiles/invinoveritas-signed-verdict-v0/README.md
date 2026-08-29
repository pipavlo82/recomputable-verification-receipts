# invinoveritas signed verdict profile v0

This directory is the second executable external Verification Profile for RVR.
It verifies the deterministic bindings and BIP-340 signature of a real
invinoveritas `/review` verdict artifact.

The profile deliberately does **not** re-run or reproduce the LLM judgment.
`approve_with_concerns`, its confidence, and its issues remain signed,
content-addressed judgment data. The RVR outcome answers the narrower,
profile-bound proposition: whether the committed artifact, policy, decision,
event identity, and signature bindings verify under the exact pinned contracts.

The exact upstream `verdict_proof.json` Git blob is vendored under `upstream/`.
No live API, package, producer implementation, mutable key endpoint, or ambient
policy input is used by the gate.

Run the exact gate from the repository root:

```bash
python profiles/invinoveritas-signed-verdict-v0/adapter.py --check
```

Run the focused tests:

```bash
python profiles/invinoveritas-signed-verdict-v0/test_profile.py
```

This profile is experimental and non-normative with respect to the frozen RVR
`v0.0.1-rc.2` core. The profile contracts are authority; the adapter is an
independent, standard-library-only implementation and is not authoritative.
