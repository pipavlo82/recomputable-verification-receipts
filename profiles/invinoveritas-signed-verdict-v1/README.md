# invinoveritas signed verdict profile v1

This directory is the second executable external Verification Profile for RVR.
It verifies the deterministic bindings, v17 freshness-beacon commitment, and
BIP-340 signature of a real invinoveritas `/review` verdict artifact.

The profile deliberately does **not** re-run or reproduce the LLM judgment.
`reject`, its confidence, and its issues remain signed,
content-addressed judgment data. The RVR outcome answers the narrower,
profile-bound proposition: whether the committed artifact, policy, decision,
freshness commitment, event identity, and signature bindings verify under the
exact pinned contracts.

The profile reproduces the freshness-beacon content address; it does not claim
that the named Bitcoin block was historically canonical or sufficiently final.
That stronger proposition requires committed header/consensus evidence in a
different profile and cannot be inferred from mutable explorer lookups.

The exact upstream `verdict_proof_v17.json` Git blob is vendored under
`upstream/`. Its identity is established from the raw Git object, not from a
platform-dependent working-tree checkout. The gate verifies its byte length and
SHA-256 and independently recomputes its Git blob OID before parsing or use. No
live API, package, producer implementation, mutable key endpoint, or ambient
policy input is used by the gate.

Run the exact gate from the repository root:

```bash
python profiles/invinoveritas-signed-verdict-v1/adapter.py --check
```

Run the focused tests:

```bash
python profiles/invinoveritas-signed-verdict-v1/test_profile.py
```

This profile is experimental and non-normative with respect to the frozen RVR
`v0.0.1-rc.2` core. The profile contracts are authority; the adapter is an
independent, standard-library-only implementation and is not authoritative.
