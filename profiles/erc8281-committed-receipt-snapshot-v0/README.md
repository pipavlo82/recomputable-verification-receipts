# ERC-8281 committed receipt snapshot profile v0

This directory is the first executable external Verification Profile for RVR.
It evaluates the ERC-8281/OCP verification invariant over exact observation
bytes and a canonical committed receipt snapshot.

The profile is deliberately non-normative with respect to the generic RVR core
and does not modify the frozen `v0.0.1-rc.2` package. Its proposition is narrower
than consensus-authenticated or finalized chain inclusion: it reproduces the
ERC-8281 invariant over the exact snapshot committed by the evidence closure.

Run the exact gate from the repository root:

```bash
python profiles/erc8281-committed-receipt-snapshot-v0/adapter.py --check
```

Run the focused tests:

```bash
python -m unittest profiles/erc8281-committed-receipt-snapshot-v0/test_profile.py
```

The profile, its pinned specification, schemas, and vectors are authority. The
adapter is standard-library-only conformance evidence and imports neither the
upstream ERC-8281 reference verifier nor the RVR RC2 adapters.
