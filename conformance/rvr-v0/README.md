# RVR v0 conformance gate

This directory contains the frozen generic RVR v0 profile, schemas, vectors,
expectations, package manifest, and independent Python and TypeScript adapters.

Run:

```bash
python conformance/rvr-v0/adapter.py --check
bun conformance/rvr-v0/adapter.ts --check
```

Each gate independently parses strict JSON, validates schemas, audits exact
dependency and package identities, runs canonical-byte vectors, constructs
receipts, and recomputes every semantic and negative-control case. Neither
imports a producer implementation or the other adapter.

`verification-profile.json` and the contracts it identifies are authority.
Both adapters are only conformance evidence and are deliberately excluded from
`verificationProfileDigest`.
