# RVR v0 conformance gate

This directory contains the frozen generic RVR v0 profile, schemas, vectors,
expectations, package manifest, and a standard-library-only Python adapter.

Run:

```bash
python conformance/rvr-v0/adapter.py --check
```

The gate strictly parses JSON, validates schemas, audits exact dependency and
package identities, runs canonical-byte vectors, constructs receipts, and
recomputes every semantic and negative-control case. It does not import a
producer implementation.

`verification-profile.json` and the contracts it identifies are authority.
`adapter.py` is only conformance evidence and is deliberately excluded from
`verificationProfileDigest`.
