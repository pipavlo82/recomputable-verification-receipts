# RVR v0 conformance gate

This directory contains the frozen generic RVR v0 profile, generic profile
manifest schema, profile-specific constraints schema, schemas, vectors,
expectations, package manifest, and independent Python and TypeScript adapters.

Run:

```bash
python conformance/rvr-v0/adapter.py --check
bun conformance/rvr-v0/adapter.ts --check
```

Each gate independently parses strict JSON, validates schemas, audits exact
dependency and package identities, runs canonical-byte vectors, constructs
receipts, recomputes every semantic and negative-control case, and proves that
all pinned adversarial semantic mutants are killed by their named witnesses.
This is a semantic falsification audit, not a claim of a complete
mutation-testing harness. Neither adapter imports a producer implementation or
the other adapter.

`verification-profile.json` and the contracts it identifies are authority. The
profile is first validated by `verification-profile-manifest.schema.json`, then
by `rvr-generic-sha256-equals-v0.profile.schema.json`. Its dependency paths are
resolved only from the explicitly supplied profile package root before exact
SHA-256 verification. Both adapters are only conformance evidence and are
deliberately excluded from `verificationProfileDigest`.
