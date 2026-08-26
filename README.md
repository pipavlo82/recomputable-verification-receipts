# Recomputable Verification Receipts

This repository defines a generic, implementation-neutral core for
Recomputable Verification Receipts (RVR).

RVR separates two axes:

- verification outcome: `VERIFIED`, `REFUTED`, or `UNVERIFIABLE`;
- recomputation status: `REPRODUCED`, `DIVERGED`, or `CANNOT_RECOMPUTE`.

The v0 thin slice is intentionally small. It establishes content-addressed
Verification Profiles, exact canonical bytes, evidence closure, canonical
result identity, projection checks, and mechanically distinct failure paths.
It has no dependency on ReceiptOS, TSEI, Protected Relation Fixtures, an
on-chain registry, or a particular producer implementation.

Run the gate:

```bash
python conformance/rvr-v0/adapter.py --check
bun conformance/rvr-v0/adapter.ts --check
```

Run the test entrypoint used by CI:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

The Verification Profile and its committed contracts are authority. The
independent Python and TypeScript adapters are cross-implementation evidence
of conformance; neither implementation is authoritative.

## License

Licensed under the [Apache License 2.0](LICENSE).
