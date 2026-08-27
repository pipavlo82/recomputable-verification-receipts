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

The v0 Verification Profile format has a generic manifest boundary plus a
separately pinned profile-specific constraints schema. Normative dependency
paths resolve from an explicit supplied profile package root; they are never
interpreted relative to ambient process state.

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

## RC2 review and discussion lane

The frozen [`v0.0.1-rc.2` baseline](docs/review/RVR_V0_0_1_RC2_BASELINE.md)
is followed by non-normative review material that does not change its profile
or package identities:

- an [independent Rust implementation/reviewer](review/rc2-independent-rust/README.md);
- an [ERC-overlap audit](docs/review/ERC_OVERLAP_AUDIT_RC2.md);
- a [Magicians-ready pre-ERC proposal](docs/proposals/RVR_MAGICIANS_PROPOSAL.md).

The discussion draft requests community feedback before any formal ERC pull
request is considered.

## License

Licensed under the [Apache License 2.0](LICENSE).
