# Independent Rust review of RVR RC2

This is non-normative review evidence for the frozen `v0.0.1-rc.2` baseline.
It is deliberately outside `conformance/rvr-v0/` and is not included in the
RC2 Verification Profile or conformance-package identity.

The reviewer was designed from the frozen specification and vectors. It does
not import, invoke, translate, or share code with either conformance adapter.
It independently implements:

- strict JSON parsing with duplicate-key rejection;
- `rvr-canonical-json-v0`, including the complete frozen escaping table;
- profile dependency and package-manifest identity checks;
- package-root dependency resolution and resolver vectors;
- evidence closure and the SHA256_EQUALS evaluation profile;
- canonical result identity, receipt projections, and recomputation statuses;
- the six required semantic/negative cases.

It intentionally does not present itself as a third authoritative schema
engine. The pinned JSON Schemas remain contract authority; this reviewer checks
their exact identities and independently checks the profile fields exercised by
the RC2 vectors.

Run from any process working directory:

```bash
cargo run --locked --manifest-path review/rc2-independent-rust/Cargo.toml -- --package-root .
```

After the independent report passes, compare it with the two frozen adapters:

```bash
python conformance/rvr-v0/adapter.py --check
bun conformance/rvr-v0/adapter.ts --check
```
