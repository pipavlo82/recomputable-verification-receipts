# RVR v0.0.1-rc.2 implementation baseline

Status: frozen experimental implementation baseline.

Snapshot date: 2026-08-26.

## Frozen identity

| Item | Identity |
| --- | --- |
| Git tag | `v0.0.1-rc.2` |
| Annotated tag object | `dccf408d93835d6e6b8a0b16f51fb753cd222d89` |
| Peeled commit | `f4476754c92e0bea549474722108ec60ded1385a` |
| Verification Profile digest | `ac16ba13abe00d8b7fac14bf5c35ee3175de3dbd7d70a296be27a094a99ef29c` |
| Package digest | `e2c7712e4ce5551628cf2d1b65b0ae4458d5d2f7aaed7ffd3c969505ee29d63c` |
| Release | [v0.0.1-rc.2](https://github.com/pipavlo82/recomputable-verification-receipts/releases/tag/v0.0.1-rc.2) |

The tag, release, tagged tree, Verification Profile, conformance package, and
their identities are not to be rewritten. Corrections or extensions require a
new version and new identities.

## What is frozen

RC2 freezes the experimental thin slice demonstrated by the tagged package:

- the six-field receipt;
- the two independent status axes;
- the generic Verification Profile manifest boundary;
- the profile-specific constraints boundary;
- `rvr-canonical-json-v0` and its exact string escaping rules;
- package-root dependency resolution;
- evidence closure and canonical-result projection enforcement;
- the pinned falsification vectors and package identity;
- the Python and TypeScript conformance results recorded by the release.

This is an implementation baseline, not a claim of stable-standard status. A
future release may intentionally change a contract, but it must do so under a
new content identity and must not reinterpret RC2.

## Post-freeze review lane

Work after RC2 is isolated from the frozen conformance package. In particular,
the independent Rust reviewer under `review/rc2-independent-rust/` is
non-normative review evidence. It is deliberately excluded from the RC2
Verification Profile and package digests.

The publication drafts under `docs/review/` and `docs/proposals/` describe and
audit RC2. They do not amend its normative contracts.
