# Exact-profile migration candidate

This is a local, read-only compatibility layer, not an extension to ERC-8404,
a new receipt format, authorization service or automatic receipt upgrader.
It is a research candidate for independent review; production remains HOLD.

The caller supplies an independently selected `--expected-profile` digest.
The receipt must bind that exact digest. A pinned local registry selects one
package by canonical profile identity, never by profileId, timestamps, claimed
adapter/version or file paths supplied by the receipt. RC2 and published-v0
have the same profileId but different digests and separate routes.

The registry's SHA-256 is pinned in dispatch.py. Every selected adapter,
schema, specification, vector and distribution-manifest file is checked before
use. Checked bytes are copied into a fresh temporary package; verification
executes only that snapshot, avoiding a second read of mutable source files.
The registry is not self-authenticating: independently reviewed source/commit
pins and a trusted local runtime are required. A local administrator can replace
the dispatcher and its pins. This is not OS-wide enforcement or a sandbox.

Both Python and TypeScript recompute the supplied bundle using the selected
historical or new implementation. The Python bridge imports unchanged code.
The TypeScript bridge appends a small exported wrapper to an ephemeral copy;
the original source is an exact byte prefix and is not rewritten. The wrapper
calls auditProfile and recompute without changing their logic. It is part of
the reviewed adapter identity, not a claim that arbitrary receipts were supported
by the old conformance CLI. A disagreement yields HOLD/CANNOT_RECOMPUTE, without
choosing a winner or changing a receipt. Unknown profiles and missing historical
contracts also have no fallback. Runtime faults are not evidence invalidity.

`migrationStatus` and dispatcher reasons belong only to this layer. They do not
add normative RVR outcome/status values. A gate rejection has no invented
semantic outcome. A selected result is returned under `result` unchanged;
REPRODUCED can describe a REFUTED or UNVERIFIABLE semantic outcome.

Supported replay runtimes: Python 3.12.10, Bun 1.3.14; the new Unicode route
also needs Node 22.15.0. Other versions produce CANNOT_RECOMPUTE pending replay,
not an assertion that a receipt is wrong. No installation or network request
occurs during verification. Inputs are limited to 2 MiB. Duplicate JSON keys
and malformed envelopes are rejected. Canonical profile bytes retain the old
number-free, scalar-Unicode RVR domain.

## Routes and migration rule

- `rc2-frozen`: exact package from f4476754c92e0bea549474722108ec60ded1385a;
  profile ac16ba13abe00d8b7fac14bf5c35ee3175de3dbd7d70a296be27a094a99ef29c.
- `published-v0`: original conformance route restored byte for byte from
  9dd36e882dd372f264b77b179130948aa5adcbde;
  profile 51f79442e96339ca45e9e6cc0c8232833efbee20e7480df00987dbc97da72948.
- `ucd17-v1`: separately packaged repaired code from f42d356d9e6cc4df93d80573471456b647ba95b2,
  with a NEW authenticated specification/schema/profile. Exact final digest
  and all package file pins are in registry.json. Unicode 17, code-point lengths,
  pattern search and conjunctive supported $ref siblings are explicit. This
  profile deliberately requires a nonempty present-evidence mediaType. The
  old profile permitted empty and continues to do so.

Use the new identity only for newly issued receipts under that contract.
No conversion, replacement signature, outcome overwrite or automatic aliasing
is provided. Previously published external profiles remain unchanged in their
own CLIs; this narrow dispatcher does not support them and returns CANNOT_RECOMPUTE.
Other historical profiles, even with a familiar name, require separately reviewed
pins and contracts. Finite fixture equivalence is not universal historical proof.

## Use and reproduce

```
python migration/dispatch.py --request request.json --expected-profile DIGEST
python research/schema-string-repair/migration_campaign.py --output OUT
python research/schema-string-repair/migration_mutations.py --output MUTATIONS
python research/schema-string-repair/unicode_data_campaign.py --output UNICODE
python research/schema-string-repair/unicode_data_mutations.py --output REMOVALS
python research/schema-string-repair/regressions.py --output REGRESSIONS
```

A request contains `bundle` (receipt, claim, evidenceSet, payloadsBase64,
verificationProfile, canonicalResult), optionally a distinct `candidateCase`.
The constructor/oracle in migration_campaign.py hashes bytes independently and
does not import either adapter. All fixtures are synthetic, unsigned test inputs;
the layer does not authenticate an issuer or attest execution. Initial failed
predictions and mutation survivors remain in the external evidence package.

Historical repair campaign scripts remain historical experiments; the current
Unicode campaign explicitly reads the separately packaged repaired runtime.
Do not publish a new policy under an old profile digest or silently reseal an
old manifest. New-package manifests are derived distribution identities only.
