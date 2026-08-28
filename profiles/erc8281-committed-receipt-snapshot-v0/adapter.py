#!/usr/bin/env python3
"""Independent executable gate for the RVR x ERC-8281 snapshot profile.

The pinned contracts are authority.  This standard-library-only adapter is
non-authoritative conformance evidence and imports neither the RVR RC2
adapters nor an ERC-8281 producer/verifier implementation.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "profiles/erc8281-committed-receipt-snapshot-v0"
PROFILE_PATH = PACKAGE / "verification-profile.json"
MANIFEST_PATH = PACKAGE / "manifest.json"
GENERIC_PROFILE_SCHEMA = ROOT / "conformance/rvr-v0/verification-profile-manifest.schema.json"
PROFILE_SCHEMA_PATH = PACKAGE / "profile.schema.json"
RVR_SCHEMA_PATH = PACKAGE / "rvr.schema.json"
VECTORS_PATH = PACKAGE / "vectors.json"
EXPECTED_PATH = PACKAGE / "expected.json"
UPSTREAM_SPEC_PATH = PACKAGE / "upstream/erc-8281.md"
UPSTREAM_VECTORS_PATH = PACKAGE / "upstream/test-vectors.json"

UPSTREAM_SPEC_SHA256 = "8036fb5e232f4f01591d58efd920defd696211b7a5f91d425d672a75890f7bb4"
UPSTREAM_VECTORS_SHA256 = "ab50fa0dfbad2966ac998b78d34cdab05e110870ee98f3a9bbe6c944e75da31f"

TOPIC0 = "0xdca60c2087041cbb12d9a57628c6cad28ecbd0437e47c7ab6c3aa6e162bf4497"
PROPOSITION = "rvr.erc8281.v0.observation_commitment_at_committed_receipt_snapshot"
ENVELOPE_PROJECTION_FIELDS = (
    "version",
    "digest",
    "hash_function",
    "chain_id",
    "contract",
    "tx_hash",
    "block_number",
    "receipt_log_position",
    "committer",
    "block_hash",
)

PACKAGE_MEMBERS = (
    "conformance/rvr-v0/verification-profile-manifest.schema.json",
    "profiles/erc8281-committed-receipt-snapshot-v0/README.md",
    "profiles/erc8281-committed-receipt-snapshot-v0/SPEC.md",
    "profiles/erc8281-committed-receipt-snapshot-v0/adapter.py",
    "profiles/erc8281-committed-receipt-snapshot-v0/expected.json",
    "profiles/erc8281-committed-receipt-snapshot-v0/profile.schema.json",
    "profiles/erc8281-committed-receipt-snapshot-v0/rvr.schema.json",
    "profiles/erc8281-committed-receipt-snapshot-v0/test_profile.py",
    "profiles/erc8281-committed-receipt-snapshot-v0/upstream/erc-8281.md",
    "profiles/erc8281-committed-receipt-snapshot-v0/upstream/test-vectors.json",
    "profiles/erc8281-committed-receipt-snapshot-v0/vectors.json",
    "profiles/erc8281-committed-receipt-snapshot-v0/verification-profile.json",
)


class ProfileError(Exception):
    pass


class SchemaError(ProfileError):
    pass


class GateRejected(ProfileError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_constant(value: str) -> Any:
    raise ProfileError(f"non-standard JSON constant: {value}")


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_surrogates(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ProfileError("JSON contains a surrogate code point")
    elif isinstance(value, list):
        for item in value:
            reject_surrogates(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            reject_surrogates(key)
            reject_surrogates(item)


def parse_json(data: bytes, label: str) -> Any:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProfileError(f"invalid JSON in {label}: {error}") from error
    reject_surrogates(value)
    return value


def load_json(path: Path) -> Any:
    try:
        return parse_json(path.read_bytes(), str(path))
    except OSError as error:
        raise ProfileError(f"cannot read {path}: {error}") from error


def canonical_string(value: str) -> str:
    short = {
        0x08: "\\b",
        0x09: "\\t",
        0x0A: "\\n",
        0x0C: "\\f",
        0x0D: "\\r",
        0x22: '\\"',
        0x5C: "\\\\",
    }
    output = ['"']
    for character in value:
        code = ord(character)
        if 0xD800 <= code <= 0xDFFF:
            raise ProfileError("canonical JSON forbids surrogates")
        if code in short:
            output.append(short[code])
        elif code <= 0x1F:
            output.append(f"\\u{code:04x}")
        else:
            output.append(character)
    output.append('"')
    return "".join(output)


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return canonical_string(value)
    if isinstance(value, (int, float)):
        raise ProfileError("rvr-canonical-json-v0 forbids numbers")
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ProfileError("canonical JSON object key is not a string")
        keys = sorted(value, key=lambda key: tuple(ord(character) for character in key))
        return "{" + ",".join(
            canonical_string(key) + ":" + canonical_json(value[key]) for key in keys
        ) + "}"
    raise ProfileError(f"unsupported canonical value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return sha256(canonical_bytes(value))


def resolve_pointer(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if reference == "#":
        return root
    if not reference.startswith("#/"):
        raise SchemaError(f"unsupported schema reference: {reference}")
    value: Any = root
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or token not in value:
            raise SchemaError(f"unresolved schema reference: {reference}")
        value = value[token]
    if not isinstance(value, dict):
        raise SchemaError(f"schema reference is not an object: {reference}")
    return value


def schema_type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "null": value is None,
        "integer": isinstance(value, int) and not isinstance(value, bool),
    }.get(expected, False)


def validate_schema(value: Any, schema: dict[str, Any], root: dict[str, Any], at: str = "$") -> None:
    if "$ref" in schema:
        validate_schema(value, resolve_pointer(root, schema["$ref"]), root, at)
        return
    if "oneOf" in schema:
        matches = 0
        for candidate in schema["oneOf"]:
            try:
                validate_schema(value, candidate, root, at)
                matches += 1
            except SchemaError:
                pass
        if matches != 1:
            raise SchemaError(f"{at}: oneOf matched {matches} branches")
    if "const" in schema and value != schema["const"]:
        raise SchemaError(f"{at}: const mismatch")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaError(f"{at}: value not in enum")
    expected_type = schema.get("type")
    if expected_type is not None and not schema_type_matches(value, expected_type):
        raise SchemaError(f"{at}: expected {expected_type}")
    if isinstance(value, str) and "pattern" in schema:
        if re.fullmatch(schema["pattern"], value) is None:
            raise SchemaError(f"{at}: pattern mismatch")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise SchemaError(f"{at}: too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise SchemaError(f"{at}: too many items")
        if "items" in schema:
            for index, item in enumerate(value):
                validate_schema(item, schema["items"], root, f"{at}[{index}]")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for required in schema.get("required", []):
            if required not in value:
                raise SchemaError(f"{at}: missing {required}")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise SchemaError(f"{at}: additional properties {sorted(extra)}")
        for key, child in value.items():
            if key in properties:
                validate_schema(child, properties[key], root, f"{at}.{key}")


def dependency_rows(members: list[dict[str, Any]]) -> bytes:
    rows = [f"{member['path']}\t{member['sha256']}\n" for member in members]
    return "".join(sorted(rows)).encode("utf-8")


def profile_dependencies(profile: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        profile["profileSchemaContract"]["manifest"],
        profile["profileSchemaContract"]["constraints"],
        profile["verificationSpecification"],
        *profile["conformanceVectorSet"]["members"],
        *profile["schemaContracts"],
    ]


def safe_dependency_path(raw: str) -> Path:
    if "\\" in raw or ":" in raw or raw.startswith("/"):
        raise ProfileError(f"invalid dependency path: {raw}")
    segments = raw.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise ProfileError(f"invalid dependency path: {raw}")
    path = (ROOT / Path(*segments)).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ProfileError(f"dependency escapes package root: {raw}") from error
    return path


def validate_eip55(address: str) -> bool:
    if re.fullmatch(r"0x[0-9A-Fa-f]{40}", address) is None:
        return False
    body = address[2:]
    digest = keccak256(body.lower().encode("ascii")).hex()
    for index, character in enumerate(body):
        if character.isalpha() and character.isupper() != (int(digest[index], 16) >= 8):
            return False
    return True


ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
MASK64 = (1 << 64) - 1


def rotate_left(value: int, count: int) -> int:
    if count == 0:
        return value & MASK64
    return ((value << count) | (value >> (64 - count))) & MASK64


def keccak_f(state: list[int]) -> None:
    for constant in ROUND_CONSTANTS:
        column = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        delta = [column[(x - 1) % 5] ^ rotate_left(column[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= delta[x]
        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = rotate_left(state[x + 5 * y], ROTATION[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = moved[x + 5 * y] ^ ((~moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y])
        state[0] ^= constant


def keccak256(data: bytes) -> bytes:
    rate = 136
    padding = bytearray(data)
    padding.append(0x01)
    padding.extend(b"\x00" * ((rate - len(padding) % rate) % rate))
    padding[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padding), rate):
        block = padding[offset:offset + rate]
        for index in range(rate // 8):
            state[index] ^= int.from_bytes(block[index * 8:(index + 1) * 8], "little")
        keccak_f(state)
    return b"".join(word.to_bytes(8, "little") for word in state)[:32]


def observation_hash(name: str, data: bytes) -> str:
    if name == "sha2-256":
        return sha256(data)
    if name == "keccak-256":
        return keccak256(data).hex()
    if name == "blake2b-256":
        return hashlib.blake2b(data, digest_size=32).hexdigest()
    raise GateRejected("rvr.gate.schema_invalid", f"unsupported hash function: {name}")


def audit_profile(
    dependency_overrides: dict[str, bytes] | None = None,
) -> tuple[dict[str, Any], str, dict[str, Any], dict[str, bytes]]:
    profile = parse_json(PROFILE_PATH.read_bytes(), str(PROFILE_PATH))
    generic_schema_bytes = GENERIC_PROFILE_SCHEMA.read_bytes()
    generic_schema = parse_json(generic_schema_bytes, str(GENERIC_PROFILE_SCHEMA))
    try:
        validate_schema(profile, generic_schema, generic_schema)
    except SchemaError as error:
        raise GateRejected("rvr.gate.schema_invalid", str(error)) from error

    pinned_bytes: dict[str, bytes] = {}
    for dependency in profile_dependencies(profile):
        try:
            dependency_bytes = (
                dependency_overrides[dependency["id"]]
                if dependency_overrides and dependency["id"] in dependency_overrides
                else safe_dependency_path(dependency["path"]).read_bytes()
            )
        except OSError as error:
            raise GateRejected("rvr.gate.identity_mismatch", f"dependency unavailable: {dependency['id']}") from error
        if sha256(dependency_bytes) != dependency["sha256"]:
            raise GateRejected("rvr.gate.identity_mismatch", f"dependency mismatch: {dependency['id']}")
        pinned_bytes[dependency["id"]] = dependency_bytes

    manifest_dependency = profile["profileSchemaContract"]["manifest"]
    if pinned_bytes[manifest_dependency["id"]] != generic_schema_bytes:
        raise GateRejected("rvr.gate.identity_mismatch", "generic bootstrap schema differs from its pinned bytes")
    upstream_artifacts = (
        ("erc8281-specification", UPSTREAM_SPEC_PATH, UPSTREAM_SPEC_SHA256, "erc8281-specification-sha256:"),
        ("erc8281-vectors", UPSTREAM_VECTORS_PATH, UPSTREAM_VECTORS_SHA256, "erc8281-vectors-sha256:"),
    )
    commitments = profile["externalContextPolicy"]["immutableCommitments"]
    for artifact_id, path, expected_digest, commitment_prefix in upstream_artifacts:
        try:
            artifact_bytes = path.read_bytes()
        except OSError as error:
            raise GateRejected("rvr.gate.identity_mismatch", f"vendored normative artifact unavailable: {path.name}") from error
        if sha256(artifact_bytes) != expected_digest or commitment_prefix + expected_digest not in commitments:
            raise GateRejected("rvr.gate.identity_mismatch", f"vendored normative artifact mismatch: {path.name}")
        pinned_bytes[artifact_id] = artifact_bytes

    constraints_dependency = profile["profileSchemaContract"]["constraints"]
    specific_schema = parse_json(
        pinned_bytes[constraints_dependency["id"]],
        constraints_dependency["path"],
    )
    try:
        validate_schema(profile, specific_schema, specific_schema)
    except SchemaError as error:
        raise GateRejected("rvr.gate.schema_invalid", str(error)) from error

    parse_json(pinned_bytes["erc8281-vectors"], str(UPSTREAM_VECTORS_PATH))
    vector_members = profile["conformanceVectorSet"]["members"]
    if sha256(dependency_rows(vector_members)) != profile["conformanceVectorSet"]["digest"]:
        raise GateRejected("rvr.gate.identity_mismatch", "vector-set digest mismatch")
    rvr_schema_dependency = next(
        dependency for dependency in profile["schemaContracts"] if dependency["id"] == "rvr-schema"
    )
    rvr_schema_digest = sha256(pinned_bytes[rvr_schema_dependency["id"]])
    if profile["evidenceSetContract"]["schemaSha256"] != rvr_schema_digest:
        raise GateRejected("rvr.gate.identity_mismatch", "evidence schema binding mismatch")
    if profile["canonicalResultContract"]["schemaSha256"] != rvr_schema_digest:
        raise GateRejected("rvr.gate.identity_mismatch", "result schema binding mismatch")
    rvr_schema = parse_json(pinned_bytes[rvr_schema_dependency["id"]], rvr_schema_dependency["path"])
    return profile, canonical_digest(profile), rvr_schema, pinned_bytes


def present_member(identifier: str, media_type: str, payload: bytes) -> dict[str, Any]:
    return {
        "id": identifier,
        "status": "PRESENT",
        "mediaType": media_type,
        "byteLength": str(len(payload)),
        "digest": sha256(payload),
    }


def evidence_for(observation: bytes | None, snapshot: dict[str, Any]) -> tuple[dict[str, Any], dict[str, bytes]]:
    snapshot_bytes = canonical_bytes(snapshot)
    if observation is None:
        observation_member = {
            "id": "observation-bytes",
            "status": "UNAVAILABLE",
            "reasonCode": "rvr.erc8281.v0.evidence_unavailable",
        }
        payloads: dict[str, bytes] = {"receipt-snapshot": snapshot_bytes}
    else:
        observation_member = present_member("observation-bytes", "application/octet-stream", observation)
        payloads = {"observation-bytes": observation, "receipt-snapshot": snapshot_bytes}
    members = [
        observation_member,
        present_member("receipt-snapshot", "application/json", snapshot_bytes),
    ]
    members.sort(key=lambda member: member["id"])
    return {"schema": "rvr.evidence-set.v0", "members": members}, payloads


def evidence_digest(evidence_set: dict[str, Any]) -> str:
    normalized = copy.deepcopy(evidence_set)
    normalized["members"].sort(key=lambda member: member["id"])
    return canonical_digest(normalized)


def validate_envelope_projection(projection: dict[str, Any], rvr_schema: dict[str, Any]) -> None:
    try:
        validate_schema(
            projection,
            resolve_pointer(rvr_schema, "#/$defs/envelopeProjection"),
            rvr_schema,
        )
    except SchemaError as error:
        raise GateRejected("rvr.gate.schema_invalid", str(error)) from error
    if not validate_eip55(projection["contract"]) or not validate_eip55(projection["committer"]):
        raise GateRejected("rvr.gate.schema_invalid", "contract or committer has an invalid EIP-55 checksum")


def derive_envelope_projection(raw_envelope: dict[str, Any], rvr_schema: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw_envelope, dict):
        raise GateRejected("rvr.gate.schema_invalid", "raw ERC-8281 envelope must be an object")
    missing = [field for field in ENVELOPE_PROJECTION_FIELDS if field not in raw_envelope]
    if missing:
        raise GateRejected("rvr.gate.schema_invalid", f"raw ERC-8281 envelope missing fields: {missing}")
    projection = {field: copy.deepcopy(raw_envelope[field]) for field in ENVELOPE_PROJECTION_FIELDS}
    validate_envelope_projection(projection, rvr_schema)
    return projection


def validate_claim(claim: dict[str, Any], rvr_schema: dict[str, Any]) -> None:
    try:
        validate_schema(claim, resolve_pointer(rvr_schema, "#/$defs/claim"), rvr_schema)
    except SchemaError as error:
        raise GateRejected("rvr.gate.schema_invalid", str(error)) from error
    validate_envelope_projection(claim["envelopeProjection"], rvr_schema)


def validate_evidence(evidence_set: dict[str, Any], payloads: dict[str, bytes], rvr_schema: dict[str, Any]) -> None:
    try:
        validate_schema(evidence_set, resolve_pointer(rvr_schema, "#/$defs/evidenceSet"), rvr_schema)
    except SchemaError as error:
        raise GateRejected("rvr.gate.schema_invalid", str(error)) from error
    members = {member["id"]: member for member in evidence_set["members"]}
    if len(members) != 2 or set(members) != {"observation-bytes", "receipt-snapshot"}:
        raise GateRejected("rvr.gate.evidence_closure_incomplete", "evidence member closure mismatch")
    if members["receipt-snapshot"]["status"] != "PRESENT":
        raise GateRejected("rvr.gate.evidence_closure_incomplete", "snapshot descriptor must be PRESENT")
    expected_media = {"observation-bytes": "application/octet-stream", "receipt-snapshot": "application/json"}
    for identifier, member in members.items():
        if member["status"] == "UNAVAILABLE":
            if identifier in payloads:
                raise GateRejected("rvr.gate.evidence_closure_incomplete", "UNAVAILABLE evidence has hidden payload")
            continue
        if member["mediaType"] != expected_media[identifier]:
            raise GateRejected("rvr.gate.schema_invalid", "evidence media type mismatch")
        if identifier not in payloads:
            continue
        payload = payloads[identifier]
        if member["byteLength"] != str(len(payload)) or member["digest"] != sha256(payload):
            raise GateRejected("rvr.gate.identity_mismatch", f"payload identity mismatch: {identifier}")
    if set(payloads) - {identifier for identifier, member in members.items() if member["status"] == "PRESENT"}:
        raise GateRejected("rvr.gate.evidence_closure_incomplete", "uncommitted evidence payload")


def evaluation_record(claim: dict[str, Any], snapshot: dict[str, Any], observation_digest: str | None) -> dict[str, Any]:
    envelope = claim["envelopeProjection"]
    position = int(envelope["receipt_log_position"])
    selected = snapshot["logs"][position] if position < len(snapshot["logs"]) else None
    topics = selected["topics"] if selected else []
    return {
        "procedure": "ERC8281_RECOMPUTE_COMPARE_CONFIRM_INCLUSION",
        "snapshotAssurance": "COMMITTED_RECEIPT_SNAPSHOT",
        "hashFunction": envelope["hash_function"],
        "observationDigest": observation_digest,
        "envelopeDigest": envelope["digest"][2:],
        "receiptSnapshotDigest": canonical_digest(snapshot),
        "chainId": snapshot["chainId"],
        "transactionHash": snapshot["transactionHash"],
        "blockNumber": snapshot["blockNumber"],
        "blockHash": snapshot["blockHash"],
        "receiptLogPosition": envelope["receipt_log_position"],
        "emittingContract": selected["address"] if selected else None,
        "onChainDigest": topics[1] if len(topics) > 1 else None,
        "committer": "0x" + topics[2][-40:] if len(topics) > 2 else None,
    }


def result(outcome: str, reason: str, evaluation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "rvr.canonical-result.erc8281-committed-receipt-snapshot.v0",
        "proposition": PROPOSITION,
        "outcome": outcome,
        "reasonCode": reason,
        "evaluation": evaluation,
    }


def evaluate(claim: dict[str, Any], evidence_set: dict[str, Any], payloads: dict[str, bytes], rvr_schema: dict[str, Any]) -> dict[str, Any]:
    validate_claim(claim, rvr_schema)
    validate_evidence(evidence_set, payloads, rvr_schema)
    snapshot_payload = payloads.get("receipt-snapshot")
    if snapshot_payload is None:
        raise ProfileError("snapshot payload unavailable to evaluator")
    snapshot = parse_json(snapshot_payload, "receipt-snapshot")
    try:
        validate_schema(snapshot, resolve_pointer(rvr_schema, "#/$defs/receiptSnapshot"), rvr_schema)
    except SchemaError as error:
        raise GateRejected("rvr.gate.schema_invalid", str(error)) from error
    if canonical_bytes(snapshot) != snapshot_payload:
        raise GateRejected("rvr.gate.identity_mismatch", "snapshot is not exact canonical JSON")
    members = {member["id"]: member for member in evidence_set["members"]}
    if members["observation-bytes"]["status"] == "UNAVAILABLE":
        evaluation = evaluation_record(claim, snapshot, None)
        return result("UNVERIFIABLE", "rvr.erc8281.v0.required_observation_unavailable", evaluation)
    observation = payloads.get("observation-bytes")
    if observation is None:
        raise GateRejected("rvr.gate.identity_mismatch", "present observation payload is unavailable")
    envelope = claim["envelopeProjection"]
    digest = observation_hash(envelope["hash_function"], observation)
    evaluation = evaluation_record(claim, snapshot, digest)
    checks = [
        (digest == envelope["digest"][2:], "rvr.erc8281.v0.observation_digest_mismatch"),
        (snapshot["chainId"] == envelope["chain_id"], "rvr.erc8281.v0.chain_id_mismatch"),
        (snapshot["transactionHash"] == envelope["tx_hash"], "rvr.erc8281.v0.transaction_hash_mismatch"),
        (snapshot["status"] == "SUCCESS", "rvr.erc8281.v0.receipt_reverted"),
    ]
    for passed, reason in checks:
        if not passed:
            return result("REFUTED", reason, evaluation)
    position = int(envelope["receipt_log_position"])
    if position >= len(snapshot["logs"]):
        return result("REFUTED", "rvr.erc8281.v0.log_position_out_of_range", evaluation)
    selected = snapshot["logs"][position]
    if selected["address"] != envelope["contract"].lower():
        return result("REFUTED", "rvr.erc8281.v0.contract_mismatch", evaluation)
    topics = selected["topics"]
    if len(topics) != 3:
        return result("REFUTED", "rvr.erc8281.v0.topic_count_invalid", evaluation)
    if topics[0] != TOPIC0:
        return result("REFUTED", "rvr.erc8281.v0.topic0_mismatch", evaluation)
    if topics[1] != envelope["digest"]:
        return result("REFUTED", "rvr.erc8281.v0.onchain_digest_mismatch", evaluation)
    if topics[2][-40:] != envelope["committer"][2:].lower():
        return result("REFUTED", "rvr.erc8281.v0.committer_mismatch", evaluation)
    if snapshot["blockNumber"] != envelope["block_number"]:
        return result("REFUTED", "rvr.erc8281.v0.block_number_mismatch", evaluation)
    if snapshot["blockHash"] != envelope["block_hash"]:
        return result("REFUTED", "rvr.erc8281.v0.block_hash_mismatch", evaluation)
    return result("VERIFIED", "rvr.erc8281.v0.commitment_verified", evaluation)


def make_bundle(claim: dict[str, Any], observation: bytes | None, snapshot: dict[str, Any], profile_digest: str, rvr_schema: dict[str, Any]) -> dict[str, Any]:
    evidence_set, payloads = evidence_for(observation, snapshot)
    canonical_result = evaluate(claim, evidence_set, payloads, rvr_schema)
    receipt = {
        "claimDigest": canonical_digest(claim),
        "evidenceSetDigest": evidence_digest(evidence_set),
        "verificationProfileDigest": profile_digest,
        "outcome": canonical_result["outcome"],
        "reasonCode": canonical_result["reasonCode"],
        "resultDigest": canonical_digest(canonical_result),
    }
    return {"receipt": receipt, "claim": claim, "evidenceSet": evidence_set, "payloads": payloads, "canonicalResult": canonical_result}


def validate_bundle(bundle: dict[str, Any], profile_digest: str, rvr_schema: dict[str, Any]) -> None:
    receipt = bundle["receipt"]
    canonical_result = bundle["canonicalResult"]
    try:
        validate_schema(receipt, rvr_schema, rvr_schema)
        validate_schema(canonical_result, resolve_pointer(rvr_schema, "#/$defs/canonicalResult"), rvr_schema)
    except SchemaError as error:
        raise GateRejected("rvr.gate.schema_invalid", str(error)) from error
    validate_claim(bundle["claim"], rvr_schema)
    validate_evidence(bundle["evidenceSet"], bundle["payloads"], rvr_schema)
    identities = {
        "claimDigest": canonical_digest(bundle["claim"]),
        "evidenceSetDigest": evidence_digest(bundle["evidenceSet"]),
        "verificationProfileDigest": profile_digest,
        "resultDigest": canonical_digest(canonical_result),
    }
    if any(receipt[key] != value for key, value in identities.items()):
        raise GateRejected("rvr.gate.identity_mismatch", "stored identity mismatch")
    if receipt["outcome"] != canonical_result["outcome"] or receipt["reasonCode"] != canonical_result["reasonCode"]:
        raise GateRejected("rvr.gate.result_projection_mismatch", "receipt/result projection mismatch")


def recompute(
    stored: dict[str, Any],
    candidate_claim: dict[str, Any],
    candidate_evidence: dict[str, Any],
    candidate_payloads: dict[str, bytes],
    profile_digest: str,
    rvr_schema: dict[str, Any],
    *,
    dependencies_available: bool = True,
    hidden_inputs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate_bundle(stored, profile_digest, rvr_schema)
    if hidden_inputs:
        raise GateRejected("rvr.gate.evidence_closure_incomplete", "ambient outcome-relevant input supplied")
    if not dependencies_available:
        return {"recomputationStatus": "CANNOT_RECOMPUTE", "reasonCode": "rvr.recompute.normative_dependency_unavailable", "evaluationPerformed": False}
    if "receipt-snapshot" not in candidate_payloads:
        return {"recomputationStatus": "CANNOT_RECOMPUTE", "reasonCode": "rvr.recompute.committed_snapshot_unavailable", "evaluationPerformed": False}
    candidate_members = {member["id"]: member for member in candidate_evidence["members"]}
    if (
        candidate_members.get("observation-bytes", {}).get("status") == "PRESENT"
        and "observation-bytes" not in candidate_payloads
    ):
        return {"recomputationStatus": "CANNOT_RECOMPUTE", "reasonCode": "rvr.recompute.committed_evidence_unavailable", "evaluationPerformed": False}
    candidate_result = evaluate(candidate_claim, candidate_evidence, candidate_payloads, rvr_schema)
    same = (
        canonical_digest(candidate_claim) == stored["receipt"]["claimDigest"]
        and evidence_digest(candidate_evidence) == stored["receipt"]["evidenceSetDigest"]
        and canonical_digest(candidate_result) == stored["receipt"]["resultDigest"]
    )
    return {
        "recomputationStatus": "REPRODUCED" if same else "DIVERGED",
        "reasonCode": "rvr.recompute.identical" if same else "rvr.recompute.canonical_result_diverged",
        "evaluationPerformed": True,
        "verificationOutcome": candidate_result["outcome"],
        "verificationReasonCode": candidate_result["reasonCode"],
        "canonicalResult": candidate_result,
    }


def semantic_mutation(identifier: str, claim: dict[str, Any], observation: bytes, snapshot: dict[str, Any]) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    mutated_claim = copy.deepcopy(claim)
    mutated_observation = observation
    mutated_snapshot = copy.deepcopy(snapshot)
    zero32 = "0x" + "00" * 32
    if identifier == "observation-digest-mismatch":
        mutated_observation += b" altered"
    elif identifier == "chain-id-mismatch":
        mutated_snapshot["chainId"] = "1"
    elif identifier == "transaction-hash-mismatch":
        mutated_snapshot["transactionHash"] = zero32
    elif identifier == "receipt-reverted":
        mutated_snapshot["status"] = "REVERTED"
    elif identifier == "log-position-out-of-range":
        mutated_snapshot["logs"] = []
    elif identifier == "contract-mismatch":
        mutated_snapshot["logs"][0]["address"] = "0x0000000000000000000000000000000000000001"
    elif identifier == "topic-count-invalid":
        mutated_snapshot["logs"][0]["topics"] = mutated_snapshot["logs"][0]["topics"][:2]
    elif identifier == "topic0-mismatch":
        mutated_snapshot["logs"][0]["topics"][0] = zero32
    elif identifier == "onchain-digest-mismatch":
        mutated_snapshot["logs"][0]["topics"][1] = zero32
    elif identifier == "committer-mismatch":
        mutated_snapshot["logs"][0]["topics"][2] = zero32
    elif identifier == "block-number-mismatch":
        mutated_snapshot["blockNumber"] = "1"
    elif identifier == "block-hash-mismatch":
        mutated_snapshot["blockHash"] = zero32
    else:
        raise ProfileError(f"unknown semantic mutation: {identifier}")
    return mutated_claim, mutated_observation, mutated_snapshot


def expect_rejection(action: Any, reason_code: str) -> dict[str, Any]:
    try:
        action()
    except GateRejected as error:
        if error.reason_code != reason_code:
            raise ProfileError(f"expected {reason_code}, received {error.reason_code}") from error
        return {"gateStatus": "REJECTED", "reasonCode": error.reason_code}
    raise ProfileError(f"negative control did not reject with {reason_code}")


def audit_manifest() -> tuple[str, int]:
    manifest = load_json(MANIFEST_PATH)
    expected_members = [{"path": path, "sha256": sha256(safe_dependency_path(path).read_bytes())} for path in PACKAGE_MEMBERS]
    if manifest.get("members") != expected_members or manifest.get("memberCount") != len(expected_members):
        raise GateRejected("rvr.gate.identity_mismatch", "profile package manifest member drift")
    digest = sha256(dependency_rows(expected_members))
    if manifest.get("packageDigest") != digest:
        raise GateRejected("rvr.gate.identity_mismatch", "profile package digest drift")
    return digest, len(expected_members)


def run_gate() -> dict[str, Any]:
    _, profile_digest, rvr_schema, pinned_bytes = audit_profile()
    package_digest, member_count = audit_manifest()
    vectors = parse_json(pinned_bytes["erc8281-verification-vectors"], str(VECTORS_PATH))
    expected = parse_json(pinned_bytes["erc8281-expected-results"], str(EXPECTED_PATH))
    base = vectors["baseCase"]
    claim = base["claim"]
    raw_envelope = base["rawEnvelope"]
    derived_projection = derive_envelope_projection(raw_envelope, rvr_schema)
    if derived_projection != claim["envelopeProjection"]:
        raise ProfileError("base raw envelope does not derive the committed projection")
    observation = base64.b64decode(base["observationBase64"], validate=True)
    snapshot = base["snapshot"]
    original = make_bundle(claim, observation, snapshot, profile_digest, rvr_schema)
    reproduced = recompute(original, claim, original["evidenceSet"], original["payloads"], profile_digest, rvr_schema)

    diverged_observation = base64.b64decode(vectors["negativeControls"]["divergedObservationBase64"], validate=True)
    diverged_evidence, diverged_payloads = evidence_for(diverged_observation, snapshot)
    diverged = recompute(original, claim, diverged_evidence, diverged_payloads, profile_digest, rvr_schema)

    unavailable = make_bundle(claim, None, snapshot, profile_digest, rvr_schema)
    unavailable_reproduced = recompute(unavailable, claim, unavailable["evidenceSet"], unavailable["payloads"], profile_digest, rvr_schema)
    unresolved_payloads = dict(original["payloads"])
    del unresolved_payloads["receipt-snapshot"]
    cannot = recompute(original, claim, original["evidenceSet"], unresolved_payloads, profile_digest, rvr_schema)
    normative_cannot = recompute(
        original,
        claim,
        original["evidenceSet"],
        original["payloads"],
        profile_digest,
        rvr_schema,
        dependencies_available=False,
    )
    unresolved_observation_payloads = dict(original["payloads"])
    del unresolved_observation_payloads["observation-bytes"]
    observation_cannot = recompute(
        original,
        claim,
        original["evidenceSet"],
        unresolved_observation_payloads,
        profile_digest,
        rvr_schema,
    )

    tampered_constraints = expect_rejection(
        lambda: audit_profile({"erc8281-profile-schema": b"{not-valid-json"}),
        "rvr.gate.identity_mismatch",
    )
    tampered_constraints["constraintsApplied"] = False

    contradictory = copy.deepcopy(original)
    contradictory["receipt"]["outcome"] = vectors["negativeControls"]["projectionReplacement"]
    projection = expect_rejection(lambda: validate_bundle(contradictory, profile_digest, rvr_schema), "rvr.gate.result_projection_mismatch")
    hidden = expect_rejection(
        lambda: recompute(original, claim, original["evidenceSet"], original["payloads"], profile_digest, rvr_schema, hidden_inputs=vectors["negativeControls"]["hiddenAmbientInput"]),
        "rvr.gate.evidence_closure_incomplete",
    )
    hidden["evaluationPerformed"] = False
    invalid_claim = copy.deepcopy(claim)
    invalid_claim["envelopeProjection"]["committer"] = vectors["negativeControls"]["invalidEip55Committer"]
    invalid_eip55 = expect_rejection(lambda: make_bundle(invalid_claim, observation, snapshot, profile_digest, rvr_schema), "rvr.gate.schema_invalid")
    extended_raw_envelope = copy.deepcopy(raw_envelope)
    extended_raw_envelope.update(vectors["negativeControls"]["ignoredEnvelopeExtension"])
    extended_projection = derive_envelope_projection(extended_raw_envelope, rvr_schema)
    extended_claim = copy.deepcopy(claim)
    extended_claim["envelopeProjection"] = extended_projection
    extension_identity = {
        "sameProjection": extended_projection == derived_projection,
        "sameClaimDigest": canonical_digest(extended_claim) == canonical_digest(claim),
    }
    closed_projection_extension = copy.deepcopy(claim)
    closed_projection_extension["envelopeProjection"].update(vectors["negativeControls"]["ignoredEnvelopeExtension"])
    closed_projection_rejection = expect_rejection(
        lambda: make_bundle(closed_projection_extension, observation, snapshot, profile_digest, rvr_schema),
        "rvr.gate.schema_invalid",
    )

    hash_passed = 0
    for case in vectors["hashFunctionCases"]:
        payload = base64.b64decode(case["observationBase64"], validate=True)
        if observation_hash(case["hashFunction"], payload) != case["digest"]:
            raise ProfileError(f"hash vector failed: {case['id']}")
        hash_passed += 1

    failure_results: dict[str, str] = {}
    for case in vectors["semanticFailures"]:
        mutated_claim, mutated_observation, mutated_snapshot = semantic_mutation(case["id"], claim, observation, snapshot)
        bundle = make_bundle(mutated_claim, mutated_observation, mutated_snapshot, profile_digest, rvr_schema)
        actual = bundle["canonicalResult"]
        if actual["outcome"] != "REFUTED" or actual["reasonCode"] != case["expectedReasonCode"]:
            raise ProfileError(f"semantic failure did not go red: {case['id']}")
        failure_results[case["id"]] = actual["reasonCode"]

    cases = {
        "REPRODUCED": reproduced,
        "DIVERGED": diverged,
        "UNVERIFIABLE_REPRODUCED": unavailable_reproduced,
        "CANNOT_RECOMPUTE": cannot,
        "NORMATIVE_DEPENDENCY_CANNOT_RECOMPUTE": normative_cannot,
        "PRESENT_OBSERVATION_UNRESOLVED": observation_cannot,
        "TAMPERED_PROFILE_CONSTRAINTS_PIN": tampered_constraints,
        "PROJECTION_NEGATIVE_CONTROL": projection,
        "HIDDEN_STATE_NEGATIVE_CONTROL": hidden,
        "INVALID_EIP55_NEGATIVE_CONTROL": invalid_eip55,
        "IGNORED_EXTENSION_PROJECTION_IDENTITY": extension_identity,
        "CLOSED_PROJECTION_EXTENSION_REJECTED": closed_projection_rejection,
    }
    for identifier, expected_case in expected["cases"].items():
        for key, value in expected_case.items():
            if cases[identifier].get(key) != value:
                raise ProfileError(f"expected mismatch at {identifier}.{key}")
    return {
        "gate": "RVR_ERC8281_COMMITTED_RECEIPT_SNAPSHOT_PASS",
        "profileId": "rvr-erc8281-committed-receipt-snapshot-v0",
        "snapshotAssurance": "COMMITTED_RECEIPT_SNAPSHOT",
        "verificationProfileDigest": profile_digest,
        "packageDigest": package_digest,
        "packageMembers": member_count,
        "upstream": vectors["upstream"],
        "hashFunctionCases": {"passed": hash_passed, "total": len(vectors["hashFunctionCases"])},
        "semanticFailures": {"passed": len(failure_results), "total": len(vectors["semanticFailures"]), "results": failure_results},
        "cases": cases,
    }


def write_derived() -> None:
    profile = load_json(PROFILE_PATH)
    for dependency in profile_dependencies(profile):
        dependency["sha256"] = sha256(safe_dependency_path(dependency["path"]).read_bytes())
    vector_members = profile["conformanceVectorSet"]["members"]
    profile["conformanceVectorSet"]["digest"] = sha256(dependency_rows(vector_members))
    rvr_digest = sha256(RVR_SCHEMA_PATH.read_bytes())
    profile["evidenceSetContract"]["schemaSha256"] = rvr_digest
    profile["canonicalResultContract"]["schemaSha256"] = rvr_digest
    PROFILE_PATH.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    members = [{"path": path, "sha256": sha256(safe_dependency_path(path).read_bytes())} for path in PACKAGE_MEMBERS]
    manifest = {
        "schema": "rvr.profile-package-manifest.v0",
        "hashAlgorithm": "sha256-lowercase-hex",
        "memberCount": len(members),
        "members": members,
        "packageDigestRule": "sha256-utf8-sorted-path-tab-file-sha256-lf-rows-manifest-excluded",
        "packageDigest": sha256(dependency_rows(members)),
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="run the exact external-profile gate")
    parser.add_argument("--write-derived", action="store_true", help="rewrite committed hashes and package manifest")
    arguments = parser.parse_args()
    try:
        if arguments.write_derived:
            write_derived()
        report = run_gate()
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (ProfileError, OSError, KeyError, ValueError) as error:
        print(f"RVR_ERC8281_COMMITTED_RECEIPT_SNAPSHOT_FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
