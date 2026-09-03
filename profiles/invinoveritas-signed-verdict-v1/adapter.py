#!/usr/bin/env python3
"""Independent gate for the RVR x invinoveritas signed-verdict profile.

The pinned contracts are authority. This standard-library-only adapter imports
neither invinoveritas nor either RVR RC2 implementation.
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
PACKAGE = ROOT / "profiles/invinoveritas-signed-verdict-v1"
PROFILE_PATH = PACKAGE / "verification-profile.json"
MANIFEST_PATH = PACKAGE / "manifest.json"
GENERIC_PROFILE_SCHEMA = ROOT / "conformance/rvr-v0/verification-profile-manifest.schema.json"
PROFILE_SCHEMA_PATH = PACKAGE / "profile.schema.json"
RVR_SCHEMA_PATH = PACKAGE / "rvr.schema.json"
VECTORS_PATH = PACKAGE / "vectors.json"
EXPECTED_PATH = PACKAGE / "expected.json"
UPSTREAM_PATH = PACKAGE / "upstream/verdict_proof_v17.json.base64"

PROFILE_ID = "rvr-invinoveritas-signed-verdict-v1"
PROPOSITION = "rvr.invinoveritas.v1.signed_verdict_artifact_bindings"
ISSUER_PUBKEY = "6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7"
UPSTREAM_SHA256 = "77058e47d3fc1ac9b84e5110ae4b5b9432ea7aac99903f14c38c41de5c97a1f6"
UPSTREAM_REVISION = "0e4f1f7b2d24924fc51c9d8c037448ffefaca4f1"
UPSTREAM_GIT_BLOB = "2b30c729503f96f5545f8d8875e3d473d884a9eb"
UPSTREAM_REPOSITORY = "babyblueviper1/invinoveritas"
UPSTREAM_SOURCE_PATH = "examples/rvr-verdict-worked-example/verdict_proof_v17.json"
UPSTREAM_BYTE_LENGTH = "14362"
JUDGMENT_BOUNDARY = "COMMITTED_AUTHENTICATED_NOT_REDERIVED"
FRESHNESS_BOUNDARY = "COMMITMENT_REPRODUCED_CANONICALITY_NOT_ESTABLISHED"
DECISION_FIELDS = (
    "artifact_hash",
    "artifact_type",
    "policy_version",
    "verdict",
    "source_class",
    "vantage_limitation",
    "related_decision_ref",
    "intended_audience",
    "confidentiality_tier",
    "disclosed_summary",
    "intended_verifier",
    "policy_commitment",
    "verified_at",
    "registry_as_of",
    "registry_snapshot_sha256",
    "action_binding_tool_hash",
    "action_binding_args_hash",
    "action_binding_agent_id",
    "action_binding_nonce",
    "freshness_beacon_hash",
)

PACKAGE_MEMBERS = (
    "conformance/rvr-v0/verification-profile-manifest.schema.json",
    "profiles/invinoveritas-signed-verdict-v1/README.md",
    "profiles/invinoveritas-signed-verdict-v1/SPEC.md",
    "profiles/invinoveritas-signed-verdict-v1/adapter.py",
    "profiles/invinoveritas-signed-verdict-v1/expected.json",
    "profiles/invinoveritas-signed-verdict-v1/profile.schema.json",
    "profiles/invinoveritas-signed-verdict-v1/rvr.schema.json",
    "profiles/invinoveritas-signed-verdict-v1/test_profile.py",
    "profiles/invinoveritas-signed-verdict-v1/upstream/verdict_proof_v17.json.base64",
    "profiles/invinoveritas-signed-verdict-v1/vectors.json",
    "profiles/invinoveritas-signed-verdict-v1/verification-profile.json",
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


def decode_upstream_artifact(encoded: bytes) -> bytes:
    """Decode the exact upstream bytes from one-line RFC 4648 Base64 + LF."""
    try:
        text = encoded.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProfileError("upstream transport is not ASCII") from error
    if not text.endswith("\n") or "\r" in text or "\n" in text[:-1]:
        raise ProfileError("upstream transport is not one Base64 line followed by LF")
    payload = text[:-1]
    try:
        decoded = base64.b64decode(payload, validate=True)
    except ValueError as error:
        raise ProfileError("upstream transport is not valid RFC 4648 Base64") from error
    if base64.b64encode(decoded).decode("ascii") != payload:
        raise ProfileError("upstream transport is not canonical RFC 4648 Base64")
    return decoded


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


def external_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9007199254740991:
            raise ProfileError("external byte contract forbids unsafe integers")
        return str(value)
    if isinstance(value, float):
        raise ProfileError("external byte contract forbids floats")
    if isinstance(value, str):
        return canonical_string(value)
    if isinstance(value, list):
        return "[" + ",".join(external_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) and key.isascii() for key in value):
            raise ProfileError("external byte contract requires ASCII object keys")
        return "{" + ",".join(
            canonical_string(key) + ":" + external_json(value[key]) for key in sorted(value)
        ) + "}"
    raise ProfileError(f"unsupported external value: {type(value).__name__}")


def external_bytes(value: Any) -> bytes:
    return external_json(value).encode("utf-8")


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


def audit_profile(overrides: dict[str, bytes] | None = None) -> tuple[dict[str, Any], str, dict[str, Any], dict[str, bytes]]:
    generic_schema = load_json(GENERIC_PROFILE_SCHEMA)
    profile = load_json(PROFILE_PATH)
    validate_schema(profile, generic_schema, generic_schema)

    pinned: dict[str, bytes] = {}
    override_map = overrides or {}
    for dependency in profile_dependencies(profile):
        data = override_map.get(dependency["id"])
        if data is None:
            data = safe_dependency_path(dependency["path"]).read_bytes()
        if sha256(data) != dependency["sha256"]:
            raise GateRejected(
                "rvr.gate.identity_mismatch",
                f"dependency digest mismatch before use: {dependency['id']}",
            )
        pinned[dependency["id"]] = data

    constraints = parse_json(
        pinned["invinoveritas-signed-verdict-v1-profile-schema"],
        "pinned profile constraints",
    )
    validate_schema(profile, constraints, constraints)
    rvr_schema = parse_json(pinned["rvr-schema"], "pinned RVR schema")
    return profile, canonical_digest(profile), rvr_schema, pinned


def validate_claim(claim: dict[str, Any], rvr_schema: dict[str, Any]) -> None:
    try:
        validate_schema(claim, resolve_pointer(rvr_schema, "#/$defs/claim"), rvr_schema)
    except SchemaError as error:
        raise GateRejected("rvr.gate.schema_invalid", str(error)) from error


def evidence_digest(evidence_set: dict[str, Any]) -> str:
    normalized = copy.deepcopy(evidence_set)
    normalized["members"] = sorted(normalized["members"], key=lambda member: member["id"])
    return canonical_digest(normalized)


def present_member(identifier: str, media_type: str, payload: bytes) -> dict[str, str]:
    return {
        "id": identifier,
        "status": "PRESENT",
        "mediaType": media_type,
        "byteLength": str(len(payload)),
        "digest": sha256(payload),
    }


def unavailable_member(identifier: str) -> dict[str, str]:
    return {
        "id": identifier,
        "status": "UNAVAILABLE",
        "reasonCode": "rvr.invinoveritas.v1.evidence_unavailable",
    }


def evidence_for(
    artifact: bytes | None,
    policy: dict[str, Any] | None,
    event: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    payloads: dict[str, bytes] = {}
    members: list[dict[str, str]] = []
    if artifact is None:
        members.append(unavailable_member("artifact-bytes"))
    else:
        payloads["artifact-bytes"] = artifact
        members.append(present_member("artifact-bytes", "text/plain; charset=utf-8", artifact))
    if policy is None:
        members.append(unavailable_member("policy-preimage"))
    else:
        policy_payload = external_bytes(policy)
        payloads["policy-preimage"] = policy_payload
        members.append(present_member("policy-preimage", "application/json; profile=invinoveritas-jcs-safe-integer-v0", policy_payload))
    if event is None:
        members.append(unavailable_member("signed-event"))
    else:
        event_payload = external_bytes(event)
        payloads["signed-event"] = event_payload
        members.append(present_member("signed-event", "application/json; profile=invinoveritas-jcs-safe-integer-v0", event_payload))
    return {"schema": "rvr.evidence-set.v0", "members": sorted(members, key=lambda member: member["id"])}, payloads


def validate_evidence(
    evidence_set: dict[str, Any],
    payloads: dict[str, bytes],
    rvr_schema: dict[str, Any],
    *,
    require_payloads: bool,
) -> None:
    try:
        validate_schema(evidence_set, resolve_pointer(rvr_schema, "#/$defs/evidenceSet"), rvr_schema)
    except SchemaError as error:
        raise GateRejected("rvr.gate.schema_invalid", str(error)) from error
    identifiers = [member["id"] for member in evidence_set["members"]]
    if identifiers != ["artifact-bytes", "policy-preimage", "signed-event"]:
        raise GateRejected("rvr.gate.evidence_closure_incomplete", "evidence member set or order mismatch")
    for member in evidence_set["members"]:
        payload = payloads.get(member["id"])
        if member["status"] == "UNAVAILABLE":
            if payload is not None:
                raise GateRejected("rvr.gate.identity_mismatch", "unavailable member has hidden payload")
            continue
        if payload is None:
            if require_payloads:
                raise GateRejected("rvr.gate.identity_mismatch", "present member payload unavailable")
            continue
        if member["byteLength"] != str(len(payload)) or member["digest"] != sha256(payload):
            raise GateRejected("rvr.gate.identity_mismatch", "evidence payload identity mismatch")


def source_inputs(source: dict[str, Any]) -> tuple[dict[str, Any], bytes, dict[str, Any], dict[str, Any]]:
    proof = source["proof_payload"]
    policy_inputs = proof["policy_commitment_inputs"]
    policy = {
        "policy_version": proof["policy_version"],
        "rubric_sha256": policy_inputs["rubric_sha256"],
        "conformance_suite_repo": policy_inputs["conformance_suite_repo"],
        "conformance_suite_commit": policy_inputs["conformance_suite_commit"],
    }
    claim = {
        "schema": "rvr.claim.invinoveritas-signed-verdict.v1",
        "proposition": PROPOSITION,
        "artifactMember": "artifact-bytes",
        "policyMember": "policy-preimage",
        "signedEventMember": "signed-event",
        "artifactHash": proof["artifact_hash"],
        "policyCommitment": proof["policy_commitment"].removeprefix("sha256:"),
        "decisionRef": proof["decision_ref"].removeprefix("sha256:"),
        "freshnessBeaconHash": proof["freshness_beacon_hash"].removeprefix("sha256:"),
        "eventId": source["signed_event"]["id"],
        "issuerPubkey": ISSUER_PUBKEY,
        "judgmentBoundary": JUDGMENT_BOUNDARY,
    }
    return claim, source["artifact_submitted"].encode("utf-8"), policy, source["signed_event"]


def result(outcome: str, reason_code: str, evaluation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "rvr.canonical-result.invinoveritas-signed-verdict.v1",
        "proposition": PROPOSITION,
        "outcome": outcome,
        "reasonCode": reason_code,
        "evaluation": evaluation,
    }


def blank_evaluation(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "procedure": "INVINO_SIGNED_VERDICT_BINDING_VERIFY_V1",
        "judgmentSemantics": JUDGMENT_BOUNDARY,
        "freshnessSemantics": FRESHNESS_BOUNDARY,
        "artifactDigest": None,
        "declaredArtifactDigest": claim["artifactHash"],
        "policyDigest": None,
        "declaredPolicyDigest": claim["policyCommitment"],
        "decisionDigest": None,
        "declaredDecisionDigest": claim["decisionRef"],
        "freshnessBeaconDigest": None,
        "declaredFreshnessBeaconDigest": claim["freshnessBeaconHash"],
        "eventDigest": None,
        "declaredEventDigest": claim["eventId"],
        "contentDigest": None,
        "issuerPubkey": claim["issuerPubkey"],
        "producerVerdict": None,
        "signatureCheck": "NOT_PERFORMED",
    }


P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G_POINT = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def point_add(first: tuple[int, int] | None, second: tuple[int, int] | None) -> tuple[int, int] | None:
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2 and (y1 + y2) % P_FIELD == 0:
        return None
    if first == second:
        slope = (3 * x1 * x1) * pow(2 * y1, P_FIELD - 2, P_FIELD) % P_FIELD
    else:
        slope = (y2 - y1) * pow(x2 - x1, P_FIELD - 2, P_FIELD) % P_FIELD
    x3 = (slope * slope - x1 - x2) % P_FIELD
    return x3, (slope * (x1 - x3) - y1) % P_FIELD


def point_mul(scalar: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    result_point = None
    addend = point
    while scalar:
        if scalar & 1:
            result_point = point_add(result_point, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result_point


def lift_x(x_coordinate: int) -> tuple[int, int] | None:
    if x_coordinate >= P_FIELD:
        return None
    candidate = (pow(x_coordinate, 3, P_FIELD) + 7) % P_FIELD
    y_coordinate = pow(candidate, (P_FIELD + 1) // 4, P_FIELD)
    if pow(y_coordinate, 2, P_FIELD) != candidate:
        return None
    if y_coordinate & 1:
        y_coordinate = P_FIELD - y_coordinate
    return x_coordinate, y_coordinate


def tagged_hash(tag: str, message: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def verify_bip340(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(public_key) != 32 or len(message) != 32 or len(signature) != 64:
        return False
    point = lift_x(int.from_bytes(public_key, "big"))
    if point is None:
        return False
    r_value = int.from_bytes(signature[:32], "big")
    s_value = int.from_bytes(signature[32:], "big")
    if r_value >= P_FIELD or s_value >= N_ORDER:
        return False
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", signature[:32] + public_key + message),
        "big",
    ) % N_ORDER
    reconstructed = point_add(
        point_mul(s_value, G_POINT),
        point_mul(N_ORDER - challenge, point),
    )
    return (
        reconstructed is not None
        and reconstructed[1] % 2 == 0
        and reconstructed[0] == r_value
    )


def valid_event_shape(event: Any) -> bool:
    if not isinstance(event, dict) or set(event) != {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}:
        return False
    if not all(isinstance(event[key], str) for key in ("id", "pubkey", "content", "sig")):
        return False
    if re.fullmatch(r"[0-9a-f]{64}", event["id"]) is None:
        return False
    if re.fullmatch(r"[0-9a-f]{64}", event["pubkey"]) is None:
        return False
    if re.fullmatch(r"[0-9a-f]{128}", event["sig"]) is None:
        return False
    for key in ("created_at", "kind"):
        if not isinstance(event[key], int) or isinstance(event[key], bool) or not (0 <= event[key] <= 9007199254740991):
            return False
    return isinstance(event["tags"], list) and all(
        isinstance(tag, list) and all(isinstance(item, str) for item in tag)
        for tag in event["tags"]
    )


def parse_external_object(payload: bytes, label: str) -> dict[str, Any]:
    value = parse_json(payload, label)
    if not isinstance(value, dict):
        raise ProfileError(f"{label} is not an object")
    if external_bytes(value) != payload:
        raise ProfileError(f"{label} bytes are not canonical")
    return value


def evaluate(
    claim: dict[str, Any],
    evidence_set: dict[str, Any],
    payloads: dict[str, bytes],
    rvr_schema: dict[str, Any],
) -> dict[str, Any]:
    validate_claim(claim, rvr_schema)
    validate_evidence(evidence_set, payloads, rvr_schema, require_payloads=True)
    members = {member["id"]: member for member in evidence_set["members"]}
    evaluation = blank_evaluation(claim)

    unavailable_reasons = (
        ("artifact-bytes", "rvr.invinoveritas.v1.required_artifact_unavailable"),
        ("policy-preimage", "rvr.invinoveritas.v1.required_policy_preimage_unavailable"),
        ("signed-event", "rvr.invinoveritas.v1.required_signed_event_unavailable"),
    )
    for identifier, reason_code in unavailable_reasons:
        if members[identifier]["status"] == "UNAVAILABLE":
            return result("UNVERIFIABLE", reason_code, evaluation)

    artifact = payloads["artifact-bytes"]
    evaluation["artifactDigest"] = sha256(artifact)

    try:
        policy = parse_external_object(payloads["policy-preimage"], "policy-preimage")
    except ProfileError:
        return result("REFUTED", "rvr.invinoveritas.v1.policy_commitment_mismatch", evaluation)
    expected_policy_fields = {
        "policy_version",
        "rubric_sha256",
        "conformance_suite_repo",
        "conformance_suite_commit",
    }
    if set(policy) != expected_policy_fields or not all(isinstance(value, str) for value in policy.values()):
        return result("REFUTED", "rvr.invinoveritas.v1.policy_commitment_mismatch", evaluation)
    evaluation["policyDigest"] = sha256(payloads["policy-preimage"])

    try:
        event = parse_external_object(payloads["signed-event"], "signed-event")
    except ProfileError:
        return result("REFUTED", "rvr.invinoveritas.v1.signed_event_invalid", evaluation)
    if not valid_event_shape(event):
        return result("REFUTED", "rvr.invinoveritas.v1.signed_event_invalid", evaluation)

    event_serialization = external_bytes([
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ])
    evaluation["eventDigest"] = sha256(event_serialization)
    evaluation["contentDigest"] = sha256(event["content"].encode("utf-8"))
    signature_valid = verify_bip340(event["pubkey"], bytes.fromhex(event["id"]), event["sig"])
    evaluation["signatureCheck"] = "VALID" if signature_valid else "INVALID"

    try:
        content = parse_json(event["content"].encode("utf-8"), "signed-event.content")
    except ProfileError:
        return result("REFUTED", "rvr.invinoveritas.v1.event_content_invalid", evaluation)
    if not isinstance(content, dict):
        return result("REFUTED", "rvr.invinoveritas.v1.event_content_invalid", evaluation)
    producer_verdict = content.get("verdict")
    evaluation["producerVerdict"] = producer_verdict if isinstance(producer_verdict, str) else None

    freshness_beacon = content.get("freshness_beacon")
    if (
        not isinstance(freshness_beacon, dict)
        or set(freshness_beacon) != {"source", "height", "hash", "block_time"}
        or freshness_beacon.get("source") != "bitcoin"
        or not isinstance(freshness_beacon.get("hash"), str)
        or re.fullmatch(r"[0-9a-f]{64}", freshness_beacon["hash"]) is None
        or not all(
            isinstance(freshness_beacon.get(field), int)
            and not isinstance(freshness_beacon[field], bool)
            and 0 <= freshness_beacon[field] <= 9007199254740991
            for field in ("height", "block_time")
        )
    ):
        return result("REFUTED", "rvr.invinoveritas.v1.freshness_beacon_invalid", evaluation)
    evaluation["freshnessBeaconDigest"] = sha256(external_bytes(freshness_beacon))

    declared_fields = content.get("decision_ref_preimage_fields")
    if declared_fields != list(DECISION_FIELDS):
        return result("REFUTED", "rvr.invinoveritas.v1.event_content_invalid", evaluation)
    decision_preimage = {field: content.get(field) for field in DECISION_FIELDS}
    try:
        evaluation["decisionDigest"] = sha256(external_bytes(decision_preimage))
    except ProfileError:
        return result("REFUTED", "rvr.invinoveritas.v1.event_content_invalid", evaluation)

    checks = (
        (evaluation["artifactDigest"] == claim["artifactHash"], "rvr.invinoveritas.v1.artifact_digest_mismatch"),
        (evaluation["policyDigest"] == claim["policyCommitment"], "rvr.invinoveritas.v1.policy_commitment_mismatch"),
        (event["pubkey"] == ISSUER_PUBKEY and event["pubkey"] == claim["issuerPubkey"], "rvr.invinoveritas.v1.issuer_pubkey_mismatch"),
        (evaluation["eventDigest"] == event["id"] and event["id"] == claim["eventId"], "rvr.invinoveritas.v1.event_id_mismatch"),
        (signature_valid, "rvr.invinoveritas.v1.signature_invalid"),
        (content.get("artifact_hash") == claim["artifactHash"], "rvr.invinoveritas.v1.event_artifact_binding_mismatch"),
        (content.get("policy_commitment") == "sha256:" + claim["policyCommitment"], "rvr.invinoveritas.v1.event_policy_binding_mismatch"),
        (content.get("decision_ref") == "sha256:" + claim["decisionRef"], "rvr.invinoveritas.v1.event_decision_binding_mismatch"),
        (
            content.get("freshness_beacon_hash") == "sha256:" + claim["freshnessBeaconHash"]
            and evaluation["freshnessBeaconDigest"] == claim["freshnessBeaconHash"],
            "rvr.invinoveritas.v1.freshness_beacon_binding_mismatch",
        ),
        (
            content.get("policy_version") == policy["policy_version"]
            and isinstance(content.get("policy_commitment_inputs"), dict)
            and content["policy_commitment_inputs"].get("rubric_sha256") == policy["rubric_sha256"]
            and content["policy_commitment_inputs"].get("conformance_suite_repo") == policy["conformance_suite_repo"]
            and content["policy_commitment_inputs"].get("conformance_suite_commit") == policy["conformance_suite_commit"],
            "rvr.invinoveritas.v1.event_policy_binding_mismatch",
        ),
        (evaluation["decisionDigest"] == claim["decisionRef"], "rvr.invinoveritas.v1.decision_ref_mismatch"),
    )
    for passed, reason_code in checks:
        if not passed:
            return result("REFUTED", reason_code, evaluation)
    return result("VERIFIED", "rvr.invinoveritas.v1.signed_verdict_bindings_verified", evaluation)


def make_bundle(
    claim: dict[str, Any],
    artifact: bytes | None,
    policy: dict[str, Any] | None,
    event: dict[str, Any] | None,
    profile_digest: str,
    rvr_schema: dict[str, Any],
) -> dict[str, Any]:
    evidence_set, payloads = evidence_for(artifact, policy, event)
    canonical_result = evaluate(claim, evidence_set, payloads, rvr_schema)
    receipt = {
        "claimDigest": canonical_digest(claim),
        "evidenceSetDigest": evidence_digest(evidence_set),
        "verificationProfileDigest": profile_digest,
        "outcome": canonical_result["outcome"],
        "reasonCode": canonical_result["reasonCode"],
        "resultDigest": canonical_digest(canonical_result),
    }
    return {
        "receipt": receipt,
        "claim": claim,
        "evidenceSet": evidence_set,
        "payloads": payloads,
        "canonicalResult": canonical_result,
    }


def validate_bundle(bundle: dict[str, Any], profile_digest: str, rvr_schema: dict[str, Any]) -> None:
    receipt = bundle["receipt"]
    canonical_result = bundle["canonicalResult"]
    try:
        validate_schema(receipt, rvr_schema, rvr_schema)
        validate_schema(canonical_result, resolve_pointer(rvr_schema, "#/$defs/canonicalResult"), rvr_schema)
    except SchemaError as error:
        raise GateRejected("rvr.gate.schema_invalid", str(error)) from error
    validate_claim(bundle["claim"], rvr_schema)
    validate_evidence(bundle["evidenceSet"], bundle["payloads"], rvr_schema, require_payloads=True)
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
        return {
            "recomputationStatus": "CANNOT_RECOMPUTE",
            "reasonCode": "rvr.recompute.normative_dependency_unavailable",
            "evaluationPerformed": False,
        }
    validate_evidence(candidate_evidence, candidate_payloads, rvr_schema, require_payloads=False)
    for member in candidate_evidence["members"]:
        if member["status"] == "PRESENT" and member["id"] not in candidate_payloads:
            return {
                "recomputationStatus": "CANNOT_RECOMPUTE",
                "reasonCode": "rvr.recompute.committed_evidence_unavailable",
                "evaluationPerformed": False,
            }
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


def semantic_mutation(
    identifier: str,
    claim: dict[str, Any],
    artifact: bytes,
    policy: dict[str, Any],
    event: dict[str, Any],
) -> tuple[dict[str, Any], bytes, dict[str, Any], dict[str, Any]]:
    changed_claim = copy.deepcopy(claim)
    changed_artifact = artifact
    changed_policy = copy.deepcopy(policy)
    changed_event = copy.deepcopy(event)
    if identifier == "artifact-digest-mismatch":
        changed_artifact += b" altered"
    elif identifier == "policy-commitment-mismatch":
        changed_policy["rubric_sha256"] = "0" * 64
    elif identifier == "issuer-pubkey-mismatch":
        changed_event["pubkey"] = "0" * 64
    elif identifier == "event-id-mismatch":
        changed_event["id"] = "0" * 64
    elif identifier == "signature-invalid":
        changed_event["sig"] = changed_event["sig"][:-1] + ("0" if changed_event["sig"][-1] != "0" else "1")
    elif identifier == "decision-binding-mismatch":
        changed_claim["decisionRef"] = "0" * 64
    elif identifier == "freshness-beacon-binding-mismatch":
        changed_claim["freshnessBeaconHash"] = "0" * 64
    else:
        raise ProfileError(f"unknown semantic mutation: {identifier}")
    return changed_claim, changed_artifact, changed_policy, changed_event


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
    expected_members = [
        {"path": path, "sha256": sha256(safe_dependency_path(path).read_bytes())}
        for path in PACKAGE_MEMBERS
    ]
    if manifest.get("members") != expected_members or manifest.get("memberCount") != len(expected_members):
        raise GateRejected("rvr.gate.identity_mismatch", "profile package manifest member drift")
    digest = sha256(dependency_rows(expected_members))
    if manifest.get("packageDigest") != digest:
        raise GateRejected("rvr.gate.identity_mismatch", "profile package digest drift")
    return digest, len(expected_members)


def run_gate() -> dict[str, Any]:
    _, profile_digest, rvr_schema, pinned = audit_profile()
    package_digest, member_count = audit_manifest()
    vectors = parse_json(pinned["invinoveritas-v1-verification-vectors"], str(VECTORS_PATH))
    expected = parse_json(pinned["invinoveritas-v1-expected-results"], str(EXPECTED_PATH))
    upstream_transport = pinned["invinoveritas-upstream-verdict-proof-v17"]
    upstream_bytes = decode_upstream_artifact(upstream_transport)
    expected_source = {
        "repository": UPSTREAM_REPOSITORY,
        "revision": UPSTREAM_REVISION,
        "path": UPSTREAM_SOURCE_PATH,
        "gitBlob": UPSTREAM_GIT_BLOB,
        "byteLength": UPSTREAM_BYTE_LENGTH,
        "sha256": UPSTREAM_SHA256,
    }
    if vectors.get("upstream") != expected_source:
        raise ProfileError("upstream source metadata mismatch")
    if sha256(upstream_bytes) != UPSTREAM_SHA256 or str(len(upstream_bytes)) != UPSTREAM_BYTE_LENGTH:
        raise ProfileError("upstream source identity mismatch")
    source = parse_json(upstream_bytes, str(UPSTREAM_PATH))
    claim, artifact, policy, event = source_inputs(source)

    original = make_bundle(claim, artifact, policy, event, profile_digest, rvr_schema)
    reproduced = recompute(original, claim, original["evidenceSet"], original["payloads"], profile_digest, rvr_schema)

    diverged_artifact = artifact + vectors["negativeControls"]["artifactSuffix"].encode("utf-8")
    diverged_evidence, diverged_payloads = evidence_for(diverged_artifact, policy, event)
    diverged = recompute(original, claim, diverged_evidence, diverged_payloads, profile_digest, rvr_schema)

    unavailable = make_bundle(claim, None, policy, event, profile_digest, rvr_schema)
    unavailable_reproduced = recompute(unavailable, claim, unavailable["evidenceSet"], unavailable["payloads"], profile_digest, rvr_schema)

    missing_payloads = dict(original["payloads"])
    del missing_payloads["signed-event"]
    cannot = recompute(original, claim, original["evidenceSet"], missing_payloads, profile_digest, rvr_schema)
    normative_cannot = recompute(
        original,
        claim,
        original["evidenceSet"],
        original["payloads"],
        profile_digest,
        rvr_schema,
        dependencies_available=False,
    )

    tampered_constraints = expect_rejection(
        lambda: audit_profile({"invinoveritas-signed-verdict-v1-profile-schema": b"{not-valid-json"}),
        "rvr.gate.identity_mismatch",
    )
    tampered_constraints["constraintsApplied"] = False

    contradictory = copy.deepcopy(original)
    contradictory["receipt"]["outcome"] = vectors["negativeControls"]["projectionReplacement"]
    projection = expect_rejection(
        lambda: validate_bundle(contradictory, profile_digest, rvr_schema),
        "rvr.gate.result_projection_mismatch",
    )
    hidden = expect_rejection(
        lambda: recompute(
            original,
            claim,
            original["evidenceSet"],
            original["payloads"],
            profile_digest,
            rvr_schema,
            hidden_inputs=vectors["negativeControls"]["hiddenAmbientInput"],
        ),
        "rvr.gate.evidence_closure_incomplete",
    )
    hidden["evaluationPerformed"] = False

    evaluation = original["canonicalResult"]["evaluation"]
    judgment_boundary = {
        "verificationOutcome": original["canonicalResult"]["outcome"],
        "producerVerdict": evaluation["producerVerdict"],
        "judgmentSemantics": evaluation["judgmentSemantics"],
        "producerVerdictEqualsRvrOutcome": evaluation["producerVerdict"] == original["canonicalResult"]["outcome"],
    }
    freshness_boundary = {
        "verificationOutcome": original["canonicalResult"]["outcome"],
        "freshnessSemantics": evaluation["freshnessSemantics"],
        "freshnessCommitmentMatches": evaluation["freshnessBeaconDigest"]
        == evaluation["declaredFreshnessBeaconDigest"],
        "bitcoinCanonicalityEstablished": False,
    }

    semantic_results: dict[str, str] = {}
    for case in vectors["semanticFailures"]:
        changed_claim, changed_artifact, changed_policy, changed_event = semantic_mutation(
            case["id"], claim, artifact, policy, event
        )
        bundle = make_bundle(changed_claim, changed_artifact, changed_policy, changed_event, profile_digest, rvr_schema)
        actual = bundle["canonicalResult"]
        if actual["outcome"] != "REFUTED" or actual["reasonCode"] != case["expectedReasonCode"]:
            raise ProfileError(f"semantic failure did not go red: {case['id']} -> {actual['reasonCode']}")
        semantic_results[case["id"]] = actual["reasonCode"]

    cases = {
        "REPRODUCED": reproduced,
        "DIVERGED": diverged,
        "UNVERIFIABLE_REPRODUCED": unavailable_reproduced,
        "CANNOT_RECOMPUTE": cannot,
        "NORMATIVE_DEPENDENCY_CANNOT_RECOMPUTE": normative_cannot,
        "TAMPERED_PROFILE_CONSTRAINTS_PIN": tampered_constraints,
        "PROJECTION_NEGATIVE_CONTROL": projection,
        "HIDDEN_STATE_NEGATIVE_CONTROL": hidden,
        "JUDGMENT_BOUNDARY": judgment_boundary,
        "FRESHNESS_BOUNDARY": freshness_boundary,
    }
    for identifier, expected_case in expected["cases"].items():
        for key, value in expected_case.items():
            if cases[identifier].get(key) != value:
                raise ProfileError(f"expected mismatch at {identifier}.{key}")

    return {
        "gate": "RVR_INVINO_SIGNED_VERDICT_V1_PASS",
        "profileId": PROFILE_ID,
        "proposition": PROPOSITION,
        "verificationProfileDigest": profile_digest,
        "packageDigest": package_digest,
        "packageMembers": member_count,
        "upstream": vectors["upstream"],
        "cryptography": {
            "eventIdentity": "NIP-01",
            "signature": "BIP-340",
            "issuerPubkey": ISSUER_PUBKEY,
        },
        "semanticFailures": {
            "passed": len(semantic_results),
            "total": len(vectors["semanticFailures"]),
            "results": semantic_results,
        },
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
    PROFILE_PATH.write_text(
        json.dumps(profile, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    members = [
        {"path": path, "sha256": sha256(safe_dependency_path(path).read_bytes())}
        for path in PACKAGE_MEMBERS
    ]
    manifest = {
        "schema": "rvr.profile-package-manifest.v0",
        "hashAlgorithm": "sha256-lowercase-hex",
        "memberCount": len(members),
        "members": members,
        "packageDigestRule": "sha256-utf8-sorted-path-tab-file-sha256-lf-rows-manifest-excluded",
        "packageDigest": sha256(dependency_rows(members)),
    }
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


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
        print(f"RVR_INVINO_SIGNED_VERDICT_FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
