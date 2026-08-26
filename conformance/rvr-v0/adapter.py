#!/usr/bin/env python3
"""Independent, standard-library-only RVR v0 conformance adapter.

The profile and its pinned contracts are authority. This adapter is only
evidence of conformance and imports no producer implementation.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "conformance/rvr-v0"
PROFILE_PATH = PACKAGE / "verification-profile.json"
PROFILE_SCHEMA_PATH = PACKAGE / "verification-profile.schema.json"
RVR_SCHEMA_PATH = PACKAGE / "rvr.schema.json"
VECTORS_PATH = PACKAGE / "vectors.json"
EXPECTED_PATH = PACKAGE / "expected.json"
MUTANTS_PATH = PACKAGE / "mutants.json"
MANIFEST_PATH = PACKAGE / "manifest.json"

MANIFEST_MEMBERS = (
    "conformance/rvr-v0/README.md",
    "conformance/rvr-v0/adapter.py",
    "conformance/rvr-v0/adapter.ts",
    "conformance/rvr-v0/expected.json",
    "conformance/rvr-v0/mutants.json",
    "conformance/rvr-v0/rvr.schema.json",
    "conformance/rvr-v0/vectors.json",
    "conformance/rvr-v0/verification-profile.json",
    "conformance/rvr-v0/verification-profile.schema.json",
    "docs/spec/RECOMPUTABLE_VERIFICATION_RECEIPTS_V0.md",
)


class RvrError(Exception):
    pass


class StrictJsonError(RvrError):
    pass


class CanonicalizationError(RvrError):
    pass


class SchemaValidationError(RvrError):
    pass


class GateRejection(RvrError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_scalar_text(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        code = ord(value[index])
        if 0xD800 <= code <= 0xDBFF:
            if index + 1 >= len(value):
                raise StrictJsonError("lone high surrogate")
            low = ord(value[index + 1])
            if not 0xDC00 <= low <= 0xDFFF:
                raise StrictJsonError("lone high surrogate")
            scalar = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
            output.append(chr(scalar))
            index += 2
            continue
        if 0xDC00 <= code <= 0xDFFF:
            raise StrictJsonError("lone low surrogate")
        output.append(value[index])
        index += 1
    return "".join(output)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for raw_key, value in pairs:
        key = normalize_scalar_text(raw_key)
        if key in output:
            raise StrictJsonError(f"duplicate object key: {key!r}")
        output[key] = value
    return output


def normalize_json_strings(value: Any) -> Any:
    if isinstance(value, str):
        return normalize_scalar_text(value)
    if isinstance(value, list):
        return [normalize_json_strings(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize_json_strings(item) for key, item in value.items()}
    return value


def strict_json_loads(text: str) -> Any:
    def reject_nonstandard_constant(value: str) -> Any:
        raise StrictJsonError(f"non-standard JSON constant: {value}")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=strict_object,
            parse_constant=reject_nonstandard_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as error:
        raise StrictJsonError(str(error)) from error
    return normalize_json_strings(parsed)


def load_json(path: Path) -> Any:
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise StrictJsonError(f"cannot read UTF-8 JSON {path}: {error}") from error
    return strict_json_loads(text)


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        normalized = normalize_scalar_text(value)
        return json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, (int, float)):
        raise CanonicalizationError("rvr-canonical-json-v0 forbids numbers")
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        normalized_items: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
            normalized_key = normalize_scalar_text(key)
            if normalized_key in normalized_items:
                raise CanonicalizationError("duplicate object key after Unicode decoding")
            normalized_items[normalized_key] = item
        keys = list(normalized_items)
        keys.sort(key=lambda item: tuple(ord(character) for character in item))
        return "{" + ",".join(
            f"{canonical_json(key)}:{canonical_json(normalized_items[key])}" for key in keys
        ) + "}"
    raise CanonicalizationError(f"unsupported canonical value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return sha256_hex(canonical_bytes(value))


def json_same(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(json_same(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(json_same(a, b) for a, b in zip(left, right))
    return left == right


def schema_pointer(root: dict[str, Any], pointer: str) -> dict[str, Any]:
    if pointer in ("", "#"):
        return root
    if not pointer.startswith("#/"):
        raise SchemaValidationError(f"unsupported schema pointer: {pointer}")
    current: Any = root
    for raw_token in pointer[2:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            raise SchemaValidationError(f"unresolved schema pointer: {pointer}")
        current = current[token]
    if not isinstance(current, dict):
        raise SchemaValidationError(f"schema pointer is not an object: {pointer}")
    return current


def schema_type_matches(value: Any, expected_type: str) -> bool:
    if expected_type == "null":
        return value is None
    if expected_type == "boolean":
        return type(value) is bool
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "integer":
        return type(value) is int
    if expected_type == "number":
        return type(value) in (int, float)
    raise SchemaValidationError(f"unsupported schema type: {expected_type}")


def validate_schema(
    value: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any] | None = None,
    path: str = "$",
) -> list[str]:
    root = root_schema or schema
    if "$ref" in schema:
        target = schema_pointer(root, schema["$ref"])
        return validate_schema(value, target, root, path)

    errors: list[str] = []
    if "const" in schema and not json_same(value, schema["const"]):
        errors.append(f"{path}: const")
    if "enum" in schema and not any(json_same(value, item) for item in schema["enum"]):
        errors.append(f"{path}: enum")

    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(schema_type_matches(value, item) for item in types):
            errors.append(f"{path}: type")
            return errors

    if isinstance(value, str) and "pattern" in schema:
        if re.fullmatch(schema["pattern"], value) is None:
            errors.append(f"{path}: pattern")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: minItems")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: maxItems")
        if "items" in schema:
            for index, item in enumerate(value):
                errors.extend(validate_schema(item, schema["items"], root, f"{path}[{index}]"))

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for required in schema.get("required", []):
            if required not in value:
                errors.append(f"{path}.{required}: required")
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}.{key}: additionalProperties")
        for key, child_schema in properties.items():
            if key in value:
                errors.extend(validate_schema(value[key], child_schema, root, f"{path}.{key}"))

    if "oneOf" in schema:
        matches = sum(
            not validate_schema(value, child, root, path)
            for child in schema["oneOf"]
        )
        if matches != 1:
            errors.append(f"{path}: oneOf({matches})")
    return errors


def require_schema(value: Any, schema: dict[str, Any], pointer: str = "#", label: str = "value") -> None:
    target = schema_pointer(schema, pointer)
    errors = validate_schema(value, target, schema)
    if errors:
        raise GateRejection("rvr.gate.schema_invalid", f"{label}: " + "; ".join(errors))


def dependency_entries(profile: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        profile["verificationSpecification"],
        *profile["conformanceVectorSet"]["members"],
        *profile["schemaContracts"],
    ]


def exact_file_digest(repository_path: str) -> str:
    path = ROOT / repository_path
    if not path.is_file():
        raise FileNotFoundError(repository_path)
    return sha256_hex(path.read_bytes())


def audit_profile(profile: dict[str, Any], profile_schema: dict[str, Any]) -> str:
    require_schema(profile, profile_schema, label="verification profile")
    entries = dependency_entries(profile)
    ids = [entry["id"] for entry in entries]
    if len(ids) != len(set(ids)):
        raise GateRejection("rvr.gate.identity_mismatch", "duplicate profile dependency id")
    for entry in entries:
        try:
            actual = exact_file_digest(entry["path"])
        except FileNotFoundError as error:
            raise GateRejection("rvr.gate.identity_mismatch", f"missing pinned dependency: {error}") from error
        if actual != entry["sha256"]:
            raise GateRejection("rvr.gate.identity_mismatch", f"dependency digest mismatch: {entry['id']}")

    vector_members = sorted(profile["conformanceVectorSet"]["members"], key=lambda item: item["path"])
    rows = "".join(f"{item['path']}\t{item['sha256']}\n" for item in vector_members)
    if sha256_hex(rows.encode("utf-8")) != profile["conformanceVectorSet"]["digest"]:
        raise GateRejection("rvr.gate.identity_mismatch", "conformance vector-set digest mismatch")

    rvr_schema_pin = next(item for item in profile["schemaContracts"] if item["id"] == "rvr-schema")
    if profile["evidenceSetContract"]["schemaSha256"] != rvr_schema_pin["sha256"]:
        raise GateRejection("rvr.gate.identity_mismatch", "evidence-set schema pin mismatch")
    if profile["canonicalResultContract"]["schemaSha256"] != rvr_schema_pin["sha256"]:
        raise GateRejection("rvr.gate.identity_mismatch", "canonical-result schema pin mismatch")
    return canonical_digest(profile)


def normalize_evidence_set(evidence_set: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(evidence_set)
    members = normalized["members"]
    ids = [member["id"] for member in members]
    if len(ids) != len(set(ids)):
        raise GateRejection("rvr.gate.evidence_closure_incomplete", "duplicate evidence member id")
    members.sort(key=lambda item: tuple(ord(character) for character in item["id"]))
    return normalized


def decode_payloads(payloads_base64: dict[str, str]) -> dict[str, bytes]:
    output: dict[str, bytes] = {}
    for member_id, encoded in payloads_base64.items():
        if not isinstance(member_id, str) or not isinstance(encoded, str):
            raise GateRejection("rvr.gate.schema_invalid", "payload map must contain string keys and values")
        try:
            output[member_id] = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise GateRejection("rvr.gate.schema_invalid", f"invalid base64 payload: {member_id}") from error
    return output


def validate_evidence_closure(
    evidence_set: dict[str, Any],
    payloads_base64: dict[str, str],
    outcome_relevant_inputs: list[dict[str, Any]] | None = None,
) -> dict[str, bytes]:
    if outcome_relevant_inputs:
        for item in outcome_relevant_inputs:
            if item.get("commitment") is None:
                raise GateRejection(
                    "rvr.gate.evidence_closure_incomplete",
                    f"uncommitted outcome-relevant input: {item.get('name', '<unnamed>')}",
                )

    payloads = decode_payloads(payloads_base64)
    present_ids: set[str] = set()
    unavailable_ids: set[str] = set()
    for member in evidence_set["members"]:
        member_id = member["id"]
        if member["status"] == "PRESENT":
            present_ids.add(member_id)
            if member_id not in payloads:
                raise GateRejection("rvr.gate.evidence_closure_incomplete", f"missing payload: {member_id}")
            payload = payloads[member_id]
            if str(len(payload)) != member["byteLength"]:
                raise GateRejection("rvr.gate.identity_mismatch", f"payload length mismatch: {member_id}")
            if sha256_hex(payload) != member["digest"]:
                raise GateRejection("rvr.gate.identity_mismatch", f"payload digest mismatch: {member_id}")
        else:
            unavailable_ids.add(member_id)
            if member_id in payloads:
                raise GateRejection("rvr.gate.evidence_closure_incomplete", f"unavailable member has payload: {member_id}")
    extra = set(payloads) - present_ids
    if extra:
        raise GateRejection("rvr.gate.evidence_closure_incomplete", f"uncommitted payloads: {sorted(extra)}")
    if present_ids & unavailable_ids:
        raise GateRejection("rvr.gate.evidence_closure_incomplete", "conflicting evidence member status")
    return payloads


def evidence_set_digest(evidence_set: dict[str, Any]) -> str:
    return canonical_digest(normalize_evidence_set(evidence_set))


def evaluate(
    claim: dict[str, Any],
    evidence_set: dict[str, Any],
    payloads: dict[str, bytes],
    rvr_schema: dict[str, Any],
) -> dict[str, Any]:
    member = next((item for item in evidence_set["members"] if item["id"] == claim["evidenceMember"]), None)
    if member is None:
        raise GateRejection(
            "rvr.gate.evidence_closure_incomplete",
            f"claim member absent from evidence closure: {claim['evidenceMember']}",
        )
    if member["status"] == "UNAVAILABLE":
        observed_digest = None
        outcome = "UNVERIFIABLE"
        reason_code = "rvr.v0.required_evidence_unavailable"
    else:
        observed_digest = sha256_hex(payloads[member["id"]])
        if observed_digest == claim["expectedDigest"]:
            outcome = "VERIFIED"
            reason_code = "rvr.v0.digest_match"
        else:
            outcome = "REFUTED"
            reason_code = "rvr.v0.digest_mismatch"
    result = {
        "schema": "rvr.canonical-result.v0",
        "outcome": outcome,
        "reasonCode": reason_code,
        "evaluation": {
            "operation": "SHA256_EQUALS",
            "evidenceMember": claim["evidenceMember"],
            "expectedDigest": claim["expectedDigest"],
            "observedDigest": observed_digest,
        },
    }
    require_schema(result, rvr_schema, "#/$defs/canonicalResult", "canonical result")
    return result


def make_bundle(
    case: dict[str, Any],
    profile: dict[str, Any],
    profile_digest: str,
    rvr_schema: dict[str, Any],
) -> dict[str, Any]:
    claim = copy.deepcopy(case["claim"])
    evidence_set = copy.deepcopy(case["evidenceSet"])
    payloads_base64 = copy.deepcopy(case["payloadsBase64"])
    require_schema(claim, rvr_schema, "#/$defs/claim", "claim")
    require_schema(evidence_set, rvr_schema, "#/$defs/evidenceSet", "evidence set")
    payloads = validate_evidence_closure(evidence_set, payloads_base64)
    result = evaluate(claim, evidence_set, payloads, rvr_schema)
    receipt = {
        "claimDigest": canonical_digest(claim),
        "evidenceSetDigest": evidence_set_digest(evidence_set),
        "verificationProfileDigest": profile_digest,
        "outcome": result["outcome"],
        "reasonCode": result["reasonCode"],
        "resultDigest": canonical_digest(result),
    }
    require_schema(receipt, rvr_schema, label="receipt")
    bundle = {
        "receipt": receipt,
        "claim": claim,
        "evidenceSet": evidence_set,
        "payloadsBase64": payloads_base64,
        "verificationProfile": profile,
        "canonicalResult": result,
    }
    validate_receipt_envelope(bundle, profile_digest, rvr_schema)
    return bundle


def project(document: dict[str, Any], pointer: str) -> Any:
    if not pointer.startswith("/"):
        raise GateRejection("rvr.gate.identity_mismatch", f"unsupported result projection: {pointer}")
    current: Any = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            raise GateRejection("rvr.gate.result_projection_mismatch", f"missing projection: {pointer}")
        current = current[token]
    return current


def validate_receipt_envelope(bundle: dict[str, Any], profile_digest: str, rvr_schema: dict[str, Any]) -> None:
    receipt = bundle["receipt"]
    claim = bundle["claim"]
    evidence_set = bundle["evidenceSet"]
    result = bundle["canonicalResult"]
    profile = bundle["verificationProfile"]
    require_schema(receipt, rvr_schema, label="receipt")
    require_schema(claim, rvr_schema, "#/$defs/claim", "claim")
    require_schema(evidence_set, rvr_schema, "#/$defs/evidenceSet", "evidence set")
    require_schema(result, rvr_schema, "#/$defs/canonicalResult", "canonical result")
    identities = {
        "claimDigest": canonical_digest(claim),
        "evidenceSetDigest": evidence_set_digest(evidence_set),
        "verificationProfileDigest": profile_digest,
        "resultDigest": canonical_digest(result),
    }
    for field, actual in identities.items():
        if receipt[field] != actual:
            raise GateRejection("rvr.gate.identity_mismatch", f"receipt identity mismatch: {field}")
    result_contract = profile["canonicalResultContract"]
    projected_outcome = project(result, result_contract["outcomeProjection"])
    projected_reason = project(result, result_contract["reasonCodeProjection"])
    if receipt["outcome"] != projected_outcome or receipt["reasonCode"] != projected_reason:
        raise GateRejection("rvr.gate.result_projection_mismatch", "receipt contradicts canonical result projection")


def required_dependency_failure(
    profile: dict[str, Any], unavailable_dependency_ids: set[str]
) -> str | None:
    for dependency in dependency_entries(profile):
        if not dependency["requiredForRecomputation"]:
            continue
        if dependency["id"] in unavailable_dependency_ids:
            return dependency["id"]
        try:
            actual = exact_file_digest(dependency["path"])
        except FileNotFoundError:
            return dependency["id"]
        if actual != dependency["sha256"]:
            return dependency["id"]
    return None


def recompute(
    original_bundle: dict[str, Any],
    candidate_case: dict[str, Any],
    profile_digest: str,
    rvr_schema: dict[str, Any],
    unavailable_dependency_ids: set[str] | None = None,
    outcome_relevant_inputs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    validate_receipt_envelope(original_bundle, profile_digest, rvr_schema)
    profile = original_bundle["verificationProfile"]
    unavailable = unavailable_dependency_ids or set()
    dependency_failure = required_dependency_failure(profile, unavailable)
    if dependency_failure is not None:
        return {
            "recomputationStatus": "CANNOT_RECOMPUTE",
            "reasonCode": "rvr.recompute.normative_dependency_unavailable",
            "unavailableDependencyId": dependency_failure,
            "evaluationPerformed": False,
        }

    claim = copy.deepcopy(candidate_case["claim"])
    evidence_set = copy.deepcopy(candidate_case["evidenceSet"])
    payloads_base64 = copy.deepcopy(candidate_case["payloadsBase64"])
    require_schema(claim, rvr_schema, "#/$defs/claim", "candidate claim")
    require_schema(evidence_set, rvr_schema, "#/$defs/evidenceSet", "candidate evidence set")
    payloads = validate_evidence_closure(evidence_set, payloads_base64, outcome_relevant_inputs)
    result = evaluate(claim, evidence_set, payloads, rvr_schema)
    recomputed = {
        "claimDigest": canonical_digest(claim),
        "evidenceSetDigest": evidence_set_digest(evidence_set),
        "verificationProfileDigest": profile_digest,
        "resultDigest": canonical_digest(result),
    }
    receipt = original_bundle["receipt"]
    reproduced = all(receipt[field] == digest for field, digest in recomputed.items())
    return {
        "verificationOutcome": result["outcome"],
        "verificationReasonCode": result["reasonCode"],
        "recomputationStatus": "REPRODUCED" if reproduced else "DIVERGED",
        "reasonCode": "rvr.recompute.identical" if reproduced else "rvr.recompute.canonical_result_diverged",
        "evaluationPerformed": True,
        "canonicalResultDigest": recomputed["resultDigest"],
    }


def mutate_evidence_case(case: dict[str, Any], member_id: str, replacement_base64: str) -> dict[str, Any]:
    candidate = copy.deepcopy(case)
    payload = base64.b64decode(replacement_base64, validate=True)
    candidate["payloadsBase64"][member_id] = replacement_base64
    member = next(item for item in candidate["evidenceSet"]["members"] if item["id"] == member_id)
    member["byteLength"] = str(len(payload))
    member["digest"] = sha256_hex(payload)
    return candidate


def run_canonical_vectors(vectors: dict[str, Any]) -> dict[str, Any]:
    passed: list[str] = []
    for vector in vectors["canonicalByteVectors"]:
        kind = vector["kind"]
        if kind == "canonical":
            if canonical_json(vector["value"]) != vector["expected"]:
                raise AssertionError(vector["id"])
        elif kind == "canonical-json":
            if canonical_json(strict_json_loads(vector["rawJson"])) != vector["expected"]:
                raise AssertionError(vector["id"])
        elif kind == "different":
            if canonical_bytes(vector["left"]) == canonical_bytes(vector["right"]):
                raise AssertionError(vector["id"])
        elif kind == "reject-value":
            try:
                canonical_json(vector["value"])
            except CanonicalizationError:
                pass
            else:
                raise AssertionError(vector["id"])
        elif kind == "reject-json":
            try:
                strict_json_loads(vector["rawJson"])
            except StrictJsonError:
                pass
            else:
                raise AssertionError(vector["id"])
        else:
            raise AssertionError(f"unsupported canonical vector: {kind}")
        passed.append(vector["id"])
    return {"passed": len(passed), "vectorIds": passed}


def mutant_sort_arrays_as_sets(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return canonical_json(value)
    if isinstance(value, (int, float)):
        raise CanonicalizationError("mutant rejects numbers")
    if isinstance(value, list):
        entries = sorted(set(mutant_sort_arrays_as_sets(item) for item in value))
        return "[" + ",".join(entries) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda item: tuple(ord(character) for character in item))
        return "{" + ",".join(
            f"{canonical_json(key)}:{mutant_sort_arrays_as_sets(value[key])}" for key in keys
        ) + "}"
    raise CanonicalizationError("mutant unsupported value")


def mutant_normalize_unicode_nfc(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return canonical_json(unicodedata.normalize("NFC", value))
    if isinstance(value, (int, float)):
        raise CanonicalizationError("mutant rejects numbers")
    if isinstance(value, list):
        return "[" + ",".join(mutant_normalize_unicode_nfc(item) for item in value) + "]"
    if isinstance(value, dict):
        normalized = {unicodedata.normalize("NFC", key): item for key, item in value.items()}
        keys = sorted(normalized, key=lambda item: tuple(ord(character) for character in item))
        return "{" + ",".join(
            f"{canonical_json(key)}:{mutant_normalize_unicode_nfc(normalized[key])}" for key in keys
        ) + "}"
    raise CanonicalizationError("mutant unsupported value")


def mutant_accepts_without_projection(
    bundle: dict[str, Any], profile_digest: str, rvr_schema: dict[str, Any]
) -> bool:
    receipt = bundle["receipt"]
    require_schema(receipt, rvr_schema, label="mutant receipt")
    identities = {
        "claimDigest": canonical_digest(bundle["claim"]),
        "evidenceSetDigest": evidence_set_digest(bundle["evidenceSet"]),
        "verificationProfileDigest": profile_digest,
        "resultDigest": canonical_digest(bundle["canonicalResult"]),
    }
    return all(receipt[field] == actual for field, actual in identities.items())


def run_mutant_audit(
    mutants: dict[str, Any],
    expected: dict[str, Any],
    vectors: dict[str, Any],
    reproduced_bundle: dict[str, Any],
    diverged: dict[str, Any],
    cannot: dict[str, Any],
    contradictory_bundle: dict[str, Any],
    projection: dict[str, Any],
    unsafe_result: dict[str, Any],
    hidden: dict[str, Any],
    profile_digest: str,
    rvr_schema: dict[str, Any],
) -> dict[str, Any]:
    definitions = mutants["mutants"]
    required = expected["mutantAudit"]["requiredKilled"]
    if [item["id"] for item in definitions] != [item["id"] for item in required]:
        raise AssertionError("mutant inventory differs from expected kill matrix")
    canonical_by_id = {item["id"]: item for item in vectors["canonicalByteVectors"]}
    results: list[dict[str, Any]] = []

    for definition, expected_kill in zip(definitions, required):
        mutant_id = definition["id"]
        if definition["requiredWitness"] != expected_kill["killedBy"]:
            raise AssertionError(f"{mutant_id}: witness mismatch")
        if definition["expectedFaultObservation"] != expected_kill["faultObservation"]:
            raise AssertionError(f"{mutant_id}: fault observation mismatch")

        if mutant_id == "sort_arrays_as_sets":
            witness = canonical_by_id[definition["requiredWitness"]]
            fault_observed = (
                canonical_json(witness["left"]) != canonical_json(witness["right"])
                and mutant_sort_arrays_as_sets(witness["left"])
                == mutant_sort_arrays_as_sets(witness["right"])
            )
        elif mutant_id == "normalize_unicode_nfc":
            witness = canonical_by_id[definition["requiredWitness"]]
            fault_observed = (
                canonical_json(witness["left"]) != canonical_json(witness["right"])
                and mutant_normalize_unicode_nfc(witness["left"])
                == mutant_normalize_unicode_nfc(witness["right"])
            )
        elif mutant_id == "ignore_result_projection":
            fault_observed = (
                projection["gateStatus"] == "REJECTED"
                and mutant_accepts_without_projection(contradictory_bundle, profile_digest, rvr_schema)
            )
        elif mutant_id == "missing_dependency_as_refuted":
            mutant_output = {
                "verificationOutcome": "REFUTED",
                "recomputationStatus": "REPRODUCED",
                "evaluationPerformed": False,
            }
            fault_observed = (
                cannot["recomputationStatus"] == "CANNOT_RECOMPUTE"
                and mutant_output["verificationOutcome"] == "REFUTED"
            )
        elif mutant_id == "allow_uncommitted_ambient_override":
            fault_observed = (
                hidden["gateStatus"] == "REJECTED"
                and unsafe_result["outcome"] == "REFUTED"
            )
        elif mutant_id == "trust_stored_result_without_evaluation":
            mutant_output = {
                "verificationOutcome": reproduced_bundle["receipt"]["outcome"],
                "recomputationStatus": "REPRODUCED",
                "evaluationPerformed": False,
            }
            fault_observed = (
                diverged["recomputationStatus"] == "DIVERGED"
                and diverged["evaluationPerformed"] is True
                and mutant_output["recomputationStatus"] == "REPRODUCED"
                and mutant_output["evaluationPerformed"] is False
            )
        else:
            raise AssertionError(f"unimplemented mutant: {mutant_id}")

        if not fault_observed:
            raise AssertionError(f"mutant survived: {mutant_id}")
        results.append({**expected_kill, "killed": True})

    return {"killed": len(results), "total": len(definitions), "results": results}


def manifest_rows(members: list[dict[str, str]]) -> bytes:
    rows = "".join(f"{item['path']}\t{item['sha256']}\n" for item in members)
    return rows.encode("utf-8")


def build_manifest() -> dict[str, Any]:
    members = [
        {"path": path, "sha256": exact_file_digest(path)}
        for path in sorted(MANIFEST_MEMBERS)
    ]
    return {
        "schema": "rvr.conformance-manifest.v0",
        "hashAlgorithm": "sha256-lowercase-hex",
        "memberCount": len(members),
        "members": members,
        "packageDigestRule": "sha256-utf8-sorted-path-tab-file-sha256-lf-rows-manifest-excluded",
        "packageDigest": sha256_hex(manifest_rows(members)),
    }


def write_manifest() -> None:
    manifest = build_manifest()
    MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def audit_manifest() -> dict[str, Any]:
    manifest = load_json(MANIFEST_PATH)
    expected_paths = sorted(MANIFEST_MEMBERS)
    actual_paths = [member["path"] for member in manifest["members"]]
    if actual_paths != expected_paths or manifest["memberCount"] != len(expected_paths):
        raise GateRejection("rvr.gate.identity_mismatch", "manifest inventory mismatch")
    actual = build_manifest()
    if manifest != actual:
        raise GateRejection("rvr.gate.identity_mismatch", "manifest digest drift")
    return {
        "memberCount": manifest["memberCount"],
        "packageDigest": manifest["packageDigest"],
    }


def assert_expected(actual: dict[str, Any], expected: dict[str, Any], case_name: str) -> None:
    for key, expected_value in expected.items():
        if actual.get(key) != expected_value:
            raise AssertionError(f"{case_name}.{key}: expected {expected_value!r}, got {actual.get(key)!r}")


def run_gate() -> dict[str, Any]:
    profile_schema = load_json(PROFILE_SCHEMA_PATH)
    rvr_schema = load_json(RVR_SCHEMA_PATH)
    profile = load_json(PROFILE_PATH)
    vectors = load_json(VECTORS_PATH)
    expected = load_json(EXPECTED_PATH)
    mutants = load_json(MUTANTS_PATH)

    profile_digest = audit_profile(profile, profile_schema)
    manifest_report = audit_manifest()
    canonical_report = run_canonical_vectors(vectors)

    reproduced_case = vectors["verificationCases"]["reproduced"]
    reproduced_bundle = make_bundle(reproduced_case, profile, profile_digest, rvr_schema)
    reproduced = recompute(reproduced_bundle, reproduced_case, profile_digest, rvr_schema)
    assert_expected(reproduced, expected["cases"]["REPRODUCED"], "REPRODUCED")

    diverged_control = vectors["negativeControls"]["diverged"]
    diverged_case = mutate_evidence_case(
        reproduced_case,
        diverged_control["mutation"]["memberId"],
        diverged_control["mutation"]["replacementBase64"],
    )
    if canonical_digest(diverged_case["claim"]) != reproduced_bundle["receipt"]["claimDigest"]:
        raise AssertionError("DIVERGED control changed the fixed receipt claim")
    diverged = recompute(reproduced_bundle, diverged_case, profile_digest, rvr_schema)
    assert_expected(diverged, expected["cases"]["DIVERGED"], "DIVERGED")

    unverifiable_case = vectors["verificationCases"]["unverifiableReproduced"]
    unverifiable_bundle = make_bundle(unverifiable_case, profile, profile_digest, rvr_schema)
    unverifiable = recompute(unverifiable_bundle, unverifiable_case, profile_digest, rvr_schema)
    assert_expected(
        unverifiable,
        expected["cases"]["UNVERIFIABLE_REPRODUCED"],
        "UNVERIFIABLE_REPRODUCED",
    )

    cannot_control = vectors["negativeControls"]["cannotRecompute"]
    cannot = recompute(
        reproduced_bundle,
        reproduced_case,
        profile_digest,
        rvr_schema,
        unavailable_dependency_ids={cannot_control["unavailableDependencyId"]},
    )
    assert_expected(cannot, expected["cases"]["CANNOT_RECOMPUTE"], "CANNOT_RECOMPUTE")

    projection_control = vectors["negativeControls"]["projectionContradiction"]
    contradictory_bundle = copy.deepcopy(reproduced_bundle)
    field = projection_control["mutateReceiptField"]
    contradictory_bundle["receipt"][field] = projection_control["replacement"]
    if contradictory_bundle["receipt"]["resultDigest"] != reproduced_bundle["receipt"]["resultDigest"]:
        raise AssertionError("projection control changed resultDigest")
    try:
        validate_receipt_envelope(contradictory_bundle, profile_digest, rvr_schema)
    except GateRejection as error:
        projection = {"gateStatus": "REJECTED", "reasonCode": error.reason_code}
    else:
        raise AssertionError("contradictory projection was accepted")
    assert_expected(
        projection,
        expected["cases"]["PROJECTION_NEGATIVE_CONTROL"],
        "PROJECTION_NEGATIVE_CONTROL",
    )

    hidden_control = vectors["negativeControls"]["hiddenState"]
    unsafe_claim = copy.deepcopy(reproduced_case["claim"])
    unsafe_claim["expectedDigest"] = hidden_control["outcomeRelevantInput"]["value"]
    unsafe_case = copy.deepcopy(reproduced_case)
    unsafe_case["claim"] = unsafe_claim
    unsafe_payloads = validate_evidence_closure(unsafe_case["evidenceSet"], unsafe_case["payloadsBase64"])
    unsafe_result = evaluate(unsafe_claim, unsafe_case["evidenceSet"], unsafe_payloads, rvr_schema)
    if unsafe_result["outcome"] == reproduced_bundle["canonicalResult"]["outcome"]:
        raise AssertionError("hidden-state counterfactual did not change outcome")
    try:
        recompute(
            reproduced_bundle,
            reproduced_case,
            profile_digest,
            rvr_schema,
            outcome_relevant_inputs=[hidden_control["outcomeRelevantInput"]],
        )
    except GateRejection as error:
        hidden = {
            "gateStatus": "REJECTED",
            "reasonCode": error.reason_code,
            "evaluationPerformed": False,
        }
    else:
        raise AssertionError("hidden-state attempt was accepted")
    assert_expected(
        hidden,
        expected["cases"]["HIDDEN_STATE_NEGATIVE_CONTROL"],
        "HIDDEN_STATE_NEGATIVE_CONTROL",
    )

    mutant_audit = run_mutant_audit(
        mutants,
        expected,
        vectors,
        reproduced_bundle,
        diverged,
        cannot,
        contradictory_bundle,
        projection,
        unsafe_result,
        hidden,
        profile_digest,
        rvr_schema,
    )

    return {
        "gate": "RVR_V0_CONFORMANCE_PASS",
        "implementation": "python-independent-rvr-v0",
        "profileId": profile["profileId"],
        "verificationProfileDigest": profile_digest,
        "canonicalByteContract": profile["canonicalByteContract"]["id"],
        "canonicalByteVectors": canonical_report,
        "manifest": manifest_report,
        "cases": {
            "REPRODUCED": reproduced,
            "DIVERGED": diverged,
            "UNVERIFIABLE_REPRODUCED": unverifiable,
            "CANNOT_RECOMPUTE": cannot,
            "PROJECTION_NEGATIVE_CONTROL": projection,
            "HIDDEN_STATE_NEGATIVE_CONTROL": hidden,
        },
        "adversarialMutants": mutant_audit,
        "producerImports": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="RVR v0 independent conformance adapter")
    parser.add_argument("--check", action="store_true", help="run the complete conformance gate")
    parser.add_argument("--write-manifest", action="store_true", help="regenerate the derived package manifest")
    args = parser.parse_args()
    try:
        if args.write_manifest:
            write_manifest()
            print(MANIFEST_PATH.relative_to(ROOT).as_posix())
            return 0
        if not args.check:
            parser.error("one of --check or --write-manifest is required")
        print(json.dumps(run_gate(), ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        print(f"RVR v0 gate failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
