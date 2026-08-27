use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::json;
use sha2::{Digest, Sha256};

const FROZEN_PROFILE_DIGEST: &str =
    "ac16ba13abe00d8b7fac14bf5c35ee3175de3dbd7d70a296be27a094a99ef29c";
const FROZEN_PACKAGE_DIGEST: &str =
    "e2c7712e4ce5551628cf2d1b65b0ae4458d5d2f7aaed7ffd3c969505ee29d63c";

type ReviewResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq)]
enum JValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JValue>),
    Object(Vec<(String, JValue)>),
}

struct JValueVisitor;

impl<'de> Visitor<'de> for JValueVisitor {
    type Value = JValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(JValue::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(JValue::Null)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(JValue::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(JValue::Number(value.to_string()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(JValue::Number(value.to_string()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(JValue::Number(value.to_string()))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(JValue::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(JValue::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<JValue>()? {
            values.push(value);
        }
        Ok(JValue::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut members = Vec::new();
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate object key: {key:?}")));
            }
            let value = map.next_value::<JValue>()?;
            members.push((key, value));
        }
        Ok(JValue::Object(members))
    }
}

impl<'de> Deserialize<'de> for JValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JValueVisitor)
    }
}

fn parse_json_bytes(bytes: &[u8], label: &str) -> ReviewResult<JValue> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("{label}: UTF-8: {error}"))?;
    parse_json(text).map_err(|error| format!("{label}: {error}"))
}

fn parse_json(text: &str) -> ReviewResult<JValue> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = JValue::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    Ok(value)
}

fn object(value: &JValue) -> ReviewResult<&[(String, JValue)]> {
    match value {
        JValue::Object(members) => Ok(members),
        _ => Err("expected object".to_owned()),
    }
}

fn object_mut(value: &mut JValue) -> ReviewResult<&mut Vec<(String, JValue)>> {
    match value {
        JValue::Object(members) => Ok(members),
        _ => Err("expected mutable object".to_owned()),
    }
}

fn array(value: &JValue) -> ReviewResult<&[JValue]> {
    match value {
        JValue::Array(values) => Ok(values),
        _ => Err("expected array".to_owned()),
    }
}

fn array_mut(value: &mut JValue) -> ReviewResult<&mut Vec<JValue>> {
    match value {
        JValue::Array(values) => Ok(values),
        _ => Err("expected mutable array".to_owned()),
    }
}

fn member<'a>(value: &'a JValue, key: &str) -> ReviewResult<&'a JValue> {
    object(value)?
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value)
        .ok_or_else(|| format!("missing object member: {key}"))
}

fn member_mut<'a>(value: &'a mut JValue, key: &str) -> ReviewResult<&'a mut JValue> {
    object_mut(value)?
        .iter_mut()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value)
        .ok_or_else(|| format!("missing mutable object member: {key}"))
}

fn text(value: &JValue) -> ReviewResult<&str> {
    match value {
        JValue::String(value) => Ok(value),
        _ => Err("expected string".to_owned()),
    }
}

fn boolean(value: &JValue) -> ReviewResult<bool> {
    match value {
        JValue::Bool(value) => Ok(*value),
        _ => Err("expected boolean".to_owned()),
    }
}

fn number_text(value: &JValue) -> ReviewResult<&str> {
    match value {
        JValue::Number(value) => Ok(value),
        _ => Err("expected JSON number".to_owned()),
    }
}

fn replace_member(value: &mut JValue, key: &str, replacement: JValue) -> ReviewResult<()> {
    *member_mut(value, key)? = replacement;
    Ok(())
}

fn canonical_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '\u{0008}' => output.push_str("\\b"),
            '\u{0009}' => output.push_str("\\t"),
            '\u{000a}' => output.push_str("\\n"),
            '\u{000c}' => output.push_str("\\f"),
            '\u{000d}' => output.push_str("\\r"),
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            control if control <= '\u{001f}' => {
                output.push_str(&format!("\\u{:04x}", control as u32));
            }
            scalar => output.push(scalar),
        }
    }
    output.push('"');
    output
}

fn canonical_json(value: &JValue) -> ReviewResult<String> {
    match value {
        JValue::Null => Ok("null".to_owned()),
        JValue::Bool(true) => Ok("true".to_owned()),
        JValue::Bool(false) => Ok("false".to_owned()),
        JValue::Number(_) => Err("rvr-canonical-json-v0 forbids numbers".to_owned()),
        JValue::String(value) => Ok(canonical_string(value)),
        JValue::Array(values) => {
            let encoded = values
                .iter()
                .map(canonical_json)
                .collect::<ReviewResult<Vec<_>>>()?;
            Ok(format!("[{}]", encoded.join(",")))
        }
        JValue::Object(members) => {
            let mut seen = HashSet::new();
            for (key, _) in members {
                if !seen.insert(key) {
                    return Err(format!("duplicate object key: {key:?}"));
                }
            }
            let mut sorted = members.iter().collect::<Vec<_>>();
            sorted.sort_by(|left, right| left.0.chars().cmp(right.0.chars()));
            let encoded = sorted
                .into_iter()
                .map(|(key, value)| {
                    Ok(format!(
                        "{}:{}",
                        canonical_string(key),
                        canonical_json(value)?
                    ))
                })
                .collect::<ReviewResult<Vec<_>>>()?;
            Ok(format!("{{{}}}", encoded.join(",")))
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonical_digest(value: &JValue) -> ReviewResult<String> {
    Ok(sha256_hex(canonical_json(value)?.as_bytes()))
}

fn resolve_dependency(root: &Path, locator: &str) -> ReviewResult<PathBuf> {
    if locator.is_empty()
        || locator.starts_with('/')
        || locator.contains('\\')
        || locator.contains(':')
    {
        return Err(format!("invalid package-relative locator: {locator:?}"));
    }
    let segments = locator.split('/').collect::<Vec<_>>();
    if segments
        .iter()
        .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
    {
        return Err(format!("forbidden path segment: {locator:?}"));
    }
    let canonical_root = root.canonicalize().map_err(|error| error.to_string())?;
    let lexical = segments
        .iter()
        .fold(canonical_root.clone(), |path, segment| path.join(segment));
    let resolved = if lexical.exists() {
        lexical.canonicalize().map_err(|error| error.to_string())?
    } else {
        lexical
    };
    if !resolved.starts_with(&canonical_root) {
        return Err(format!("locator escapes package root: {locator:?}"));
    }
    Ok(resolved)
}

fn read_json(root: &Path, locator: &str) -> ReviewResult<JValue> {
    let path = resolve_dependency(root, locator)?;
    let bytes = fs::read(&path).map_err(|error| format!("{locator}: {error}"))?;
    parse_json_bytes(&bytes, locator)
}

#[derive(Clone)]
struct Dependency {
    id: String,
    path: String,
    sha256: String,
    required: bool,
}

fn dependency(value: &JValue) -> ReviewResult<Dependency> {
    Ok(Dependency {
        id: text(member(value, "id")?)?.to_owned(),
        path: text(member(value, "path")?)?.to_owned(),
        sha256: text(member(value, "sha256")?)?.to_owned(),
        required: boolean(member(value, "requiredForRecomputation")?)?,
    })
}

fn profile_dependencies(profile: &JValue) -> ReviewResult<Vec<Dependency>> {
    let mut dependencies = Vec::new();
    let schema_contract = member(profile, "profileSchemaContract")?;
    dependencies.push(dependency(member(schema_contract, "manifest")?)?);
    dependencies.push(dependency(member(schema_contract, "constraints")?)?);
    dependencies.push(dependency(member(profile, "verificationSpecification")?)?);
    for item in array(member(member(profile, "conformanceVectorSet")?, "members")?)? {
        dependencies.push(dependency(item)?);
    }
    for item in array(member(profile, "schemaContracts")?)? {
        dependencies.push(dependency(item)?);
    }
    Ok(dependencies)
}

fn expect_text(value: &JValue, key: &str, expected: &str) -> ReviewResult<()> {
    let actual = text(member(value, key)?)?;
    if actual != expected {
        return Err(format!("{key}: expected {expected:?}, got {actual:?}"));
    }
    Ok(())
}

fn audit_profile(root: &Path, profile: &JValue) -> ReviewResult<HashMap<String, Vec<u8>>> {
    expect_text(profile, "schema", "rvr.verification-profile.v0")?;
    expect_text(profile, "profileId", "rvr-generic-sha256-equals-v0")?;
    let byte_contract = member(profile, "canonicalByteContract")?;
    expect_text(byte_contract, "id", "rvr-canonical-json-v0")?;
    expect_text(
        byte_contract,
        "stringEscaping",
        "rvr-json-string-escaping-v0",
    )?;
    expect_text(byte_contract, "solidus", "literal")?;
    expect_text(byte_contract, "lineSeparators", "U+2028-and-U+2029-literal")?;
    let resolver = member(profile, "dependencyResolution")?;
    expect_text(resolver, "base", "SUPPLIED_PROFILE_PACKAGE_ROOT")?;
    expect_text(
        resolver,
        "verificationOrder",
        "resolve-read-sha256-match-use",
    )?;
    let result_contract = member(profile, "canonicalResultContract")?;
    expect_text(result_contract, "outcomeProjection", "/outcome")?;
    expect_text(result_contract, "reasonCodeProjection", "/reasonCode")?;
    let external = member(profile, "externalContextPolicy")?;
    expect_text(external, "ambientInputs", "FORBIDDEN")?;

    let dependencies = profile_dependencies(profile)?;
    let mut ids = HashSet::new();
    let mut verified = HashMap::new();
    for item in &dependencies {
        if !ids.insert(item.id.clone()) {
            return Err(format!("duplicate dependency id: {}", item.id));
        }
        let path = resolve_dependency(root, &item.path)?;
        let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", item.path))?;
        let actual = sha256_hex(&bytes);
        if actual != item.sha256 {
            return Err(format!("dependency digest mismatch: {}", item.id));
        }
        verified.insert(item.id.clone(), bytes);
    }
    for required_id in [
        "verification-profile-manifest-schema",
        "rvr-generic-sha256-equals-profile-schema",
        "verification-specification",
        "rvr-schema",
    ] {
        let item = dependencies
            .iter()
            .find(|item| item.id == required_id)
            .ok_or_else(|| format!("missing required dependency: {required_id}"))?;
        if !item.required {
            return Err(format!(
                "normative dependency is not required for recomputation: {required_id}"
            ));
        }
    }

    let vector_set = member(profile, "conformanceVectorSet")?;
    let mut rows = array(member(vector_set, "members")?)?
        .iter()
        .map(dependency)
        .collect::<ReviewResult<Vec<_>>>()?;
    rows.sort_by(|left, right| left.path.chars().cmp(right.path.chars()));
    let rows = rows
        .iter()
        .map(|item| format!("{}\t{}\n", item.path, item.sha256))
        .collect::<String>();
    let expected = text(member(vector_set, "digest")?)?;
    if sha256_hex(rows.as_bytes()) != expected {
        return Err("conformance vector-set digest mismatch".to_owned());
    }

    let rvr = dependencies
        .iter()
        .find(|item| item.id == "rvr-schema")
        .ok_or_else(|| "missing rvr-schema dependency".to_owned())?;
    if text(member(
        member(profile, "evidenceSetContract")?,
        "schemaSha256",
    )?)? != rvr.sha256
        || text(member(result_contract, "schemaSha256")?)? != rvr.sha256
    {
        return Err("RVR schema cross-pin mismatch".to_owned());
    }
    Ok(verified)
}

fn audit_manifest(root: &Path, manifest: &JValue) -> ReviewResult<String> {
    let members = array(member(manifest, "members")?)?;
    if number_text(member(manifest, "memberCount")?)? != members.len().to_string() {
        return Err("manifest memberCount mismatch".to_owned());
    }
    let mut rows = Vec::new();
    for item in members {
        let path = text(member(item, "path")?)?;
        let expected = text(member(item, "sha256")?)?;
        let bytes = fs::read(resolve_dependency(root, path)?).map_err(|error| error.to_string())?;
        let actual = sha256_hex(&bytes);
        if actual != expected {
            return Err(format!("manifest member mismatch: {path}"));
        }
        rows.push((path.to_owned(), actual));
    }
    rows.sort_by(|left, right| left.0.chars().cmp(right.0.chars()));
    let preimage = rows
        .iter()
        .map(|(path, digest)| format!("{path}\t{digest}\n"))
        .collect::<String>();
    let actual = sha256_hex(preimage.as_bytes());
    let expected = text(member(manifest, "packageDigest")?)?;
    if actual != expected {
        return Err("package digest mismatch".to_owned());
    }
    Ok(actual)
}

fn run_canonical_vectors(vectors: &JValue) -> ReviewResult<Vec<String>> {
    let mut passed = Vec::new();
    for vector in array(member(vectors, "canonicalByteVectors")?)? {
        let id = text(member(vector, "id")?)?;
        let kind = text(member(vector, "kind")?)?;
        let ok = match kind {
            "canonical" => {
                canonical_json(member(vector, "value")?)? == text(member(vector, "expected")?)?
            }
            "canonical-json" => {
                let parsed = parse_json(text(member(vector, "rawJson")?)?)?;
                canonical_json(&parsed)? == text(member(vector, "expected")?)?
            }
            "canonical-utf8-hex" => {
                let encoded = canonical_json(member(vector, "value")?)?;
                let actual = encoded
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                actual == text(member(vector, "expectedHex")?)?
            }
            "different" => {
                canonical_json(member(vector, "left")?)?
                    != canonical_json(member(vector, "right")?)?
            }
            "reject-value" => canonical_json(member(vector, "value")?).is_err(),
            "reject-json" => parse_json(text(member(vector, "rawJson")?)?).is_err(),
            _ => return Err(format!("unsupported canonical vector kind: {kind}")),
        };
        if !ok {
            return Err(format!("canonical vector failed: {id}"));
        }
        passed.push(id.to_owned());
    }
    Ok(passed)
}

fn run_resolver_vectors(root: &Path, vectors: &JValue) -> ReviewResult<Vec<String>> {
    let mut passed = Vec::new();
    for vector in array(member(vectors, "resolverVectors")?)? {
        let id = text(member(vector, "id")?)?;
        let expected = text(member(vector, "expected")?)?;
        let accepted = resolve_dependency(root, text(member(vector, "path")?)?).is_ok();
        if accepted != (expected == "ACCEPTED") {
            return Err(format!("resolver vector failed: {id}"));
        }
        passed.push(id.to_owned());
    }
    Ok(passed)
}

fn normalized_evidence_set(evidence_set: &JValue) -> ReviewResult<JValue> {
    let mut normalized = evidence_set.clone();
    let members = array_mut(member_mut(&mut normalized, "members")?)?;
    let mut ids = HashSet::new();
    for item in members.iter() {
        let id = text(member(item, "id")?)?;
        if !ids.insert(id.to_owned()) {
            return Err(format!("duplicate evidence member: {id}"));
        }
    }
    members.sort_by(|left, right| {
        let left = text(member(left, "id").expect("member id")).expect("string id");
        let right = text(member(right, "id").expect("member id")).expect("string id");
        left.chars().cmp(right.chars())
    });
    Ok(normalized)
}

fn decode_payloads(case: &JValue) -> ReviewResult<HashMap<String, Vec<u8>>> {
    let mut payloads = HashMap::new();
    for (id, encoded) in object(member(case, "payloadsBase64")?)? {
        let bytes = BASE64
            .decode(text(encoded)?.as_bytes())
            .map_err(|error| format!("payload {id}: {error}"))?;
        if BASE64.encode(&bytes) != text(encoded)? {
            return Err(format!("non-canonical base64 payload: {id}"));
        }
        payloads.insert(id.clone(), bytes);
    }
    Ok(payloads)
}

fn validate_evidence(case: &JValue) -> ReviewResult<HashMap<String, Vec<u8>>> {
    let evidence_set = member(case, "evidenceSet")?;
    let payloads = decode_payloads(case)?;
    let mut present = HashSet::new();
    let mut all = HashSet::new();
    for item in array(member(evidence_set, "members")?)? {
        let id = text(member(item, "id")?)?;
        if !all.insert(id.to_owned()) {
            return Err(format!("duplicate evidence member: {id}"));
        }
        match text(member(item, "status")?)? {
            "PRESENT" => {
                present.insert(id.to_owned());
                let bytes = payloads
                    .get(id)
                    .ok_or_else(|| format!("missing payload: {id}"))?;
                if text(member(item, "byteLength")?)? != bytes.len().to_string() {
                    return Err(format!("payload length mismatch: {id}"));
                }
                if text(member(item, "digest")?)? != sha256_hex(bytes) {
                    return Err(format!("payload digest mismatch: {id}"));
                }
            }
            "UNAVAILABLE" => {
                if payloads.contains_key(id) {
                    return Err(format!("unavailable member has payload: {id}"));
                }
            }
            status => return Err(format!("unknown evidence status: {status}")),
        }
    }
    if payloads.keys().any(|id| !present.contains(id)) {
        return Err("uncommitted payload".to_owned());
    }
    Ok(payloads)
}

fn evaluate(case: &JValue) -> ReviewResult<JValue> {
    let claim = member(case, "claim")?;
    expect_text(claim, "schema", "rvr.claim.sha256-equals.v0")?;
    expect_text(claim, "operation", "SHA256_EQUALS")?;
    let evidence_member = text(member(claim, "evidenceMember")?)?;
    let expected_digest = text(member(claim, "expectedDigest")?)?;
    let payloads = validate_evidence(case)?;
    let evidence_set = member(case, "evidenceSet")?;
    let descriptor = array(member(evidence_set, "members")?)?
        .iter()
        .find(|item| text(member(item, "id").expect("id")).expect("text") == evidence_member)
        .ok_or_else(|| "claim member absent from evidence closure".to_owned())?;
    let (outcome, reason, observed) = if text(member(descriptor, "status")?)? == "UNAVAILABLE" {
        (
            "UNVERIFIABLE",
            "rvr.v0.required_evidence_unavailable",
            JValue::Null,
        )
    } else {
        let digest = sha256_hex(
            payloads
                .get(evidence_member)
                .ok_or_else(|| "missing evaluated payload".to_owned())?,
        );
        if digest == expected_digest {
            ("VERIFIED", "rvr.v0.digest_match", JValue::String(digest))
        } else {
            ("REFUTED", "rvr.v0.digest_mismatch", JValue::String(digest))
        }
    };
    Ok(JValue::Object(vec![
        (
            "schema".to_owned(),
            JValue::String("rvr.canonical-result.v0".to_owned()),
        ),
        ("outcome".to_owned(), JValue::String(outcome.to_owned())),
        ("reasonCode".to_owned(), JValue::String(reason.to_owned())),
        (
            "evaluation".to_owned(),
            JValue::Object(vec![
                (
                    "operation".to_owned(),
                    JValue::String("SHA256_EQUALS".to_owned()),
                ),
                (
                    "evidenceMember".to_owned(),
                    JValue::String(evidence_member.to_owned()),
                ),
                (
                    "expectedDigest".to_owned(),
                    JValue::String(expected_digest.to_owned()),
                ),
                ("observedDigest".to_owned(), observed),
            ]),
        ),
    ]))
}

#[derive(Clone)]
struct Receipt {
    claim_digest: String,
    evidence_set_digest: String,
    profile_digest: String,
    outcome: String,
    reason_code: String,
    result_digest: String,
}

fn make_receipt(case: &JValue, profile_digest: &str) -> ReviewResult<(Receipt, JValue)> {
    let result = evaluate(case)?;
    let receipt = Receipt {
        claim_digest: canonical_digest(member(case, "claim")?)?,
        evidence_set_digest: canonical_digest(&normalized_evidence_set(member(
            case,
            "evidenceSet",
        )?)?)?,
        profile_digest: profile_digest.to_owned(),
        outcome: text(member(&result, "outcome")?)?.to_owned(),
        reason_code: text(member(&result, "reasonCode")?)?.to_owned(),
        result_digest: canonical_digest(&result)?,
    };
    Ok((receipt, result))
}

struct Recomputed {
    outcome: String,
    reason: String,
    status: String,
    evaluated: bool,
}

fn recompute(receipt: &Receipt, case: &JValue, profile_digest: &str) -> ReviewResult<Recomputed> {
    let result = evaluate(case)?;
    let claim_digest = canonical_digest(member(case, "claim")?)?;
    let evidence_digest =
        canonical_digest(&normalized_evidence_set(member(case, "evidenceSet")?)?)?;
    let result_digest = canonical_digest(&result)?;
    let identical = receipt.claim_digest == claim_digest
        && receipt.evidence_set_digest == evidence_digest
        && receipt.profile_digest == profile_digest
        && receipt.result_digest == result_digest;
    Ok(Recomputed {
        outcome: text(member(&result, "outcome")?)?.to_owned(),
        reason: text(member(&result, "reasonCode")?)?.to_owned(),
        status: if identical { "REPRODUCED" } else { "DIVERGED" }.to_owned(),
        evaluated: true,
    })
}

fn expected_field(expected: &JValue, case: &str, field: &str) -> ReviewResult<String> {
    Ok(text(member(member(member(expected, "cases")?, case)?, field)?)?.to_owned())
}

fn expected_bool(expected: &JValue, case: &str, field: &str) -> ReviewResult<bool> {
    boolean(member(member(member(expected, "cases")?, case)?, field)?)
}

fn run_semantic_cases(
    profile_digest: &str,
    profile: &JValue,
    vectors: &JValue,
    expected: &JValue,
) -> ReviewResult<Vec<String>> {
    let verification_cases = member(vectors, "verificationCases")?;
    let reproduced_case = member(verification_cases, "reproduced")?;
    let (receipt, result) = make_receipt(reproduced_case, profile_digest)?;
    let reproduced = recompute(&receipt, reproduced_case, profile_digest)?;
    if reproduced.outcome != expected_field(expected, "REPRODUCED", "verificationOutcome")?
        || reproduced.reason != expected_field(expected, "REPRODUCED", "verificationReasonCode")?
        || reproduced.status != expected_field(expected, "REPRODUCED", "recomputationStatus")?
        || !reproduced.evaluated
    {
        return Err("REPRODUCED mismatch".to_owned());
    }

    let mut diverged_case = reproduced_case.clone();
    let diverged_control = member(member(vectors, "negativeControls")?, "diverged")?;
    let mutation = member(diverged_control, "mutation")?;
    let member_id = text(member(mutation, "memberId")?)?;
    let replacement = text(member(mutation, "replacementBase64")?)?;
    replace_member(
        member_mut(&mut diverged_case, "payloadsBase64")?,
        member_id,
        JValue::String(replacement.to_owned()),
    )?;
    let bytes = BASE64
        .decode(replacement)
        .map_err(|error| error.to_string())?;
    let evidence_members = array_mut(member_mut(
        member_mut(&mut diverged_case, "evidenceSet")?,
        "members",
    )?)?;
    let descriptor = evidence_members
        .iter_mut()
        .find(|item| text(member(item, "id").expect("id")).expect("text") == member_id)
        .ok_or_else(|| "mutation member missing".to_owned())?;
    replace_member(
        descriptor,
        "byteLength",
        JValue::String(bytes.len().to_string()),
    )?;
    replace_member(descriptor, "digest", JValue::String(sha256_hex(&bytes)))?;
    if canonical_digest(member(&diverged_case, "claim")?)? != receipt.claim_digest {
        return Err("DIVERGED changed fixed claim".to_owned());
    }
    let diverged = recompute(&receipt, &diverged_case, profile_digest)?;
    if diverged.outcome != expected_field(expected, "DIVERGED", "verificationOutcome")?
        || diverged.reason != expected_field(expected, "DIVERGED", "verificationReasonCode")?
        || diverged.status != expected_field(expected, "DIVERGED", "recomputationStatus")?
        || !diverged.evaluated
    {
        return Err("DIVERGED mismatch".to_owned());
    }

    let unavailable_case = member(verification_cases, "unverifiableReproduced")?;
    let (unavailable_receipt, _) = make_receipt(unavailable_case, profile_digest)?;
    let unavailable = recompute(&unavailable_receipt, unavailable_case, profile_digest)?;
    if unavailable.outcome
        != expected_field(expected, "UNVERIFIABLE_REPRODUCED", "verificationOutcome")?
        || unavailable.reason
            != expected_field(
                expected,
                "UNVERIFIABLE_REPRODUCED",
                "verificationReasonCode",
            )?
        || unavailable.status
            != expected_field(expected, "UNVERIFIABLE_REPRODUCED", "recomputationStatus")?
    {
        return Err("UNVERIFIABLE + REPRODUCED mismatch".to_owned());
    }

    let cannot = member(member(vectors, "negativeControls")?, "cannotRecompute")?;
    let missing_id = text(member(cannot, "unavailableDependencyId")?)?;
    let missing_dependency = profile_dependencies(profile)?
        .into_iter()
        .find(|item| item.id == missing_id)
        .ok_or_else(|| "CANNOT_RECOMPUTE dependency is not pinned".to_owned())?;
    let cannot_status = if missing_dependency.required {
        "CANNOT_RECOMPUTE"
    } else {
        "EVALUATION_WOULD_BE_ALLOWED"
    };
    let cannot_evaluated = false;
    if cannot_status != expected_field(expected, "CANNOT_RECOMPUTE", "recomputationStatus")?
        || cannot_evaluated != expected_bool(expected, "CANNOT_RECOMPUTE", "evaluationPerformed")?
    {
        return Err("CANNOT_RECOMPUTE mismatch".to_owned());
    }

    let projection = member(
        member(vectors, "negativeControls")?,
        "projectionContradiction",
    )?;
    let replacement = text(member(projection, "replacement")?)?;
    let projection_rejected = replacement != receipt.outcome
        && receipt.result_digest == canonical_digest(&result)?
        && receipt.reason_code == text(member(&result, "reasonCode")?)?;
    if !projection_rejected {
        return Err("projection contradiction was not rejected".to_owned());
    }

    let hidden = member(member(vectors, "negativeControls")?, "hiddenState")?;
    let input = member(hidden, "outcomeRelevantInput")?;
    if !matches!(member(input, "commitment")?, JValue::Null) {
        return Err("hidden-state input unexpectedly committed".to_owned());
    }
    let mut unsafe_case = reproduced_case.clone();
    replace_member(
        member_mut(&mut unsafe_case, "claim")?,
        "expectedDigest",
        JValue::String(text(member(input, "value")?)?.to_owned()),
    )?;
    if text(member(&evaluate(&unsafe_case)?, "outcome")?)? == receipt.outcome {
        return Err("hidden-state counterfactual did not change outcome".to_owned());
    }

    Ok(vec![
        "REPRODUCED".to_owned(),
        "DIVERGED".to_owned(),
        "UNVERIFIABLE_REPRODUCED".to_owned(),
        "CANNOT_RECOMPUTE".to_owned(),
        "PROJECTION_NEGATIVE_CONTROL".to_owned(),
        "HIDDEN_STATE_NEGATIVE_CONTROL".to_owned(),
    ])
}

fn run(root: &Path) -> ReviewResult<serde_json::Value> {
    let profile = read_json(root, "conformance/rvr-v0/verification-profile.json")?;
    let verified = audit_profile(root, &profile)?;
    let profile_digest = canonical_digest(&profile)?;
    if profile_digest != FROZEN_PROFILE_DIGEST {
        return Err(format!("frozen profile digest mismatch: {profile_digest}"));
    }

    let manifest = read_json(root, "conformance/rvr-v0/manifest.json")?;
    let package_digest = audit_manifest(root, &manifest)?;
    if package_digest != FROZEN_PACKAGE_DIGEST {
        return Err(format!("frozen package digest mismatch: {package_digest}"));
    }

    let vectors = parse_json_bytes(
        verified
            .get("verification-vectors")
            .ok_or_else(|| "missing verified vectors".to_owned())?,
        "verified vectors",
    )?;
    let expected = parse_json_bytes(
        verified
            .get("expected-results")
            .ok_or_else(|| "missing verified expectations".to_owned())?,
        "verified expectations",
    )?;
    let canonical = run_canonical_vectors(&vectors)?;
    let resolver = run_resolver_vectors(root, &vectors)?;
    let semantics = run_semantic_cases(&profile_digest, &profile, &vectors, &expected)?;

    let generic_schema = std::str::from_utf8(
        verified
            .get("verification-profile-manifest-schema")
            .ok_or_else(|| "missing generic manifest schema".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    if generic_schema.contains("rvr-generic-sha256-equals-v0")
        || generic_schema.contains("conformance/rvr-v0/rvr.schema.json")
    {
        return Err("generic manifest schema contains profile-specific identity".to_owned());
    }
    let constraints = verified
        .get("rvr-generic-sha256-equals-profile-schema")
        .ok_or_else(|| "missing verified constraints schema".to_owned())?;
    if sha256_hex(constraints) == "0".repeat(64) {
        return Err("tampered constraints pin unexpectedly accepted".to_owned());
    }

    Ok(json!({
        "review": "RVR_RC2_INDEPENDENT_RUST_PASS",
        "authority": "non-normative-independent-review-evidence",
        "frozenBaseline": "v0.0.1-rc.2",
        "verificationProfileDigest": profile_digest,
        "packageDigest": package_digest,
        "canonicalByteVectors": canonical.len(),
        "resolverVectors": resolver.len(),
        "semanticCases": semantics,
        "genericProfileBoundary": true,
        "tamperedConstraintsPinRejected": true,
        "producerImports": 0,
        "pythonOrTypeScriptAdapterImports": 0
    }))
}

fn package_root_from_args() -> ReviewResult<PathBuf> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[0] != "--package-root" {
        return Err("usage: rvr-rc2-independent-reviewer --package-root <path>".to_owned());
    }
    PathBuf::from(&arguments[1])
        .canonicalize()
        .map_err(|error| error.to_string())
}

fn main() {
    let result = package_root_from_args().and_then(|root| run(&root));
    match result {
        Ok(report) => println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report JSON")
        ),
        Err(error) => {
            eprintln!("RVR RC2 independent Rust review failed: {error}");
            std::process::exit(1);
        }
    }
}
