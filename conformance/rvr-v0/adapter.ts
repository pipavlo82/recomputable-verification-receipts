#!/usr/bin/env bun
/** Independent TypeScript/Bun implementation of the RVR v0 profile. */
import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"

type Json = null | boolean | number | string | Json[] | { [key: string]: Json }
type RecordJson = { [key: string]: any }

const ROOT = resolve(import.meta.dir, "../..")
const PACKAGE = resolve(ROOT, "conformance/rvr-v0")
const PROFILE_PATH = resolve(PACKAGE, "verification-profile.json")
const PROFILE_SCHEMA_PATH = resolve(PACKAGE, "verification-profile.schema.json")
const RVR_SCHEMA_PATH = resolve(PACKAGE, "rvr.schema.json")
const VECTORS_PATH = resolve(PACKAGE, "vectors.json")
const EXPECTED_PATH = resolve(PACKAGE, "expected.json")
const MUTANTS_PATH = resolve(PACKAGE, "mutants.json")
const MANIFEST_PATH = resolve(PACKAGE, "manifest.json")

const MANIFEST_MEMBERS = [
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
] as const

class RvrError extends Error {}
class StrictJsonError extends RvrError {}
class CanonicalizationError extends RvrError {}
class SchemaValidationError extends RvrError {}
class GateRejection extends RvrError {
  constructor(readonly reasonCode: string, message: string) {
    super(message)
  }
}

const sha256Hex = (bytes: Uint8Array | string): string => createHash("sha256").update(bytes).digest("hex")
const readBytes = (path: string): Buffer => readFileSync(path)
const exactFileDigest = (repositoryPath: string): string => sha256Hex(readBytes(resolve(ROOT, repositoryPath)))

function assertScalarString(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(index + 1)
      if (!(low >= 0xdc00 && low <= 0xdfff)) throw new StrictJsonError("lone high surrogate")
      index += 1
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new StrictJsonError("lone low surrogate")
    }
  }
}

class StrictJsonParser {
  private index = 0

  constructor(private readonly source: string) {}

  parse(): Json {
    this.skipWhitespace()
    const value = this.parseValue()
    this.skipWhitespace()
    if (this.index !== this.source.length) throw new StrictJsonError(`unexpected trailing input at ${this.index}`)
    return value
  }

  private skipWhitespace(): void {
    while (this.index < this.source.length && /[\x20\t\r\n]/.test(this.source[this.index]!)) this.index += 1
  }

  private parseValue(): Json {
    const current = this.source[this.index]
    if (current === "{") return this.parseObject()
    if (current === "[") return this.parseArray()
    if (current === '"') return this.parseString()
    if (this.source.startsWith("true", this.index)) { this.index += 4; return true }
    if (this.source.startsWith("false", this.index)) { this.index += 5; return false }
    if (this.source.startsWith("null", this.index)) { this.index += 4; return null }
    if (current === "-" || (current !== undefined && /[0-9]/.test(current))) return this.parseNumber()
    throw new StrictJsonError(`unexpected token at ${this.index}`)
  }

  private parseObject(): { [key: string]: Json } {
    this.index += 1
    this.skipWhitespace()
    const output: { [key: string]: Json } = Object.create(null)
    const keys = new Set<string>()
    if (this.source[this.index] === "}") { this.index += 1; return output }
    while (true) {
      if (this.source[this.index] !== '"') throw new StrictJsonError(`object key expected at ${this.index}`)
      const key = this.parseString()
      if (keys.has(key)) throw new StrictJsonError(`duplicate object key: ${JSON.stringify(key)}`)
      keys.add(key)
      this.skipWhitespace()
      if (this.source[this.index] !== ":") throw new StrictJsonError(`colon expected at ${this.index}`)
      this.index += 1
      this.skipWhitespace()
      output[key] = this.parseValue()
      this.skipWhitespace()
      if (this.source[this.index] === "}") { this.index += 1; return output }
      if (this.source[this.index] !== ",") throw new StrictJsonError(`comma expected at ${this.index}`)
      this.index += 1
      this.skipWhitespace()
    }
  }

  private parseArray(): Json[] {
    this.index += 1
    this.skipWhitespace()
    const output: Json[] = []
    if (this.source[this.index] === "]") { this.index += 1; return output }
    while (true) {
      output.push(this.parseValue())
      this.skipWhitespace()
      if (this.source[this.index] === "]") { this.index += 1; return output }
      if (this.source[this.index] !== ",") throw new StrictJsonError(`comma expected at ${this.index}`)
      this.index += 1
      this.skipWhitespace()
    }
  }

  private parseString(): string {
    this.index += 1
    let output = ""
    while (this.index < this.source.length) {
      const current = this.source[this.index]!
      if (current === '"') { this.index += 1; return output }
      if (current === "\\") {
        this.index += 1
        output += this.parseEscape()
        continue
      }
      const unit = current.charCodeAt(0)
      if (unit < 0x20) throw new StrictJsonError(`unescaped control character at ${this.index}`)
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = this.source[this.index + 1]
        if (next === undefined || !(next.charCodeAt(0) >= 0xdc00 && next.charCodeAt(0) <= 0xdfff)) {
          throw new StrictJsonError("lone high surrogate")
        }
        output += current + next
        this.index += 2
        continue
      }
      if (unit >= 0xdc00 && unit <= 0xdfff) throw new StrictJsonError("lone low surrogate")
      output += current
      this.index += 1
    }
    throw new StrictJsonError("unterminated string")
  }

  private parseEscape(): string {
    const escape = this.source[this.index]
    if (escape === undefined) throw new StrictJsonError("unterminated escape")
    this.index += 1
    const simple: Record<string, string> = {
      '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t",
    }
    if (escape in simple) return simple[escape]!
    if (escape !== "u") throw new StrictJsonError(`invalid escape: \\${escape}`)
    const high = this.parseHexUnit()
    if (high >= 0xd800 && high <= 0xdbff) {
      if (this.source.slice(this.index, this.index + 2) !== "\\u") throw new StrictJsonError("lone high surrogate")
      this.index += 2
      const low = this.parseHexUnit()
      if (!(low >= 0xdc00 && low <= 0xdfff)) throw new StrictJsonError("lone high surrogate")
      const scalar = 0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
      return String.fromCodePoint(scalar)
    }
    if (high >= 0xdc00 && high <= 0xdfff) throw new StrictJsonError("lone low surrogate")
    return String.fromCharCode(high)
  }

  private parseHexUnit(): number {
    const encoded = this.source.slice(this.index, this.index + 4)
    if (!/^[0-9a-fA-F]{4}$/.test(encoded)) throw new StrictJsonError(`invalid Unicode escape at ${this.index}`)
    this.index += 4
    return Number.parseInt(encoded, 16)
  }

  private parseNumber(): number {
    const matched = this.source.slice(this.index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/)
    if (!matched) throw new StrictJsonError(`invalid number at ${this.index}`)
    const value = Number(matched[0])
    if (!Number.isFinite(value)) throw new StrictJsonError("non-finite JSON number")
    this.index += matched[0].length
    return value
  }
}

const strictJsonParse = (text: string): Json => new StrictJsonParser(text).parse()
const loadJson = (path: string): RecordJson => strictJsonParse(readBytes(path).toString("utf8")) as RecordJson

function compareScalarStrings(left: string, right: string): number {
  assertScalarString(left)
  assertScalarString(right)
  const a = [...left]
  const b = [...right]
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const leftPoint = a[index]!.codePointAt(0)!
    const rightPoint = b[index]!.codePointAt(0)!
    if (leftPoint !== rightPoint) return leftPoint < rightPoint ? -1 : 1
  }
  return a.length - b.length
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null"
  if (value === true) return "true"
  if (value === false) return "false"
  if (typeof value === "string") { assertScalarString(value); return JSON.stringify(value) }
  if (typeof value === "number") throw new CanonicalizationError("rvr-canonical-json-v0 forbids numbers")
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`
  if (typeof value === "object") {
    const record = value as Record<string, unknown>
    const keys = Object.keys(record)
    for (const key of keys) assertScalarString(key)
    keys.sort(compareScalarStrings)
    return `{${keys.map((key) => `${canonicalJson(key)}:${canonicalJson(record[key])}`).join(",")}}`
  }
  throw new CanonicalizationError(`unsupported canonical value: ${typeof value}`)
}

const canonicalBytes = (value: unknown): Buffer => Buffer.from(canonicalJson(value), "utf8")
const canonicalDigest = (value: unknown): string => sha256Hex(canonicalBytes(value))

function jsonSame(left: unknown, right: unknown): boolean {
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
    return typeof left === typeof right && Object.is(left, right)
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length
      && left.every((item, index) => jsonSame(item, right[index]))
  }
  const a = left as Record<string, unknown>
  const b = right as Record<string, unknown>
  const aKeys = Object.keys(a).sort(compareScalarStrings)
  const bKeys = Object.keys(b).sort(compareScalarStrings)
  return aKeys.length === bKeys.length
    && aKeys.every((key, index) => key === bKeys[index] && jsonSame(a[key], b[key]))
}

function schemaPointer(root: RecordJson, pointer: string): RecordJson {
  if (pointer === "" || pointer === "#") return root
  if (!pointer.startsWith("#/")) throw new SchemaValidationError(`unsupported schema pointer: ${pointer}`)
  let current: unknown = root
  for (const raw of pointer.slice(2).split("/")) {
    const token = raw.replace(/~1/g, "/").replace(/~0/g, "~")
    if (typeof current !== "object" || current === null || Array.isArray(current) || !(token in current)) {
      throw new SchemaValidationError(`unresolved schema pointer: ${pointer}`)
    }
    current = (current as Record<string, unknown>)[token]
  }
  if (typeof current !== "object" || current === null || Array.isArray(current)) {
    throw new SchemaValidationError(`schema pointer is not an object: ${pointer}`)
  }
  return current as RecordJson
}

function schemaTypeMatches(value: unknown, expected: string): boolean {
  if (expected === "null") return value === null
  if (expected === "boolean") return typeof value === "boolean"
  if (expected === "string") return typeof value === "string"
  if (expected === "array") return Array.isArray(value)
  if (expected === "object") return typeof value === "object" && value !== null && !Array.isArray(value)
  if (expected === "integer") return typeof value === "number" && Number.isInteger(value)
  if (expected === "number") return typeof value === "number"
  throw new SchemaValidationError(`unsupported schema type: ${expected}`)
}

function validateSchema(value: unknown, schema: RecordJson, root = schema, path = "$", errors: string[] = []): string[] {
  if (schema.$ref) return validateSchema(value, schemaPointer(root, schema.$ref), root, path, errors)
  if (schema.const !== undefined && !jsonSame(value, schema.const)) errors.push(`${path}: const`)
  if (schema.enum && !schema.enum.some((item: unknown) => jsonSame(value, item))) errors.push(`${path}: enum`)
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type]
    if (!types.some((item: string) => schemaTypeMatches(value, item))) { errors.push(`${path}: type`); return errors }
  }
  if (typeof value === "string" && schema.pattern && !new RegExp(schema.pattern).test(value)) errors.push(`${path}: pattern`)
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errors.push(`${path}: minItems`)
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${path}: maxItems`)
    if (schema.items) value.forEach((item, index) => validateSchema(item, schema.items, root, `${path}[${index}]`, errors))
  }
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const record = value as Record<string, unknown>
    const properties = schema.properties ?? {}
    for (const required of schema.required ?? []) if (!(required in record)) errors.push(`${path}.${required}: required`)
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(record)) if (!(key in properties)) errors.push(`${path}.${key}: additionalProperties`)
    }
    for (const [key, child] of Object.entries(properties)) {
      if (key in record) validateSchema(record[key], child as RecordJson, root, `${path}.${key}`, errors)
    }
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((child: RecordJson) => validateSchema(value, child, root, path, []).length === 0).length
    if (matches !== 1) errors.push(`${path}: oneOf(${matches})`)
  }
  return errors
}

function requireSchema(value: unknown, schema: RecordJson, pointer = "#", label = "value"): void {
  const errors = validateSchema(value, schemaPointer(schema, pointer), schema)
  if (errors.length) throw new GateRejection("rvr.gate.schema_invalid", `${label}: ${errors.join("; ")}`)
}

function dependencyEntries(profile: RecordJson): RecordJson[] {
  return [profile.verificationSpecification, ...profile.conformanceVectorSet.members, ...profile.schemaContracts]
}

function auditProfile(profile: RecordJson, profileSchema: RecordJson): string {
  requireSchema(profile, profileSchema, "#", "verification profile")
  const entries = dependencyEntries(profile)
  const ids = entries.map((item) => item.id)
  if (new Set(ids).size !== ids.length) throw new GateRejection("rvr.gate.identity_mismatch", "duplicate profile dependency id")
  for (const dependency of entries) {
    if (exactFileDigest(dependency.path) !== dependency.sha256) {
      throw new GateRejection("rvr.gate.identity_mismatch", `dependency digest mismatch: ${dependency.id}`)
    }
  }
  const vectorMembers = [...profile.conformanceVectorSet.members].sort((a, b) => compareScalarStrings(a.path, b.path))
  const rows = vectorMembers.map((item) => `${item.path}\t${item.sha256}\n`).join("")
  if (sha256Hex(rows) !== profile.conformanceVectorSet.digest) {
    throw new GateRejection("rvr.gate.identity_mismatch", "conformance vector-set digest mismatch")
  }
  const rvrSchemaPin = profile.schemaContracts.find((item: RecordJson) => item.id === "rvr-schema")
  if (profile.evidenceSetContract.schemaSha256 !== rvrSchemaPin.sha256
    || profile.canonicalResultContract.schemaSha256 !== rvrSchemaPin.sha256) {
    throw new GateRejection("rvr.gate.identity_mismatch", "profile schema pin mismatch")
  }
  return canonicalDigest(profile)
}

function normalizeEvidenceSet(evidenceSet: RecordJson): RecordJson {
  const normalized = structuredClone(evidenceSet)
  const ids = normalized.members.map((item: RecordJson) => item.id)
  if (new Set(ids).size !== ids.length) {
    throw new GateRejection("rvr.gate.evidence_closure_incomplete", "duplicate evidence member id")
  }
  normalized.members.sort((a: RecordJson, b: RecordJson) => compareScalarStrings(a.id, b.id))
  return normalized
}

function decodeBase64Exact(encoded: string, memberId: string): Buffer {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new GateRejection("rvr.gate.schema_invalid", `invalid base64 payload: ${memberId}`)
  }
  const bytes = Buffer.from(encoded, "base64")
  if (bytes.toString("base64") !== encoded) {
    throw new GateRejection("rvr.gate.schema_invalid", `non-canonical base64 payload: ${memberId}`)
  }
  return bytes
}

function validateEvidenceClosure(
  evidenceSet: RecordJson,
  payloadsBase64: RecordJson,
  outcomeRelevantInputs: RecordJson[] = [],
): Map<string, Buffer> {
  for (const input of outcomeRelevantInputs) {
    if (input.commitment === null || input.commitment === undefined) {
      throw new GateRejection("rvr.gate.evidence_closure_incomplete", `uncommitted outcome-relevant input: ${input.name}`)
    }
  }
  const payloads = new Map<string, Buffer>()
  for (const [memberId, encoded] of Object.entries(payloadsBase64)) {
    if (typeof encoded !== "string") throw new GateRejection("rvr.gate.schema_invalid", "payload values must be strings")
    payloads.set(memberId, decodeBase64Exact(encoded, memberId))
  }
  const present = new Set<string>()
  for (const member of evidenceSet.members) {
    if (member.status === "PRESENT") {
      present.add(member.id)
      const payload = payloads.get(member.id)
      if (!payload) throw new GateRejection("rvr.gate.evidence_closure_incomplete", `missing payload: ${member.id}`)
      if (String(payload.length) !== member.byteLength) {
        throw new GateRejection("rvr.gate.identity_mismatch", `payload length mismatch: ${member.id}`)
      }
      if (sha256Hex(payload) !== member.digest) {
        throw new GateRejection("rvr.gate.identity_mismatch", `payload digest mismatch: ${member.id}`)
      }
    } else if (payloads.has(member.id)) {
      throw new GateRejection("rvr.gate.evidence_closure_incomplete", `unavailable member has payload: ${member.id}`)
    }
  }
  const extra = [...payloads.keys()].filter((item) => !present.has(item))
  if (extra.length) throw new GateRejection("rvr.gate.evidence_closure_incomplete", `uncommitted payloads: ${extra.join(",")}`)
  return payloads
}

const evidenceSetDigest = (evidenceSet: RecordJson): string => canonicalDigest(normalizeEvidenceSet(evidenceSet))

function evaluate(claim: RecordJson, evidenceSet: RecordJson, payloads: Map<string, Buffer>, rvrSchema: RecordJson): RecordJson {
  const member = evidenceSet.members.find((item: RecordJson) => item.id === claim.evidenceMember)
  if (!member) throw new GateRejection("rvr.gate.evidence_closure_incomplete", "claim member absent from evidence closure")
  let observedDigest: string | null
  let outcome: string
  let reasonCode: string
  if (member.status === "UNAVAILABLE") {
    observedDigest = null
    outcome = "UNVERIFIABLE"
    reasonCode = "rvr.v0.required_evidence_unavailable"
  } else {
    observedDigest = sha256Hex(payloads.get(member.id)!)
    outcome = observedDigest === claim.expectedDigest ? "VERIFIED" : "REFUTED"
    reasonCode = outcome === "VERIFIED" ? "rvr.v0.digest_match" : "rvr.v0.digest_mismatch"
  }
  const result = {
    schema: "rvr.canonical-result.v0",
    outcome,
    reasonCode,
    evaluation: {
      operation: "SHA256_EQUALS",
      evidenceMember: claim.evidenceMember,
      expectedDigest: claim.expectedDigest,
      observedDigest,
    },
  }
  requireSchema(result, rvrSchema, "#/$defs/canonicalResult", "canonical result")
  return result
}

function project(document: RecordJson, pointer: string): unknown {
  if (!pointer.startsWith("/")) throw new GateRejection("rvr.gate.identity_mismatch", `unsupported projection: ${pointer}`)
  let current: unknown = document
  for (const raw of pointer.slice(1).split("/")) {
    const token = raw.replace(/~1/g, "/").replace(/~0/g, "~")
    if (typeof current !== "object" || current === null || Array.isArray(current) || !(token in current)) {
      throw new GateRejection("rvr.gate.result_projection_mismatch", `missing projection: ${pointer}`)
    }
    current = (current as Record<string, unknown>)[token]
  }
  return current
}

function validateReceiptEnvelope(bundle: RecordJson, profileDigest: string, rvrSchema: RecordJson): void {
  const { receipt, claim, evidenceSet, canonicalResult: result, verificationProfile: profile } = bundle
  requireSchema(receipt, rvrSchema, "#", "receipt")
  requireSchema(claim, rvrSchema, "#/$defs/claim", "claim")
  requireSchema(evidenceSet, rvrSchema, "#/$defs/evidenceSet", "evidence set")
  requireSchema(result, rvrSchema, "#/$defs/canonicalResult", "canonical result")
  const identities: Record<string, string> = {
    claimDigest: canonicalDigest(claim),
    evidenceSetDigest: evidenceSetDigest(evidenceSet),
    verificationProfileDigest: profileDigest,
    resultDigest: canonicalDigest(result),
  }
  for (const [field, actual] of Object.entries(identities)) {
    if (receipt[field] !== actual) throw new GateRejection("rvr.gate.identity_mismatch", `receipt identity mismatch: ${field}`)
  }
  const contract = profile.canonicalResultContract
  if (receipt.outcome !== project(result, contract.outcomeProjection)
    || receipt.reasonCode !== project(result, contract.reasonCodeProjection)) {
    throw new GateRejection("rvr.gate.result_projection_mismatch", "receipt contradicts canonical result projection")
  }
}

function makeBundle(caseValue: RecordJson, profile: RecordJson, profileDigest: string, rvrSchema: RecordJson): RecordJson {
  const claim = structuredClone(caseValue.claim)
  const evidenceSet = structuredClone(caseValue.evidenceSet)
  const payloadsBase64 = structuredClone(caseValue.payloadsBase64)
  requireSchema(claim, rvrSchema, "#/$defs/claim", "claim")
  requireSchema(evidenceSet, rvrSchema, "#/$defs/evidenceSet", "evidence set")
  const payloads = validateEvidenceClosure(evidenceSet, payloadsBase64)
  const result = evaluate(claim, evidenceSet, payloads, rvrSchema)
  const receipt = {
    claimDigest: canonicalDigest(claim),
    evidenceSetDigest: evidenceSetDigest(evidenceSet),
    verificationProfileDigest: profileDigest,
    outcome: result.outcome,
    reasonCode: result.reasonCode,
    resultDigest: canonicalDigest(result),
  }
  const bundle = { receipt, claim, evidenceSet, payloadsBase64, verificationProfile: profile, canonicalResult: result }
  validateReceiptEnvelope(bundle, profileDigest, rvrSchema)
  return bundle
}

function requiredDependencyFailure(profile: RecordJson, unavailable: Set<string>): string | null {
  for (const dependency of dependencyEntries(profile)) {
    if (!dependency.requiredForRecomputation) continue
    if (unavailable.has(dependency.id)) return dependency.id
    try {
      if (exactFileDigest(dependency.path) !== dependency.sha256) return dependency.id
    } catch {
      return dependency.id
    }
  }
  return null
}

function recompute(
  originalBundle: RecordJson,
  candidateCase: RecordJson,
  profileDigest: string,
  rvrSchema: RecordJson,
  unavailable = new Set<string>(),
  outcomeRelevantInputs: RecordJson[] = [],
): RecordJson {
  validateReceiptEnvelope(originalBundle, profileDigest, rvrSchema)
  const dependencyFailure = requiredDependencyFailure(originalBundle.verificationProfile, unavailable)
  if (dependencyFailure) {
    return {
      recomputationStatus: "CANNOT_RECOMPUTE",
      reasonCode: "rvr.recompute.normative_dependency_unavailable",
      unavailableDependencyId: dependencyFailure,
      evaluationPerformed: false,
    }
  }
  const claim = structuredClone(candidateCase.claim)
  const evidenceSet = structuredClone(candidateCase.evidenceSet)
  const payloadsBase64 = structuredClone(candidateCase.payloadsBase64)
  requireSchema(claim, rvrSchema, "#/$defs/claim", "candidate claim")
  requireSchema(evidenceSet, rvrSchema, "#/$defs/evidenceSet", "candidate evidence set")
  const payloads = validateEvidenceClosure(evidenceSet, payloadsBase64, outcomeRelevantInputs)
  const result = evaluate(claim, evidenceSet, payloads, rvrSchema)
  const identities: Record<string, string> = {
    claimDigest: canonicalDigest(claim),
    evidenceSetDigest: evidenceSetDigest(evidenceSet),
    verificationProfileDigest: profileDigest,
    resultDigest: canonicalDigest(result),
  }
  const reproduced = Object.entries(identities).every(([field, digest]) => originalBundle.receipt[field] === digest)
  return {
    verificationOutcome: result.outcome,
    verificationReasonCode: result.reasonCode,
    recomputationStatus: reproduced ? "REPRODUCED" : "DIVERGED",
    reasonCode: reproduced ? "rvr.recompute.identical" : "rvr.recompute.canonical_result_diverged",
    evaluationPerformed: true,
    canonicalResultDigest: identities.resultDigest,
  }
}

function mutateEvidenceCase(caseValue: RecordJson, memberId: string, replacementBase64: string): RecordJson {
  const candidate = structuredClone(caseValue)
  const payload = decodeBase64Exact(replacementBase64, memberId)
  candidate.payloadsBase64[memberId] = replacementBase64
  const member = candidate.evidenceSet.members.find((item: RecordJson) => item.id === memberId)
  member.byteLength = String(payload.length)
  member.digest = sha256Hex(payload)
  return candidate
}

function runCanonicalVectors(vectors: RecordJson): RecordJson {
  const passed: string[] = []
  for (const vector of vectors.canonicalByteVectors) {
    if (vector.kind === "canonical") {
      if (canonicalJson(vector.value) !== vector.expected) throw new Error(vector.id)
    } else if (vector.kind === "canonical-json") {
      if (canonicalJson(strictJsonParse(vector.rawJson)) !== vector.expected) throw new Error(vector.id)
    } else if (vector.kind === "different") {
      if (canonicalJson(vector.left) === canonicalJson(vector.right)) throw new Error(vector.id)
    } else if (vector.kind === "reject-value") {
      let rejected = false
      try { canonicalJson(vector.value) } catch (error) { if (error instanceof CanonicalizationError) rejected = true }
      if (!rejected) throw new Error(vector.id)
    } else if (vector.kind === "reject-json") {
      let rejected = false
      try { strictJsonParse(vector.rawJson) } catch (error) { if (error instanceof StrictJsonError) rejected = true }
      if (!rejected) throw new Error(vector.id)
    } else throw new Error(`unsupported canonical vector: ${vector.kind}`)
    passed.push(vector.id)
  }
  return { passed: passed.length, vectorIds: passed }
}

function mutantSortArraysAsSets(value: unknown): string {
  if (value === null) return "null"
  if (value === true) return "true"
  if (value === false) return "false"
  if (typeof value === "string") return canonicalJson(value)
  if (typeof value === "number") throw new CanonicalizationError("mutant rejects numbers")
  if (Array.isArray(value)) {
    const entries = [...new Set(value.map(mutantSortArraysAsSets))].sort()
    return `[${entries.join(",")}]`
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>
    const keys = Object.keys(record).sort(compareScalarStrings)
    return `{${keys.map((key) => `${canonicalJson(key)}:${mutantSortArraysAsSets(record[key])}`).join(",")}}`
  }
  throw new CanonicalizationError("mutant unsupported value")
}

function mutantNormalizeUnicodeNfc(value: unknown): string {
  if (value === null) return "null"
  if (value === true) return "true"
  if (value === false) return "false"
  if (typeof value === "string") return canonicalJson(value.normalize("NFC"))
  if (typeof value === "number") throw new CanonicalizationError("mutant rejects numbers")
  if (Array.isArray(value)) return `[${value.map(mutantNormalizeUnicodeNfc).join(",")}]`
  if (typeof value === "object") {
    const record = value as Record<string, unknown>
    const normalized: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(record)) normalized[key.normalize("NFC")] = item
    const keys = Object.keys(normalized).sort(compareScalarStrings)
    return `{${keys.map((key) => `${canonicalJson(key)}:${mutantNormalizeUnicodeNfc(normalized[key])}`).join(",")}}`
  }
  throw new CanonicalizationError("mutant unsupported value")
}

function mutantAcceptsWithoutProjection(bundle: RecordJson, profileDigest: string, rvrSchema: RecordJson): boolean {
  requireSchema(bundle.receipt, rvrSchema, "#", "mutant receipt")
  const identities: Record<string, string> = {
    claimDigest: canonicalDigest(bundle.claim),
    evidenceSetDigest: evidenceSetDigest(bundle.evidenceSet),
    verificationProfileDigest: profileDigest,
    resultDigest: canonicalDigest(bundle.canonicalResult),
  }
  return Object.entries(identities).every(([field, actual]) => bundle.receipt[field] === actual)
}

function runMutantAudit(
  mutants: RecordJson,
  expected: RecordJson,
  vectors: RecordJson,
  reproducedBundle: RecordJson,
  diverged: RecordJson,
  cannot: RecordJson,
  contradictoryBundle: RecordJson,
  projection: RecordJson,
  unsafeResult: RecordJson,
  hidden: RecordJson,
  profileDigest: string,
  rvrSchema: RecordJson,
): RecordJson {
  const definitions = mutants.mutants as RecordJson[]
  const required = expected.mutantAudit.requiredKilled as RecordJson[]
  if (!jsonSame(definitions.map((item) => item.id), required.map((item) => item.id))) {
    throw new Error("mutant inventory differs from expected kill matrix")
  }
  const canonicalById = new Map<string, RecordJson>(
    vectors.canonicalByteVectors.map((item: RecordJson) => [item.id, item]),
  )
  const results: RecordJson[] = []

  definitions.forEach((definition, index) => {
    const expectedKill = required[index]!
    const mutantId = definition.id
    if (definition.requiredWitness !== expectedKill.killedBy) throw new Error(`${mutantId}: witness mismatch`)
    if (definition.expectedFaultObservation !== expectedKill.faultObservation) {
      throw new Error(`${mutantId}: fault observation mismatch`)
    }
    let faultObserved = false
    if (mutantId === "sort_arrays_as_sets") {
      const witness = canonicalById.get(definition.requiredWitness)!
      faultObserved = canonicalJson(witness.left) !== canonicalJson(witness.right)
        && mutantSortArraysAsSets(witness.left) === mutantSortArraysAsSets(witness.right)
    } else if (mutantId === "normalize_unicode_nfc") {
      const witness = canonicalById.get(definition.requiredWitness)!
      faultObserved = canonicalJson(witness.left) !== canonicalJson(witness.right)
        && mutantNormalizeUnicodeNfc(witness.left) === mutantNormalizeUnicodeNfc(witness.right)
    } else if (mutantId === "ignore_result_projection") {
      faultObserved = projection.gateStatus === "REJECTED"
        && mutantAcceptsWithoutProjection(contradictoryBundle, profileDigest, rvrSchema)
    } else if (mutantId === "missing_dependency_as_refuted") {
      const mutantOutput = {
        verificationOutcome: "REFUTED",
        recomputationStatus: "REPRODUCED",
        evaluationPerformed: false,
      }
      faultObserved = cannot.recomputationStatus === "CANNOT_RECOMPUTE"
        && mutantOutput.verificationOutcome === "REFUTED"
    } else if (mutantId === "allow_uncommitted_ambient_override") {
      faultObserved = hidden.gateStatus === "REJECTED" && unsafeResult.outcome === "REFUTED"
    } else if (mutantId === "trust_stored_result_without_evaluation") {
      const mutantOutput = {
        verificationOutcome: reproducedBundle.receipt.outcome,
        recomputationStatus: "REPRODUCED",
        evaluationPerformed: false,
      }
      faultObserved = diverged.recomputationStatus === "DIVERGED"
        && diverged.evaluationPerformed === true
        && mutantOutput.recomputationStatus === "REPRODUCED"
        && mutantOutput.evaluationPerformed === false
    } else throw new Error(`unimplemented mutant: ${mutantId}`)

    if (!faultObserved) throw new Error(`mutant survived: ${mutantId}`)
    results.push({ ...expectedKill, killed: true })
  })

  return { killed: results.length, total: definitions.length, results }
}

function buildManifest(): RecordJson {
  const members = [...MANIFEST_MEMBERS].sort(compareScalarStrings).map((path) => ({ path, sha256: exactFileDigest(path) }))
  const rows = members.map((item) => `${item.path}\t${item.sha256}\n`).join("")
  return {
    schema: "rvr.conformance-manifest.v0",
    hashAlgorithm: "sha256-lowercase-hex",
    memberCount: members.length,
    members,
    packageDigestRule: "sha256-utf8-sorted-path-tab-file-sha256-lf-rows-manifest-excluded",
    packageDigest: sha256Hex(rows),
  }
}

function auditManifest(): RecordJson {
  const manifest = loadJson(MANIFEST_PATH)
  const actual = buildManifest()
  if (!jsonSame(manifest, actual)) throw new GateRejection("rvr.gate.identity_mismatch", "manifest digest drift")
  return { memberCount: manifest.memberCount, packageDigest: manifest.packageDigest }
}

function assertExpected(actual: RecordJson, expected: RecordJson, caseName: string): void {
  for (const [key, value] of Object.entries(expected)) {
    if (!jsonSame(actual[key], value)) throw new Error(`${caseName}.${key}: expected ${String(value)}, got ${String(actual[key])}`)
  }
}

export function runGate(): RecordJson {
  const profileSchema = loadJson(PROFILE_SCHEMA_PATH)
  const rvrSchema = loadJson(RVR_SCHEMA_PATH)
  const profile = loadJson(PROFILE_PATH)
  const vectors = loadJson(VECTORS_PATH)
  const expected = loadJson(EXPECTED_PATH)
  const mutants = loadJson(MUTANTS_PATH)
  const profileDigest = auditProfile(profile, profileSchema)
  const manifest = auditManifest()
  const canonicalByteVectors = runCanonicalVectors(vectors)

  const reproducedCase = vectors.verificationCases.reproduced
  const reproducedBundle = makeBundle(reproducedCase, profile, profileDigest, rvrSchema)
  const reproduced = recompute(reproducedBundle, reproducedCase, profileDigest, rvrSchema)
  assertExpected(reproduced, expected.cases.REPRODUCED, "REPRODUCED")

  const divergedControl = vectors.negativeControls.diverged
  const divergedCase = mutateEvidenceCase(
    reproducedCase,
    divergedControl.mutation.memberId,
    divergedControl.mutation.replacementBase64,
  )
  if (canonicalDigest(divergedCase.claim) !== reproducedBundle.receipt.claimDigest) throw new Error("fixed claim changed")
  const diverged = recompute(reproducedBundle, divergedCase, profileDigest, rvrSchema)
  assertExpected(diverged, expected.cases.DIVERGED, "DIVERGED")

  const unverifiableCase = vectors.verificationCases.unverifiableReproduced
  const unverifiableBundle = makeBundle(unverifiableCase, profile, profileDigest, rvrSchema)
  const unverifiable = recompute(unverifiableBundle, unverifiableCase, profileDigest, rvrSchema)
  assertExpected(unverifiable, expected.cases.UNVERIFIABLE_REPRODUCED, "UNVERIFIABLE_REPRODUCED")

  const cannotControl = vectors.negativeControls.cannotRecompute
  const cannot = recompute(
    reproducedBundle,
    reproducedCase,
    profileDigest,
    rvrSchema,
    new Set([cannotControl.unavailableDependencyId]),
  )
  assertExpected(cannot, expected.cases.CANNOT_RECOMPUTE, "CANNOT_RECOMPUTE")

  const projectionControl = vectors.negativeControls.projectionContradiction
  const contradictoryBundle = structuredClone(reproducedBundle)
  contradictoryBundle.receipt[projectionControl.mutateReceiptField] = projectionControl.replacement
  let projection: RecordJson
  try {
    validateReceiptEnvelope(contradictoryBundle, profileDigest, rvrSchema)
    throw new Error("contradictory projection accepted")
  } catch (error) {
    if (!(error instanceof GateRejection)) throw error
    projection = { gateStatus: "REJECTED", reasonCode: error.reasonCode }
  }
  assertExpected(projection, expected.cases.PROJECTION_NEGATIVE_CONTROL, "PROJECTION_NEGATIVE_CONTROL")

  const hiddenControl = vectors.negativeControls.hiddenState
  const unsafeCase = structuredClone(reproducedCase)
  unsafeCase.claim.expectedDigest = hiddenControl.outcomeRelevantInput.value
  const unsafePayloads = validateEvidenceClosure(unsafeCase.evidenceSet, unsafeCase.payloadsBase64)
  const unsafeResult = evaluate(unsafeCase.claim, unsafeCase.evidenceSet, unsafePayloads, rvrSchema)
  if (unsafeResult.outcome === reproducedBundle.canonicalResult.outcome) throw new Error("hidden-state control did not change outcome")
  let hidden: RecordJson
  try {
    recompute(
      reproducedBundle,
      reproducedCase,
      profileDigest,
      rvrSchema,
      new Set(),
      [hiddenControl.outcomeRelevantInput],
    )
    throw new Error("hidden-state attempt accepted")
  } catch (error) {
    if (!(error instanceof GateRejection)) throw error
    hidden = { gateStatus: "REJECTED", reasonCode: error.reasonCode, evaluationPerformed: false }
  }
  assertExpected(hidden, expected.cases.HIDDEN_STATE_NEGATIVE_CONTROL, "HIDDEN_STATE_NEGATIVE_CONTROL")

  const mutantAudit = runMutantAudit(
    mutants,
    expected,
    vectors,
    reproducedBundle,
    diverged,
    cannot,
    contradictoryBundle,
    projection,
    unsafeResult,
    hidden,
    profileDigest,
    rvrSchema,
  )

  return {
    gate: "RVR_V0_CONFORMANCE_PASS",
    implementation: "typescript-independent-rvr-v0",
    profileId: profile.profileId,
    verificationProfileDigest: profileDigest,
    canonicalByteContract: profile.canonicalByteContract.id,
    canonicalByteVectors,
    manifest,
    cases: {
      REPRODUCED: reproduced,
      DIVERGED: diverged,
      UNVERIFIABLE_REPRODUCED: unverifiable,
      CANNOT_RECOMPUTE: cannot,
      PROJECTION_NEGATIVE_CONTROL: projection,
      HIDDEN_STATE_NEGATIVE_CONTROL: hidden,
    },
    adversarialMutants: mutantAudit,
    producerImports: 0,
  }
}

if (import.meta.main) {
  if (!process.argv.includes("--check")) {
    console.error("usage: bun conformance/rvr-v0/adapter.ts --check")
    process.exit(2)
  }
  try {
    console.log(JSON.stringify(runGate(), null, 2))
  } catch (error) {
    console.error(`RVR v0 TypeScript gate failed: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }
}
