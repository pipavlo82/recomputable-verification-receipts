"""EXPERIMENTAL settlement profile outside unchanged VECA/RVR Core.
No network or payment side effects. Native VECA conjunction is reused only as
a reducer, NOT represented as an upstream-supported settlement profile.
"""
from pathlib import Path
import sys,json,hashlib,base64,importlib.util
from nacl.signing import VerifyKey
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'sources/veca'))
from src.integration.engine import combined
spec=importlib.util.spec_from_file_location('native_generic_rvr',ROOT/'sources/rvr/conformance/rvr-v0/adapter.py')
rvr=importlib.util.module_from_spec(spec);sys.modules[spec.name]=rvr;spec.loader.exec_module(rvr)
PROFILE=rvr.load_json(rvr.PROFILE_PATH)
MSRAW=rvr.PROFILE_MANIFEST_SCHEMA_PATH.read_bytes()
PD,_,DEPS=rvr.audit_profile(PROFILE,rvr.parse_json_bytes(MSRAW,'manifest'),MSRAW)
RS=rvr.parse_json_bytes(DEPS['rvr-schema'],'schema')
FIELDS=set('chain_id escrow_contract job_id client provider evaluator token_contract token_parameters amount deliverable_sha256 rubric_digest assessment_id assessment_digest assessment_issuer rvr_profile_digest rvr_receipt_digest veca_claim_digest nonce expiry revocation_epoch settlement_conditions_digest'.split())
TYPE='ERC8378_ESCROW_SETTLEMENT_V1'
def canon(x):return rvr.canonical_bytes(x)
def sha(x):return hashlib.sha256(x).hexdigest()
def dig(x):return sha(canon(x))
def domain(x):return b'AI_WORK_ESCROW_ASSESSMENT_V1\x00'+canon(x)
def receipt(raw):
    case={'claim':{'schema':'rvr.claim.sha256-equals.v0','operation':'SHA256_EQUALS','evidenceMember':'assessment','expectedDigest':sha(raw)},'evidenceSet':{'schema':'rvr.evidence-set.v0','members':[{'id':'assessment','status':'PRESENT','mediaType':'application/json','byteLength':str(len(raw)),'digest':sha(raw)}]},'payloadsBase64':{'assessment':base64.b64encode(raw).decode()}}
    return rvr.make_bundle(case,PROFILE,PD,RS),case
def assess(e,policy,state):
    checks={};native=None
    def ck(k,b):checks[k]='VERIFIED' if b else 'REFUTED'
    def out():
        s=combined(checks.values())
        return {'status':s,'admitted':s=='VERIFIED','checks':checks,'native_rvr':native,'profile':TYPE,'native_veca_scope':'conjunction reducer only; settlement extension NOT upstream-approved','payment_authorized':False}
    if policy is None:checks['policy']='UNVERIFIABLE';return out()
    required={'binding','assessment','signature','deliverable','rubric','conditions','rvr','rvr_case','claim','obligations'}
    if not isinstance(e,dict) or not required.issubset(e):
        checks['missing_evidence']='UNVERIFIABLE';return out()
    try:
        b=e['binding'];a=e['assessment'];claim=e['claim']
        ck('shape',set(b)==FIELDS and set(e)=={'binding','assessment','signature','deliverable','rubric','conditions','rvr','rvr_case','claim','obligations'})
        ck('binding',b==policy['binding']) # GUARD binding
        ck('scope',claim['type']==TYPE and claim['consumer']==policy['consumer'] and claim['action']=='request-evaluator-settlement')
        ck('obligations',e['obligations']==policy['required_obligations']) # GUARD obligations
        ck('claim',dig(claim)==b['veca_claim_digest'] and claim['assessment_digest']==b['assessment_digest'] and claim['rvr_receipt_digest']==b['rvr_receipt_digest'])
        ck('source',sha(bytes.fromhex(e['deliverable']))==b['deliverable_sha256'] and dig(e['rubric'])==b['rubric_digest'] and dig(e['conditions'])==b['settlement_conditions_digest']) # GUARD source
        ck('assessment',dig(a)==b['assessment_digest'] and a['id']==b['assessment_id'] and a['issuer']==b['assessment_issuer'] and a['job_id']==b['job_id'] and a['deliverable_sha256']==b['deliverable_sha256'] and a['rubric_digest']==b['rubric_digest'])
        sigok=False
        try:VerifyKey(bytes.fromhex(policy['assessor_key'])).verify(domain(a),bytes.fromhex(e['signature']));sigok=True
        except Exception:pass
        ck('signature',sigok) # GUARD signature
        ck('authority',a['issuer']==policy['assessor'] and a['issuer'] not in policy['revoked_assessors'] and a['id'] not in policy['revoked_assessments']) # GUARD authority
        ck('freshness',int(state['now'])<int(b['expiry']) and b['revocation_epoch']==policy['epoch'] and b['nonce']==state['next_nonce'] and b['nonce'] not in state['used_nonces']) # GUARD freshness
        ck('job',all(b[k]==state[k] for k in ('chain_id','escrow_contract','job_id','client','provider','evaluator','token_contract','token_parameters','amount')) and state['status']=='Submitted')
        raw=bytes.fromhex(e['deliverable']);rub=e['rubric']
        ck('rubric_result',rub==policy['rubric'] and a['accepted'] is True and len(raw)==int(rub['length']) and raw==bytes.fromhex(rub['exact_hex'])) # GUARD rubric
        native=rvr.recompute(e['rvr'],e['rvr_case'],PD,RS)
        if native['recomputationStatus']=='CANNOT_RECOMPUTE':
            checks['rvr']='UNVERIFIABLE';return out()
        ck('rvr',native['recomputationStatus']=='REPRODUCED' and native['verificationOutcome']=='VERIFIED' and b['rvr_profile_digest']==PD and dig(e['rvr']['receipt'])==b['rvr_receipt_digest'] and e['rvr_case']['claim']['expectedDigest']==b['assessment_digest'] and base64.b64decode(e['rvr_case']['payloadsBase64']['assessment'],validate=True)==canon(a)) # GUARD rvr
        return out()
    except rvr.GateRejection as ex:
        checks['rvr_gate']='REFUTED';return out()
    except (KeyError,TypeError,ValueError,OverflowError) as ex:
        checks['missing_or_malformed']='UNVERIFIABLE';return out()
