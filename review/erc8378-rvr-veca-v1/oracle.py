"""Separate offline specification checker. Does NOT import boundary/experiment.
Consumes evidence bytes, external policy, state snapshot; not producer verdicts.
Native RVR is an explicitly pinned dependency, not its saved result flags.
"""
import json,hashlib,base64,sys,importlib.util
from pathlib import Path
from nacl.signing import VerifyKey
ROOT=Path(__file__).resolve().parent
def canonical(v):
    def walk(x):
        if x is None or type(x) is bool:return
        if type(x) is str:
            if any(0xD800<=ord(c)<=0xDFFF for c in x):raise ValueError('surrogate')
            return
        if type(x) is list:
            for y in x:walk(y)
            return
        if type(x) is dict and all(type(k)is str for k in x):
            for k,y in x.items():walk(k);walk(y)
            return
        raise ValueError('non-canonical type')
    walk(v);return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf-8')
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()
spec=importlib.util.spec_from_file_location('oracle_native_rvr',ROOT/'sources/rvr/conformance/rvr-v0/adapter.py')
native=importlib.util.module_from_spec(spec);sys.modules[spec.name]=native;spec.loader.exec_module(native)
profile=native.load_json(native.PROFILE_PATH);ms=native.PROFILE_MANIFEST_SCHEMA_PATH.read_bytes()
pd,_,deps=native.audit_profile(profile,native.parse_json_bytes(ms,'manifest'),ms)
rs=native.parse_json_bytes(deps['rvr-schema'],'schema')
def evaluate(e,p,s):
    if p is None or not {'binding','assessment','signature','deliverable','rubric','conditions','rvr','rvr_case','claim','obligations'}<=set(e):return 'UNVERIFIABLE'
    errors=[]
    try:
        B=e['binding'];A=e['assessment'];C=e['claim'];raw=bytes.fromhex(e['deliverable'])
        errors.extend([B!=p['binding'],e['obligations']!=p['required_obligations'],C['type']!='ERC8378_ESCROW_SETTLEMENT_V1',C['consumer']!=p['consumer'],C['action']!='request-evaluator-settlement',digest(C)!=B['veca_claim_digest'],digest(A)!=B['assessment_digest'],hashlib.sha256(raw).hexdigest()!=B['deliverable_sha256'],digest(e['rubric'])!=B['rubric_digest'],digest(e['conditions'])!=B['settlement_conditions_digest']])
        errors.extend([A['id']!=B['assessment_id'],A['issuer']!=B['assessment_issuer'],A['issuer']!=p['assessor'],A['issuer'] in p['revoked_assessors'],A['id'] in p['revoked_assessments'],A['job_id']!=B['job_id'],A['deliverable_sha256']!=B['deliverable_sha256'],A['rubric_digest']!=B['rubric_digest']])
        try:VerifyKey(bytes.fromhex(p['assessor_key'])).verify(b'AI_WORK_ESCROW_ASSESSMENT_V1\0'+canonical(A),bytes.fromhex(e['signature']))
        except Exception:errors.append(True)
        errors.extend([int(s['now'])>=int(B['expiry']),B['nonce'] in s['used_nonces'],B['nonce']!=s['next_nonce'],B['revocation_epoch']!=p['epoch'],s['status']!='Submitted'])
        errors.extend(B[k]!=s[k] for k in ('chain_id','escrow_contract','job_id','client','provider','evaluator','token_contract','token_parameters','amount'))
        errors.extend([A['accepted'] is not True,e['rubric']!=p['rubric'],len(raw)!=int(p['rubric']['length']),raw!=bytes.fromhex(p['rubric']['exact_hex'])])
        result=native.recompute(e['rvr'],e['rvr_case'],pd,rs)
        if result['recomputationStatus']=='CANNOT_RECOMPUTE':return 'REFUTED' if any(errors) else 'UNVERIFIABLE'
        errors.extend([result['verificationOutcome']!='VERIFIED',result['recomputationStatus']!='REPRODUCED',B['rvr_profile_digest']!=pd,digest(e['rvr']['receipt'])!=B['rvr_receipt_digest'],e['rvr_case']['claim']['expectedDigest']!=digest(A),base64.b64decode(e['rvr_case']['payloadsBase64']['assessment'])!=canonical(A),C['assessment_digest']!=digest(A),C['rvr_receipt_digest']!=digest(e['rvr']['receipt'])])
        return 'REFUTED' if any(errors) else 'VERIFIED'
    except native.GateRejection:return 'REFUTED'
    except (ValueError,KeyError,TypeError):return 'UNVERIFIABLE'
def replay(folder):
    fixture=json.loads((folder/'fixture.json').read_bytes());rows=[]
    positive=evaluate(fixture['evidence'],fixture['policy'],fixture['state']);rows.append({'id':'positive','observed':positive,'expected':'VERIFIED','pass':positive=='VERIFIED'})
    from eth_utils import keccak
    positive_raw=json.loads((folder/'positive.json').read_bytes());B=fixture['evidence']['binding']
    transfer_topic='0x'+keccak(text='Transfer(address,address,uint256)').hex();moves=[]
    for tx in positive_raw['transactions']:
        for log in tx['logs']:
            if log['address'].lower()==B['token_contract'] and log['topics'][0]==transfer_topic:
                moves.append(('0x'+log['topics'][1][-40:],'0x'+log['topics'][2][-40:],int(log['data'],16)))
    expected_moves=[('0x'+'0'*40,B['client'],1000),(B['client'],B['escrow_contract'],100),(B['escrow_contract'],B['provider'],100)]
    rows.append({'id':'native_transfer_events','observed':moves,'expected':expected_moves,'pass':moves==expected_moves})
    completed_topic='0x'+keccak(text='JobCompleted(uint256,address,bytes32)').hex()
    completed=[log for tx in positive_raw['transactions'] for log in tx['logs'] if log['address'].lower()==B['escrow_contract'] and log['topics'][0]==completed_topic]
    ok=len(completed)==1 and int(completed[0]['topics'][1],16)==int(B['job_id']) and ('0x'+completed[0]['topics'][2][-40:])==B['evaluator'] and completed[0]['data']=='0x'+digest(B)
    rows.append({'id':'native_completion_event_binding','observed':completed,'pass':ok})
    for row in json.loads((folder/'matrix.json').read_bytes()):
        if 'input_evidence' in row:
            outcome=evaluate(row['input_evidence'],row['policy'],row['state']);rows.append({'id':row['id'],'observed':outcome,'expected':row['expected'],'pass':outcome==row['expected']==row['actual']})
        else:
            before=row['funds_before'];after=row['funds_after'];tx=row['transactions'];kind=row['expected']
            unchanged=after==before
            paid=after['provider']-before['provider']==100 and after['escrow']==0 and after['client']==before['client']
            refund=after['client']-before['client']==100 and after['escrow']==0 and after['provider']==before['provider']
            statuses=[r['status'] for r in tx];failed_tx=type(statuses[-1]) is int and statuses[-1]==0
            ok=failed_tx and (unchanged if kind=='ONCHAIN_REFUSED' else paid if kind=='ONE_PAYMENT_ONLY' else refund) and after['supply']==before['supply'] and sum(after[k] for k in ('client','provider','escrow','attacker'))==after['supply']
            rows.append({'id':row['id'],'expected':kind,'observed':'MATCH' if ok else 'FAIL','pass':ok})
    return {'checks':len(rows),'passed':sum(x['pass'] for x in rows),'rows':rows,'independence':'different implementation, same agent/host; not independent reviewer','onchain_scope':'saved RPC receipts/balances, not offline consensus verification'}
if __name__=='__main__':
    result=replay(Path(sys.argv[1]));print(json.dumps(result,indent=2,sort_keys=True));raise SystemExit(0 if result['checks']==result['passed'] else 1)
