"""Issuer boundary controls; authority configuration is not a bridge request."""
import sys,json,copy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from eth_account import Account
import verifier_service as vs
import test_credentials as credentials

def main(folder):
 selected=sys.argv[2] if len(sys.argv)>2 else None
 f=json.loads((folder/'ffi-issuance.json').read_bytes());key=Account.from_key(credentials.raw('verifier'))
 cfg={'policy':f['policy'],'pinned_binding':bytes.fromhex(f['pinned_binding']),'verifier':key.address};rows=[]
 def run(name,request=None,config=None,state=None,epoch=0,revoked=False,used=(),signer=key,want=False):
  if selected and name not in ['valid_evidence',selected]:return
  result=vs.issue_checked(request if request is not None else {'evidence':f['evidence']},config or cfg,state or f['state'],int(f['state']['now']),epoch,revoked,used,signer)
  rows.append({'id':name,'expected_issued':want,'observed_issued':result['issued'],'reason':result.get('reason'),'pass':result['issued']==want})
 run('valid_evidence',want=True)
 run('bridge_verified_true',{'verified':True})
 run('bridge_flag_added',{'evidence':f['evidence'],'verified':True})
 run('bridge_result_only',{'result':'VERIFIED'})
 run('missing_evidence',{})
 for name in ['missing_rvr','missing_payload','diverged','refuted','wrong_deliverable','unsupported_claim','missing_obligation','wrong_assessor_signature','unknown_evidence_flag']:
  e=copy.deepcopy(f['evidence'])
  if name=='missing_rvr':del e['rvr']
  if name=='missing_payload':e['rvr_case']['payloadsBase64']={}
  if name=='diverged':e['rvr']['receipt']['recomputationStatus']='DIVERGED'
  if name=='refuted':e['assessment']['accepted']=False
  if name=='wrong_deliverable':e['deliverable']='00'
  if name=='unsupported_claim':e['claim']['type']='OTHER'
  if name=='missing_obligation':e['obligations']=[]
  if name=='wrong_assessor_signature':e['signature']='00'*64
  if name=='unknown_evidence_flag':e['verified']=True
  run(name,{'evidence':e})
 for field,value in f['evidence']['binding'].items():
  e=copy.deepcopy(f['evidence']);e['binding'][field]=['2','3'] if isinstance(value,list) else 'other';run('binding_'+field,{'evidence':e})
 run('revoked_verifier',revoked=True);run('old_epoch',epoch=1);run('nonce_reused',used=[int(f['evidence']['binding']['nonce']).to_bytes(32,'big')])
 run('wrong_verifier_key',signer=Account.from_key(credentials.raw('wrong_verifier')))
 altered=copy.deepcopy(cfg);altered['pinned_binding']=b'X'*32;run('wrong_client_pin',config=altered)
 altered=copy.deepcopy(cfg);altered['policy']['revoked_assessors']=[altered['policy']['assessor']];run('revoked_assessor',config=altered)
 st=copy.deepcopy(f['state']);st['now']=f['evidence']['binding']['expiry'];run('expired_evidence',state=st)
 st=copy.deepcopy(f['state']);st['submitted_deliverable_sha256']='00'*32;run('different_actual_submission',state=st)
 result={'checks':len(rows),'passed':sum(x['pass'] for x in rows),'rows':rows};print(json.dumps(result,sort_keys=True,indent=2));return result
if __name__=='__main__':
 r=main(Path(sys.argv[1]));raise SystemExit(0 if r['passed']==r['checks'] else 1)
