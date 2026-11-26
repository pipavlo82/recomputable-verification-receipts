"""Separate checker: no producer, issuer or bridge module imports.

Frozen RVR is a shared pinned dependency. Saved native EVM logs are checked for
consistency, not verified against a blockchain consensus proof. Same author/host;
this is a separate implementation, not an independent human/security audit.
"""
import sys,json,copy,hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import oracle
from eth_abi import encode,decode
from eth_keys import keys
from eth_utils import keccak

SCALARS=['uint256','address','address','address','uint256']+['bytes32']*11+['uint256']*3+['uint64']*2
STRUCT='('+','.join(SCALARS)+')'
REQUIRED=set('binding assessment signature deliverable rubric conditions rvr rvr_case claim obligations'.split())
def sha(x):return hashlib.sha256(oracle.canonical(x)).hexdigest()
def expected_confirmation(f):
 e,p,s=f['evidence'],f['policy'],f['state'];b=e['binding'];h=lambda x:bytes.fromhex(x)
 return [int(b['job_id']),b['client'],b['provider'],b['token_contract'],int(b['amount']),h(sha(b)),h(sha(e)),h(sha(p)),h(b['deliverable_sha256']),h(b['rvr_profile_digest']),h(b['rvr_receipt_digest']),h(b['veca_claim_digest']),keccak(text='VERIFIED'),keccak(text='REPRODUCED'),keccak(text='VERIFIED'),int(b['nonce']).to_bytes(32,'big'),int(s['now']),min(int(s['now'])+600,int(b['expiry'])),int(b['revocation_epoch']),int(b['token_parameters'][0]),int(b['token_parameters'][1])]
def evidence_ok(e,p,s):return type(e) is dict and set(e)==REQUIRED and e.get('binding',{}).get('deliverable_sha256')==s.get('submitted_deliverable_sha256') and oracle.evaluate(e,p,s)=='VERIFIED'
def verify(c,sig,f,authority,chain,gate,escrow,*,now=None,used=(),revoked=False,epoch=0):
 try:
  if not evidence_ok(f['evidence'],f['policy'],f['state']):return False
  if list(c)!=expected_confirmation(f):return False
  at=int(f['state']['now']) if now is None else now
  if revoked or c[18]!=epoch or c[15] in used or not(c[16]<=at<c[17]) or c[17]-c[16]>3600:return False
  d=keccak(encode(['bytes32','uint256','address','address',STRUCT],[keccak(text='ERC8378_EVIDENCE_GATE_V2'),chain,gate,escrow,c]))
  normalized=bytes(sig[:-1])+bytes([sig[-1]-27])
  signer=keys.Signature(normalized).recover_public_key_from_msg_hash(d).to_checksum_address()
  return signer.lower()==authority.lower()
 except Exception:return False
def replay(folder):
 f=json.loads((folder/'ffi-issuance.json').read_bytes());n=json.loads((folder/'native-payout.json').read_bytes());refusal=json.loads((folder/'bridge-refusal.json').read_bytes())
 c=list(decode([STRUCT],bytes.fromhex(n['confirmation'][2:]))[0]);sig=bytes.fromhex(n['signature'][2:]);s=f['state'];rows=[]
 def check(name,ok):rows.append({'id':name,'pass':bool(ok)})
 check('evidence_recomputed',evidence_ok(f['evidence'],f['policy'],s))
 check('confirmation_all_fields_rebuilt',c==expected_confirmation(f))
 check('client_binding_pin',f['pinned_binding']==sha(f['evidence']['binding']))
 check('signature_and_complete_domain',verify(c,sig,f,n['verifier'],n['chain_id'],n['gate'],n['escrow']))
 check('native_exact_payment',n['provider_after']-n['provider_before']==100 and n['escrow_before']-n['escrow_after']==100 and n['nonce_used'] is True)
 transfers=[];completions=[]
 for i in range(n['log_count']):
  ts=decode(['bytes32[]'],bytes.fromhex(n[f'log{i}_topics'][2:]))[0];data=bytes.fromhex(n[f'log{i}_data'][2:]);emitter=n[f'log{i}_emitter'].lower()
  if ts[0]==keccak(text='Transfer(address,address,uint256)') and emitter==s['token_contract']:
   transfers.append(('0x'+ts[1][-20:].hex(),'0x'+ts[2][-20:].hex(),decode(['uint256'],data)[0]))
  if ts[0]==keccak(text='JobCompleted(uint256,address,bytes32)') and emitter==s['escrow_contract']:
   completions.append((int.from_bytes(ts[1],'big'),'0x'+ts[2][-20:].hex(),data.hex()))
 check('actual_erc8378_transfer_event',transfers==[(s['escrow_contract'],s['provider'],100)])
 check('completion_bound_to_job_gate_binding',completions==[(int(s['job_id']),s['evaluator'],sha(f['evidence']['binding']))])
 check('bridge_without_signature_native_refused',refusal['payout_call_succeeded'] is False and refusal['provider_after']==refusal['provider_before']==0 and refusal['escrow_after']==refusal['escrow_before']==100 and refusal['nonce_used'] is False and refusal['revert_data']!='0x')
 for i,t in enumerate(SCALARS):
  changed=list(c);changed[i]=('0x'+'ab'*20) if t=='address' else bytes([c[i][0]^1])+c[i][1:] if t=='bytes32' else c[i]+1
  check(f'bound_field_{i}_substitution',not verify(changed,sig,f,n['verifier'],n['chain_id'],n['gate'],n['escrow']))
 for name,kw in [('expired',{'now':c[17]}),('nonce_replay',{'used':[c[15]]}),('revoked_verifier',{'revoked':True}),('old_epoch',{'epoch':1})]:
  check(name,not verify(c,sig,f,n['verifier'],n['chain_id'],n['gate'],n['escrow'],**kw))
 check('other_chain',not verify(c,sig,f,n['verifier'],n['chain_id']+1,n['gate'],n['escrow']))
 check('other_gate',not verify(c,sig,f,n['verifier'],n['chain_id'],'0x'+'ab'*20,n['escrow']))
 check('other_escrow',not verify(c,sig,f,n['verifier'],n['chain_id'],n['gate'],'0x'+'ab'*20))
 check('other_verifier',not verify(c,sig,f,'0x'+'ab'*20,n['chain_id'],n['gate'],n['escrow']))
 mutations=['missing_rvr','missing_payload','rvr_diverged','bad_assessor_signature','wrong_deliverable','wrong_claim','missing_obligation','wrong_digest','revoked_assessor','unknown_flag','absent_policy']
 for name in mutations:
  e,p,st=copy.deepcopy((f['evidence'],f['policy'],s))
  if name=='missing_rvr':del e['rvr']
  if name=='missing_payload':e['rvr_case']['payloadsBase64']={}
  if name=='rvr_diverged':e['rvr']['receipt']['verificationOutcome']='REFUTED'
  if name=='bad_assessor_signature':e['signature']='00'*64
  if name=='wrong_deliverable':e['deliverable']='00'
  if name=='wrong_claim':e['claim']['type']='UNSUPPORTED'
  if name=='missing_obligation':e['obligations']=[]
  if name=='wrong_digest':e['binding']['rvr_receipt_digest']='00'*32
  if name=='revoked_assessor':p['revoked_assessors']=[p['assessor']]
  if name=='unknown_flag':e['verified']=True
  if name=='absent_policy':p=None
  check(name,not evidence_ok(e,p,st))
 result={'checks':len(rows),'passed':sum(r['pass'] for r in rows),'rows':rows,'independence':__doc__}
 return result
if __name__=='__main__':
 result=replay(Path(sys.argv[1]));print(json.dumps(result,sort_keys=True,indent=2));raise SystemExit(0 if result['checks']==result['passed'] else 1)
