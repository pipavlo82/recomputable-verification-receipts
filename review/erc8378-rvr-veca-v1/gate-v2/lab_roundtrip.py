"""FFI test transport for the in-process native EVM; no RPC or public deployment.

The test controller provisions policy/state and ephemeral runtime test keys.
This transport and shared host do not demonstrate independently administered
custody. Never use this transport for production authority.
"""
import sys,os,json,copy,hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import boundary as b
from nacl.signing import SigningKey
from eth_abi import encode,decode
from eth_account import Account
import verifier_service as vs
import test_credentials as credentials

STATE_TYPES=['uint256','address','address','address','address','address','uint256','uint256','uint256','uint256','bytes32','bytes32']
def fixture(values):
 chain,escrow,gate,token,client,provider,job,amount,now,expiry,pinned,submitted=values
 state=dict(chain_id=str(chain),escrow_contract=escrow.lower(),evaluator=gate.lower(),token_contract=token.lower(),client=client.lower(),provider=provider.lower(),job_id=str(job),amount=str(amount),token_parameters=['7000000000000','1'],status='Submitted',now=str(now),next_nonce='77',used_nonces=[])
 state['submitted_deliverable_sha256']=submitted.hex()
 raw=b'2+2=4\n';rubric={'schema':'exact-answer.v1','length':str(len(raw)),'exact_hex':raw.hex()}
 conditions={'schema':'settlement-conditions.v1','kind':'full-payout-after-exact-answer','fees':'0','normal_accounts_only':True,'immutable_round':'1','mutable_prediction':'7000000000000'}
 a={'schema':'synthetic-assessment.v1','id':'assessment-ffi','issuer':'laboratory-assessor','job_id':str(job),'deliverable_sha256':b.sha(raw),'rubric_digest':b.dig(rubric),'accepted':True}
 bundle,case=b.receipt(b.canon(a));claim={'type':b.TYPE,'consumer':'local-evidence-gate-v2','action':'request-evaluator-settlement','assessment_digest':b.dig(a),'rvr_receipt_digest':b.dig(bundle['receipt'])}
 binding={k:state[k] for k in ('chain_id','escrow_contract','job_id','client','provider','evaluator','token_contract','token_parameters','amount')}
 binding.update(deliverable_sha256=b.sha(raw),rubric_digest=b.dig(rubric),assessment_id=a['id'],assessment_digest=b.dig(a),assessment_issuer=a['issuer'],rvr_profile_digest=b.PD,rvr_receipt_digest=b.dig(bundle['receipt']),veca_claim_digest=b.dig(claim),nonce='77',expiry=str(expiry),revocation_epoch='0',settlement_conditions_digest=b.dig(conditions))
 obligations=['exact-context','assessor-signature','current-authority','rubric-replay','rvr-recompute','token-compatibility','fresh-admission']
 assessor=SigningKey(credentials.raw('assessor'))
 evidence=dict(binding=binding,assessment=a,signature=assessor.sign(b.domain(a)).signature.hex(),deliverable=raw.hex(),rubric=rubric,conditions=conditions,rvr=bundle,rvr_case=case,claim=claim,obligations=obligations)
 policy={'binding':copy.deepcopy(binding),'assessor':a['issuer'],'assessor_key':bytes(assessor.verify_key).hex(),'revoked_assessors':[],'revoked_assessments':[],'epoch':'0','rubric':rubric,'consumer':claim['consumer'],'required_obligations':obligations}
 return evidence,policy,state

def main():
 values=decode(STATE_TYPES,bytes.fromhex(sys.argv[2].removeprefix('0x')))
 e,p,s=fixture(values)
 if sys.argv[1]=='prepare':print('0x'+b.dig(e['binding']));return
 # Runtime test key is provided by the laboratory controller, never by a bridge request.
 key=Account.from_key(credentials.raw('verifier'))
 cfg={'policy':p,'pinned_binding':values[-2],'verifier':key.address}
 result=vs.issue_checked({'evidence':e},cfg,s,int(s['now']),0,False,[],key)
 if sys.argv[1]=='check':print('0x'+encode(['bool'],[result['issued']]).hex());return
 if not result['issued']:raise RuntimeError(result)
 out=Path(os.environ.get('V2_EVIDENCE_OUT',str(Path(__file__).resolve().parent/'runs/ffi')))
 out.mkdir(parents=True,exist_ok=True)
 payload={'evidence':e,'policy':p,'state':s,'issuance':result,'pinned_binding':values[-2].hex(),'transport':'LAB_FFI_SHARED_HOST_NOT_INDEPENDENT_CUSTODY'}
 (out/'ffi-issuance.json').write_text(json.dumps(payload,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('0x'+encode(['('+','.join(vs.TYPES)+')','bytes'],[vs.unwire(result['confirmation']),bytes.fromhex(result['signature'][2:])]).hex())

if __name__=='__main__':main()
