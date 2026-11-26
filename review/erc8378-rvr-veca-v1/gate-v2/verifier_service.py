"""Laboratory verifier subprocess: no raw signing endpoint; no caller verdict input.
Private key and policy paths are provisioned by lab controller, not bridge messages.
Same Windows user is NOT independently administered custody. Production HOLD.
"""
import sys,json,hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import oracle
import boundary
from eth_account import Account
from eth_abi import encode
from eth_utils import keccak
from web3 import Web3
TYPES=['uint256','address','address','address','uint256']+['bytes32']*11+['uint256']*3+['uint64']*2
DOMAIN=keccak(text='ERC8378_EVIDENCE_GATE_V2')
def digest(c,chain,gate,escrow):return keccak(encode(['bytes32','uint256','address','address','('+','.join(TYPES)+')'],[DOMAIN,chain,gate,escrow,c]))
def build(e,p,state,now,epoch):
 b=e['binding'];h=lambda v:bytes.fromhex(v)
 return [int(b['job_id']),Web3.to_checksum_address(b['client']),Web3.to_checksum_address(b['provider']),Web3.to_checksum_address(b['token_contract']),int(b['amount']),h(oracle.digest(b)),h(oracle.digest(e)),h(oracle.digest(p)),h(b['deliverable_sha256']),h(b['rvr_profile_digest']),h(b['rvr_receipt_digest']),h(b['veca_claim_digest']),keccak(text='VERIFIED'),keccak(text='REPRODUCED'),keccak(text='VERIFIED'),int(b['nonce']).to_bytes(32,'big'),now,min(now+600,int(b['expiry'])),epoch,int(b['token_parameters'][0]),int(b['token_parameters'][1])]
def wire(c):return ['0x'+v.hex() if isinstance(v,bytes) else v for v in c]
def unwire(c):return [bytes.fromhex(v[2:]) if t=='bytes32' else v for t,v in zip(TYPES,c)]

def issue_checked(request, cfg, state, now, epoch, revoked, used, key):
 """The bridge provides evidence only; policy and state come from verifier authority.
 This function cannot establish who administers its host, policy or private key.
 """
 if type(request) is not dict or set(request)!={'evidence'}:return {'issued':False,'reason':'REQUEST_SCHEMA'}
 e=request['evidence'];p=cfg['policy'];s=state
 if type(e) is not dict or e.get('binding',{}).get('deliverable_sha256')!=s.get('submitted_deliverable_sha256'):return {'issued':False,'reason':'SUBMISSION_BINDING'}
 result=boundary.assess(e,p,s)
 if result['status']!='VERIFIED':return {'issued':False,'reason':result['status'],'checks':result['checks']}
 if revoked:return {'issued':False,'reason':'VERIFIER_REVOKED'}
 if int(e['binding']['revocation_epoch'])!=epoch:return {'issued':False,'reason':'EPOCH'}
 c=build(e,p,s,now,epoch)
 if c[15] in used:return {'issued':False,'reason':'NONCE_USED'}
 if bytes.fromhex(oracle.digest(e['binding']))!=cfg['pinned_binding']:return {'issued':False,'reason':'CLIENT_PIN'}
 if key.address.lower()!=cfg['verifier'].lower():return {'issued':False,'reason':'KEY_PIN'}
 d=digest(c,int(s['chain_id']),s['evaluator'],s['escrow_contract'])
 return {'issued':True,'confirmation':wire(c),'signature':'0x'+key.unsafe_sign_hash(d).signature.hex(),
         'signer':key.address,'digest':'0x'+d.hex(),'result':result['status'],'checks':result['checks'],
         'scope':'experimental profile; verifier assertion, not proof of truth','observed_state':s}
def main():
 cfg=json.loads(Path(sys.argv[1]).read_bytes());request=json.load(sys.stdin)
 if set(request)!={'evidence'}:return {'issued':False,'reason':'REQUEST_SCHEMA'}
 e=request['evidence'];p=cfg['policy'];s=dict(cfg['state'])
 w=Web3(Web3.HTTPProvider('http://127.0.0.1:18783'))
 if w.eth.chain_id!=31337:raise ValueError('NOT_LOCAL')
 acp=w.eth.contract(address=Web3.to_checksum_address(s['escrow_contract']),abi=cfg['acp_abi']);gate=w.eth.contract(address=Web3.to_checksum_address(s['evaluator']),abi=cfg['gate_abi']);token=w.eth.contract(address=Web3.to_checksum_address(s['token_contract']),abi=cfg['token_abi'])
 job=acp.functions.getJob(int(s['job_id'])).call();now=w.eth.get_block('latest').timestamp
 submitted=acp.events.JobSubmitted().get_logs(from_block=0,to_block='latest',argument_filters={'jobId':int(s['job_id'])})
 if len(submitted)!=1:return {'issued':False,'reason':'SUBMISSION_UNVERIFIABLE'}
 s['submitted_deliverable_sha256']=bytes(submitted[0]['args']['deliverable']).hex()
 s.update(chain_id=str(w.eth.chain_id),client=job[1].lower(),provider=job[2].lower(),evaluator=job[3].lower(),amount=str(job[5]),status=['Open','Funded','Submitted','Completed','Rejected','Expired'][job[7]],token_contract=acp.functions.paymentToken().call().lower(),now=str(now),token_parameters=[str(token.functions.parameterOf(acp.address,0,i).call()) for i in range(2)])
 key=Account.from_key(Path(sys.argv[2]).read_bytes())
 cfg.update(pinned_binding=gate.functions.pinned(int(s['job_id'])).call(),verifier=gate.functions.verifier().call())
 nonce=int(e['binding']['nonce']).to_bytes(32,'big')
 result=issue_checked(request,cfg,s,now,gate.functions.epoch().call(),gate.functions.verifierRevoked().call(),[nonce] if gate.functions.used(nonce).call() else [],key)
 if result['issued'] and bytes.fromhex(result['digest'][2:])!=gate.functions.digestOf(unwire(result['confirmation'])).call():raise ValueError('DIGEST_DISAGREEMENT')
 return result
if __name__=='__main__':
 try:print(json.dumps(main(),sort_keys=True))
 except Exception as e:print(json.dumps({'issued':False,'reason':'UNVERIFIABLE','exception':type(e).__name__,'message':str(e)}));sys.exit(2)
