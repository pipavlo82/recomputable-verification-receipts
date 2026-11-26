"""Physical source edits in separate copies. Crashes/compile failures are INVALID,
never KILLED. Each kill requires an intact positive and a failing negative control.
"""
import sys,os,json,shutil,subprocess,hashlib,re
from pathlib import Path
import test_credentials as credentials
ROOT=Path(__file__).resolve().parents[1]
def main():
 label=sys.argv[1];fixture=ROOT/'gate-v2/runs'/sys.argv[2]
 dest=ROOT/'gate-v2/mutations'/label;dest.mkdir(parents=True,exist_ok=False)
 forge=os.environ.get('V2_FORGE') or shutil.which('forge') or str(Path.home()/'.foundry/bin'/('forge.exe' if os.name=='nt' else 'forge'))
 native=[('caller','testWrongCaller'),('revocation','testRevokedVerifier'),('signature','testBridgeSignatureCannotReplaceVerifier'),('outcomes','testRefutedEvenWhenSigned'),('evidence','testZeroEvidenceRefusedEvenWhenSigned'),('binding','testSignedWrongBinding'),('freshness','testExpired'),('replay','testReplayNonceAcrossJobs'),('job','testExpiredJobCannotSettleWithFreshConfirmation'),('context','testSignedWrongRecipient')]
 cases=[{'name':name,'kind':'native','path':'evm/src/EvidenceGateV2.sol','marker':'// V2GUARD '+name,'test':test} for name,test in native]
 for name,old,new in [('chain_domain','block.chainid','uint256(0)'),('gate_domain','address(this),address(escrow),c','address(0),address(escrow),c'),('escrow_domain','address(this),address(escrow),c','address(this),address(0),c')]:
  cases.append({'name':name,'kind':'native','path':'evm/src/EvidenceGateV2.sol','old':old,'new':new,'test':'testDigestMatchesIndependentDomainEncoding'})
 for name in ['admin','upgrade']:cases.append({'name':'factory_'+name,'kind':'native','path':'evm/src/LockedGateFactory.sol','marker':'// V2FACTORY '+name,'test':'testFactoryRetainsNoEscrowRoles'})
 for name,needle,test in [('issuer_validation'," if result['status']!='VERIFIED':",'wrong_deliverable'),('issuer_submission'," if type(e) is not dict or e.get('binding',{}).get('deliverable_sha256')",'different_actual_submission'),('issuer_revocation',' if revoked:','revoked_verifier'),('issuer_client_pin'," if bytes.fromhex(oracle.digest(e['binding']))",'wrong_client_pin'),('issuer_key_pin',' if key.address.lower()!=cfg','wrong_verifier_key')]:
  cases.append({'name':name,'kind':'issuer','path':'gate-v2/verifier_service.py','marker':needle,'test':test})
 results=[]
 for case in cases:
  work=dest/case['name'];work.mkdir()
  if case['kind']=='native':
   shutil.copytree(ROOT/'evm',work/'evm',ignore=shutil.ignore_patterns('out','cache'))
   (work/'gate-v2/runs').mkdir(parents=True)
  else:
   for name in ['boundary.py','oracle.py']:shutil.copyfile(ROOT/name,work/name)
   shutil.copytree(ROOT/'sources',work/'sources',ignore=shutil.ignore_patterns('__pycache__','.git'))
   (work/'gate-v2').mkdir()
   for name in ['verifier_service.py','issuer_tests.py','test_credentials.py']:shutil.copyfile(ROOT/'gate-v2'/name,work/'gate-v2'/name)
  target=work/case['path'];original=target.read_text(encoding='utf-8')
  if 'marker' in case:
   lines=original.splitlines(keepends=True);selected=[i for i,x in enumerate(lines) if case['marker'] in x]
   if len(selected)!=1:raise RuntimeError(('MUTATION_LOCATION',case,selected))
   changed=''.join(x for i,x in enumerate(lines) if i!=selected[0])
  else:
   if original.count(case['old'])!=1:raise RuntimeError('MUTATION_LOCATION')
   changed=original.replace(case['old'],case['new'])
  target.write_text(changed,encoding='utf-8',newline='\n')
  if case['kind']=='native':args=[forge,'test','--root',str(work/'evm'),'--offline','--match-contract','EvidenceGateControls','--match-test',f'^(testPositiveNativeERC8378PaymentOnce|{case["test"]})\\(\\)$','--json']
  else:args=[sys.executable,'-B']+(['-O'] if sys.flags.optimize else [])+[str(work/'gate-v2/issuer_tests.py'),str(fixture),case['test']]
  p=subprocess.run(args,cwd=work,capture_output=True,timeout=180,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
  (work/'stdout').write_bytes(p.stdout);(work/'stderr').write_bytes(p.stderr)
  status='INVALID';detail={}
  try:
   data=json.loads(p.stdout)
   if case['kind']=='native':
    tests={n:r for suite in data.values() for n,r in suite['test_results'].items()}
    positive=tests.get('testPositiveNativeERC8378PaymentOnce()',{}).get('status')=='Success'
    negative=tests.get(case['test']+'()',{}).get('status')=='Failure'
    if positive:status='KILLED' if negative and p.returncode!=0 else 'SURVIVED'
    detail={'positive_passed':positive,'negative_failed':negative,'tests':{n:{'status':r['status'],'reason':r['reason']} for n,r in tests.items()}}
   else:
    positive=next(x for x in data['rows'] if x['id']=='valid_evidence')['pass'];accepted=[x['id'] for x in data['rows'] if not x['pass'] and x['observed_issued']]
    if positive:status='KILLED' if accepted and p.returncode!=0 else 'SURVIVED'
    detail={'positive_passed':positive,'invalid_issuances':accepted}
  except Exception as ex:detail={'parse_error':type(ex).__name__}
  row={**case,'status':status,'exit':p.returncode,'source_before_sha256':hashlib.sha256(original.encode()).hexdigest(),'source_after_sha256':hashlib.sha256(changed.encode()).hexdigest(),'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'detail':detail}
  results.append(row);print(case['name'],status,flush=True)
  (dest/'results.json').write_text(json.dumps(results,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
 if not results or any(x['status']!='KILLED' for x in results):raise SystemExit(1)
if __name__=='__main__':credentials.run(main)
