"""Run native EVM, real frozen-core recomputation and two separate checkers.
All contracts are instantiated only inside Foundry's test EVM. No public RPC,
broadcast, deployment, push or publication commands are used.
"""
import sys,os,json,subprocess,hashlib,shutil
from pathlib import Path
import test_credentials as credentials
ROOT=Path(__file__).resolve().parents[1]
def main():
 name=sys.argv[1]
 if not name.replace('-','').isalnum():raise ValueError('Run name')
 out=ROOT/'gate-v2/runs'/name;out.mkdir(parents=True,exist_ok=False)
 env=dict(os.environ,V2_EVIDENCE_OUT=str(out),V2_OPTIMIZED='true' if sys.flags.optimize else 'false',PYTHONDONTWRITEBYTECODE='1')
 forge=os.environ.get('V2_FORGE') or shutil.which('forge') or str(Path.home()/'.foundry/bin'/('forge.exe' if os.name=='nt' else 'forge'))
 python=[sys.executable,'-B']+(['-O'] if sys.flags.optimize else [])
 commands=[('foundry',[forge,'test','--root',str(ROOT/'evm'),'--offline','--ffi','--json']),
           ('offline-checker',python+[str(ROOT/'gate-v2/offline_checker.py'),str(out)]),
           ('issuer-controls',python+[str(ROOT/'gate-v2/issuer_tests.py'),str(out)]),
           ('frozen-rvr',python+[str(ROOT/'sources/rvr/conformance/rvr-v0/adapter.py'),'--check'])]
 rows=[];results={}
 for label,args in commands:
  p=subprocess.run(args,cwd=ROOT,env=env,capture_output=True,timeout=180)
  (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
  rows.append({'name':label,'argv':args,'exit':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()})
  (out/'commands.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
  if p.returncode:raise RuntimeError(f'{label} failed; inspect {out}')
  if label=='foundry':
   native=json.loads(p.stdout);statuses={suite_name+'::'+test:r['status'] for suite_name,suite in native.items() for test,r in suite['test_results'].items()}
   if not statuses or any(v!='Success' for v in statuses.values()):raise RuntimeError('Native tests failed/empty')
   results[label]={'checks':len(statuses),'passed':sum(v=='Success' for v in statuses.values()),'tests':statuses}
  elif label in ['offline-checker','issuer-controls']:
   result=json.loads(p.stdout)
   if result['checks']==0 or result['checks']!=result['passed']:raise RuntimeError('Checker failed/empty')
   results[label]={'checks':result['checks'],'passed':result['passed']}
  else:results[label]={'exit':p.returncode}
 files=['ffi-issuance.json','native-payout.json','bridge-refusal.json','offline-checker.stdout','issuer-controls.stdout']
 results['payload_hashes']={f:hashlib.sha256((out/f).read_bytes()).hexdigest() for f in files}
 results['production']='HOLD';results['status']='ITERATE';results['custody']='NOT_ESTABLISHED_ON_SHARED_HOST'
 (out/'summary.json').write_text(json.dumps(results,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
 print(json.dumps(results,sort_keys=True))
if __name__=='__main__':credentials.run(main)
