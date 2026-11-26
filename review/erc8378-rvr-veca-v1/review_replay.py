"""Run normal/repeat/-O and optional mutations using one temporary credential set.
Only relative command names and public result facts are exported as review evidence.
Private credentials are removed on exit and never included in the evidence files.
"""
import os,sys,json,subprocess,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'gate-v2'))
import test_credentials as credentials

def main():
 label=sys.argv[1]
 if not label.replace('-','').isalnum():raise ValueError('Invalid review run name')
 records=[];summaries={}
 with credentials.provision() as env:
  for suffix,optimized in [('normal',False),('repeat',False),('optimized',True)]:
   name=label+'-'+suffix;args=[sys.executable,'-B']+(['-O'] if optimized else [])+['gate-v2/reproduce.py',name]
   proc=subprocess.run(args,cwd=ROOT,env=env,capture_output=True,timeout=180)
   if proc.returncode:raise RuntimeError('Review '+suffix+' failed; retain private diagnostics locally')
   summaries[suffix]=json.loads((ROOT/'gate-v2/runs'/name/'summary.json').read_bytes())
   records.append({'command':['python','-B']+(['-O'] if optimized else [])+['gate-v2/reproduce.py',name],'exit':proc.returncode})
   print(suffix, {k:[v['passed'],v['checks']] for k,v in summaries[suffix].items() if isinstance(v,dict) and 'checks' in v},flush=True)
  if all(x['payload_hashes']==summaries['normal']['payload_hashes'] for x in summaries.values()) is not True:raise RuntimeError('Replay payload mismatch')
  if '--mutations' in sys.argv:
   args=[sys.executable,'-B','gate-v2/physical_mutations.py',label+'-campaign',label+'-normal']
   proc=subprocess.run(args,cwd=ROOT,env=env,capture_output=True,timeout=300)
   print(proc.stdout.decode(errors='replace'),flush=True)
   if proc.returncode:raise RuntimeError('Mutation campaign failed; do not publish partial results')
   mutants=json.loads((ROOT/'gate-v2/mutations'/(label+'-campaign')/'results.json').read_bytes())
  else:mutants=[]
 public=ROOT/'evidence';public.mkdir(exist_ok=True)
 result={'baseline_source_commit':'3ecd05e97499463e54992fe57f5f223a7532a955','review_changes':'runtime-only ephemeral test credentials; pinned dependency fetch; additive review documentation','status':'ITERATE','production':'HOLD','modes':{name:{k:v for k,v in value.items() if k in ['foundry','offline-checker','issuer-controls','frozen-rvr']} for name,value in summaries.items()},'payloads_identical_across_modes':True,'mutations':{kind:sum(m['status']==kind for m in mutants) for kind in ['KILLED','SURVIVED','INVALID']},'commands':records,'scope':'Foundry local EVM + Python FFI; same host/author; independent operational key custody NOT_ESTABLISHED'}
 (public/'review-results.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
 folder=ROOT/'gate-v2/runs'/(label+'-normal')
 for filename in ['ffi-issuance.json','native-payout.json','bridge-refusal.json']:(public/filename).write_bytes((folder/filename).read_bytes())
 safe_mutations=[{key:value for key,value in m.items() if key in ['name','kind','test','status','exit','source_before_sha256','source_after_sha256','stdout_sha256','detail']} for m in mutants]
 (public/'mutation-results.json').write_text(json.dumps(safe_mutations,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
 print(json.dumps({'evidence_exported':True,'private_credentials_exported':False,'mutations':result['mutations']}),flush=True)
if __name__=='__main__':main()
