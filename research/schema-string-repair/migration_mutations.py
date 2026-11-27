"""Physical dispatcher removals; separate controls, preserved mutant files.
Synthetic dependency/runtime faults are scoped to disposable test copies.
"""
import argparse,pathlib,json,shutil,sys
import migration_campaign as c
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 source=(c.ROOT/'migration/dispatch.py').read_text(encoding='utf-8');registry=json.loads((c.ROOT/'migration/registry.json').read_bytes())
 cases={x['id']:x for x in c.cases()};positive=cases['published-original'];rows=[]
 defs=[
  ('expected-pin','if expected_profile!=digest:', 'if False:', 'wrong-independent-pin','none'),
  ('profile-bytes',"if sha(canonical(bundle['verificationProfile']).encode())!=digest:", 'if False:', 'profile-substitution','none'),
  ('unknown-fallback',"if len(routes)!=1:return cannot('UNKNOWN_OR_AMBIGUOUS_PROFILE')", "if len(routes)!=1:return reject('PROFILE_BYTES_MISMATCH')", 'same-name-unknown-identity','none'),
  ('registry-pin','if sha(registry_raw)!=REGISTRY_SHA256:', 'if False:', 'registry-changed','registry'),
  ('source-pin','if sha(b)!=pin:', 'if False:', 'source-changed','source'),
  ('agreement','if reports[0]!=reports[1]:','if False:','runtime-disagreement','runtime'),
 ]
 for name,old,new,case_id,fault in defs:
  root=out/'copies'/name;root.mkdir(parents=True)
  for route in registry['routes']:
   for f in route['files']:
    p=root/route['root']/f;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((c.ROOT/route['root']/f).read_bytes())
  (root/'migration').mkdir(exist_ok=True);shutil.copy2(c.ROOT/'migration/registry.json',root/'migration/registry.json')
  d=root/'migration/dispatch.py';d.write_text(source,encoding='utf-8',newline='\n')
  p=c.observe(out,name+'-positive',root,positive,'normal')
  witness=cases.get(case_id)
  if witness is None:
   witness=json.loads(json.dumps(positive));witness['id']=case_id;witness['status']='HOLD'
  if fault=='registry':
   reg=root/'migration/registry.json';reg.write_bytes(reg.read_bytes()+b'\n');witness['detail']='TRUST_REGISTRY_INTEGRITY'
  elif fault=='source':
   f=root/'conformance/rvr-v0/adapter.py';f.write_bytes(f.read_bytes()+b'\n# physical source identity mutation\n');witness['detail']='ADAPTER_OR_DEPENDENCY_INTEGRITY'
  elif fault=='runtime':
   # Synthetic conflicting implementation observation, not a historical receipt claim.
   witness['detail']='HISTORICAL_OR_RUNTIME_AMBIGUITY';witness['request']['testDisagreement']=True
   instrument="   if req.get('testDisagreement'):reports[1]={'kind':'GATE','reason':'synthetic.runtime.disagreement'}\n"
   d.write_text(source.replace('   if reports[0]!=reports[1]:',instrument+'   if reports[0]!=reports[1]:'),encoding='utf-8',newline='\n')
  control=d.read_text(encoding='utf-8')
  neg=c.observe(out,name+'-negative',root,witness,'normal')
  if control.count(old)!=1:raise RuntimeError((name,'replacement count'))
  mutant=control.replace(old,new);d.write_text(mutant,encoding='utf-8',newline='\n');(root/'migration/dispatch.py.mutant').write_text(mutant,encoding='utf-8',newline='\n')
  got=c.observe(out,name+'-mutant',root,witness,'normal')
  d.write_text(control,encoding='utf-8',newline='\n');restored=c.observe(out,name+'-restored-negative',root,witness,'normal')
  # Restore faulted dependency bytes as well, then repeat a positive control.
  for route in registry['routes']:
   for f in route['files']:(root/route['root']/f).write_bytes((c.ROOT/route['root']/f).read_bytes())
  shutil.copy2(c.ROOT/'migration/registry.json',root/'migration/registry.json');d.write_text(source,encoding='utf-8',newline='\n')
  rp=c.observe(out,name+'-restored-positive',root,positive,'normal')
  healthy=all(x['match'] for x in [p,neg,restored,rp])
  verdict='INVALID' if not healthy or got['status']=='CRASH' else 'SURVIVED' if got['match'] else 'KILLED'
  rows.append(dict(id=name,verdict=verdict,positive=p,negative=neg,mutant=got,restored=restored,restoredPositive=rp,mutantSha256=c.sha(mutant.encode()),scope='source/dependency integrity and classification controls; no assertion of OS-wide enforcement'))
  print(name,verdict,flush=True)
 c.save(out/'RESULTS.json',rows)
 if any(r['verdict']!='KILLED' for r in rows):raise SystemExit(1)
if __name__=='__main__':main()
