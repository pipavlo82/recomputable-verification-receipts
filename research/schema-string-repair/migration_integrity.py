"""Check original profiles/packages against external exact Git identities.
No imports from dispatcher or adapters; no local manifest self-resealing.
"""
import pathlib,hashlib,json,subprocess,re
ROOT=pathlib.Path(__file__).resolve().parents[2]
BASE='9dd36e882dd372f264b77b179130948aa5adcbde'
RC2='f4476754c92e0bea549474722108ec60ded1385a'
REPAIRED='f42d356d9e6cc4df93d80573471456b647ba95b2'
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT)
def main():
 old=[]
 for name in git('ls-tree','-r','--name-only',BASE).decode().splitlines():
  if name.startswith(('conformance/','profiles/','docs/spec/')):
   if (ROOT/name).read_bytes()!=git('show',BASE+':'+name):raise RuntimeError('Historical source changed: '+name)
   old.append(name)
 registry=json.loads((ROOT/'migration/registry.json').read_bytes());n=0
 for route in registry['routes']:
  root=ROOT/route['root']
  for name,pin in route['files'].items():
   b=(root/name).read_bytes()
   if hashlib.sha256(b).hexdigest()!=pin:raise RuntimeError('Route file drift: '+name)
   if route['adapterId']=='rc2-frozen' and b!=git('show',RC2+':'+name):raise RuntimeError('RC2 changed: '+name)
   n+=1
 for name in ['adapter.py','adapter.ts','ecma-unicode.cjs']:
  path='conformance/rvr-v0/'+name
  if (ROOT/'profiles/generic-ucd17-v1'/path).read_bytes()!=git('show',REPAIRED+':'+path):raise RuntimeError('Repaired algorithm changed during packaging')
 pin=re.search("REGISTRY_SHA256='([0-9a-f]{64})'",(ROOT/'migration/dispatch.py').read_text(encoding='utf-8')).group(1)
 if hashlib.sha256((ROOT/'migration/registry.json').read_bytes()).hexdigest()!=pin:raise RuntimeError('Registry trust pin drift')
 print(json.dumps(dict(historical_files=len(old),registered_file_hashes=n,repaired_algorithms_unchanged=3,baseline=BASE,rc2=RC2,candidate=REPAIRED,status='MATCH'),indent=2))
if __name__=='__main__':main()
