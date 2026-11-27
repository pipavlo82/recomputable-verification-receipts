"""Read-only exact-profile dispatcher. No network, caller-selected code or fallback.

The reviewed source and pinned registry are the local trust root. Profile names,
receipt timestamps and a package's self-reported version never select code.
"""
from __future__ import annotations
import argparse,hashlib,json,os,pathlib,re,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
REGISTRY_SHA256='61223cba5a84784cfd8c7ce4c796be093e85740c8617d55e6da70f58957c31e5'
MAX_INPUT=2*1024*1024
sha=lambda b:hashlib.sha256(b).hexdigest()

def pairs(xs):
 d={}
 for k,v in xs:
  if k in d:raise ValueError('duplicate JSON key')
  d[k]=v
 return d

def parse(b):
 if len(b)>MAX_INPUT:raise ValueError('input too large')
 return json.loads(b.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def canonical(x):
 if x is None:return 'null'
 if x is True:return 'true'
 if x is False:return 'false'
 if isinstance(x,str):
  if any(0xd800<=ord(c)<=0xdfff for c in x):raise ValueError('surrogate in canonical domain')
  return json.dumps(x,ensure_ascii=False,separators=(',',':'))
 if isinstance(x,list):return '['+','.join(map(canonical,x))+']'
 if isinstance(x,dict):return '{'+','.join(canonical(k)+':'+canonical(x[k]) for k in sorted(x))+'}'
 raise ValueError('numbers outside pinned canonical domain')

def cannot(reason,**extra):return dict(migrationStatus='HOLD',recomputationStatus='CANNOT_RECOMPUTE',evaluationPerformed=False,reason=reason,**extra)
def reject(reason):return dict(migrationStatus='GATE_REJECTED',evaluationPerformed=False,reason=reason)

PY_BRIDGE='''import importlib.util,json,pathlib,sys
p=pathlib.Path(__file__).parent/'conformance/rvr-v0/adapter.py'
s=importlib.util.spec_from_file_location('selected_rvr',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
try:
 req=m.parse_json_bytes(sys.stdin.buffer.read(),'migration request')
 raw=m.PROFILE_MANIFEST_SCHEMA_PATH.read_bytes();profile=m.load_json(m.PROFILE_PATH)
 digest,_,pinned=m.audit_profile(profile,m.parse_json_bytes(raw,'profile schema'),raw)
 schema=m.parse_json_bytes(pinned['rvr-schema'],'rvr-schema')
 result=m.recompute(req['bundle'],req.get('candidateCase') or req['bundle'],digest,schema)
 print(json.dumps(dict(kind='RESULT',result=result)))
except m.GateRejection as e:print(json.dumps(dict(kind='GATE',reason=e.reason_code)))
except Exception as e:print(json.dumps(dict(kind='UNAVAILABLE',error=type(e).__name__)))
'''
TS_BRIDGE='''
export function migrationBridge(raw: Buffer): unknown {
 try {
  const req=parseJsonBytes(raw);const schemaBytes=readBytes(PROFILE_MANIFEST_SCHEMA_PATH);
  const profile=loadJson(PROFILE_PATH);
  const [digest,,pinned]=auditProfile(profile,parseJsonBytes(schemaBytes),schemaBytes);
  const schema=parseJsonBytes(pinned.get('rvr-schema')!);
  return {kind:'RESULT',result:recompute(req.bundle,req.candidateCase??req.bundle,digest,schema)};
 } catch(e) {
  return e instanceof GateRejection ? {kind:'GATE',reason:e.reasonCode} : {kind:'UNAVAILABLE',error:e instanceof Error?e.name:'Error'};
 }
}
'''
TS_RUNNER="import {migrationBridge} from './conformance/rvr-v0/receipt-bridge.ts';\nconsole.log(JSON.stringify(migrationBridge(Buffer.from(await Bun.stdin.arrayBuffer()))));\n"

def dispatch(raw:bytes,expected_profile:str):
 try:
  req=parse(raw);bundle=req['bundle'];receipt=bundle['receipt'];digest=receipt['verificationProfileDigest']
  if not isinstance(digest,str) or re.fullmatch('[0-9a-f]{64}',digest) is None:return reject('MALFORMED_PROFILE_IDENTITY')
  if expected_profile!=digest:return reject('EXPECTED_PROFILE_MISMATCH')
  registry_raw=(ROOT/'migration/registry.json').read_bytes()
  if sha(registry_raw)!=REGISTRY_SHA256:return cannot('TRUST_REGISTRY_INTEGRITY')
  registry=parse(registry_raw)
  routes=[r for r in registry['routes'] if r['profileDigest']==digest]
  if len(routes)!=1:return cannot('UNKNOWN_OR_AMBIGUOUS_PROFILE')
  route=routes[0]
  # Authenticate the profile object before accepting any of its asserted fields.
  if 'verificationProfile' not in bundle:return cannot('PROFILE_NOT_SUPPLIED')
  if sha(canonical(bundle['verificationProfile']).encode())!=digest:return reject('PROFILE_BYTES_MISMATCH')
  root=(ROOT/route['root']).resolve()
  if not root.is_relative_to(ROOT.resolve()):return cannot('PACKAGE_ROOT_ESCAPE')
  snapshot={}
  for name,pin in route['files'].items():
   path=(root/name).resolve()
   if not path.is_relative_to(root):return cannot('PACKAGE_PATH_ESCAPE')
   b=path.read_bytes()
   if sha(b)!=pin:return cannot('ADAPTER_OR_DEPENDENCY_INTEGRITY',path=name)
   snapshot[name]=b
  profile=parse(snapshot['conformance/rvr-v0/verification-profile.json'])
  if sha(canonical(profile).encode())!=digest:return cannot('REGISTERED_PROFILE_IDENTITY_MISMATCH')
  if sys.version_info[:3]!=(3,12,10):return cannot('UNSUPPORTED_REPLAY_RUNTIME')
  for executable,version in [('bun','1.3.14')]+([('node','v22.15.0')] if route['adapterId']=='ucd17-v1' else []):
   p=subprocess.run([executable,'--version'],capture_output=True,timeout=10)
   if p.returncode or p.stdout.decode().strip()!=version:return cannot('UNSUPPORTED_REPLAY_RUNTIME')
  # Evaluate only the byte snapshot verified above, never caller-supplied modules.
  with tempfile.TemporaryDirectory(prefix='rvr-selected-profile-') as temp:
   stage=pathlib.Path(temp)
   for name,b in snapshot.items():
    dest=stage/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(b)
   (stage/'bridge.py').write_text(PY_BRIDGE,encoding='utf-8',newline='\n')
   ts=stage/'conformance/rvr-v0/receipt-bridge.ts'
   ts.write_bytes(snapshot['conformance/rvr-v0/adapter.ts']+TS_BRIDGE.encode())
   (stage/'bridge.ts').write_text(TS_RUNNER,encoding='utf-8',newline='\n')
   reports=[]
   for command in [[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(stage/'bridge.py')],['bun',str(stage/'bridge.ts')]]:
    p=subprocess.run(command,input=raw,capture_output=True,cwd=stage,timeout=30,env={**os.environ,'PYTHONIOENCODING':'utf-8','PYTHONDONTWRITEBYTECODE':'1'})
    if p.returncode!=0:return cannot('ADAPTER_PROCESS_FAILURE',adapterId=route['adapterId'],exit=p.returncode)
    reports.append(parse(p.stdout))
   if reports[0]!=reports[1]:return cannot('HISTORICAL_OR_RUNTIME_AMBIGUITY',adapterId=route['adapterId'],implementationResults=reports)
   result=reports[0]
   if result['kind']=='UNAVAILABLE':return cannot('ADAPTER_CHECK_UNAVAILABLE',adapterId=route['adapterId'])
   if result['kind']=='GATE':return reject(result['reason'])
   return dict(migrationStatus='SELECTED',adapterId=route['adapterId'],verificationProfileDigest=digest,result=result['result'])
 except (KeyError,TypeError,ValueError,UnicodeError,json.JSONDecodeError):return reject('MALFORMED_INPUT')
 except (OSError,subprocess.SubprocessError):return cannot('DEPENDENCY_OR_RUNTIME_UNAVAILABLE')

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--request',type=pathlib.Path,required=True);ap.add_argument('--expected-profile',required=True);args=ap.parse_args()
 try:raw=args.request.read_bytes();result=dispatch(raw,args.expected_profile)
 except OSError:result=cannot('REQUEST_UNAVAILABLE')
 print(json.dumps(result,ensure_ascii=True,indent=2))
 return 0 if result['migrationStatus']=='SELECTED' else 2
if __name__=='__main__':raise SystemExit(main())
