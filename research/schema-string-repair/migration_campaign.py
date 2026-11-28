"""Independent fixed migration oracle through the public dispatcher CLI.
Builds receipts by hashing exact bytes, without importing adapters/dispatcher.
Never manufactures new signatures or changes existing receipt fixtures.
"""
import pathlib,json,hashlib,base64,copy,subprocess,sys,argparse,datetime,shutil
ROOT=pathlib.Path(__file__).resolve().parents[2]
BASE='9dd36e882dd372f264b77b179130948aa5adcbde'
sha=lambda b:hashlib.sha256(b).hexdigest()
canon=lambda x:json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(json.dumps(x,ensure_ascii=False,indent=2).encode()+b'\n')

def bundle(root,media='text/plain',identifier=None):
 p=json.loads((root/'conformance/rvr-v0/verification-profile.json').read_bytes())
 v=json.loads((root/'conformance/rvr-v0/vectors.json').read_bytes())['verificationCases']['reproduced']
 c=copy.deepcopy(v['claim']);e=copy.deepcopy(v['evidenceSet']);payloads=copy.deepcopy(v['payloadsBase64'])
 e['members'][0]['mediaType']=media
 if identifier is not None:
  old=e['members'][0]['id'];e['members'][0]['id']=identifier;c['evidenceMember']=identifier;payloads[identifier]=payloads.pop(old)
 found=next(m for m in e['members'] if m['id']==c['evidenceMember'])
 observed=sha(base64.b64decode(payloads[c['evidenceMember']]))
 result=dict(schema='rvr.canonical-result.v0',outcome='VERIFIED',reasonCode='rvr.v0.digest_match',evaluation=dict(operation=c['operation'],evidenceMember=c['evidenceMember'],expectedDigest=c['expectedDigest'],observedDigest=observed))
 normalized=copy.deepcopy(e);normalized['members'].sort(key=lambda m:m['id'])
 receipt=dict(claimDigest=sha(canon(c)),evidenceSetDigest=sha(canon(normalized)),verificationProfileDigest=sha(canon(p)),outcome=result['outcome'],reasonCode=result['reasonCode'],resultDigest=sha(canon(result)))
 return dict(receipt=receipt,claim=c,evidenceSet=e,payloadsBase64=payloads,verificationProfile=p,canonicalResult=result)

def cases():
 old=ROOT;rc2=ROOT/'migration/packages/rc2';new=ROOT/'profiles/generic-ucd17-v1'
 b=bundle(old);n=bundle(new);r=bundle(rc2)
 # Oracle expectations declared independently of candidate results.
 rows=[]
 def add(id,b,status='SELECTED',detail='REPRODUCED',expected=None):rows.append(dict(id=id,request={'bundle':b},expectedProfile=expected or b['receipt']['verificationProfileDigest'],status=status,detail=detail))
 add('published-original',b);add('rc2-original',r)
 add('legacy-empty-preserved',bundle(old,''));add('rc2-empty-preserved',bundle(rc2,''))
 add('new-empty-rejected',bundle(new,''),'GATE_REJECTED','rvr.gate.schema_invalid')
 add('new-original',n);add('new-emoji',bundle(new,'😀'));add('new-ucd17-character',bundle(new,chr(0x11de0)))
 add('legacy-newline-rejected',bundle(old,identifier='x\n'),'GATE_REJECTED','rvr.gate.schema_invalid')
 x=copy.deepcopy(b);x['receipt']['verificationProfileDigest']='f6f3566807bd137bdd30e246e6c6cf098c89d43530de94debe6a494432292e44';add('historical-unregistered-string-lab',x,'HOLD','UNKNOWN_OR_AMBIGUOUS_PROFILE')
 add('wrong-independent-pin',b,'GATE_REJECTED','EXPECTED_PROFILE_MISMATCH',n['receipt']['verificationProfileDigest'])
 x=copy.deepcopy(b);x['verificationProfile']['profileId']='unknown';x['receipt']['verificationProfileDigest']=sha(canon(x['verificationProfile']));add('unknown-profile',x,'HOLD','UNKNOWN_OR_AMBIGUOUS_PROFILE')
 x=copy.deepcopy(b);x['verificationProfile']['extension']='unknown';x['receipt']['verificationProfileDigest']=sha(canon(x['verificationProfile']));add('same-name-unknown-identity',x,'HOLD','UNKNOWN_OR_AMBIGUOUS_PROFILE')
 x=copy.deepcopy(b);x['verificationProfile']=n['verificationProfile'];add('profile-substitution',x,'GATE_REJECTED','PROFILE_BYTES_MISMATCH')
 x=copy.deepcopy(b);del x['verificationProfile'];add('historical-profile-unavailable',x,'HOLD','PROFILE_NOT_SUPPLIED')
 x=copy.deepcopy(b);x['receipt']['resultDigest']='0'*64;add('tampered-receipt',x,'GATE_REJECTED','rvr.gate.identity_mismatch')
 x=copy.deepcopy(n);x['receipt']['outcome']='REFUTED';add('contradictory-outcome',x,'GATE_REJECTED','rvr.gate.result_projection_mismatch')
 x=copy.deepcopy(n);x['payloadsBase64']={};add('unavailable-payload',x,'SELECTED','CANNOT_RECOMPUTE')
 x=copy.deepcopy(n);k=next(iter(x['payloadsBase64']));x['payloadsBase64'][k]='eA==';add('tampered-payload',x,'GATE_REJECTED','rvr.gate.identity_mismatch')
 x=copy.deepcopy(b);x['adapter']='ucd17-v1';x['version']='latest';add('ignored-claimed-adapter',x)
 x=copy.deepcopy(b);x['receipt']['verificationProfileDigest']='../adapter.py';add('path-as-identity',x,'GATE_REJECTED','MALFORMED_PROFILE_IDENTITY')
 add('candidate-diverged',b,'SELECTED','DIVERGED');rows[-1]['request']['candidateCase']=copy.deepcopy(b);rows[-1]['request']['candidateCase']['claim']['expectedDigest']='0'*64
 return rows

def observe(out,name,root,row,mode):
 p=out/'requests'/(row['id']+'.json')
 if not p.exists():save(p,row['request'])
 cmd=[sys.executable,'-B',*(['-O'] if mode=='optimized' else []),str(root/'migration/dispatch.py'),'--request',str(p),'--expected-profile',row['expectedProfile']]
 start=datetime.datetime.now(datetime.timezone.utc).isoformat();proc=subprocess.run(cmd,capture_output=True,cwd=root,timeout=90)
 log=out/'logs'/name;log.parent.mkdir(parents=True,exist_ok=True)
 log.with_suffix('.stdout').write_bytes(proc.stdout);log.with_suffix('.stderr').write_bytes(proc.stderr)
 save(log.with_suffix('.command.json'),dict(command=cmd,start=start,end=datetime.datetime.now(datetime.timezone.utc).isoformat(),exit=proc.returncode))
 try:
  result=json.loads(proc.stdout);status=result['migrationStatus'];detail=result.get('reason') if status!='SELECTED' else result['result']['recomputationStatus']
  healthy=(proc.returncode==0 if status=='SELECTED' else proc.returncode==2) and not proc.stderr
 except Exception:result={};status='CRASH';detail='CRASH';healthy=False
 return dict(status=status,detail=detail,match=healthy and status==row['status'] and detail==row['detail'],result=result,exit=proc.returncode,requestSha256=sha(p.read_bytes()))

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);ap.add_argument('--mutations',action='store_true');args=ap.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
 cs=cases();save(out/'CASES.json',cs);rows=[]
 for mode in ['normal','repeat','optimized']:
  for c in cs:
   got=observe(out,c['id']+'-'+mode,ROOT,c,mode);rows.append(dict(id=c['id'],mode=mode,**got));print(c['id'],mode,got['match'],got['status'],got['detail'],flush=True)
 save(out/'RESULTS.json',rows)
 save(out/'SUMMARY.json',dict(unique=len(cs),executions=len(rows),matched=sum(r['match'] for r in rows),failures=[r['id']+':'+r['mode'] for r in rows if not r['match']],independence='Receipt constructor and fixed status oracle import no candidate; same Codex session, not third-party review'))
 if not all(r['match'] for r in rows):raise SystemExit(1)
if __name__=='__main__':main()
