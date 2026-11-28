"""One-time packaging of separately versioned profiles; never changes old commits."""
import pathlib,subprocess,json,hashlib,shutil
ROOT=pathlib.Path(__file__).resolve().parents[2]
BASE='9dd36e882dd372f264b77b179130948aa5adcbde'
CANDIDATE='f42d356d9e6cc4df93d80573471456b647ba95b2'
RC2='f4476754c92e0bea549474722108ec60ded1385a'
sha=lambda b:hashlib.sha256(b).hexdigest()
def blob(commit,path):return subprocess.check_output(['git','show',commit+':'+path],cwd=ROOT)
def save(p,obj):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
def canonical(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def snapshot(commit,dest):
 manifest=json.loads(blob(commit,'conformance/rvr-v0/manifest.json'))
 for path in [m['path'] for m in manifest['members']]+['conformance/rvr-v0/manifest.json']:
  p=dest/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(blob(commit,path))

def main():
 new=ROOT/'profiles/generic-ucd17-v1'
 old=ROOT/'migration/packages/rc2'
 if new.exists() or old.exists():raise RuntimeError('Packaging already performed; do not reseal')
 snapshot(CANDIDATE,new);snapshot(RC2,old)
 # Restore the published route exactly; the repaired runtime now has its own package.
 for n in ['adapter.py','adapter.ts','manifest.json']:(ROOT/'conformance/rvr-v0'/n).write_bytes(blob(BASE,'conformance/rvr-v0/'+n))
 (ROOT/'conformance/rvr-v0/ecma-unicode.cjs').unlink()
 pkg=new/'conformance/rvr-v0';profile=json.loads((pkg/'verification-profile.json').read_bytes())
 profile['profileId']='rvr-generic-sha256-equals-ucd17-v1'
 constraints=json.loads((pkg/'rvr-generic-sha256-equals-v0.profile.schema.json').read_bytes())
 constraints['properties']['profileId']['const']=profile['profileId'];save(pkg/'rvr-generic-sha256-equals-v0.profile.schema.json',constraints)
 schema=json.loads((pkg/'rvr.schema.json').read_bytes())
 schema['$defs']['mediaTypeString']={'type':'string'}
 schema['$defs']['presentEvidenceMember']['properties']['mediaType']={'$ref':'#/$defs/mediaTypeString','minLength':1}
 save(pkg/'rvr.schema.json',schema)
 policy='''\n\n## Versioned schema contract: rvr-generic-sha256-equals-ucd17-v1

This NEW opt-in profile uses the same six-field RVR receipt and SHA256_EQUALS
operation. It does not redefine ERC-8404 or migrate any old receipt.
The schema is the bounded subset implemented by the separately pinned adapter,
not a claim of full JSON Schema 2020-12 support. All supported local $ref siblings
are conjunctive. String minLength/maxLength count Unicode code points; pattern
is ECMAScript Unicode u search with Unicode 17.0.0 data, no implicit anchoring
and no i/m/s/g/v flags. \\d is ASCII. Malformed patterns cannot produce acceptance.
The pinned regexpu-core6.4.0/regjsparser0.13.0/regenerate-unicode-properties10.2.2
bundle supplies Unicode data; engine absence is inability to verify.
The present-evidence mediaType string has minLength1 in this profile, intentionally
unlike the original generic profile, which permitted the empty string. No old
receipt acquires this constraint. The assertion subset is local $ref, type,
const, enum, pattern, minLength, maxLength, minItems, maxItems, items,
properties, required, additionalProperties:false, and oneOf. Other assertion
keywords are not supported by this profile. The pinned schemas use this subset;
a changed schema is a different profile identity and has no automatic route.
Historical profiles must use their authenticated historical contracts. Unknown
or ambiguous identities have no automatic fallback to this profile. New profile
identity means new receipts; old signed bytes and old results are never rewritten.
'''
 spec=new/'docs/spec/RECOMPUTABLE_VERIFICATION_RECEIPTS_V0.md';spec.write_text(spec.read_text(encoding='utf-8')+policy,encoding='utf-8',newline='\n')
 for dep in [*profile['profileSchemaContract'].values(),profile['verificationSpecification'],*profile['schemaContracts'],*profile['conformanceVectorSet']['members']]:dep['sha256']=sha((new/dep['path']).read_bytes())
 sd=sha((pkg/'rvr.schema.json').read_bytes())
 for k in ['evidenceSetContract','canonicalResultContract']:profile[k]['schemaSha256']=sd
 save(pkg/'verification-profile.json',profile)
 manifest=json.loads((pkg/'manifest.json').read_bytes())
 for m in manifest['members']:m['sha256']=sha((new/m['path']).read_bytes())
 manifest['packageDigest']=sha(''.join(m['path']+'\t'+m['sha256']+'\n' for m in manifest['members']).encode());save(pkg/'manifest.json',manifest)
 routes=[]
 for name,root,source in [('rc2-frozen',old,RC2),('published-v0',ROOT,BASE),('ucd17-v1',new,CANDIDATE)]:
  pp=root/'conformance/rvr-v0/verification-profile.json';p=json.loads(pp.read_bytes());m=json.loads((pp.parent/'manifest.json').read_bytes())
  members={x['path']:x['sha256'] for x in m['members']};members['conformance/rvr-v0/manifest.json']=sha((pp.parent/'manifest.json').read_bytes())
  routes.append(dict(adapterId=name,profileDigest=sha(canonical(p)),profileId=p['profileId'],root=root.relative_to(ROOT).as_posix(),sourceCommit=source,files=members))
 save(ROOT/'migration/registry.json',{'format':'rvr.local-profile-routes.v1','routes':routes})
 print(json.dumps({'registrySha256':sha((ROOT/'migration/registry.json').read_bytes()),'routes':[{k:r[k] for k in ['adapterId','profileDigest','profileId']} for r in routes]},indent=2))
if __name__=='__main__':main()
