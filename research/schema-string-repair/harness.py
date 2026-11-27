"""Public CLI repair campaign; all faulted packages are disposable copies.
Existing expected.json/mutants.json/profile schemas in Git remain unchanged.
"""
import argparse,copy,datetime,hashlib,io,json,shutil,subprocess,sys,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BASE='9dd36e882dd372f264b77b179130948aa5adcbde'
sha=lambda b:hashlib.sha256(b).hexdigest()
def save(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
def baseline():
    raw=subprocess.check_output(['git','archive','--format=zip',BASE],cwd=ROOT)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:return {n:z.read(n) for n in z.namelist() if not n.endswith('/')}
def package(dest,files,case=None,adapters=None):
    if dest.exists():raise RuntimeError('Refuse package overwrite '+str(dest))
    for name,raw in files.items():
        p=dest/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
    pkg=dest/'conformance/rvr-v0'
    if case:
        schema=json.loads((pkg/'rvr.schema.json').read_bytes());v=json.loads((pkg/'vectors.json').read_bytes());target=case.get('target','media')
        evidence=v['verificationCases']['reproduced']['evidenceSet']
        if target=='media':
            schema['$defs']['presentEvidenceMember']['properties']['mediaType']=case['rule'];evidence['members'][0]['mediaType']=case['value']
        elif target=='members':schema['$defs']['evidenceSet']['properties']['members'].update(case['rule'])
        elif target=='evidence':schema['$defs']['evidenceSet'].update(case['rule'])
        elif target=='extra-evidence':evidence['extra']='uncommitted'
        else:raise RuntimeError(target)
        save(pkg/'rvr.schema.json',schema);save(pkg/'vectors.json',v)
        profile=json.loads((pkg/'verification-profile.json').read_bytes());profile['profileId']='rvr-lab-schema-string-repair'
        constraints=json.loads((pkg/'rvr-generic-sha256-equals-v0.profile.schema.json').read_bytes());constraints['properties']['profileId']['const']=profile['profileId'];save(pkg/'rvr-generic-sha256-equals-v0.profile.schema.json',constraints)
        spec=dest/'docs/spec/RECOMPUTABLE_VERIFICATION_RECEIPTS_V0.md'
        spec.write_text(spec.read_text(encoding='utf-8')+'\n\n## Disposable schema-string repair laboratory profile\n\nNot the frozen profile identity. SHA256_EQUALS evaluation is unchanged. Schema roles in rvr-schema are receipt #, claim #/$defs/claim, evidence #/$defs/evidenceSet, result #/$defs/canonicalResult. The schema dialect is JSON Schema draft 2020-12. String lengths count Unicode code points; pattern has ECMA-262 search semantics without added flags or implicit anchors. Unsupported assertions are not evidence of instance validity. This profile is synthetic test input; no historical receipts are reinterpreted.\n',encoding='utf-8',newline='\n')
        deps=[*profile['profileSchemaContract'].values(),profile['verificationSpecification'],*profile['schemaContracts'],*profile['conformanceVectorSet']['members']]
        for d in deps:d['sha256']=sha((dest/d['path']).read_bytes())
        sd=sha((pkg/'rvr.schema.json').read_bytes());profile['evidenceSetContract']['schemaSha256']=sd;profile['canonicalResultContract']['schemaSha256']=sd
        profile['conformanceVectorSet']['digest']=sha(''.join(d['path']+'\t'+d['sha256']+'\n' for d in sorted(profile['conformanceVectorSet']['members'],key=lambda d:d['path'])).encode());save(pkg/'verification-profile.json',profile)
    if adapters:
        for n,raw in adapters.items():(pkg/n).write_bytes(raw)
    # New derived distribution identity only in this disposable package.
    manifest=json.loads((pkg/'manifest.json').read_bytes())
    for m in manifest['members']:m['sha256']=sha((dest/m['path']).read_bytes())
    manifest['packageDigest']=sha(''.join(m['path']+'\t'+m['sha256']+'\n' for m in manifest['members']).encode());save(pkg/'manifest.json',manifest)
    for n in ['expected.json','mutants.json']:
        if (pkg/n).read_bytes()!=files['conformance/rvr-v0/'+n]:raise RuntimeError('Changed historical expectations')
    return dest
def run(out,name,cmd,cwd):
    d=out/'logs'/name;d.parent.mkdir(parents=True,exist_ok=True)
    if d.with_suffix('.command.json').exists():raise RuntimeError('Refuse log overwrite '+name)
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();r=subprocess.run(cmd,cwd=cwd,capture_output=True)
    d.with_suffix('.stdout').write_bytes(r.stdout);d.with_suffix('.stderr').write_bytes(r.stderr)
    save(d.with_suffix('.command.json'),{'command':cmd,'cwd':str(cwd),'start':start,'end':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit':r.returncode})
    if r.returncode==0:
        report=json.loads(r.stdout);return {'status':'ACCEPT','profile_digest':report['verificationProfileDigest'],'report':report,'exit':0}
    err=r.stderr.decode(errors='replace')
    if 'invalid schema keyword:' in err or 'invalid schema pattern' in err:status='INVALID_SCHEMA'
    elif 'evidence set:' in err or 'claim:' in err:status='REJECT'
    else:status='CRASH_OR_UNCLASSIFIED'
    return {'status':status,'exit':r.returncode,'stderr':err}
def cli(out,name,pkg,lang,mode):
    cmd=[sys.executable,'-B']+(['-O'] if mode=='optimized' else [])+[str(pkg/'conformance/rvr-v0/adapter.py'),'--check'] if lang=='python' else ['bun',str(pkg/'conformance/rvr-v0/adapter.ts'),'--check']
    return run(out,name,cmd,pkg)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);ap.add_argument('--baseline-too',action='store_true');args=ap.parse_args();out=args.output.resolve()
    if out.exists():raise RuntimeError('Output exists')
    out.mkdir(parents=True)
    files=baseline();adapters={n:(ROOT/'conformance/rvr-v0'/n).read_bytes() for n in ['adapter.py','adapter.ts']};cases=json.loads((Path(__file__).parent/'cases.json').read_bytes())
    save(out/'SOURCE_PINS.json',{'base':BASE,'candidate_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip(),'candidate_adapters':{n:sha(b) for n,b in adapters.items()},'baseline_files':{n:sha(b) for n,b in files.items()},'cases_sha256':sha((Path(__file__).parent/'cases.json').read_bytes())})
    rows=[]
    for variant in (['before','after'] if args.baseline_too else ['after']):
        for case in cases:
            pkg=package(out/'packages'/variant/case['id'],files,case,adapters if variant=='after' else None)
            results={}
            for lang,modes in [('python',['normal','repeat','optimized']),('typescript',['normal','repeat'])]:
                results[lang]={m:cli(out,variant+'-'+case['id']+'-'+lang+'-'+m,pkg,lang,m) for m in modes}
            pd=sha(json.dumps(json.loads((pkg/'conformance/rvr-v0/verification-profile.json').read_bytes()),sort_keys=True,ensure_ascii=False,separators=(',',':')).encode())
            row={'variant':variant,'id':case['id'],'expected':case['expected'],'known_gap':case.get('known_gap',False),'required':case.get('required',False),'profile_digest':pd,'results':results}
            rows.append(row);print(variant,case['id'],[results[l]['normal']['status'] for l in results],flush=True)
    save(out/'RESULTS.json',rows)
    after=[r for r in rows if r['variant']=='after'];unexpected=[r['id'] for r in after if not r['known_gap'] and any(v['status']!=r['expected'] for modes in r['results'].values() for v in modes.values())]
    unstable=[r['id'] for r in rows if any(len({v['status'] for v in modes.values()})!=1 for modes in r['results'].values())]
    save(out/'SUMMARY.json',{'datasets':len(rows),'cases':len(cases),'required_cases':sum(c['required'] for c in after),'unexpected':unexpected,'unstable':unstable,'known_gaps':[r['id'] for r in after if r['known_gap']],'scope':'Full documented CLI in disposable packages. Repeats are not independent scenarios; known gaps remain HOLD.'})
    if unexpected or unstable:raise SystemExit(1)
if __name__=='__main__':main()
