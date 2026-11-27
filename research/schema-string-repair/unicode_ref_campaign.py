"""New pinned Unicode laboratory contract. Preserves the old no-flags suite."""
import argparse,copy,io,json,subprocess,zipfile
from pathlib import Path
import harness as h
PRIOR='ceb9bf18a7c346d4bebcca7f92dfc76fa40e4dea'
HERE=Path(__file__).resolve().parent

def cases():
    rows=copy.deepcopy(json.loads((HERE/'cases.json').read_bytes()))
    for r in rows:
        r['known_gap']=False
        if r['id']=='gap-dot-astral':
            r['expected']='ACCEPT';r['contract_change']='NEW_UNICODE_PROFILE; old no-flags expected remains REJECT'
    def add(name,rule,value,expected='ACCEPT',**extra):rows.append(dict(id=name,rule=rule,value=value,expected=expected,**extra))
    add('unicode-dot-ascii',{'pattern':'^.$'},'x')
    for name,value in [('cr','\r'),('lf','\n'),('ls','\u2028'),('ps','\u2029')]:add('unicode-dot-'+name,{'pattern':'^.$'},value,'REJECT')
    add('unicode-dot-escaped-pair',{'pattern':'^.$'},'😀',escaped_pair=True)
    add('ascii-digit',{'pattern':r'^\d$'},'7')
    add('devanagari-digit',{'pattern':r'^\d$'},'७','REJECT')
    add('non-ascii-nondigit',{'pattern':r'^\D$'},'١')
    add('unicode-decimal-property',{'pattern':r'^\p{Decimal_Number}$'},'١')
    add('word-ascii',{'pattern':r'^\w$'},'a')
    add('word-unicode',{'pattern':r'^\w$'},'é','REJECT')
    add('space-bom',{'pattern':r'^\s$'},'\ufeff')
    add('space-nel',{'pattern':r'^\s$'},'\u0085','REJECT')
    add('unicode-codepoint-escape',{'pattern':r'^\u{1F600}$'},'😀')
    add('unicode-surrogate-pattern',{'pattern':r'^\uD83D\uDE00$'},'😀')
    add('unicode-invalid-escape',{'pattern':r'\q'},'q','INVALID_SCHEMA')
    add('unicode-invalid-range',{'pattern':'[z-a]'},'x','INVALID_SCHEMA')
    add('unicode-invalid-paren',{'pattern':'('},'x','INVALID_SCHEMA')
    for name,rule,expected in [
      ('ref-min-pass',{'minLength':3},'ACCEPT'),('ref-min-reject',{'minLength':4},'REJECT'),
      ('ref-max-reject',{'maxLength':2},'REJECT'),('ref-pattern-pass',{'pattern':'b'},'ACCEPT'),
      ('ref-pattern-reject',{'pattern':'^z'},'REJECT'),('ref-type-reject',{'type':'boolean'},'REJECT'),
      ('ref-enum-pass',{'enum':['abc']},'ACCEPT'),('ref-enum-reject',{'enum':['def']},'REJECT'),
      ('ref-oneof-reject',{'oneOf':[{'const':'abc'},{'type':'string'}]},'REJECT')]:
        add(name,{'$ref':'#/$defs/identifier',**rule},'abc',expected)
    add('ref-target-reject',{'$ref':'#/$defs/identifier','minLength':1},'ABC','REJECT')
    for name,rule,expected,target,definition in [
      ('ref-object-pass',{},'ACCEPT','evidence',{'anyObject':{'type':'object'}}),
      ('ref-required-reject',{'required':['missing']},'REJECT','evidence',{'anyObject':{'type':'object'}}),
      ('ref-properties-reject',{'properties':{'schema':{'const':'wrong'}}},'REJECT','evidence',{'anyObject':{'type':'object'}}),
      ('ref-additional-reject',{'properties':{},'additionalProperties':False},'REJECT','evidence',{'anyObject':{'type':'object'}}),
      ('ref-minitems-reject',{'minItems':2},'REJECT','members',{'anyArray':{'type':'array'}}),
      ('ref-maxitems-reject',{'maxItems':0},'REJECT','members',{'anyArray':{'type':'array'}}),
      ('ref-items-reject',{'items':{'const':None}},'REJECT','members',{'anyArray':{'type':'array'}})]:
        add(name,{'$ref':'#/$defs/'+next(iter(definition)),**rule},None,expected,target=target,definitions=definition)
    return rows

def package(out,files,case,adapters):
    root=h.package(out,files,case,adapters);pkg=root/'conformance/rvr-v0'
    p=json.loads((pkg/'verification-profile.json').read_bytes());p['profileId']='rvr-lab-ecma-unicode-ref-candidate'
    if case.get('definitions'):
        schema=json.loads((pkg/'rvr.schema.json').read_bytes());schema['$defs'].update(case['definitions']);h.save(pkg/'rvr.schema.json',schema)
        p['evidenceSetContract']['schemaSha256']=p['canonicalResultContract']['schemaSha256']=h.sha((pkg/'rvr.schema.json').read_bytes())
    constraints=json.loads((pkg/'rvr-generic-sha256-equals-v0.profile.schema.json').read_bytes());constraints['properties']['profileId']['const']=p['profileId'];h.save(pkg/'rvr-generic-sha256-equals-v0.profile.schema.json',constraints)
    spec=root/'docs/spec/RECOMPUTABLE_VERIFICATION_RECEIPTS_V0.md'
    text=spec.read_text(encoding='utf-8').split('\n\n## Disposable schema-string repair laboratory profile')[0]
    text+='\n\n## Explicit Unicode reference research profile\n\nThis new laboratory profile is not an old signed profile. SHA256_EQUALS evaluation unchanged. Schema roles: receipt #, claim #/$defs/claim, evidence #/$defs/evidenceSet, result #/$defs/canonicalResult. JSON Schema draft 2020-12; pattern is ECMA-262 Unicode RegExp with exactly u, search semantics. Dot consumes a Unicode code point except ECMAScript line terminators. Digit escape means ASCII [0-9]. Local $ref and all supported adjacent assertions apply conjunctively. Length counts Unicode code points. No historical no-flags profile is reinterpreted.\n'
    spec.write_text(text,encoding='utf-8',newline='\n')
    if case.get('escaped_pair'):
        v=pkg/'vectors.json';v.write_bytes(v.read_bytes().replace('😀'.encode(),b'\\ud83d\\ude00'))
    deps=[*p['profileSchemaContract'].values(),p['verificationSpecification'],*p['schemaContracts'],*p['conformanceVectorSet']['members']]
    for d in deps:d['sha256']=h.sha((root/d['path']).read_bytes())
    p['conformanceVectorSet']['digest']=h.sha(''.join(d['path']+'\t'+d['sha256']+'\n' for d in sorted(p['conformanceVectorSet']['members'],key=lambda d:d['path'])).encode());h.save(pkg/'verification-profile.json',p)
    m=json.loads((pkg/'manifest.json').read_bytes())
    for d in m['members']:d['sha256']=h.sha((root/d['path']).read_bytes())
    m['packageDigest']=h.sha(''.join(d['path']+'\t'+d['sha256']+'\n' for d in m['members']).encode());h.save(pkg/'manifest.json',m)
    return root

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);ap.add_argument('--before',action='store_true');ap.add_argument('--ids');a=ap.parse_args();out=a.output.resolve()
    if out.exists():raise RuntimeError('Existing evidence')
    out.mkdir(parents=True);rows=cases()
    if a.ids:rows=[r for r in rows if r['id'] in a.ids.split(',')]
    h.save(out/'CASES.json',rows)
    files=h.baseline()
    if a.before:
        raw=subprocess.check_output(['git','archive','--format=zip',PRIOR],cwd=h.ROOT)
        with zipfile.ZipFile(io.BytesIO(raw)) as z:adapters={n:z.read('conformance/rvr-v0/'+n) for n in ['adapter.py','adapter.ts']}
    else:adapters={n:(h.ROOT/'conformance/rvr-v0'/n).read_bytes() for n in ['adapter.py','adapter.ts']}
    h.save(out/'SOURCE_PINS.json',{'prior':PRIOR,'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=h.ROOT).decode().strip(),'adapters':{n:h.sha(b) for n,b in adapters.items()}})
    results=[]
    for c in rows:
        pkg=package(out/'packages'/c['id'],files,c,adapters)
        r={l:{m:h.cli(out,c['id']+'-'+l+'-'+m,pkg,l,m) for m in modes} for l,modes in [('python',['normal','repeat','optimized']),('typescript',['normal','repeat'])]}
        results.append({'id':c['id'],'expected':c['expected'],'profile_bytes_sha256':h.sha((pkg/'conformance/rvr-v0/verification-profile.json').read_bytes()),'results':r})
        print(c['id'],*[r[l]['normal']['status'] for l in r],flush=True)
    h.save(out/'RESULTS.json',results)
    bad=[x['id'] for x in results if any(v['status']!=x['expected'] for modes in x['results'].values() for v in modes.values())]
    h.save(out/'SUMMARY.json',{'cases':len(rows),'executions':len(rows)*5,'mismatches':bad,'before':a.before})
    if bad and not a.before:raise SystemExit(1)
if __name__=='__main__':main()
