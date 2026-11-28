"""Additive Unicode-data campaign; historical expectations remain unchanged."""
import argparse,io,json,subprocess,zipfile,concurrent.futures
from pathlib import Path
import harness as h
import unicode_ref_campaign as u
PRIOR='ab476f466ad3f3c039b40b5174ec318da2ef8012'
POLICY='ECMA-262 Unicode u search; Unicode Character Database 17.0.0; no i/m/s/g/v flags. Explicit property ranges from pinned regexpu-core 6.4.0 and regenerate-unicode-properties 10.2.2. No dependency on host Unicode property tables. This is a new opt-in laboratory contract, not reinterpretation of any historical profile.'

def cases():
    rows=u.cases()
    def add(i,rule,v,want='ACCEPT'):rows.append(dict(id=i,rule=rule,value=v,expected=want))
    for cp in range(0x11dde,0x11dec):
        s=chr(cp);digit=0x11de0<=cp<=0x11de9;key=f'{cp:05x}'
        add('ucd-nd-'+key,{'pattern':r'^\p{Decimal_Number}$'},s,'ACCEPT' if digit else 'REJECT')
        add('ucd-notnd-'+key,{'pattern':r'^\P{Decimal_Number}$'},s,'REJECT' if digit else 'ACCEPT')
        add('ucd-ascii-digit-'+key,{'pattern':r'^\d$'},s,'REJECT')
    s=chr(0x11de0)
    for i,rule,want in [('dot',{'pattern':'^.$'},'ACCEPT'),('min1',{'minLength':1},'ACCEPT'),('min2',{'minLength':2},'REJECT'),('max1',{'maxLength':1},'ACCEPT'),('max0',{'maxLength':0},'REJECT'),('search',{'pattern':r'\p{Nd}'},'ACCEPT'),('refpass',{'$ref':'#/$defs/stringValue','pattern':r'^\p{Nd}$','minLength':1},'ACCEPT'),('refreject',{'$ref':'#/$defs/stringValue','pattern':r'^\p{Nd}$','minLength':2},'REJECT')]:
        add('ucd-'+i,rule,s,want)
        if i.startswith('ref'):rows[-1]['definitions']={'stringValue':{'type':'string'}}
    add('ucd-escaped-pair',{'pattern':r'^\p{Nd}$'},s);rows[-1]['ucd_escape']=True
    for i,p,v,w in [('alias',r'^\p{General_Category=Decimal_Number}$',s,'ACCEPT'),('class',r'^[\p{Nd}x]$',s,'ACCEPT'),('script',r'^\p{Script=Tolong_Siki}$',s,'ACCEPT'),('letter',r'^\p{Letter}$',s,'REJECT'),('assigned',r'^\p{Assigned}$',s,'ACCEPT'),('unknown-property',r'\p{NotAProperty}',s,'INVALID_SCHEMA'),('escaped-literal',r'^\\p\{Nd\}$',r'\p{Nd}','ACCEPT')]:add('ucd-'+i,{'pattern':p},v,w)
    name=chr(0x11db0)
    add('ucd-group-name',{'pattern':'^(?<'+name+'>.)$'},'x')
    add('ucd-group-backref',{'pattern':'^(?<'+name+'>.)\\k<'+name+'>$'},'xx')
    add('ucd-group-backref-negative',{'pattern':'^(?<'+name+'>.)\\k<'+name+'>$'},'xy','REJECT')
    return rows

def sources(before=False):
    if before:
        raw=subprocess.check_output(['git','archive','--format=zip',PRIOR],cwd=h.ROOT)
        with zipfile.ZipFile(io.BytesIO(raw)) as z:return {n:z.read('conformance/rvr-v0/'+n) for n in ['adapter.py','adapter.ts']}
    return {n:(h.ROOT/'profiles/generic-ucd17-v1/conformance/rvr-v0'/n).read_bytes() for n in ['adapter.py','adapter.ts','ecma-unicode.cjs']}

def package(out,files,case,src):
    root=u.package(out,files,case,src);pkg=root/'conformance/rvr-v0'
    p=json.loads((pkg/'verification-profile.json').read_bytes());p['profileId']='rvr-lab-unicode-data-17-candidate'
    c=json.loads((pkg/'rvr-generic-sha256-equals-v0.profile.schema.json').read_bytes());c['properties']['profileId']['const']=p['profileId'];h.save(pkg/'rvr-generic-sha256-equals-v0.profile.schema.json',c)
    spec=root/'docs/spec/RECOMPUTABLE_VERIFICATION_RECEIPTS_V0.md';spec.write_text(spec.read_text(encoding='utf-8')+'\n\n## Pinned Unicode data research contract\n\n'+POLICY+'\n',encoding='utf-8',newline='\n')
    if case.get('ucd_escape'):
        v=pkg/'vectors.json';v.write_bytes(v.read_bytes().replace(chr(0x11de0).encode(),b'\\ud807\\udde0'))
    deps=[*p['profileSchemaContract'].values(),p['verificationSpecification'],*p['schemaContracts'],*p['conformanceVectorSet']['members']]
    for d in deps:d['sha256']=h.sha((root/d['path']).read_bytes())
    p['conformanceVectorSet']['digest']=h.sha(''.join(d['path']+'\t'+d['sha256']+'\n' for d in sorted(p['conformanceVectorSet']['members'],key=lambda d:d['path'])).encode());h.save(pkg/'verification-profile.json',p)
    m=json.loads((pkg/'manifest.json').read_bytes())
    if 'ecma-unicode.cjs' in src:m['members'].append({'path':'conformance/rvr-v0/ecma-unicode.cjs','sha256':h.sha(src['ecma-unicode.cjs'])});m['members'].sort(key=lambda d:d['path'])
    for d in m['members']:d['sha256']=h.sha((root/d['path']).read_bytes())
    m['memberCount']=len(m['members'])
    m['packageDigest']=h.sha(''.join(d['path']+'\t'+d['sha256']+'\n' for d in m['members']).encode());h.save(pkg/'manifest.json',m)
    return root

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);ap.add_argument('--before',action='store_true');ap.add_argument('--new-only',action='store_true');ap.add_argument('--ids');a=ap.parse_args();o=a.output.resolve();o.mkdir(exist_ok=False)
    cs=cases();cs=cs[97:] if a.new_only else cs;h.save(o/'CASES.json',cs);src=sources(a.before);files=h.baseline();rows=[]
    if a.ids:cs=[c for c in cs if c['id'] in a.ids.split(',')];h.save(o/'CASES.json',cs)
    h.save(o/'SOURCE_PINS.json',{'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=h.ROOT).decode().strip(),'source':{n:h.sha(b) for n,b in src.items()},'before':a.before})
    def execute(c):
        p=package(o/'packages'/c['id'],files,c,src)
        r={l:{m:h.cli(o,c['id']+'-'+l+'-'+m,p,l,m) for m in modes} for l,modes in [('python',['normal','repeat','optimized']),('typescript',['normal','repeat'])]}
        row={'id':c['id'],'expected':c['expected'],'profile_bytes_sha256':h.sha((p/'conformance/rvr-v0/verification-profile.json').read_bytes()),'results':r};print(c['id'],*[r[l]['normal']['status'] for l in r],flush=True)
        return row
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:rows=list(pool.map(execute,cs))
    h.save(o/'RESULTS.json',rows);bad=[r['id'] for r in rows if any(v['status']!=r['expected'] for ms in r['results'].values() for v in ms.values())];h.save(o/'SUMMARY.json',{'scenarios':len(rows),'executions':len(rows)*5,'mismatches':bad})
    if bad and not a.before:raise SystemExit(1)
if __name__=='__main__':main()
