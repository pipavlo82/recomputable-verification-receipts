import argparse,datetime,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();out=a.output.resolve()
    if out.exists():raise RuntimeError('Existing output')
    out.mkdir(parents=True);jobs=[]
    profiles=['erc8281-committed-receipt-snapshot-v0','invinoveritas-signed-verdict-v0','invinoveritas-signed-verdict-v1','judge-protocol-rvr-v0']
    for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:
        prefix=[sys.executable,'-B',*flags]
        jobs.extend([('core-'+mode,prefix+['conformance/rvr-v0/adapter.py','--check']),('unittest-'+mode,prefix+['-m','unittest','discover','-s','tests','-p','test_*.py'])])
        for p in profiles:
            jobs.extend([(p+'-gate-'+mode,prefix+['profiles/'+p+'/adapter.py','--check']),(p+'-test-'+mode,prefix+['profiles/'+p+'/test_profile.py'])])
    for mode in ['normal','repeat']:jobs.append(('core-typescript-'+mode,['bun','conformance/rvr-v0/adapter.ts','--check']))
    rows=[]
    for name,cmd in jobs:
        start=datetime.datetime.now(datetime.timezone.utc).isoformat();p=subprocess.run(cmd,cwd=ROOT,capture_output=True)
        (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
        row={'id':name,'command':cmd,'cwd':str(ROOT),'start':start,'end':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit':p.returncode}
        (out/(name+'.command.json')).write_text(json.dumps(row,indent=2)+'\n',encoding='utf-8',newline='\n');rows.append(row);print(name,p.returncode,flush=True)
    (out/'RESULTS.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8',newline='\n')
    if any(r['exit'] for r in rows):raise SystemExit(1)
if __name__=='__main__':main()
