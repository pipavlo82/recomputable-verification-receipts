"""Physical malformed-runtime-response controls, not malformed receipts."""
import argparse,pathlib,json,shutil
import migration_campaign as c
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 root=out/'copy';registry=json.loads((c.ROOT/'migration/registry.json').read_bytes())
 for r in registry['routes']:
  for f in r['files']:
   p=root/r['root']/f;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((c.ROOT/r['root']/f).read_bytes())
 (root/'migration').mkdir(exist_ok=True);shutil.copy2(c.ROOT/'migration/registry.json',root/'migration/registry.json')
 original=(c.ROOT/'migration/dispatch.py').read_text(encoding='utf-8')
 needle='    reports.append(parse(p.stdout))'
 if needle not in original:needle='    try:reply=parse(p.stdout)'
 assert original.count(needle)==1
 instrument="    if req.get('testRuntimeFault')=='json':p.stdout=b'{'\n    if req.get('testRuntimeFault')=='shape':p.stdout=b'{}'\n"
 (root/'migration/dispatch.py').write_text(original.replace(needle,instrument+needle),encoding='utf-8',newline='\n')
 p=c.cases()[0];rows=[c.observe(out,'positive',root,p,'normal')]
 for fault in ['json','shape']:
  n=json.loads(json.dumps(p));n['id']='runtime-'+fault;n['request']['testRuntimeFault']=fault;n['status']='HOLD';n['detail']='ADAPTER_RESPONSE_INVALID'
  rows.append(c.observe(out,n['id'],root,n,'normal'))
 (root/'migration/dispatch.py').write_text(original,encoding='utf-8',newline='\n');rows.append(c.observe(out,'restored',root,p,'normal'))
 c.save(out/'RESULTS.json',rows);print(json.dumps(rows,indent=2))
 if not all(r['match'] for r in rows):raise SystemExit(1)
if __name__=='__main__':main()
