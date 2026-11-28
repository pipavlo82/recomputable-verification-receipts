"""Controls for dispatcher decoding and malformed adapter responses."""
import argparse,contextlib,io,pathlib,json,runpy,shutil,sys
from unittest.mock import patch
import migration_campaign as c

def decoder_limit_control(out):
 dispatcher=c.ROOT/'migration/dispatch.py'
 cli=runpy.run_path(str(dispatcher))['main']
 request=out/'requests'/'decoder-limit-control.json'
 request.write_bytes(b'{}')
 args=[str(dispatcher),'--request',str(request),'--expected-profile','0'*64]
 stdout,stderr=io.StringIO(),io.StringIO()
 with patch.object(sys,'argv',args),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
  with patch.object(json,'loads',side_effect=RecursionError('simulated decoder nesting limit')):
   exit_code=cli()
 log=out/'logs'/'decoder-limit-control'
 log.with_suffix('.stdout').write_text(stdout.getvalue(),encoding='utf-8',newline='\n')
 log.with_suffix('.stderr').write_text(stderr.getvalue(),encoding='utf-8',newline='\n')
 c.save(log.with_suffix('.command.json'),dict(args=args,mode='decoder-fault-injection',exit=exit_code))
 result=json.loads(stdout.getvalue())
 expected=dict(migrationStatus='GATE_REJECTED',evaluationPerformed=False,reason='MALFORMED_INPUT')
 return dict(status=result.get('migrationStatus'),detail=result.get('reason'),match=exit_code==2 and result==expected and not stderr.getvalue(),
             result=result,exit=exit_code,requestSha256=c.sha(request.read_bytes()))
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
 rows.append(decoder_limit_control(out))
 c.save(out/'RESULTS.json',rows);print(json.dumps(rows,indent=2))
 if not all(r['match'] for r in rows):raise SystemExit(1)
if __name__=='__main__':main()
