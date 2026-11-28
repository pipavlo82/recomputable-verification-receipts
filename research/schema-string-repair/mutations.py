"""Physical source removals in disposable packages; crashes are INVALID, never kills."""
import argparse,json
from pathlib import Path
import harness as h
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();out=a.output.resolve()
    if out.exists():raise RuntimeError('Existing output')
    out.mkdir(parents=True);files=h.baseline();sources={n:(h.ROOT/'conformance/rvr-v0'/n).read_bytes() for n in ['adapter.py','adapter.ts']};cases={c['id']:c for c in json.loads((Path(__file__).parent/'cases.json').read_bytes())}
    mutants=[
      ('py-remove-min','adapter.py','if "minLength" in schema and length < schema["minLength"]:','if False:','min-empty','min-ascii'),
      ('ts-remove-min','adapter.ts','if (schema.minLength !== undefined && length < schema.minLength)','if (false)','min-empty','min-ascii'),
      ('py-fullmatch','adapter.py','expression.search(value)','expression.fullmatch(value)','pattern-search','pattern-both'),
      ('ts-utf16-length','adapter.ts','Array.from(value).length','value.length','min-emoji-two','min-emoji-one'),
      ('py-remove-max','adapter.py','if "maxLength" in schema and length > schema["maxLength"]:','if False:','max-ascii-over','max-emoji-one'),
      ('ts-remove-max','adapter.ts','if (schema.maxLength !== undefined && length > schema.maxLength)','if (false)','max-ascii-over','max-emoji-one'),
      ('py-remove-pattern-check','adapter.py','if isinstance(value, str) and expression.search(value) is None:','if False:','pattern-missing','pattern-search'),
      ('ts-remove-pattern-check','adapter.ts','if (typeof value === "string" && !expression.test(value))','if (false)','pattern-missing','pattern-search'),
      ('py-remove-end-anchor-correction','adapter.py','re.compile(schema_pattern_source(schema["pattern"]))','re.compile(schema["pattern"])','gap-dollar-final-newline','pattern-both'),
      ('py-reject-integral-float','adapter.py','type(bound) is int or (type(bound) is float and bound.is_integer())','type(bound) is int','min-integral-float','min-ascii')]
    rows=[]
    for name,file,old,new,witness,positive in mutants:
        raw=sources[file].decode();lang='python' if file.endswith('.py') else 'typescript'
        if raw.count(old)!=1:raise RuntimeError(name)
        altered={**sources,file:raw.replace(old,new).encode()};observed={}
        for label,case,src in [('positive',positive,sources),('witness-before',witness,sources),('mutant',witness,altered),('witness-restored',witness,sources),('positive-restored',positive,sources)]:
            pkg=h.package(out/'packages'/(name+'-'+label),files,cases[case],src)
            observed[label]=h.cli(out,name+'-'+label,pkg,lang,'normal')
        controls=all(observed[k]['status']==cases[c]['expected'] for k,c in [('positive',positive),('positive-restored',positive),('witness-before',witness),('witness-restored',witness)])
        status=observed['mutant']['status'];verdict='INVALID' if not controls or status=='CRASH_OR_UNCLASSIFIED' else 'KILLED' if status!=cases[witness]['expected'] else 'SURVIVED'
        rows.append({'id':name,'verdict':verdict,'controls_healthy':controls,'witness':witness,'expected':cases[witness]['expected'],'mutant_actual':status,'mutant_source_sha256':h.sha(altered[file]),'observed':observed});print(name,verdict,flush=True)
    h.save(out/'RESULTS.json',rows)
    if any(r['verdict']!='KILLED' for r in rows):raise SystemExit(1)
if __name__=='__main__':main()
