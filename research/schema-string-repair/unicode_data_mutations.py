import argparse,json
from pathlib import Path
import harness as h
import unicode_data_campaign as u
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);ap.add_argument('--ids');a=ap.parse_args();o=a.output.resolve()
    if o.exists():raise RuntimeError('Existing output')
    o.mkdir(parents=True);sources=u.sources();files=h.baseline();cases={c['id']:c for c in u.cases()}
    mutations=[
      ('py-min','adapter.py','if "minLength" in schema and length < schema["minLength"]:','if False:','min-empty','min-ascii'),
      ('ts-min','adapter.ts','if (schema.minLength !== undefined && length < schema.minLength)','if (false)','min-empty','min-ascii'),
      ('py-max','adapter.py','if "maxLength" in schema and length > schema["maxLength"]:','if False:','max-ascii-over','max-emoji-one'),
      ('ts-max','adapter.ts','if (schema.maxLength !== undefined && length > schema.maxLength)','if (false)','max-ascii-over','max-emoji-one'),
      ('ts-utf16','adapter.ts','Array.from(value).length','value.length','min-emoji-two','min-emoji-one'),
      ('py-implicit-fullmatch','adapter.py',"compile(x.pattern)","compile('^(?:' + x.pattern + ')$')",'pattern-search','pattern-both'),
      ('py-no-unicode','adapter.py',"compile(x.pattern)","new RegExp(x.pattern)",'gap-dot-astral','unicode-dot-ascii'),
      ('ts-no-unicode','adapter.ts','compileUnicodePattern(schema.pattern)','new RegExp(schema.pattern)','gap-dot-astral','unicode-dot-ascii'),
      ('py-ref-skips-siblings','adapter.py','errors.extend(validate_schema(value, target, root, path))','return validate_schema(value, target, root, path)','ref-min-reject','ref-min-pass'),
      ('ts-ref-skips-siblings','adapter.ts','if ("$ref" in schema) validateSchema','if ("$ref" in schema) return validateSchema','ref-pattern-reject','ref-pattern-pass'),
      ('py-ignore-target','adapter.py','errors.extend(validate_schema(value, target, root, path))','pass # mutant ignores referenced constraints','ref-target-reject','ref-min-pass'),
      ('py-regex-bypass','adapter.py',"return response['match']",'return True','pattern-missing','pattern-search'),
      ('ts-regex-bypass','adapter.ts','if (typeof value === "string" && !expression.test(value))','if (false)','pattern-missing','pattern-search'),
      ('py-nonascii-digit-accepted','adapter.py','r.test(x.value)','r.test(x.value.replaceAll("١", "1"))','gap-unicode-digit','ascii-digit'),
      ('ts-nonascii-digit-accepted','adapter.ts','!expression.test(value)','!expression.test(value.replaceAll("١", "1"))','gap-unicode-digit','ascii-digit'),
      ('py-integral-float','adapter.py','type(bound) is int or (type(bound) is float and bound.is_integer())','type(bound) is int','min-integral-float','min-ascii'),
      ('py-multiline-anchors','adapter.py',"compile(x.pattern)","new RegExp(compile(x.pattern).source, 'm')",'gap-dollar-final-newline','pattern-both'),
      ('py-host-property-regression','adapter.py','compile(x.pattern)',"new RegExp(x.pattern, 'u')",'ucd-nd-11de0','ascii-digit'),
      ('ts-property-inversion','adapter.ts','compileUnicodePattern(schema.pattern)',"compileUnicodePattern(schema.pattern.replace('Decimal_Number', 'Letter'))",'ucd-nd-11de0','ascii-digit'),
      ('bundle-host-property-regression','ecma-unicode.cjs','return new RegExp(source);',"return new RegExp(pattern, 'u');",'ucd-nd-11de0','ascii-digit')]
    mutations.append(('bundle-native-names','ecma-unicode.cjs','unicodeFlag: "transform", namedGroups: "transform"','unicodeFlag: "transform"','ucd-group-name','pattern-search'))
    if a.ids:mutations=[m for m in mutations if m[0] in a.ids.split(',')]
    rows=[]
    for name,file,old,new,witness,positive in mutations:
        source=sources[file].decode()
        if source.count(old)!=1:raise RuntimeError(name)
        altered={**sources,file:source.replace(old,new).encode()};lang='python' if file.endswith(('.py','.cjs')) else 'typescript';observed={}
        for label,c,src in [('positive',positive,sources),('negative',witness,sources),('mutant',witness,altered),('mutant-positive',positive,altered),('restored-negative',witness,sources),('restored-positive',positive,sources)]:
            pkg=u.package(o/'packages'/(name+'-'+label),files,cases[c],src);observed[label]=h.cli(o,name+'-'+label,pkg,lang,'normal')
        healthy=all(observed[label]['status']==cases[c]['expected'] for label,c in [('positive',positive),('negative',witness),('restored-negative',witness),('restored-positive',positive)])
        actual=observed['mutant']['status'];positive_actual=observed['mutant-positive']['status']
        verdict='INVALID' if not healthy or 'CRASH_OR_UNCLASSIFIED' in [actual,positive_actual] else 'KILLED' if actual!=cases[witness]['expected'] or positive_actual!=cases[positive]['expected'] else 'SURVIVED'
        rows.append({'id':name,'verdict':verdict,'controls_healthy':healthy,'witness':witness,'expected':cases[witness]['expected'],'actual':actual,'source_sha256':h.sha(altered[file]),'observed':observed});print(name,verdict,flush=True)
    h.save(o/'RESULTS.json',rows)
    if any(r['verdict']!='KILLED' for r in rows):raise SystemExit(1)
if __name__=='__main__':main()
