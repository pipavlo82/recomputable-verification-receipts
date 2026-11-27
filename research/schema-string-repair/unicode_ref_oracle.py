"""Independent full-schema oracle; imports no adapter or candidate helper."""
import argparse,copy,hashlib,json,subprocess
from pathlib import Path
from jsonschema import Draft202012Validator,SchemaError,ValidationError,validators
def walk(x):
    yield x
    if isinstance(x,dict):
        for v in x.values():yield from walk(v)
    elif isinstance(x,list):
        for v in x:yield from walk(v)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--campaign',type=Path,required=True);a=ap.parse_args();out=[]
    for case in json.loads((a.campaign/'CASES.json').read_bytes()):
        root=a.campaign/'packages'/case['id'];pkg=root/'conformance/rvr-v0';p=json.loads((pkg/'verification-profile.json').read_bytes())
        for d in [*p['profileSchemaContract'].values(),p['verificationSpecification'],*p['schemaContracts'],*p['conformanceVectorSet']['members']]:
            if hashlib.sha256((root/d['path']).read_bytes()).hexdigest()!=d['sha256']:raise RuntimeError('Dependency pin mismatch')
        schema=json.loads((pkg/'rvr.schema.json').read_bytes());value=json.loads((pkg/'vectors.json').read_bytes())['verificationCases']['reproduced']['evidenceSet']
        patterns=sorted({x['pattern'] for x in walk(schema) if isinstance(x,dict) and isinstance(x.get('pattern'),str)})
        values=sorted({x for x in walk(value) if isinstance(x,str)})
        js="let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>{let x=JSON.parse(s);console.log(JSON.stringify(x.patterns.map(p=>{try{let r=new RegExp(p,'u');return {valid:true,matches:x.values.map(v=>r.test(v))}}catch{return {valid:false}}})))})"
        r=subprocess.run(['node','-e',js],input=json.dumps({'patterns':patterns,'values':values}).encode(),capture_output=True,check=True)
        parsed=json.loads(r.stdout);table={p:r for p,r in zip(patterns,parsed)}
        meta=copy.deepcopy(schema)
        # jsonschema's regex-format implementation uses Python syntax. Validate
        # non-regex meta-schema structure there; actual regex syntax via ECMA u.
        for x in walk(meta):
            if isinstance(x,dict) and isinstance(x.get('pattern'),str):x['pattern']=''
        try:Draft202012Validator.check_schema(meta)
        except SchemaError:actual='INVALID_SCHEMA'
        else:
            if any(not x['valid'] for x in parsed):actual='INVALID_SCHEMA'
            else:
                def pattern(validator,pattern,instance,schema):
                    if isinstance(instance,str) and not table[pattern]['matches'][values.index(instance)]:yield ValidationError('ECMA Unicode pattern mismatch')
                cls=validators.extend(Draft202012Validator,{'pattern':pattern})
                scoped={'$defs':schema['$defs'],'$ref':'#/$defs/evidenceSet'}
                actual='REJECT' if list(cls(scoped).iter_errors(value)) else 'ACCEPT'
        if actual!=case['expected']:raise RuntimeError((case['id'],actual,case['expected']))
        out.append({'id':case['id'],'expected':case['expected'],'oracle':actual,'profile_bytes_sha256':hashlib.sha256((pkg/'verification-profile.json').read_bytes()).hexdigest()})
    print(json.dumps({'passed':len(out),'results':out,'boundary':'Separate jsonschema evaluation; Node regex primitive also used by Python candidate, so not a third independently implemented regex engine.'},indent=2))
if __name__=='__main__':main()
