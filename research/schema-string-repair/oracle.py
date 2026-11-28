"""Independent contract oracle: jsonschema + native ECMAScript regex, no Core import."""
import argparse,copy,hashlib,json,subprocess
from pathlib import Path
from jsonschema import Draft202012Validator,SchemaError
sha=lambda b:hashlib.sha256(b).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--campaign',type=Path,required=True);a=ap.parse_args();campaign=a.campaign.resolve()
    cases=json.loads((Path(__file__).parent/'cases.json').read_bytes())
    # Independently evaluate ECMA-262 pattern semantics without loading adapters.
    code="let b='';process.stdin.on('data',x=>b+=x);process.stdin.on('end',()=>{console.log(JSON.stringify(JSON.parse(b).map(c=>{if(!('pattern' in c.rule))return null;if(typeof c.rule.pattern!=='string')return 'INVALID_SCHEMA';try{const r=new RegExp(c.rule.pattern);if(typeof c.value!=='string')return 'NOT_APPLICABLE';return r.test(c.value)?'MATCH':'NO_MATCH'}catch{return 'INVALID_SCHEMA'}})))})"
    node=subprocess.run(['node','-e',code],input=json.dumps(cases).encode(),capture_output=True,check=True)
    regex=json.loads(node.stdout);rows=[]
    for c,match in zip(cases,regex):
        root=campaign/'packages/after'/c['id'];pkg=root/'conformance/rvr-v0';p=json.loads((pkg/'verification-profile.json').read_bytes())
        deps=[*p['profileSchemaContract'].values(),p['verificationSpecification'],*p['schemaContracts'],*p['conformanceVectorSet']['members']]
        for d in deps:
            if sha((root/d['path']).read_bytes())!=d['sha256']:raise RuntimeError('Untrusted dependency '+c['id'])
        schema=json.loads((pkg/'rvr.schema.json').read_bytes());vectors=json.loads((pkg/'vectors.json').read_bytes());evidence=vectors['verificationCases']['reproduced']['evidenceSet']
        try:Draft202012Validator.check_schema(schema)
        except SchemaError:actual='INVALID_SCHEMA'
        else:
            if match=='INVALID_SCHEMA':actual='INVALID_SCHEMA'
            else:
                check_schema=copy.deepcopy(schema)
                # Python regex is deliberately not the oracle for ECMA pattern.
                if 'pattern' in c['rule'] and c.get('target','media')=='media':check_schema['$defs']['presentEvidenceMember']['properties']['mediaType'].pop('pattern',None)
                scoped={'$defs':check_schema['$defs'],'$ref':'#/$defs/evidenceSet'}
                valid=not list(Draft202012Validator(scoped).iter_errors(evidence))
                actual='ACCEPT' if valid and match!='NO_MATCH' else 'REJECT'
        if actual!=c['expected']:raise RuntimeError((c['id'],actual,c['expected']))
        rows.append({'id':c['id'],'expected':c['expected'],'independent_actual':actual,'ecma_regex':match,'dependencies_authenticated':True})
    print(json.dumps({'cases':rows,'passed':len(rows),'scope':'Independent schema/input oracle; not a new RVR implementation; all native mismatches remain in campaign outputs'},indent=2))
if __name__=='__main__':main()
