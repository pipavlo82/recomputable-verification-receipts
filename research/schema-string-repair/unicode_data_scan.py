"""Independent UCD oracle: enumerate ALL scalar values, not a witness allowlist."""
import argparse,hashlib,json,subprocess
from pathlib import Path
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--ucd',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    data=a.ucd.read_bytes()
    if hashlib.sha256(data).hexdigest()!='2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c':raise RuntimeError('Not the independently pinned UCD17 bytes')
    expected=[int(l.split(';')[0],16) for l in data.decode().splitlines() if l.split(';')[2]=='Nd']
    compiler=Path(__file__).resolve().parents[2]/'conformance/rvr-v0/ecma-unicode.cjs'
    js=r'''const compile=require(process.argv[1]);const native=/^\p{Decimal_Number}$/u;
const patterns=['^\\p{Decimal_Number}$','^\\P{Decimal_Number}$','^\\d$','^.$'];
const r=patterns.map(compile);let nd=[],nativeNd=[],badComplement=[],badDigit=[],badDot=[];
for(let cp=0;cp<=0x10ffff;cp++){if(cp>=0xd800&&cp<=0xdfff)continue;let s=String.fromCodePoint(cp);
if(r[0].test(s))nd.push(cp);if(native.test(s))nativeNd.push(cp);
if(r[1].test(s)===r[0].test(s))badComplement.push(cp);
if(r[2].test(s)!==(cp>=48&&cp<=57))badDigit.push(cp);
if(r[3].test(s)!==![10,13,0x2028,0x2029].includes(cp))badDot.push(cp);}
console.log(JSON.stringify({runtime:process.versions,nd,nativeNd,badComplement,badDigit,badDot}));'''
    out={}
    for engine in ['node','bun']:
        p=subprocess.run([engine,'-e',js,str(compiler)],capture_output=True,check=True);r=json.loads(p.stdout)
        if r['nd']!=expected or any(r[k] for k in ['badComplement','badDigit','badDot']):raise RuntimeError((engine,'oracle mismatch'))
        out[engine]=r
    a.output.write_text(json.dumps({'scalar_values_per_engine':1112064,'expected_decimal_count':len(expected),'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),'results':out},indent=2)+'\n',newline='\n')
    print('ALL_SCALARS_MATCH_UCD17',len(expected))
if __name__=='__main__':main()
