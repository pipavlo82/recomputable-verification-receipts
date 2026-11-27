// Reproducible, dependency-locked bundle. No runtime npm/network dependency.
const fs = require('node:fs');
const path = require('node:path');
const esbuild = require('esbuild');
const base = __dirname;
const unicodeDir = path.join(base, 'node_modules/regenerate-unicode-properties');
if (require(path.join(unicodeDir, 'unicode-version.js')) !== '17.0.0') throw Error('Wrong Unicode data');
if (require('./node_modules/regjsparser/package.json').version !== '0.13.0') throw Error('Wrong Unicode identifier parser');
const table = [];
for (const kind of fs.readdirSync(unicodeDir).sort()) {
  const dir = path.join(unicodeDir, kind);
  if (!fs.statSync(dir).isDirectory()) continue;
  for (const file of fs.readdirSync(dir).filter(x => x.endsWith('.js')).sort()) {
    const key = kind + '/' + file.slice(0, -3);
    table.push(JSON.stringify(key) + ':require(' + JSON.stringify(path.join(dir,file)) + ')');
  }
}
const original = path.join(base,'node_modules/regexpu-core/rewrite-pattern.js');
const needle = 'require(`regenerate-unicode-properties/${ path }.js`)';
esbuild.build({
  stdin: {contents: `const rewrite = require('regexpu-core');
module.exports = function compile(pattern) {
  // Transform actual parsed Unicode properties and code-point atoms, never raw text replacement.
  const source = rewrite(pattern, 'u', {unicodePropertyEscapes:'transform', unicodeFlag:'transform', namedGroups:'transform'});
  return new RegExp(source);
};`, resolveDir:base, sourcefile:'rvr-unicode17-entry.cjs'},
  bundle:true, platform:'node', format:'cjs', charset:'ascii', minify:false,
  outfile:path.resolve(base,'../../../profiles/generic-ucd17-v1/conformance/rvr-v0/ecma-unicode.cjs'),
  plugins:[{name:'static-unicode-property-table',setup(build){
    build.onLoad({filter:/rewrite-pattern\.js$/}, args=>{
      if(path.resolve(args.path)!==path.resolve(original)) return;
      let source=fs.readFileSync(original,'utf8');
      if(source.split(needle).length!==2) throw Error('Upstream loader changed');
      source='const PINNED_PROPERTY_TABLE={'+table.join(',')+'};\n'+source.replace(needle,'PINNED_PROPERTY_TABLE[path] || (()=>{throw Error("Unknown property")})()');
      return {contents:source,loader:'js',resolveDir:path.dirname(original)};
    });
  }}]
}).then(()=>{
  const modules = Object.keys(require('./package-lock.json').packages).filter(x=>x.startsWith('node_modules/') && !x.includes('@esbuild') && x!=='node_modules/esbuild');
  const notices=[];
  for (const mod of modules.sort()) {
    const dir=path.join(base,mod), meta=require(path.join(dir,'package.json'));
    notices.push('\n## '+meta.name+' '+meta.version+' ('+meta.license+')\n');
    for(const file of fs.readdirSync(dir).filter(x=>/^(LICENSE|COPYING)/i.test(x)))notices.push(fs.readFileSync(path.join(dir,file),'utf8'));
  }
  fs.writeFileSync(path.join(base,'THIRD_PARTY_NOTICES.md'),('# Bundled regex compiler notices\n'+notices.join('\n')).replace(/\r\n/g,'\n'));
}).catch(e=>{console.error(e);process.exitCode=1});
