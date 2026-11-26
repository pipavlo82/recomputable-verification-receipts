"""Materialize exact pinned dependency bytes; no dependency is edited.
Default: HTTPS from immutable upstream refs. --from-cache validates an existing
local snapshot by the same SHA-256 manifest, then copies only required files.
"""
import argparse,json,hashlib,re,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--from-cache',type=Path);args=parser.parse_args()
 manifest=json.loads((ROOT/'dependency-manifest.json').read_bytes());cache={};written=0
 for item in manifest['files']:
  name=item['path'];target=(ROOT/name).resolve()
  if not target.is_relative_to(ROOT) or Path(name).is_absolute() or '..' in Path(name).parts:raise RuntimeError('Dependency path escapes package')
  if target.exists():raw=target.read_bytes()
  elif args.from_cache:raw=(args.from_cache/name).read_bytes()
  else:
   if not re.fullmatch('[0-9a-f]{40}',item['ref']):raise RuntimeError('Unpinned upstream ref')
   url=f"https://raw.githubusercontent.com/{item['repository']}/{item['ref']}/{item['upstream_path']}"
   if url not in cache:
    with urllib.request.urlopen(url,timeout=45) as response:cache[url]=response.read()
   raw=cache[url]
   if 'extract_solidity_contains' in item:
    blocks=re.findall(r'```solidity\s*\n(.*?)```',raw.decode('utf-8'),re.S)
    matches=[block for block in blocks if item['extract_solidity_contains'] in block]
    if len(matches)!=1:raise RuntimeError('Ambiguous pinned specification extraction')
    raw=matches[0].encode('utf-8')
  if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('Dependency digest mismatch: '+name)
  if not target.exists():target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
  written+=1
 for name,expected in manifest['frozen_core'].items():
  for prefix in ['sources/rvr/','sources/veca/evidence/erc8404/core/']:
   if hashlib.sha256((ROOT/prefix/name).read_bytes()).hexdigest()!=expected:raise RuntimeError('Frozen Core changed')
 print(json.dumps({'dependencies_verified':written,'frozen_core_unchanged':len(manifest['frozen_core'])},sort_keys=True))
if __name__=='__main__':main()
