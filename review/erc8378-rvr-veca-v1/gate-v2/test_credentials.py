"""Ephemeral laboratory credentials. No key values are embedded or logged.

These keys only support local tests. All roles share one test controller/host;
this is not independently administered production custody.
"""
import os,json,secrets,tempfile
from pathlib import Path
from contextlib import contextmanager

ORDER=int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',16)
ROLES=('bridge','verifier','wrong_verifier','assessor')

def _load():
 try:
  data=json.loads(Path(os.environ['V1_KEY_FILE']).read_bytes())
  if set(data)!=set(ROLES):raise ValueError()
  result={name:bytes.fromhex(value) for name,value in data.items()}
  if any(len(value)!=32 for value in result.values()):raise ValueError()
  if any(not 0<int.from_bytes(result[name],'big')<ORDER for name in ROLES if name!='assessor'):raise ValueError()
  if len(set(result.values()))!=len(result):raise ValueError()
  return result
 except Exception:raise RuntimeError('Invalid or missing ephemeral test credentials') from None

def raw(role):return _load()[role]

@contextmanager
def provision():
 if 'V1_KEY_FILE' in os.environ:
  values=_load();path=os.environ['V1_KEY_FILE'];temporary=None
 else:
  temporary=tempfile.TemporaryDirectory(prefix='erc8378-ephemeral-')
  path=str(Path(temporary.name)/'credentials.json')
  values={name:((secrets.randbelow(ORDER-1)+1).to_bytes(32,'big') if name!='assessor' else secrets.token_bytes(32)) for name in ROLES}
  descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(descriptor,'w',encoding='ascii') as handle:json.dump({name:value.hex() for name,value in values.items()},handle)
 env=dict(os.environ,V1_KEY_FILE=path,V1_BRIDGE_KEY=str(int.from_bytes(values['bridge'],'big')),V1_VERIFIER_KEY=str(int.from_bytes(values['verifier'],'big')))
 try:yield env
 finally:
  if temporary is not None:temporary.cleanup()

def run(action):
 before={name:os.environ.get(name) for name in ['V1_KEY_FILE','V1_BRIDGE_KEY','V1_VERIFIER_KEY']}
 with provision() as env:
  for name in before:os.environ[name]=env[name]
  try:return action()
  finally:
   for name,value in before.items():
    if value is None:os.environ.pop(name,None)
    else:os.environ[name]=value
