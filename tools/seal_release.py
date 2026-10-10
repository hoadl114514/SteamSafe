import base64,json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import sys
sys.path.insert(0,str(Path(__file__).parents[1]))
from sentinel.core import sha256,canonical
root=Path(__file__).parents[1]
folder=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else root/'dist/SteamSafe'
payload={'version':'0.1.2.2-beta','entry':'SteamSafe.exe','files':{p.relative_to(folder).as_posix():sha256(p) for p in sorted(folder.rglob('*')) if p.is_file() and p.name!='release-manifest.json'}}
key=Ed25519PrivateKey.from_private_bytes((root/'.release-keys/ed25519-private.bin').read_bytes())
envelope={'payload':payload,'signature':base64.b64encode(key.sign(canonical(payload))).decode()}
(folder/'release-manifest.json').write_text(json.dumps(envelope,ensure_ascii=False,indent=2),encoding='utf-8')
print('Sealed signed application and all dependencies:',len(payload['files']))
