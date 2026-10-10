from pathlib import Path
import base64, hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from cryptography.hazmat.primitives.serialization import Encoding
from .core import SafetyError, canonical, safe_target, sha256
from .release_key import PUBLIC_KEY


def certificate_digest(exe: Path):
    data = exe.read_bytes()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    optional = pe + 24
    magic = struct.unpack_from('<H',data,optional)[0]
    directory = optional + (144 if magic == 0x20b else 128)
    offset, size = struct.unpack_from('<II',data,directory)
    if not offset or size < 8 or offset+size > len(data):
        raise SafetyError('EXE 没有有效 Authenticode 签名')
    length, revision, kind = struct.unpack_from('<IHH',data,offset)
    if kind != 2 or length > size:
        raise SafetyError('EXE 签名格式错误')
    certs = load_der_pkcs7_certificates(data[offset+8:offset+length])
    return {hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest() for c in certs}


def verify_distribution(folder: Path, cert_fingerprint: str, check_authenticode=True):
    from . import windows
    envelope = json.loads((folder/'release-manifest.json').read_text(encoding='utf-8'))
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUBLIC_KEY)).verify(
        base64.b64decode(envelope['signature'],validate=True),canonical(envelope['payload']))
    files = envelope['payload']['files']
    for name, digest in files.items():
        p = safe_target(folder,name)
        if not p.is_file() or sha256(p) != digest:
            raise SafetyError('程序自身文件校验失败：'+name)
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
    if actual - set(files) - {'release-manifest.json'}:
        raise SafetyError('程序目录中存在未签署的额外文件')
    if check_authenticode:
        executable = envelope['payload'].get('entry') or next(n for n in files if '/' not in n and n.endswith('.exe'))
        if cert_fingerprint not in certificate_digest(folder/executable):
            raise SafetyError('程序签名证书与固定公钥标识不符')
        status = windows.authenticode_status(folder/executable) & 0xffffffff
        if status not in (0,0x800B0109):
            raise SafetyError(f'程序 Authenticode 校验失败：0x{status:08x}')
    return len(files)


def startup_self_check():
    if getattr(sys,'frozen',False):
        from .authenticode_key import CERT_SHA256
        return verify_distribution(Path(sys.executable).parent,CERT_SHA256)
    return 0
