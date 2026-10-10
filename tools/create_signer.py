"""Private PFX stays in .release-keys; no trusted root store is modified."""
from pathlib import Path
import datetime, hashlib, os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

root = Path(__file__).parents[1]
keys = root / '.release-keys'
keys.mkdir(exist_ok=True)
pfx = keys / 'authenticode.pfx'
passwordfile = keys / 'authenticode.password'
if pfx.exists():
    _, cert, _ = pkcs12.load_key_and_certificates(pfx.read_bytes(), passwordfile.read_bytes())
else:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'SteamSafe Beta Self-Signed')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
        .not_valid_after(now+datetime.timedelta(days=1095)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),critical=False)
        .sign(key,hashes.SHA256()))
    password = os.urandom(32).hex().encode()
    passwordfile.write_bytes(password)
    pfx.write_bytes(pkcs12.serialize_key_and_certificates(b'SteamSafe',key,cert,None,serialization.BestAvailableEncryption(password)))
der = cert.public_bytes(serialization.Encoding.DER)
(root/'assets/code-signing.cer').write_bytes(der)
(root/'sentinel/authenticode_key.py').write_text('CERT_SHA256 = '+repr(hashlib.sha256(der).hexdigest())+'\n',encoding='utf-8')
print('Created/pinned self-signed code-signing certificate; private material excluded from distribution')
