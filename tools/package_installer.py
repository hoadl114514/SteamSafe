from pathlib import Path
import hashlib,zipfile,subprocess
root=Path(__file__).parents[1]
folder=root/'dist/SteamSafe'
payload=root/'build/installer-payload.zip'
with zipfile.ZipFile(payload,'w',zipfile.ZIP_DEFLATED) as z:
    for p in sorted(folder.rglob('*')):
        if p.is_file():z.write(p,p.relative_to(folder).as_posix())
import sys
sys.path.insert(0,str(root))
from sentinel.authenticode_key import CERT_SHA256
text=(root/'tools/Installer.cs').read_text(encoding='utf-8').replace('__PAYLOAD_HASH__',hashlib.sha256(payload.read_bytes()).hexdigest()).replace('__PRODUCT_ID__',(root/'build/product-id.txt').read_text(encoding='utf-8'))
source=root/'build/Installer.generated.cs';source.write_text(text,encoding='utf-8')
compiler=Path(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe')
subprocess.run([str(compiler),'/nologo','/target:winexe','/platform:x64','/optimize+',
    '/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:Microsoft.CSharp.dll','/reference:System.IO.Compression.dll','/reference:System.IO.Compression.FileSystem.dll',
    '/win32manifest:'+str(root/'tools/admin.manifest'),'/win32icon:'+str(root/'assets/app.ico'),
    '/resource:'+str(payload)+',payload.zip','/out:'+str(root/'dist/SteamSafe-v0.1.2.3-Beta-Setup.exe'),str(source),str(root/'build/SetupCommon.generated.cs')],check=True)
print('Built standalone protected-directory installer; does not install any trusted root certificate')
