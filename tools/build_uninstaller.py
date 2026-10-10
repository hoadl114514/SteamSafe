from pathlib import Path
import subprocess,uuid,sys
root=Path(__file__).parents[1];sys.path.insert(0,str(root))
from sentinel.authenticode_key import CERT_SHA256
product='SteamSafeBeta-'+uuid.uuid4().hex[:16]
(root/'build/product-id.txt').write_text(product,encoding='utf-8')
common=root/'build/SetupCommon.generated.cs'
common.write_text((root/'tools/SetupCommon.cs').read_text(encoding='utf-8').replace('__CERT_SHA256__',CERT_SHA256),encoding='utf-8')
source=root/'build/Uninstaller.generated.cs'
source.write_text((root/'tools/Uninstaller.cs').read_text(encoding='utf-8').replace('__PRODUCT_ID__',product),encoding='utf-8')
compiler=Path(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe')
subprocess.run([str(compiler),'/nologo','/target:winexe','/platform:x64','/optimize+','/reference:Microsoft.CSharp.dll',
 '/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll',
 '/win32manifest:'+str(root/'tools/admin.manifest'),'/win32icon:'+str(root/'assets/app.ico'),
 '/out:'+str(root/'dist/SteamSafe/Uninstall.exe'),str(source),str(common),str(root/'tools/UninstallMaintenance.cs')],check=True)

repair=root/"build/UninstallRepair.generated.cs"
repair.write_text((root/"tools/Uninstaller.cs").read_text(encoding="utf-8").replace("__PRODUCT_ID__","REPAIR_EXISTING"),encoding="utf-8")
subprocess.run([str(compiler),"/nologo","/target:winexe","/platform:x64","/optimize+","/reference:Microsoft.CSharp.dll","/reference:System.Windows.Forms.dll","/reference:System.Drawing.dll","/reference:System.Web.Extensions.dll","/win32manifest:"+str(root/"tools/admin.manifest"),"/win32icon:"+str(root/"assets/app.ico"),"/out:"+str(root/"dist/SteamSafe-Uninstall-Repair.exe"),str(repair),str(common),str(root/"tools/UninstallMaintenance.cs")],check=True)
