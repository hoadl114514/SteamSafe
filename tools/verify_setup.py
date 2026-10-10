from pathlib import Path
import subprocess,json,sys
root=Path(__file__).parents[1];sys.path.insert(0,str(root))
from sentinel.selfguard import certificate_digest
from sentinel.authenticode_key import CERT_SHA256
from sentinel.windows import authenticode_status
output=root/'test-output/setup-v0.1.2.4';output.mkdir(parents=True,exist_ok=True)
for name in ('Setup','Uninstall','Repair'):
    executable=root/'build/setup-qa'/(name+'.exe')
    result=subprocess.run([str(executable),'--ui-smoke',str(output/(name+'.png'))],timeout=30)
    assert result.returncode==0 and (output/(name+'.png')).exists(),name+' UI failed'
result=subprocess.run([str(root/'build/setup-qa/Setup.exe'),'--self-test',str(output/'paths.json')],timeout=30)
assert result.returncode==0
for executable in (root/'dist/SteamSafe-v0.1.2.4-Beta-Setup.exe',root/'dist/SteamSafe/Uninstall.exe',root/'dist/SteamSafe-Uninstall-Repair.exe'):
    assert b'level="requireAdministrator"' in executable.read_bytes()
    assert CERT_SHA256 in certificate_digest(executable)
    assert authenticode_status(executable)&0xffffffff in (0,0x800B0109)
report={'ok':True,'native_path_tests':json.loads((output/'paths.json').read_text())['tests'],
        'native_gui':['Setup','Uninstall','Repair'],'admin_manifests_and_signatures':True,
        'native_uninstall_tests':json.loads((root/'build/native-uninstall-tests/report.json').read_text())['tests'],
        'system_install_shortcuts_registry_uninstall_executed':False}
(output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print('Native setup/uninstall UI and path constraints passed; no host installation or removal')
