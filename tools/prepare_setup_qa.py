from pathlib import Path
import struct,subprocess
root=Path(__file__).parents[1]
folder=root/'build/setup-qa';folder.mkdir(exist_ok=True)
for source,name in ((root/'dist/SteamSafe-v0.1.2.4-Beta-Setup.exe','Setup.exe'),(root/'dist/SteamSafe/Uninstall.exe','Uninstall.exe'),(root/'dist/SteamSafe-Uninstall-Repair.exe','Repair.exe')):
    data=source.read_bytes();old=b'level="requireAdministrator"';new=b'level="asInvoker"'+b' '*(len(old)-len(b'level="asInvoker"'))
    if data.count(old)!=1:raise RuntimeError('Ambiguous execution-level manifest')
    data=bytearray(data.replace(old,new));pe=struct.unpack_from('<I',data,0x3c)[0];optional=pe+24
    directory=optional+(144 if struct.unpack_from('<H',data,optional)[0]==0x20b else 128)
    offset,size=struct.unpack_from('<II',data,directory);struct.pack_into('<II',data,directory,0,0)
    if offset:data=data[:offset]
    target=folder/name;target.write_bytes(data)
print('Prepared identical-code native UI diagnostics; no installation/uninstallation occurs')
