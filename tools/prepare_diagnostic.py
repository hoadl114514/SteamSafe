"""QA-only copy: change only execution-level XML, then re-sign and re-seal.
The distributable and its requireAdministrator manifest are never modified.
"""
from pathlib import Path
import shutil,struct
root=Path(__file__).parents[1]
src=root/'dist/SteamSafe'
dest=root/'build/qa-release'
shutil.copytree(src,dest,dirs_exist_ok=True)
exe=dest/'SteamSafe.exe'
data=exe.read_bytes()
old=b'level="requireAdministrator"'
new=b'level="asInvoker"'+b' '*(len(old)-len(b'level="asInvoker"'))
if data.count(old)!=1:raise RuntimeError('Execution-level manifest not found exactly once')
data=bytearray(data.replace(old,new))
pe=struct.unpack_from('<I',data,0x3c)[0];optional=pe+24
directory=optional+(144 if struct.unpack_from('<H',data,optional)[0]==0x20b else 128)
cert_offset,cert_size=struct.unpack_from('<II',data,directory)
struct.pack_into('<II',data,directory,0,0)
if cert_offset:data=data[:cert_offset]
exe.write_bytes(data)
print('QA copy prepared; distribution still requires administrator privileges')
