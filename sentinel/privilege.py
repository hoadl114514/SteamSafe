"""Private admin data. Refuse untrusted existing folders rather than adopting them."""
import ctypes
from ctypes import wintypes
from pathlib import Path
from .core import SafetyError, safe_target
from .windows import GUID

SDDL='O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'


def known_program_data():
    guid=GUID(0x62AB5D82,0xFDC1,0x4DC3,(ctypes.c_ubyte*8)(0xA9,0xDD,0x07,0x0D,0x1D,0x49,0x5D,0x97))
    shell=ctypes.WinDLL('shell32');out=wintypes.LPWSTR()
    shell.SHGetKnownFolderPath.argtypes=[ctypes.POINTER(GUID),wintypes.DWORD,wintypes.HANDLE,ctypes.POINTER(wintypes.LPWSTR)]
    if shell.SHGetKnownFolderPath(ctypes.byref(guid),0,None,ctypes.byref(out)):
        raise SafetyError('无法获取系统 ProgramData 目录')
    result=Path(out.value)
    ctypes.windll.ole32.CoTaskMemFree(ctypes.cast(out,ctypes.c_void_p))
    return result


def verify_protected_directory(path):
    for item in (path,*path.parents):
        s=item.lstat()
        if getattr(s,'st_file_attributes',0)&0x400 or item.is_symlink():
            raise SafetyError('拒绝重解析点：'+str(item))
    a=ctypes.WinDLL('advapi32',use_last_error=True);k=ctypes.WinDLL('kernel32')
    owner=ctypes.c_void_p();dacl=ctypes.c_void_p();descriptor=ctypes.c_void_p()
    a.GetNamedSecurityInfoW.argtypes=[wintypes.LPWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p)]
    a.ConvertSidToStringSidW.argtypes=[ctypes.c_void_p,ctypes.POINTER(wintypes.LPWSTR)]
    a.GetAce.argtypes=[ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p)]
    k.LocalFree.argtypes=[ctypes.c_void_p]
    def sid_string(sid):
        out=wintypes.LPWSTR()
        if not a.ConvertSidToStringSidW(sid,ctypes.byref(out)):raise ctypes.WinError(ctypes.get_last_error())
        try:return out.value
        finally:k.LocalFree(ctypes.cast(out,ctypes.c_void_p))
    rc=a.GetNamedSecurityInfoW(str(path),1,1|4,ctypes.byref(owner),None,ctypes.byref(dacl),None,ctypes.byref(descriptor))
    if rc:raise SafetyError(f'不能读取目录访问控制：{rc}')
    try:
        if not owner or sid_string(owner) not in {'S-1-5-18','S-1-5-32-544'} or not dacl:
            raise SafetyError('目录所有者或 ACL 不可信，请使用安装器创建新目录')
        count=ctypes.c_ushort.from_address(dacl.value+4).value
        for i in range(count):
            ace=ctypes.c_void_p()
            if not a.GetAce(dacl,i,ctypes.byref(ace)):raise ctypes.WinError(ctypes.get_last_error())
            kind=ctypes.c_ubyte.from_address(ace.value).value
            if kind==1:continue
            if kind!=0:raise SafetyError('目录含不支持的访问控制项')
            mask=ctypes.c_uint32.from_address(ace.value+4).value
            sid=sid_string(ctypes.c_void_p(ace.value+8))
            if sid not in {'S-1-5-18','S-1-5-32-544'} and mask & 0x500d0156:
                raise SafetyError('普通用户拥有目录写入／删除／改权限能力，拒绝使用')
    finally:k.LocalFree(descriptor)


def set_admin_default_owner():
    """Use a private thread token; never change a possibly shared primary token."""
    k=ctypes.WinDLL('kernel32',use_last_error=True);a=ctypes.WinDLL('advapi32',use_last_error=True)
    k.GetCurrentProcess.restype=wintypes.HANDLE;k.CloseHandle.argtypes=[wintypes.HANDLE];k.LocalFree.argtypes=[ctypes.c_void_p]
    a.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    a.ConvertStringSidToSidW.argtypes=[wintypes.LPCWSTR,ctypes.POINTER(ctypes.c_void_p)]
    a.SetTokenInformation.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD]
    a.DuplicateTokenEx.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    a.SetThreadToken.argtypes=[ctypes.POINTER(wintypes.HANDLE),wintypes.HANDLE]
    token=wintypes.HANDLE();private=wintypes.HANDLE();sid=ctypes.c_void_p()
    try:
        if not a.OpenProcessToken(k.GetCurrentProcess(),2|8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        if not a.DuplicateTokenEx(token,0x02000000,None,2,2,ctypes.byref(private)):raise ctypes.WinError(ctypes.get_last_error())
        if not a.ConvertStringSidToSidW('S-1-5-32-544',ctypes.byref(sid)):raise ctypes.WinError(ctypes.get_last_error())
        if not a.SetTokenInformation(private,4,ctypes.byref(sid),ctypes.sizeof(sid)):
            raise SafetyError('无法为管理员私有文件固定管理员所有者，拒绝启用修复')
        if not a.SetThreadToken(None,private):raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if sid:k.LocalFree(sid)
        if private:k.CloseHandle(private)
        if token:k.CloseHandle(token)


def protected_state():
    path=known_program_data()/'SteamSafeBeta-v0.1.2'
    safe_target(path,'acl-probe')
    if not path.exists():
        a=ctypes.WinDLL('advapi32',use_last_error=True);k=ctypes.WinDLL('kernel32',use_last_error=True)
        sd=ctypes.c_void_p()
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p]
        if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(SDDL,1,ctypes.byref(sd),None):raise ctypes.WinError(ctypes.get_last_error())
        class ATTR(ctypes.Structure):
            _fields_=[('length',wintypes.DWORD),('descriptor',ctypes.c_void_p),('inherit',wintypes.BOOL)]
        attrs=ATTR(ctypes.sizeof(ATTR),sd,False)
        k.CreateDirectoryW.argtypes=[wintypes.LPCWSTR,ctypes.POINTER(ATTR)]
        try:
            if not k.CreateDirectoryW(str(path),ctypes.byref(attrs)) and ctypes.get_last_error()!=183:raise ctypes.WinError(ctypes.get_last_error())
        finally:
            k.LocalFree.argtypes=[ctypes.c_void_p];k.LocalFree(sd)
    verify_protected_directory(path)
    for existing in path.rglob('*'):
        verify_protected_directory(existing)
    return path
