"""Windows integration. Process names alone never authorize termination."""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import winreg

import psutil
from .core import SafetyError, STEAM_NAMES, safe_target


def discover_steam() -> Path | None:
    candidates = []
    for hive, subkey, value in (
        (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", "InstallPath"),
    ):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                candidates.append(Path(winreg.QueryValueEx(key, value)[0]))
        except OSError:
            pass
    candidates.append(Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Steam")
    for p in candidates:
        if (p / "steam.exe").is_file():
            return p.absolute()
    return None


def steam_processes(root: Path) -> list[psutil.Process]:
    result = []
    root = root.resolve()
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            if (p.info["name"] or "").lower() not in STEAM_NAMES:
                continue
            exe = p.info["exe"]
            if exe and Path(exe).resolve().is_relative_to(root):
                result.append(p)
        except (psutil.Error, OSError):
            continue
    return result


def assert_stopped(root: Path):
    if steam_processes(root):
        raise SafetyError("Steam 仍在运行／重新启动，已中止文件替换")


def stop_steam(root: Path):
    targets = steam_processes(root)
    for p in targets:
        try:
            # psutil identity includes creation time and guards against PID reuse.
            if Path(p.exe()).resolve().is_relative_to(root.resolve()) and p.name().lower() in STEAM_NAMES:
                p.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(targets, timeout=4)
    for p in alive:
        if p.is_running() and Path(p.exe()).resolve().is_relative_to(root.resolve()) and p.name().lower() in STEAM_NAMES:
            p.kill()
    psutil.wait_procs(alive, timeout=3)
    assert_stopped(root)


def launch_steam(root: Path, force=True):
    if steam_processes(root):
        raise SafetyError("Steam 已在运行。强制更新参数需要完全退出后启动")
    command = [str(safe_target(root, "steam.exe"))]
    if force:
        command.append("-forcesteamupdate")
    launch_as_desktop_user(command, root)


def launch_as_desktop_user(command, cwd):
    """An elevated guardian must not make Steam/browser an elevated child."""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        return subprocess.Popen(command, cwd=cwd, close_fds=True)
    class STARTUPINFO(ctypes.Structure):
        _fields_=[('cb',wintypes.DWORD),('lpReserved',wintypes.LPWSTR),('lpDesktop',wintypes.LPWSTR),
            ('lpTitle',wintypes.LPWSTR),('dwX',wintypes.DWORD),('dwY',wintypes.DWORD),('dwXSize',wintypes.DWORD),
            ('dwYSize',wintypes.DWORD),('dwXCountChars',wintypes.DWORD),('dwYCountChars',wintypes.DWORD),
            ('dwFillAttribute',wintypes.DWORD),('dwFlags',wintypes.DWORD),('wShowWindow',wintypes.WORD),
            ('cbReserved2',wintypes.WORD),('lpReserved2',ctypes.c_void_p),('hStdInput',wintypes.HANDLE),
            ('hStdOutput',wintypes.HANDLE),('hStdError',wintypes.HANDLE)]
    class PROCESSINFO(ctypes.Structure):
        _fields_=[('hProcess',wintypes.HANDLE),('hThread',wintypes.HANDLE),('dwProcessId',wintypes.DWORD),('dwThreadId',wintypes.DWORD)]
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    a=ctypes.WinDLL('advapi32',use_last_error=True)
    u=ctypes.WinDLL('user32',use_last_error=True)
    u.GetShellWindow.restype=wintypes.HWND
    u.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
    k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    k.OpenProcess.restype=wintypes.HANDLE
    k.CloseHandle.argtypes=[wintypes.HANDLE]
    a.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    a.DuplicateTokenEx.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    a.CreateProcessWithTokenW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPCWSTR,wintypes.LPWSTR,
        wintypes.DWORD,ctypes.c_void_p,wintypes.LPCWSTR,ctypes.POINTER(STARTUPINFO),ctypes.POINTER(PROCESSINFO)]
    pid=wintypes.DWORD()
    u.GetWindowThreadProcessId(u.GetShellWindow(),ctypes.byref(pid))
    if not pid.value:
        raise SafetyError('没有可用桌面用户会话，拒绝以管理员启动 Steam')
    process=k.OpenProcess(0x1000,False,pid.value)
    token=wintypes.HANDLE(); primary=wintypes.HANDLE()
    try:
        if not process or not a.OpenProcessToken(process,0x0002|0x0008,ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not a.DuplicateTokenEx(token,0x02000000,None,2,1,ctypes.byref(primary)):
            raise ctypes.WinError(ctypes.get_last_error())
        startup=STARTUPINFO();startup.cb=ctypes.sizeof(startup);startup.lpDesktop='winsta0\\default'
        info=PROCESSINFO()
        cmd=ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        k.SetDllDirectoryW.argtypes=[wintypes.LPCWSTR]
        k.SetDllDirectoryW(None)
        try:
            if not a.CreateProcessWithTokenW(primary,1,str(command[0]),cmd,0,None,str(cwd),ctypes.byref(startup),ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            if getattr(sys,'frozen',False):
                k.SetDllDirectoryW(str(sys._MEIPASS))
        k.CloseHandle(info.hThread);k.CloseHandle(info.hProcess)
        return info.dwProcessId
    finally:
        if primary:k.CloseHandle(primary)
        if token:k.CloseHandle(token)
        if process:k.CloseHandle(process)


def authenticode_status(path):
    file=WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO),str(path),None,None)
    data=WINTRUST_DATA();data.cbStruct=ctypes.sizeof(data);data.dwUIChoice=2;data.dwUnionChoice=1
    data.pFile=ctypes.pointer(file);data.dwProvFlags=0x1000
    guid=GUID(0x00AAC56B,0xCD44,0x11D0,(ctypes.c_ubyte*8)(0x8C,0xC2,0,0xC0,0x4F,0xC2,0x95,0xEE))
    trust=ctypes.WinDLL('wintrust');trust.WinVerifyTrust.argtypes=[wintypes.HWND,ctypes.POINTER(GUID),ctypes.c_void_p]
    trust.WinVerifyTrust.restype=wintypes.LONG
    return trust.WinVerifyTrust(None,ctypes.byref(guid),ctypes.byref(data))


def autostart_command() -> str:
    if getattr(sys, "frozen", False):
        command = [sys.executable, "--background"]
    else:
        command = [sys.executable, str(Path(__file__).parents[1] / "main.py"), "--background"]
    return subprocess.list2cmdline(command)


def set_autostart(enabled: bool):
    if getattr(sys,'frozen',False):
        helper=Path(sys.executable).parent/'SteamSafeTaskHelper.exe'
        subprocess.run([str(helper),'enable' if enabled else 'disable',desktop_user_sid()],
            check=True,capture_output=True,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        return
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
        if enabled:
            winreg.SetValueEx(key, "SteamSafeBeta", 0, winreg.REG_SZ, autostart_command())
        else:
            try:
                winreg.DeleteValue(key, "SteamSafeBeta")
            except FileNotFoundError:
                pass


def autostart_enabled() -> bool:
    if getattr(sys,'frozen',False):
        buffer=ctypes.create_unicode_buffer(32768);ctypes.windll.kernel32.GetSystemDirectoryW(buffer,len(buffer))
        result=subprocess.run([str(Path(buffer.value)/'schtasks.exe'),'/Query','/TN','SteamSafeBeta','/XML'],capture_output=True,text=True,
            creationflags=subprocess.CREATE_NO_WINDOW)
        return result.returncode==0 and sys.executable.lower() in result.stdout.lower()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
            return winreg.QueryValueEx(key, "SteamSafeBeta")[0] == autostart_command()
    except OSError:
        return False


def desktop_user_sid():
    u=ctypes.WinDLL('user32');k=ctypes.WinDLL('kernel32',use_last_error=True);a=ctypes.WinDLL('advapi32',use_last_error=True)
    u.GetShellWindow.restype=wintypes.HWND;u.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
    pid=wintypes.DWORD();u.GetWindowThreadProcessId(u.GetShellWindow(),ctypes.byref(pid))
    k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];k.OpenProcess.restype=wintypes.HANDLE
    k.CloseHandle.argtypes=[wintypes.HANDLE];k.LocalFree.argtypes=[ctypes.c_void_p]
    a.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    a.GetTokenInformation.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    a.ConvertSidToStringSidW.argtypes=[ctypes.c_void_p,ctypes.POINTER(wintypes.LPWSTR)]
    process=k.OpenProcess(0x1000,False,pid.value);token=wintypes.HANDLE()
    try:
        if not process or not a.OpenProcessToken(process,8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        size=wintypes.DWORD();a.GetTokenInformation(token,1,None,0,ctypes.byref(size))
        buffer=ctypes.create_string_buffer(size.value)
        if not a.GetTokenInformation(token,1,buffer,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        sid=ctypes.c_void_p.from_buffer(buffer);text=wintypes.LPWSTR()
        if not a.ConvertSidToStringSidW(sid,ctypes.byref(text)):raise ctypes.WinError(ctypes.get_last_error())
        try:return text.value
        finally:k.LocalFree(ctypes.cast(text,ctypes.c_void_p))
    finally:
        if token:k.CloseHandle(token)
        if process:k.CloseHandle(process)


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD)]


class PROVIDER_CERT(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]


class PROVIDER_SIGNER(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("sftVerifyAsOf", wintypes.FILETIME),
                ("csCertChain", wintypes.DWORD), ("pasCertChain", ctypes.POINTER(PROVIDER_CERT))]


def signature_info(path: Path) -> tuple[bool, str]:
    """Offline Authenticode status, not a publisher allowlist or malware verdict."""
    file = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None)
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(data)
    data.dwUIChoice = 2  # WTD_UI_NONE
    data.dwUnionChoice = 1
    data.pFile = ctypes.pointer(file)
    data.dwProvFlags = 0x1000  # WTD_CACHE_ONLY_URL_RETRIEVAL
    data.dwStateAction = 1
    guid = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    trust = ctypes.WinDLL("wintrust")
    trust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    trust.WinVerifyTrust.restype = wintypes.LONG
    valid = trust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data)) == 0
    subject = ""
    try:
        if valid and data.hWVTStateData:
            trust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
            trust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
            trust.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            trust.WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(PROVIDER_SIGNER)
            provider = trust.WTHelperProvDataFromStateData(data.hWVTStateData)
            signer = trust.WTHelperGetProvSignerFromChain(provider, 0, False, 0)
            if signer and signer.contents.csCertChain:
                crypt = ctypes.WinDLL("crypt32")
                crypt.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                    ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
                crypt.CertGetNameStringW.restype = wintypes.DWORD
                buf = ctypes.create_unicode_buffer(512)
                crypt.CertGetNameStringW(signer.contents.pasCertChain[0].pCert, 4, 0, None, buf, 512)
                subject = buf.value
    finally:
        data.dwStateAction = 2
        trust.WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))
    return valid, subject


def signature_valid(path: Path) -> bool:
    return signature_info(path)[0]


def registry_values(hive: str, view: int, path: str) -> dict:
    keyhive = winreg.HKEY_CURRENT_USER if hive == "HKCU" else winreg.HKEY_LOCAL_MACHINE
    flag = winreg.KEY_WOW64_32KEY if view == 32 else winreg.KEY_WOW64_64KEY if view == 64 else 0
    try:
        with winreg.OpenKey(keyhive, path, 0, winreg.KEY_READ | flag) as key:
            result = {}
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, value, _ = winreg.EnumValue(key, i)
                result[name] = value
            return result
    except FileNotFoundError:
        return {}


class DirectoryWatcher:
    """ReadDirectoryChangesW tracks changes even when timestamps are restored."""
    def __init__(self, root: Path):
        import threading, queue
        self.root = root
        self.events = queue.Queue(maxsize=2048)
        self.closed = threading.Event()
        self.ready = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.run, name="SteamDirectoryWatch", daemon=True)
        self.thread.start()

    def drain(self):
        import queue
        values = set()
        while True:
            try:
                values.add(self.events.get_nowait())
            except queue.Empty:
                return values

    def add(self, name):
        import queue
        name = name.replace("\\", "/").lower()
        if name and name.startswith(("steamapps/", "userdata/", "logs/", "appcache/", "depotcache/")):
            return
        if name and not name.endswith((".exe", ".dll", ".drv", ".cfg", ".js", ".mjs", ".html", ".css", ".manifest")) and name != "package/beta":
            return
        try:
            self.events.put_nowait(name)
        except queue.Full:
            try:
                self.events.get_nowait()
                self.events.put_nowait("")
            except (queue.Empty, queue.Full):
                pass

    def run(self):
        import struct
        class OVERLAPPED(ctypes.Structure):
            _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                        ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD), ("hEvent", wintypes.HANDLE)]
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                 wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k.CreateFileW.restype = wintypes.HANDLE
        k.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        k.CreateEventW.restype = wintypes.HANDLE
        k.ReadDirectoryChangesW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            wintypes.BOOL, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(OVERLAPPED), ctypes.c_void_p]
        k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED), ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
        k.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED)]
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.ResetEvent.argtypes = [wintypes.HANDLE]
        handle = k.CreateFileW(str(self.root), 1, 7, None, 3, 0x02000000 | 0x40000000, None)
        if handle == ctypes.c_void_p(-1).value:
            self.error = str(ctypes.WinError(ctypes.get_last_error()))
            self.ready.set()
            self.add("")
            return
        event = k.CreateEventW(None, True, False, None)
        buffer = ctypes.create_string_buffer(65536)
        overlap = OVERLAPPED()
        overlap.hEvent = event
        try:
            while not self.closed.is_set():
                k.ResetEvent(event)
                if not k.ReadDirectoryChangesW(handle, buffer, len(buffer), True, 0x1 | 0x2 | 0x8 | 0x10,
                                                None, ctypes.byref(overlap), None):
                    self.error = str(ctypes.WinError(ctypes.get_last_error()))
                    self.ready.set()
                    self.add("")
                    break
                self.ready.set()
                while not self.closed.is_set() and k.WaitForSingleObject(event, 250) == 258:
                    pass
                if self.closed.is_set():
                    break
                count = wintypes.DWORD()
                if not k.GetOverlappedResult(handle, ctypes.byref(overlap), ctypes.byref(count), False):
                    self.add("")
                    break
                if not count.value:
                    self.add("")
                    continue
                offset = 0
                while offset + 12 <= count.value:
                    next_offset, action, length = struct.unpack_from("<III", buffer.raw, offset)
                    if offset + 12 + length > count.value:
                        self.add("")
                        break
                    self.add(buffer.raw[offset + 12:offset + 12 + length].decode("utf-16-le"))
                    if not next_offset:
                        break
                    offset += next_offset
        finally:
            k.CancelIoEx(handle, ctypes.byref(overlap))
            k.GetOverlappedResult(handle, ctypes.byref(overlap), ctypes.byref(wintypes.DWORD()), True)
            k.CloseHandle(event)
            k.CloseHandle(handle)


def startup_findings(root: Path, ref: dict) -> list[str]:
    issues = []
    for name in ("version.dll", "versionorg.dll", "msacm32.drv", "wsock32.dll"):
        p = safe_target(root, name)
        if p.is_file() and name not in ref["files"]:
            signed = signature_valid(p)
            issues.append(f"发现基线之外的加载入口 {name}（{'签名有效' if signed else '签名未通过'}）；可能是插件或劫持，请核对")
    cfg = safe_target(root, "steam.cfg")
    if cfg.is_file():
        if cfg.stat().st_size > 1024 * 1024:
            issues.append("steam.cfg 超出检查上限，未完成检查")
        else:
            text = cfg.read_text(errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "//", ";")):
                    continue
                if any(k.lower() in line.lower() for k in (
                    "BootStrapperInhibit", "ClientDownloadHost", "OverridePackageURL", "DisableDownloads")):
                    issues.append("steam.cfg 中存在更新／校验／下载来源相关配置，请核对")
                    break
    return issues


def module_findings(root: Path, previously_seen: set) -> list[str]:
    issues = []
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()
    for p in steam_processes(root):
        try:
            modules = p.memory_maps(grouped=True)
        except psutil.Error as e:
            key = (p.pid, "inaccessible")
            if key not in previously_seen:
                previously_seen.add(key)
                issues.append(f"进程 {p.pid} 模块无法读取：{type(e).__name__}；此进程未完成模块检查")
            continue
        for module in modules:
            path = Path(module.path)
            if path.suffix.lower() not in (".dll", ".exe"):
                continue
            key = (str(path).lower(), path.stat().st_mtime_ns if path.exists() else 0)
            if key in previously_seen:
                continue
            previously_seen.add(key)
            resolved = path.resolve()
            if resolved.is_relative_to(root.resolve()) or resolved.is_relative_to(system_root):
                continue
            if not signature_valid(path):
                issues.append(f"发现 Steam 加载的外部模块，签名未通过：{path}；可能是覆盖层或注入，请核对")
    return issues


def acquire_mutex(state_path: Path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    name = "Local\\SteamSafe-" + hashlib.sha256(str(state_path).lower().encode()).hexdigest()[:24]
    handle = kernel.CreateMutexW(None, False, name)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    if ctypes.get_last_error() == 183:
        kernel.CloseHandle(handle)
        return None
    return handle
