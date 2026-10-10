"""Completion is installed version + stable verified files, never just a window."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import time
from .core import SafetyError, local_identity, snapshot, verify, Repairer


@dataclass
class UpdateState:
    root: Path
    target: str
    phase: str = "preparing"
    reference: dict | None = None
    deadline: float = 0
    previous_reference: dict | None = None


class CompletionProbe:
    def __init__(self, log_offset=None):
        self.previous = None
        self.stable = 0
        self.log_offset=log_offset

    def check(self, root, ref):
        if local_identity(root)[0] != ref['version']:
            self.previous, self.stable = None, 0
            return False
        current = snapshot(root, ref)
        self.stable = self.stable + 1 if current == self.previous else 1
        self.previous = current
        if self.stable < 3:
            return False
        if self.log_offset is not None:
            import re
            logfile=root/'logs/bootstrap_log.txt'
            if not logfile.is_file():return False
            with logfile.open('rb') as f:
                if logfile.stat().st_size<self.log_offset:return False
                f.seek(self.log_offset);fresh=f.read(2*1024*1024).decode('utf-8',errors='replace')
            receipt=re.search(r'installed version\s+'+re.escape(ref['version'])+r'\b',fresh)
            if not receipt or 'Verification complete' not in fresh:return False
        return verify(root, ref).state == 'clean'


class UpdateController:
    def __init__(self, engine):
        self.engine = engine

    def run(self, root, manifest, timeout=600):
        from . import windows
        e = self.engine
        state = UpdateState(root, manifest['version'])
        state.previous_reference=e.cached_reference(root)
        e.update_state = state
        e.signals.busy.emit(True)
        try:
            windows.stop_steam(root)
            e.log(f"本地与 CDN 版本不同，Steam 已结束，目标版本 {state.target}")
            ref = e.references.get(state.target)
            if ref is None or ref['packages'] != manifest['packages']:
                ref = e.client.reference(manifest, root)
                e.references[state.target] = ref
            state.reference = ref
            # Do not execute a damaged/unknown bootstrapper merely to repair itself.
            current = e.cached_reference(root)
            trusted = current is not None and verify(root, current, quick=True).state == 'clean'
            if not trusted:
                names = list(ref['files']) if current is None else [n for n in ref['files'] if '/' not in n and n.endswith(('.exe', '.dll'))]
                Repairer(root, e.state, e.client, ref).repair(names,
                    lambda: windows.assert_stopped(root), allow_version_transition=True,allow_full_version_transition=current is None)
                e.log("已从官方验证组件恢复更新启动器和根目录依赖")
            state.phase = 'running'
            state.deadline = time.monotonic() + timeout
            log=root/'logs/bootstrap_log.txt'
            offset=log.stat().st_size if log.exists() else 0
            windows.launch_steam(root, force=True)
            e.log('更新已启动；等待安装版本、文件稳定性和完整哈希验证')
            probe = CompletionProbe(offset)
            while time.monotonic() < state.deadline:
                if e.shutdown.wait(1):
                    raise SafetyError('程序退出，更新确认已取消')
                if e.active_incident:
                    raise SafetyError('更新期间发现客户端异常，已中止更新确认')
                try:
                    completed = probe.check(root, ref)
                except (OSError, KeyError, SafetyError):
                    completed = False
                if completed:
                    # Re-query CDN so a newer release during this update is not called current.
                    latest = e.client.manifest()
                    if latest['version'] != ref['version']:
                        raise SafetyError('更新过程中 CDN 发布了不同版本，请重新检查；本次不标记最新')
                    audit = e.client_audit(root, ref, True)
                    if audit.incomplete or any(f.blocking for f in audit.findings):
                        raise SafetyError('版本已安装，但客户端安全复查未通过')
                    state.phase = 'completed'
                    e.log(f"已主动确认 Steam 更新完成：{state.target}")
                    return ref
            raise SafetyError('等待 Steam 更新完成超时，未将启动窗口或下载完成当作成功')
        except Exception:
            state.phase = 'failed'
            windows.stop_steam(root)
            e.update_failures[str(root)] = time.monotonic() + 60
            raise
        finally:
            e.update_state = None
            e.signals.busy.emit(False)
