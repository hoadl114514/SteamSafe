from __future__ import annotations
from dataclasses import asdict
import json
import logging
from pathlib import Path
import queue
import threading
import time

from .core import (CheckResult, OfficialClient, Repairer, SafetyError, local_identity,
                   read_signed_seed, snapshot, verify)
from . import windows
from .audit import ClientAuditor, AuditResult, Finding, RiskRemediator, registry_findings


class Engine:
    def __init__(self, assets: Path, state: Path, settings: dict, signals):
        self.state, self.settings, self.signals = state, settings, signals
        self.seed = read_signed_seed(assets)
        self.references = {self.seed["version"]: self.seed}
        self.client = OfficialClient(state / "packages", self.log)
        self.commands = queue.Queue()
        self.shutdown = threading.Event()
        self.last_scan = 0
        self.last_snapshot = None
        self.was_running = False
        self.stable_since = 0
        self.last_module_scan = 0
        self.seen_modules = set()
        self.last_root = None
        self.reported = set()
        self.last_result = None
        self.retry_after = 0
        self.auditor = ClientAuditor(windows.signature_info)
        self.guard_auditor = ClientAuditor(windows.signature_info)
        self.audit_lock = threading.RLock()
        self.incident_lock = threading.RLock()
        self.active_incident = None
        self.repairing = threading.Event()
        self.watcher = None
        self.guard_root = None
        self.guard_pids = set()
        self.last_guard_audit = 0
        self.last_registry_audit = 0
        self.registry_issues = []
        self.guard_errors = set()
        self.unresolved = {}
        self.last_attempt = {}
        self.update_state = None
        self.update_failures = {}
        self.last_clean_repair = {}
        self.reinfection_holds = set()
        self.last_observations = []
        self.worker_state = 'starting'
        self.guard_state = 'starting'

    def client_audit(self, root, ref, refresh_registry=False):
        with self.audit_lock:
            result = self.auditor.audit(root, ref)
        if refresh_registry or time.monotonic() - self.last_registry_audit >= 5:
            try:
                self.registry_issues = registry_findings(root, windows.registry_values)
            except OSError as e:
                result.incomplete.append(f"启动项检查未完成：{e}")
            self.last_registry_audit = time.monotonic()
        result.findings.extend(self.registry_issues)
        return result

    def cached_reference(self, root):
        try:
            return self.references.get(local_identity(root)[0])
        except (OSError, KeyError, SafetyError):
            return None

    def contain(self, root, findings, ref=None, mismatches=(), enqueue=True):
        """Stop first; downloads and file restoration run on the other worker."""
        with self.incident_lock:
            if self.active_incident is not None:
                return None
            payload = {"root": root, "findings": findings, "ref": ref, "mismatches": list(mismatches)}
            if time.monotonic()-self.last_clean_repair.get(str(root),-1000000)<300:
                self.reinfection_holds.add(str(root))
            self.active_incident = payload
        self.signals.busy.emit(True)
        try:
            if self.settings.get("stop_on_mismatch", True):
                windows.stop_steam(root)
                self.notify("客户端修改／高风险加载配置已检出，已立即结束该目录的 Steam 进程；正在尝试隔离和修复。")
            else:
                self.notify("客户端异常已检出；自动结束进程开关已关闭，请立即退出 Steam。")
            for finding in findings:
                self.log(f"[{finding.rule}] {finding.message}")
            if str(root) in self.reinfection_holds:
                self.notify('修复后异常再次出现，可能存在持续感染来源或原文件被恢复；将保持启动拦截，不能只重复恢复文件。')
            self.log('本次只处理客户端证据；如已执行恶意载荷，登录会话可能泄露，请从可信设备处理账号安全。')
            from .core import atomic_json
            atomic_json(self.state / "last-incident.json", {"root": str(root), "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "findings": [asdict(f) for f in findings], "mismatches": list(mismatches)})
            if enqueue:
                self.commands.put(("incident", payload))
            return payload
        except Exception as e:
            self.notify(f"异常已检出，但结束 Steam 失败，未写入安装文件：{e}")
            self.active_incident = None
            raise

    def handle_incident(self, payload):
        root, ref = payload["root"], payload["ref"]
        self.repairing.set()
        try:
            try:
                from .provenance import existing_sysmon_evidence
                from .core import atomic_json
                provenance=existing_sysmon_evidence(root)
                atomic_json(self.state/'last-provenance.json',provenance)
                self.log(provenance.get('note','已读取已有 Sysmon 元数据线索'))
            except Exception:
                self.log('来源元数据不可用；不把修复成功当作持续感染来源已清除')
            if self.settings.get("auto_repair", True):
                windows.assert_stopped(root)
                tx = RiskRemediator(root, self.state).apply(payload["findings"], lambda: windows.assert_stopped(root))
                if tx:
                    self.log(f"已隔离加载入口／清理危险配置；可回滚记录：{tx}")
                restore = set(payload["mismatches"])
                restore.update(n.lower() for f in payload["findings"] if f.blocking and f.action == "restore" for n in f.files)
                if restore:
                    if ref is None:
                        ref, _, _ = self.reference(root, True)
                    current = verify(root, ref)
                    if current.state != "mismatch" or not restore.issubset(current.mismatches):
                        raise SafetyError("恢复前文件状态变化／没有匹配可信版本，未覆盖文件")
                    tx = Repairer(root, self.state, self.client, ref).repair(sorted(restore), lambda: windows.assert_stopped(root))
                    self.log(f"已恢复可信原版文件：{tx}")
            with self.audit_lock:
                self.auditor.invalidate()
            after = self.client_audit(root, ref, True)
            remaining = [f for f in after.findings if f.blocking]
            hashes = verify(root, ref) if ref is not None else None
            clean = not remaining and not after.incomplete and not (hashes and hashes.state != "clean")
            if clean:
                self.unresolved.pop(str(root), None)
                self.last_clean_repair[str(root)]=time.monotonic()
            else:
                self.unresolved[str(root)] = payload
                self.last_attempt[str(root)] = time.monotonic()
            self.report(CheckResult("clean" if clean and hashes else "unverified" if clean else "blocked",
                ref["version"] if ref else "", checked=hashes.checked if hashes else 0,
                detail="异常处理已完成；未自动重启 Steam，请重新校验后启动" if clean else "仍有异常／无权修复，Steam 保持拦截；请查看报告"),
                [f.message for f in after.findings] + after.incomplete)
            self.notify("隔离／修复已完成，Steam 保持关闭，请核对报告后重新启动。" if clean else "异常尚未完全处理，Steam 已关闭；请核对报告并处理剩余项目。")
        except Exception:
            self.unresolved[str(root)] = payload
            self.last_attempt[str(root)] = time.monotonic()
            self.report(CheckResult("blocked", ref["version"] if ref else "", detail="修复失败，保留证据并继续拦截重启"),
                [f.message for f in payload["findings"]])
            self.notify("异常尚未完全处理：修复失败，已保留证据，继续拦截 Steam 重启。")
            raise
        finally:
            self.active_incident = None
            self.repairing.clear()
            self.signals.busy.emit(False)

    def guard_once(self, events=(), watch=True):
        """Independent fast guard; never waits for an HTTP request or worker queue."""
        if not self.settings.get("monitor", True) or not self.settings.get("steam_path"):
            return
        if not self.settings.get('root_confirmed',True):
            return
        root = self.root()
        if root != self.guard_root:
            if self.watcher:
                self.watcher.closed.set()
            self.watcher = windows.DirectoryWatcher(root) if watch and root.is_dir() else None
            self.guard_root = root
            self.guard_pids = set()
            self.last_guard_audit = 0
            self.last_registry_audit = 0
            self.registry_issues = []
            self.guard_auditor.invalidate()
        if self.watcher:
            events = set(events) | self.watcher.drain()
        processes = windows.steam_processes(root)
        if str(root) in self.reinfection_holds and not (self.update_state and self.update_state.root==root):
            if processes:windows.stop_steam(root)
            return
        if str(root) in self.update_failures and time.monotonic() < self.update_failures[str(root)]:
            if processes:
                windows.stop_steam(root)
            return
        identities = set()
        for process in processes:
            try:
                if process.is_running():
                    identities.add((process.pid, process.create_time()))
            except windows.psutil.NoSuchProcess:
                pass
        started = bool(identities - self.guard_pids)
        session_started = bool(identities) and not self.guard_pids
        self.guard_pids = identities
        if self.active_incident and self.active_incident["root"] == root:
            if processes and self.settings.get("stop_on_mismatch", True):
                windows.stop_steam(root)
            return
        if self.repairing.is_set():
            return
        now = time.monotonic()
        if str(root) in self.unresolved and not events and now - self.last_attempt.get(str(root), 0) < 60:
            if processes and self.settings.get("stop_on_mismatch", True):
                windows.stop_steam(root)
            return
        if not started and not events and now - self.last_guard_audit < 2:
            return
        if started or events or now - self.last_guard_audit > 30:
            self.guard_auditor.invalidate(events if events and "" not in events and not started else ())
        ref = self.cached_reference(root)
        updating = self.update_state is not None and self.update_state.root == root
        if updating and self.update_state.phase == 'preparing' and processes:
            windows.stop_steam(root)
        if updating and self.update_state.reference:
            ref = self.update_state.reference
            old=self.update_state.previous_reference
            if old:
                files={**old['files'],**ref['files']}
                files={n:{**entry,'sha256_alternates':list({entry['sha256'],old['files'].get(n,entry)['sha256']})} for n,entry in files.items()}
                ref={**ref,'files':files}
        # Never wait for the audit/cache lock held by a network worker or JS scan.
        result = self.guard_auditor.audit(root, ref, scripts=False)
        immediate = [f for f in result.findings if f.blocking]
        if immediate:
            self.last_guard_audit = now
            self.contain(root, immediate, ref)
            return
        if updating and self.update_state.phase=='preparing':
            return
        result = self.guard_auditor.audit(root, ref)
        if started or now - self.last_registry_audit >= 5:
            try:
                self.registry_issues = registry_findings(root, windows.registry_values)
            except OSError as e:
                result.incomplete.append(f"启动项检查未完成：{e}")
            self.last_registry_audit = now
        result.findings.extend(self.registry_issues)
        self.last_guard_audit = now
        high = [f for f in result.findings if f.blocking]
        mismatches = []
        # Hash changes do not excuse semantic tampering just because an update is pending.
        if ref and not high and not updating:
            normalized_events = {n.replace('\\', '/').casefold() for n in events}
            selected = set(ref["files"]) if session_started else {
                n for n in ref["files"] if n.replace('\\', '/').casefold() in normalized_events}
            if "" in events:
                selected = set(ref["files"])
            if selected:
                current = verify(root, ref, paths=selected)
                if current.state == "mismatch":
                    second = verify(root, ref, paths=selected)
                    if (second.state == "mismatch" and second.mismatches == current.mismatches
                            and local_identity(root)[0] == ref['version']):
                        mismatches = current.mismatches
                        high = [Finding("trusted-file-changed", "confirmed", "已确认同版本可信文件发生修改", tuple(mismatches), "restore")]
        if high:
            self.contain(root, high, ref, mismatches)
        elif str(root) in self.unresolved and not result.incomplete:
            checked = verify(root, ref) if ref else None
            if checked and checked.state == "clean":
                self.unresolved.pop(str(root), None)
                self.report(checked, [f.message for f in result.findings])
                self.notify("后台复查通过，已解除此前的 Steam 重启拦截。")
        if started and not updating:
            self.log('即时守护检测到 Steam 进程启动，已完成客户端规则复查并安排完整后台校验。')
            self.commands.put("scan")

    def initialize_worker(self, name):
        try:
            if windows.ctypes.windll.shell32.IsUserAnAdmin():
                from .privilege import set_admin_default_owner
                set_admin_default_owner()
        except Exception as error:
            setattr(self, name + '_state', 'failed')
            label = '即时文件守护' if name == 'guard' else '完整校验与修复'
            self.notify(f'后台{label}线程初始化失败，保护未启用：{error}')
            return False
        setattr(self, name + '_state', 'running')
        self.log('即时文件守护线程已就绪。' if name == 'guard' else '后台完整校验与修复线程已就绪。')
        return True

    def guard_run(self):
        if not self.initialize_worker('guard'):
            return
        while not self.shutdown.is_set():
            try:
                self.guard_once()
            except Exception as e:
                key = str(e)
                if key not in self.guard_errors:
                    self.guard_errors.add(key)
                    self.notify(f"即时客户端检查未完成：{e}")
            self.shutdown.wait(0.5)
        if self.watcher:
            self.watcher.closed.set()

    def log(self, text):
        logging.info(text)
        self.signals.log.emit(text)

    def root(self):
        value = self.settings.get("steam_path", "")
        if not value:
            raise SafetyError("未找到 Steam，请先选择安装目录")
        root=Path(value).absolute()
        if root.parent==root or any(p.lower() in {'steamapps','userdata'} for p in root.parts):
            raise SafetyError('拒绝磁盘根目录、游戏或用户数据目录作为 Steam 修复目标')
        buffer=windows.ctypes.create_unicode_buffer(32768)
        windows.ctypes.windll.kernel32.GetWindowsDirectoryW(buffer,len(buffer))
        system=Path(buffer.value).resolve()
        if root.resolve()==system or root.resolve().is_relative_to(system):
            raise SafetyError('拒绝 Windows 系统目录作为 Steam 修复目标')
        for folder_id in (0x26,0x2a,0x23):
            buffer=windows.ctypes.create_unicode_buffer(32768)
            if windows.ctypes.windll.shell32.SHGetFolderPathW(None,folder_id,None,0,buffer)==0 and root.resolve()==Path(buffer.value).resolve():
                raise SafetyError('拒绝系统公共目录根作为 Steam 修复目标')
        if not self.settings.get('root_confirmed',True):
            raise SafetyError('请核对安装目录并点击立即检查，确认后才启用管理员修复')
        return root

    def notify(self, text):
        self.log(text)
        self.signals.alert.emit(text)

    def report(self, result: CheckResult, findings=None):
        self.last_result = result
        data = asdict(result)
        data["findings"] = findings or []
        data['observations'] = self.last_observations
        self.signals.result.emit(data)
        from .core import atomic_json
        atomic_json(self.state / "last-report.json", {**data, "time": time.strftime("%Y-%m-%d %H:%M:%S")})

    def reference(self, root: Path, online=True):
        version, _ = local_identity(root)
        latest = ""
        offline = False
        if online:
            try:
                manifest = self.client.manifest()
                latest = manifest["version"]
            except Exception as e:
                self.log(f"联网检查失败：{e}。尝试匹配已有可信基线。")
                offline = True
                manifest = None
            if manifest and version == latest:
                existing = self.references.get(version)
                if not existing or existing["packages"] != manifest["packages"]:
                    self.references[version] = self.client.reference(manifest, root)
            elif manifest and version != latest:
                from .updater import UpdateController
                ref = UpdateController(self).run(root, manifest)
                return ref, ref['version'], False
        ref = self.references.get(version)
        if not ref:
            raise SafetyError(f"本地版本 {version} 尚无可信基线；没有判定为恶意修改，也不会自动修复")
        return ref, latest, offline

    def scan(self, online=True, quick=False, automatic=True):
        root = self.root()
        self.signals.busy.emit(True)
        try:
            initial_ref = self.cached_reference(root)
            audit = self.client_audit(root, initial_ref, True)
            high = [f for f in audit.findings if f.blocking]
            if high:
                if automatic:
                    payload = self.contain(root, high, initial_ref, enqueue=False)
                    if payload:
                        self.handle_incident(payload)
                        audit = self.client_audit(root, initial_ref, True)
                        high = [f for f in audit.findings if f.blocking]
                if high or self.active_incident:
                    result = CheckResult("blocked", initial_ref["version"] if initial_ref else "", detail="客户端规则命中高风险项，已阻止启动")
                    self.report(result, [f.message for f in audit.findings] + audit.incomplete)
                    return result, initial_ref, [f.message for f in audit.findings]
            ref, latest, offline = self.reference(root, online)
            audit = self.client_audit(root, ref, True)
            self.last_observations = [f.message for f in audit.findings if f.severity=='info']
            findings = [f.message for f in audit.findings if f.severity!='info'] + audit.incomplete
            result = verify(root, ref, quick)
            result.latest = latest
            if result.state == "clean":
                result.detail = "关键文件与匹配版本基线一致"
                if offline:
                    result.detail += "；离线检查，未确认官方最新版本"
                if latest and latest != result.version:
                    result.detail += "；官方有不同版本，建议更新"
            if result.state == "mismatch":
                # A second stable read is required before automatic termination/repair.
                self.log("发现不一致，立即复核，排除更新期间变化…")
                second = verify(root, ref, quick)
                if second.state != "mismatch" or second.mismatches != result.mismatches:
                    result = CheckResult("updating", result.version, latest,
                                         detail="两次检查结果不同，暂不结束进程或修复")
                else:
                    # If a new version is available while the old one is being replaced,
                    # avoid reverting files mid-update. User can recheck once update finishes.
                    active_update = self.update_state and self.update_state.root == root
                    if active_update or local_identity(root)[0] != ref['version'] or (latest and latest != result.version):
                        result = CheckResult("updating", result.version, latest,
                                             detail="受控更新或版本切换中；当前不一致未确认，未自动修复")
                    else:
                        text = "确认关键文件与该版本基线不一致：" + "、".join(result.mismatches[:8])
                        self.notify(text)
                        if automatic and self.settings.get("stop_on_mismatch", True):
                            windows.stop_steam(root)
                            self.log("已结束该安装目录内的 Steam 相关进程。")
                        if automatic and self.settings.get("auto_repair", True):
                            self.repair(ref, result.mismatches)
                            result = verify(root, ref, quick)
                            result.latest = latest
                            result.detail = "已隔离备份并修复；请再次通过受保护入口启动"
            self.last_scan = time.monotonic()
            self.last_snapshot = snapshot(root, ref)
            self.report(result, findings)
            for finding in findings:
                if finding not in self.reported:
                    self.reported.add(finding)
                    self.notify(finding)
            self.log(f"检查完成：{result.state}，版本 {result.version}，已检查 {result.checked} 个文件")
            if self.last_observations:
                self.log(f"另有 {len(self.last_observations)} 个未收录脚本，未发现阻断证据；仅记录到报告，不阻止启动。")
            return result, ref, findings
        finally:
            self.signals.busy.emit(False)

    def repair(self, ref, names):
        root = self.root()
        # No operation is allowed to override a running installation.
        windows.assert_stopped(root)
        current = verify(root, ref)
        if current.state != "mismatch" or not set(names).issubset(current.mismatches):
            raise SafetyError("修复前状态已改变，取消替换")
        transaction = Repairer(root, self.state, self.client, ref).repair(
            names, lambda: windows.assert_stopped(root))
        self.log(f"修复完成；隔离记录：{transaction}")

    def launch(self):
        result, ref, findings = self.scan(online=True, quick=False, automatic=True)
        if result.state != "clean":
            raise SafetyError("启动前完整性检查未通过，已阻止本次受保护启动")
        audit=self.client_audit(self.root(),ref,True)
        if audit.incomplete or any(f.blocking for f in audit.findings):
            raise SafetyError('启动前存在高风险证据或检查未完成，已阻止启动')
        # Re-read the quick set immediately before execution; still not an OS execution gate.
        last = verify(self.root(), ref, quick=True)
        if last.state != "clean":
            raise SafetyError("执行前复查未通过，已取消启动")
        if windows.steam_processes(self.root()):
            self.log('Steam 已运行且安全复查通过，无需重复启动。')
            return
        windows.launch_steam(self.root(), force=True)
        self.log("已通过受保护入口启动 Steam，并传入 -forcesteamupdate。实际更新结果由后续检查确认。")

    def rollback(self):
        root = self.root()
        windows.assert_stopped(root)
        records = sorted((self.state / "quarantine").glob("*/journal.json"), reverse=True)
        for journal_path in records:
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            if journal["status"] in ("completed", "prepared") and Path(journal["root"]).absolute() == root:
                ref = self.references.get(journal["version"], self.seed)
                Repairer(root, self.state, self.client, ref).rollback(
                    journal_path.parent, lambda: windows.assert_stopped(root))
                self.notify("已回滚最近一次修复。恢复的原文件可能不可信，请检查后再启动 Steam。")
                return
        raise SafetyError("没有可回滚的修复记录")

    def poll(self):
        if not self.settings.get('root_confirmed',True):
            return
        if time.monotonic() < self.retry_after:
            return
        if not self.settings.get("monitor", True) or not self.settings.get("steam_path"):
            return
        root = self.root()
        if root != self.last_root:
            self.last_root = root
            self.last_scan = 0
            self.last_snapshot = None
            self.was_running = False
            self.seen_modules.clear()
        running = bool(windows.steam_processes(root))
        now = time.monotonic()
        if running and not self.was_running:
            self.log("检测到 Steam 启动，将在文件稳定后执行后台检查。")
            self.stable_since = now
            self.last_scan = 0
        self.was_running = running
        if not running:
            return
        version, _ = local_identity(root)
        ref = self.references.get(version)
        current = snapshot(root, ref) if ref else None
        if current != self.last_snapshot:
            self.last_snapshot = current
            self.stable_since = now
            self.last_scan = 0
        if now - self.stable_since >= 10 and (not self.last_scan or now - self.last_scan >= 900):
            self.scan()
        elif now - self.stable_since >= 10 and self.last_result and self.last_result.state == "updating" and now - self.last_scan >= 30:
            self.scan()
        if self.settings.get("module_monitor", True) and now - self.last_module_scan >= 60:
            self.last_module_scan = now
            for issue in windows.module_findings(root, self.seen_modules):
                self.notify(issue)

    def run(self):
        if not self.initialize_worker('worker'):
            return
        while not self.shutdown.is_set():
            try:
                command = self.commands.get(timeout=1)
            except queue.Empty:
                command = "poll"
            try:
                if isinstance(command, tuple) and command[0] == "incident":
                    self.handle_incident(command[1])
                elif command == "scan":
                    self.scan()
                elif command == "launch":
                    self.launch()
                elif command == "rollback":
                    self.rollback()
                elif command == 'clear-reinfection':
                    result,ref,findings=self.scan(automatic=False)
                    if result.state!='clean' or findings:raise SafetyError('复查未通过，继续拦截复发客户端')
                    self.reinfection_holds.discard(str(self.root()))
                    self.notify('已按用户确认解除复发拦截；客户端校验通过不代表系统恶意来源已清除。')
                elif command == "poll":
                    self.poll()
                elif command == "repair":
                    result, ref, findings = self.scan(automatic=False)
                    if result.state == "mismatch":
                        windows.stop_steam(self.root())
                        self.repair(ref, result.mismatches)
                        self.scan(online=False, automatic=False)
                    else:
                        self.log("当前没有已确认且可修复的基线异常。")
            except Exception as e:
                logging.exception("Operation failed: %s", command)
                self.notify(f"操作未完成：{e}")
                self.report(CheckResult("unverified", "", detail=str(e)))
                # Back off unsupported channels/network errors; do not spam every three seconds.
                self.last_scan = time.monotonic()
                self.retry_after = time.monotonic() + 60
            finally:
                self.signals.busy.emit(bool(self.active_incident))
