"""Steam client semantic auditing, independently implemented from upstream design.

Detection directions: fenglinbei/IsMySteamSafe (Apache-2.0). This module does not
execute scripts or follow links found in the client. Game/MOD trees are excluded.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from .core import SafetyError, safe_target, sha256

LOADERS = {"version.dll", "versionorg.dll", "msacm32.drv", "wsock32.dll"}
BASE_DIRS = ("", "bin", "win64", "steamui", "clientui", "bin/cef")
ON = {"1", "true", "enable", "enabled"}
OFF = {"0", "false", "disable", "disabled"}
SUPPORT_KEYS = "SupportMessages|HelpAppPage|HelpFrontPage"
OFFICIAL_DOMAINS = {"steampowered.com", "steamcommunity.com", "steamgames.com", "steamstatic.com", "valvesoftware.com"}
SCRIPT_MAX = 32 * 1024 * 1024


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    files: tuple[str, ...] = ()
    action: str = "review"
    evidence: dict = field(default_factory=dict)

    @property
    def blocking(self):
        return self.severity in {"confirmed", "high"}


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)


def trusted_digest(expected,digest):
    return bool(expected) and (digest==expected['sha256'] or digest in expected.get('sha256_alternates',[]))


def sensitive_dirs(root: Path) -> list[str]:
    result = list(BASE_DIRS)
    cef = safe_target(root, "bin/cef")
    if cef.is_dir():
        for child in sorted(cef.iterdir()):
            if child.is_dir():
                rel = child.relative_to(root).as_posix()
                safe_target(root, rel)
                result.append(rel)
    return sorted(set(result))


def decode_config(data: bytes):
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16"), "utf-16"
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig"), "utf-8-sig"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def config_risky(key: str, value: str) -> bool:
    key, value = key.lower(), value.strip().strip('"\'').lower()
    if key.startswith("bootstrapperinhibit"):
        return value in ON
    if key == "bootstrapperforceselfupdate":
        return value in OFF
    if key in {"forceofflinemode", "disabledownloads"}:
        return value in ON
    if key in {"clientdownloadhost", "overridepackageurl"}:
        return bool(value)
    return False


def analyze_config(data: bytes) -> tuple[list[str], bytes]:
    text, encoding = decode_config(data)
    risky, retained = [], []
    for raw in text.splitlines(keepends=True):
        line = raw.strip()
        if line.startswith(("#", ";", "//")) or "=" not in line:
            retained.append(raw)
            continue
        key, value = line.split("=", 1)
        value = re.split(r"\s+(?:#|;|//)", value, maxsplit=1)[0].strip()
        if config_risky(key.strip(), value):
            risky.append(key.strip() + "=" + value)
        else:
            retained.append(raw)
    return risky, "".join(retained).encode(encoding)


def official_url(url: str) -> bool:
    try:
        u = urlsplit(url)
        host = (u.hostname or "").encode("idna").decode().lower().rstrip(".")
        return u.scheme.lower() == "https" and not u.username and not u.password and any(
            host == domain or host.endswith("." + domain) for domain in OFFICIAL_DOMAINS)
    except (ValueError, UnicodeError):
        return False


def safe_url_display(url):
    try:
        value=urlsplit(url)
        return value.scheme+'://'+(value.hostname or '')+value.path+('?[参数已隐藏]' if value.query else '')
    except ValueError:
        return '[地址格式异常]'


def script_signals(text: str) -> list[tuple[str, str, str]]:
    """Narrow function patterns, plus direct and locally assigned support routes."""
    found = []
    clipboard_hook = re.search(r"addEventListener\s*\(\s*['\"]copy['\"]|\boncopy\s*=|clipboard\.(?:writeText|write)\s*=", text, re.I)
    clipboard_rewrite = re.search(r"clipboardData\.(?:setData|clearData)|preventDefault\s*\(|writeText\s*\(\s*['\"]\s*['\"]", text, re.I)
    target_context = re.search(r"steamhelper|supportalert|SupportMessages|HelpFrontPage|https?://", text, re.I)
    if clipboard_hook and clipboard_rewrite and target_context:
        found.append(("clipboard-interference", "high", "客服／URL 上下文存在复制事件拦截或剪贴板替换"))
    timer = re.search(r"Date\.(?:now|parse)\s*\(|new\s+Date\s*\(", text)
    if timer and re.search(r"setTimeout|setInterval", text) and re.search(r"supportalert|steamhelper|SupportMessages|clipboardData", text, re.I):
        found.append(("delayed-support-payload", "high", "客服／复制干预代码与日期及延迟执行关联"))
    for method in ("BMustShowSupportAlertDialog", "BHasActiveSupportAlerts"):
        pattern = re.compile(r"\b" + method + r"\s*(?:[:=]\s*function\s*)?\([^)]{0,300}\)\s*\{\s*return\b\s*(?:true|false|[01]|!!?[01])\s*[;} ,]", re.I)
        if pattern.search(text):
            found.append(("support-constant", "confirmed", f"{method} 的函数体直接返回固定值"))
    for match in re.finditer(r"\bOnGameActionUserRequest\s*\([^)]{0,300}\)\s*\{", text):
        body = text[match.end():match.end() + 1200]
        redirect = re.search(r"ExecuteSteamURL\s*\(\s*['\"]steam://open/supportalert['\"]\s*\)\s*;?\s*return\b", body, re.I)
        if redirect and ("switch" not in body or redirect.start() < body.index("switch")):
            found.append(("game-support-redirect", "confirmed", "游戏操作被提前重定向到客服告警并返回"))
    for match in re.finditer(r"display\s*:\s*['\"]none['\"]", text, re.I):
        around = text[max(0, match.start()-1000):match.end()+1000]
        if "urlbar" in around.lower() and any(v in around for v in ("bIsSecure", "Browser_NotSecure", "Browser_Secure")):
            found.append(("hidden-urlbar", "confirmed", "地址栏与证书状态界面附近存在 display:none"))
            break
    for match in re.finditer(r"\b(?:bSecure|bIsSecure|isSecure)\s*[:=]\s*(?:true|!0)\b", text):
        if re.search(r"http|url", text[max(0,match.start()-100):match.end()+250], re.I):
            found.append(("forced-secure", "review", "URL 安全状态附近被设为常量真，需要核对"))
            break
    routes = []
    direct = re.compile(r"['\"]?(" + SUPPORT_KEYS + r")[ '\"]*[:=]\s*['\"](https?://[^'\"\s<>]+)", re.I)
    for match in direct.finditer(text):
        routes.append((match.group(1), match.group(2)))
    variable = re.compile(r"['\"]?(" + SUPPORT_KEYS + r")[ '\"]*:\s*([$A-Za-z_][$\w]*)", re.I)
    for match in variable.finditer(text):
        prefix = text[max(0, match.start()-8000):match.start()]
        assignments = list(re.finditer(r"(?<![$\w])" + re.escape(match.group(2)) + r"\s*=\s*['\"](https?://[^'\"\s<>]+)", prefix))
        if assignments:
            routes.append((match.group(1), assignments[-1].group(1)))
    for key, url in routes:
        if not official_url(url):
            found.append(("support-route", "confirmed", f"客服路由 {key} 指向非官方 HTTPS 地址：{safe_url_display(url)[:200]}"))
    return list(dict.fromkeys(found))


class ClientAuditor:
    def __init__(self, signature):
        self.signature = signature
        self.script_cache = {}
        self.signature_cache = {}

    def invalidate(self, paths=()):
        if not paths:
            self.script_cache.clear()
            self.signature_cache.clear()
        else:
            for relative in paths:
                suffix = relative.replace("\\", "/").lower()
                for cache in (self.script_cache, self.signature_cache):
                    for key in list(cache):
                        if key[0].replace("\\", "/").lower().endswith("/" + suffix):
                            cache.pop(key, None)

    def audit(self, root: Path, ref: dict | None, scripts=True) -> AuditResult:
        result = AuditResult()
        trusted = (ref or {}).get("files", {})
        for directory in sensitive_dirs(root):
            existing = []
            for name in sorted(LOADERS):
                rel = directory + "/" + name if directory else name
                path = safe_target(root, rel)
                if path.is_file():
                    existing.append(rel)
            forwarder = any(Path(n).name == "versionorg.dll" for n in existing)
            if forwarder:
                pair = tuple(n for n in existing if Path(n).name in {"version.dll", "versionorg.dll"})
                result.findings.append(Finding("version-forwarder", "confirmed", "发现 versionOrg.dll 侧载／转发结构", pair, "quarantine"))
            for rel in existing:
                if forwarder and Path(rel).name in {"version.dll", "versionorg.dll"}:
                    continue
                path = safe_target(root, rel)
                digest = sha256(path)
                if trusted_digest(trusted.get(rel.lower()),digest):
                    continue
                s = path.stat()
                key = (str(path), s.st_size, s.st_mtime_ns, digest)
                if key not in self.signature_cache:
                    self.signature_cache[key] = self.signature(path)
                valid, publisher = self.signature_cache[key]
                valve = valid and publisher.lower().strip(" .") in {"valve", "valve corp", "valve corporation"}
                result.findings.append(Finding("dll-sideload", "review" if valve else "high",
                    f"敏感目录存在额外加载入口 {rel}；签名：{publisher or '未通过／无签名'}",
                    (rel,), "review" if valve else ("restore" if rel.lower() in trusted else "quarantine"),
                    {"sha256": digest, "publisher": publisher, "signature_valid": valid}))
        cfg = safe_target(root, "steam.cfg")
        if cfg.is_file():
            if cfg.stat().st_size > 1024 * 1024:
                result.incomplete.append("steam.cfg 超过读取上限")
            else:
                risky, _ = analyze_config(cfg.read_bytes())
                if risky:
                    result.findings.append(Finding("update-controls", "high", "steam.cfg 存在更新抑制／离线／下载来源设置",
                        ("steam.cfg",), "cfg_clean", {"settings": risky, "sha256": sha256(cfg)}))
        if scripts:
            self.audit_scripts(root, trusted, result)
            self.audit_loading_graph(root, trusted, result)
        # Capture hashes for bounded remediation; changed evidence must be re-audited.
        for finding in result.findings:
            finding.evidence["file_hashes"] = {n: sha256(safe_target(root, n)) for n in finding.files}
        return result

    def audit_scripts(self, root, trusted, result):
        total = count = 0
        for relative in ("steamui", "clientui", "millennium/plugins"):
            base = safe_target(root, relative)
            if not base.is_dir():
                continue
            for directory, dirs, files in os.walk(base, followlinks=False):
                dirs[:] = [d for d in dirs if d not in {"node_modules", ".git"}]
                for name in sorted(files):
                    if not name.lower().endswith((".js", ".mjs")):
                        continue
                    rel = (Path(directory) / name).relative_to(root).as_posix()
                    path = safe_target(root, rel)
                    s = path.stat()
                    total += s.st_size
                    count += 1
                    if count > 2000 or total > 256 * 1024 * 1024:
                        result.incomplete.append("界面脚本检查达到文件数／总大小上限")
                        return
                    if s.st_size > SCRIPT_MAX:
                        result.incomplete.append(f"脚本超过单文件上限：{rel}")
                        continue
                    key = (str(path), s.st_size, s.st_mtime_ns)
                    cached = self.script_cache.get(key)
                    expected = trusted.get(rel.lower())
                    if cached is None:
                        data = path.read_bytes()
                        digest = hashlib.sha256(data).hexdigest()
                        signals = [] if trusted_digest(expected,digest) else script_signals(data.decode("utf-8", errors="replace"))
                        cached = (digest, signals)
                        self.script_cache[key] = cached
                    digest, signals = cached
                    if trusted and relative in {"steamui", "clientui"} and not expected:
                        result.findings.append(Finding("unlisted-script", "info", f"未收录界面脚本（可能为旧版残留，未判定篡改）：{rel}", (rel,), evidence={"sha256": digest}))
                    # Current official file may contain a legitimate matching pattern.
                    if trusted_digest(expected,digest):
                        continue
                    for rule, severity, message in signals:
                        result.findings.append(Finding(rule, severity, f"{rel}：{message}", (rel,),
                            "restore" if expected and severity != "review" else "quarantine-script" if trusted and relative in {'steamui','clientui'} and not expected and severity in {'high','confirmed'} else "review",
                            {"sha256": digest, "unlisted": bool(trusted) and not expected}))
                    if trusted_digest(expected,digest):
                        continue
                    text=path.read_text(encoding='utf-8',errors='replace')
                    for load in re.finditer(r"\bimport\s*\(\s*['\"]([^'\"]+)['\"]\s*\)|\bfrom\s+['\"]([^'\"]+)['\"]",text):
                        source=load.group(1) or load.group(2)
                        if not source.startswith(('.', '/', 'http:', 'https:', 'file:')):
                            continue
                        url=urlsplit(source)
                        if url.scheme or url.netloc:
                            unsafe=not official_url(source)
                        else:
                            from urllib.parse import unquote
                            target=(path.parent/unquote(url.path)).resolve() if not url.path.startswith('/') else (root/url.path.lstrip('/')).resolve()
                            unsafe=not target.is_relative_to(root.resolve()) or (bool(trusted) and target.relative_to(root.resolve()).as_posix().lower() not in trusted)
                        if unsafe:
                            result.findings.append(Finding('unexpected-js-import','high',f'{rel} 导入非基线／外部代码：{safe_url_display(source) if url.scheme else url.path}',(rel,),
                                'restore' if expected else 'quarantine-script' if trusted and relative in {'steamui','clientui'} else 'review',{'unlisted':bool(trusted) and not expected}))

    def audit_loading_graph(self, root, trusted, result):
        from html.parser import HTMLParser
        class Sources(HTMLParser):
            def __init__(self):
                super().__init__()
                self.values = []
            def handle_starttag(self, tag, attrs):
                a = dict(attrs)
                if tag.lower() == "script" and a.get("src"):
                    self.values.append(a["src"])
        for relative in ("steamui", "clientui"):
            base = safe_target(root, relative)
            if not base.is_dir():
                continue
            for path in base.rglob("*.html"):
                rel = path.relative_to(root).as_posix()
                path = safe_target(root, rel)
                if path.stat().st_size > 2 * 1024 * 1024:
                    result.incomplete.append(f"HTML 超出读取上限：{rel}")
                    continue
                data = path.read_bytes()
                expected = trusted.get(rel.lower())
                if trusted_digest(expected,hashlib.sha256(data).hexdigest()):
                    continue
                parser = Sources()
                parser.feed(data.decode("utf-8", errors="replace"))
                for source in parser.values:
                    url = urlsplit(source)
                    if url.scheme or url.netloc:
                        unsafe = not official_url(source)
                    else:
                        from urllib.parse import unquote
                        target = unquote(url.path)
                        candidate = (path.parent / target).resolve() if not target.startswith("/") else (root / target.lstrip("/")).resolve()
                        if not candidate.is_relative_to(root.resolve()):
                            unsafe = True
                        else:
                            target_rel = candidate.relative_to(root.resolve()).as_posix().lower()
                            safe_target(root, target_rel)
                            unsafe = bool(trusted) and target_rel not in trusted
                    if unsafe:
                        shown=safe_url_display(source) if url.scheme or url.netloc else url.path
                        result.findings.append(Finding("unexpected-script-load", "high", f"{rel} 加载了非基线／外部脚本：{shown[:180]}",
                            (rel,), "restore" if expected else "review", {"source": shown}))


def registry_findings(root: Path, reader) -> list[Finding]:
    """Read-only persistence audit. No registry setting is silently removed."""
    findings = []
    for hive, view in (("HKCU", 0), ("HKLM", 32), ("HKLM", 64)):
        for suffix in ("Run", "RunOnce"):
            key = "Software\\Microsoft\\Windows\\CurrentVersion\\" + suffix
            for name, raw in reader(hive, view, key).items():
                command = str(raw)
                lowered = command.lower()
                related = str(root).lower() in lowered or any(s in lowered for s in ("steamwebhelper", "millennium"))
                expected = re.fullmatch(re.escape('"' + str(root / "steam.exe") + '"') + r"(?:\s+-silent)?", command.strip(), re.I)
                if related and not expected:
                    script = any(s in lowered for s in ("powershell", "pwsh", "cmd.exe", "rundll32", "wscript", "cscript"))
                    findings.append(Finding("startup-run", "high" if script else "review",
                        f"非标准 Steam 启动项：{hive}\\{key}\\{name}", evidence={"command": command}))
    for view in (32, 64):
        for exe in ("steam.exe", "steamwebhelper.exe", "steamservice.exe"):
            key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" + "\\" + exe
            values = {k.lower(): v for k, v in reader("HKLM", view, key).items()}
            if values.get("debugger"):
                findings.append(Finding("ifeo-debugger", "high", f"{exe} 配置了 IFEO Debugger，需要核对", evidence={"command": str(values["debugger"])}))
            exitkey = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" + "\\" + exe
            exitvalues = {k.lower(): v for k, v in reader("HKLM", view, exitkey).items()}
            flag = values.get("globalflag", 0)
            try:
                flag = int(flag, 0) if isinstance(flag, str) else int(flag)
            except (ValueError, TypeError):
                flag = 0
            if flag & 0x200 or exitvalues.get("monitorprocess"):
                findings.append(Finding("silent-exit", "high", f"{exe} 配置了 SilentProcessExit 退出触发器", evidence={"command": str(exitvalues.get("monitorprocess", ""))}))
    return findings


class RiskRemediator:
    """Only known client loading paths and steam.cfg may be removed/rewritten."""
    def __init__(self, root, state):
        self.root, self.state = root, state

    def apply(self, findings, assert_stopped):
        import time, shutil, tempfile
        from .core import atomic_json
        assert_stopped()
        allowed = {d + "/" + n if d else n for d in sensitive_dirs(self.root) for n in LOADERS}
        operations = {}
        for finding in findings:
            if not finding.blocking:
                continue
            for name in finding.files:
                if finding.action == "quarantine" and name in allowed:
                    operations[name] = (None, finding.evidence["file_hashes"][name])
                elif finding.action == 'quarantine-script' and finding.evidence.get('unlisted') and name.startswith(('steamui/','clientui/')) and name.endswith(('.js','.mjs')):
                    operations[name] = (None,finding.evidence['file_hashes'][name])
                elif finding.action == "cfg_clean" and name == "steam.cfg":
                    path = safe_target(self.root, name)
                    data = path.read_bytes()
                    if hashlib.sha256(data).hexdigest() != finding.evidence["file_hashes"][name]:
                        raise SafetyError("配置已变化，取消修复")
                    _, clean = analyze_config(data)
                    operations[name] = (clean, finding.evidence["file_hashes"][name])
        if not operations:
            return None
        tx = self.state / "quarantine" / (time.strftime("%Y%m%d-%H%M%S") + "-risk-" + os.urandom(4).hex())
        tx.mkdir(parents=True)
        records = []
        journal = {"root": str(self.root.absolute()), "version": "semantic", "kind": "risk",
                   "status": "prepared", "files": records}
        atomic_json(tx / "journal.json", journal)
        for name, (replacement, digest) in operations.items():
            assert_stopped()
            path = safe_target(self.root, name)
            if not path.is_file() or sha256(path) != digest:
                raise SafetyError("风险文件在处理期间发生变化，保留现状并重新检查")
            old = safe_target(tx, "old/" + name)
            old.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, old)
            if sha256(old) != digest:
                raise SafetyError("隔离备份校验失败")
            record = {"name": name, "existed": True, "old_sha256": digest,
                      "new_sha256": hashlib.sha256(replacement).hexdigest() if replacement is not None else None,
                      "applied": True}
            records.append(record)
            atomic_json(tx / "journal.json", journal)
            if replacement is None:
                safe_target(self.root, name).unlink()
            else:
                fd, temporary = tempfile.mkstemp(prefix=".sentinel-", dir=path.parent)
                os.close(fd)
                try:
                    Path(temporary).write_bytes(replacement)
                    if sha256(path) != digest:
                        raise SafetyError("写入前配置发生变化，已取消")
                    os.replace(temporary, safe_target(self.root, name))
                finally:
                    Path(temporary).unlink(missing_ok=True)
        journal["status"] = "completed"
        atomic_json(tx / "journal.json", journal)
        return tx
