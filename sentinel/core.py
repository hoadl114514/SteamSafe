"""Version-aware Steam checks. Never trust locally discovered files as a baseline."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import ssl
import stat
import tempfile
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field

import certifi
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CDNS = (
    "https://client-update.akamai.steamstatic.com/",
    "https://client-update.fastly.steamstatic.com/",
    "https://client-update.steamstatic.com/",
)
MAX_PACKAGE = 512 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
CRITICAL_GROUPS = {"steam_win64", "bins_win64", "bins_misc_win64",
                   "bins_webhelpers_win64", "bins_cef_win64", "bins_codecs_win64",
                   "bins_hardware_all", "bins_hardware_win64", "steamui_websrc_all"}
STEAM_NAMES = {"steam.exe", "steamwebhelper.exe", "steamservice.exe",
               "gameoverlayui.exe", "steamerrorreporter.exe", "steamerrorreporter64.exe"}


class SafetyError(Exception):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def read_signed_seed(folder: Path, public_key_hex: str | None = None) -> dict:
    # Public key ships inside the bundle; private release key is never bundled.
    if public_key_hex is None:
        from .release_key import PUBLIC_KEY
        public_key_hex = PUBLIC_KEY
    public = bytes.fromhex(public_key_hex)
    envelope = json.loads((folder / "baseline.json").read_text(encoding="utf-8"))
    Ed25519PublicKey.from_public_bytes(public).verify(
        base64.b64decode(envelope["signature"], validate=True), canonical(envelope["payload"]))
    payload = envelope["payload"]
    validate_reference(payload)
    return payload


def parse_kv(text: str) -> dict:
    if len(text) > 2 * 1024 * 1024:
        raise SafetyError("清单超过大小限制")
    tokens = re.findall(r'"((?:\\.|[^"\\])*)"|([{}])|([^\s"{}]+)',
                        re.sub(r"(?m)^\s*//.*$", "", text))
    values = [a if a else b if b else c for a, b, c in tokens]
    pos = 0

    def obj(nested=False, depth=0):
        nonlocal pos
        if depth > 20:
            raise SafetyError("清单嵌套过深")
        result = {}
        while pos < len(values):
            key = values[pos]
            pos += 1
            if key == "}":
                if not nested:
                    raise SafetyError("清单括号不匹配")
                return result
            if key == "{" or pos >= len(values) or key in result:
                raise SafetyError("清单格式错误或键重复")
            val = values[pos]
            pos += 1
            if val == "{":
                val = obj(True, depth + 1)
            elif val == "}":
                raise SafetyError("清单值缺失")
            result[key] = val
        if nested:
            raise SafetyError("清单缺少结束括号")
        return result
    return obj()


def safe_relative(name: str) -> str:
    name = name.replace("\\", "/")
    p = PureWindowsPath(name)
    if not name or p.is_absolute() or p.drive or ":" in name or "\x00" in name:
        raise SafetyError(f"拒绝非法路径：{name!r}")
    parts = name.split("/")
    if any(x in ("", ".", "..") or x.endswith((".", " ")) for x in parts):
        raise SafetyError(f"拒绝路径穿越／别名：{name!r}")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    if any(x.split(".")[0].upper() in reserved for x in parts):
        raise SafetyError("拒绝 Windows 保留文件名")
    return "/".join(parts)


def safe_target(root: Path, relative: str) -> Path:
    root = root.absolute()
    rel = safe_relative(relative)
    target = root / rel
    # Refuse every existing reparse point, including root/ancestors. No junction writes.
    chain = list(root.parents) + [root]
    cur = root
    for part in rel.split("/"):
        cur = cur / part
        chain.append(cur)
    for item in chain:
        try:
            s = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(s.st_mode) or getattr(s, "st_file_attributes", 0) & 0x400:
            raise SafetyError(f"拒绝符号链接／重解析点：{item}")
    if not target.resolve().is_relative_to(root.resolve()):
        raise SafetyError("目标超出 Steam 目录")
    return target


def manifest_data(text: str) -> dict:
    kv = parse_kv(text)
    if "win64" not in kv:
        raise SafetyError("首版只支持 Windows x64 正式版清单")
    section = kv["win64"]
    if not re.fullmatch(r"\d{1,15}", str(section.get("version", ""))):
        raise SafetyError("清单版本无效")
    packages = {}
    for group in CRITICAL_GROUPS:
        raw = section.get(group)
        if not isinstance(raw, dict):
            raise SafetyError(f"清单缺少关键组件：{group}")
        name = raw.get("file", "")
        digest = raw.get("sha2", "")
        size = int(raw.get("size", 0))
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or ".zip." not in name:
            raise SafetyError("组件包文件名无效")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", digest) or not 0 < size <= MAX_PACKAGE:
            raise SafetyError("组件包哈希或大小无效")
        packages[group] = {"file": name, "sha256": digest.lower(), "size": size}
    return {"version": str(section["version"]), "platform": "win64",
            "channel": "stable", "packages": packages}


def covered_file(name: str) -> bool:
    return name.endswith((".exe", ".dll")) or (name.startswith(("steamui/", "clientui/")) and name.endswith((".js", ".css", ".html")))


def validate_reference(ref: dict):
    if ref.get("platform") != "win64" or ref.get("channel") != "stable":
        raise SafetyError("基线平台／渠道不支持")
    if not ref.get("files") or "steam.exe" not in ref["files"]:
        raise SafetyError("基线没有启动器")
    for name, entry in ref["files"].items():
        if safe_relative(name) != name or not covered_file(name):
            raise SafetyError("基线文件路径无效")
        if not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]):
            raise SafetyError("基线哈希无效")
        if entry["package"] not in ref["packages"] or not 0 < entry["size"] <= MAX_FILE:
            raise SafetyError("基线文件元数据无效")


class OfficialClient:
    def __init__(self, cache: Path, emit=lambda s: None):
        self.cache = cache
        self.emit = emit
        self.cache.mkdir(parents=True, exist_ok=True)
        context = ssl.create_default_context(cafile=certifi.where())
        class OfficialRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                if not any(newurl.startswith(host) for host in CDNS):
                    raise SafetyError("拒绝非官方 CDN 重定向")
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            OfficialRedirect(), urllib.request.HTTPSHandler(context=context))

    def response(self, name: str):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise SafetyError("下载路径无效")
        errors = []
        for base in CDNS:
            try:
                response = self.opener.open(urllib.request.Request(
                    base + name, headers={"User-Agent": "SteamSafe/0.1 Beta"}), timeout=25)
                final = response.geturl()
                if not any(final.startswith(host) for host in CDNS):
                    response.close()
                    raise SafetyError("拒绝非官方 CDN 重定向")
                return response
            except Exception as e:
                errors.append(str(e))
        raise SafetyError("官方更新服务器不可用：" + " / ".join(errors))

    def manifest(self):
        self.emit("正在获取官方 Win64 正式版清单…")
        with self.response("steam_client_win64") as response:
            data = response.read(2 * 1024 * 1024 + 1)
        return manifest_data(data.decode("utf-8-sig"))

    def package(self, info: dict, steam_root: Path | None = None) -> Path:
        dest = self.cache / (info["sha256"] + ".zip")
        if dest.is_file() and dest.stat().st_size == info["size"] and sha256(dest) == info["sha256"]:
            return dest
        if steam_root:
            candidate = safe_target(steam_root, "package/" + info["file"])
            if candidate.is_file() and candidate.stat().st_size == info["size"] and sha256(candidate) == info["sha256"]:
                shutil.copyfile(candidate, dest)
                if sha256(dest) == info["sha256"]:
                    return dest
        self.emit(f"下载并校验组件：{info['file'].split('.zip.')[0]} ({info['size'] // 1048576} MB)")
        fd, temporary = tempfile.mkstemp(prefix="download-", dir=self.cache)
        os.close(fd)
        tmp = Path(temporary)
        try:
            total = 0
            with self.response(info["file"]) as response, tmp.open("wb") as out:
                started = time.monotonic()
                next_progress = 8 * 1024 * 1024
                while block := response.read(64 * 1024):
                    total += len(block)
                    if time.monotonic() - started > 900:
                        raise SafetyError("组件下载超时，请稍后重试")
                    if total > info["size"]:
                        raise SafetyError("下载包超过清单大小")
                    out.write(block)
                    if total >= next_progress:
                        self.emit(f"组件下载进度：{total // 1048576}/{info['size'] // 1048576} MB")
                        next_progress += 8 * 1024 * 1024
            if total != info["size"] or sha256(tmp) != info["sha256"]:
                raise SafetyError("下载包大小／SHA-256 校验失败")
            os.replace(tmp, dest)
            return dest
        finally:
            tmp.unlink(missing_ok=True)

    def reference(self, manifest: dict, root: Path | None = None) -> dict:
        ref = {**manifest, "files": {}, "source": "official-https"}
        for group, info in sorted(manifest["packages"].items()):
            package = self.package(info, root)
            with zipfile.ZipFile(package) as z:
                seen = set()
                if len(z.infolist()) > 20000:
                    raise SafetyError("组件文件条目过多")
                for item in z.infolist():
                    if item.is_dir():
                        continue
                    name = safe_relative(item.filename).lower()
                    if name in seen:
                        raise SafetyError("组件包含大小写冲突／重复路径")
                    seen.add(name)
                    if stat.S_ISLNK(item.external_attr >> 16):
                        raise SafetyError("组件包包含符号链接")
                    if not covered_file(name):
                        continue
                    if not 0 < item.file_size <= MAX_FILE:
                        raise SafetyError("组件文件超过大小限制")
                    h = hashlib.sha256()
                    with z.open(item) as source:
                        for block in iter(lambda: source.read(1024 * 1024), b""):
                            h.update(block)
                    entry = {"sha256": h.hexdigest(), "size": item.file_size, "package": group,
                             "member": item.filename}
                    if name in ref["files"] and ref["files"][name]["sha256"] != entry["sha256"]:
                        raise SafetyError("不同组件包的同路径文件冲突")
                    ref["files"][name] = entry
        validate_reference(ref)
        return ref


def local_identity(root: Path) -> tuple[str, str]:
    beta = root / "package" / "beta"
    if beta.exists() and beta.read_text(errors="replace").strip():
        raise SafetyError("检测到 Steam Beta 渠道；首版不校验／修复此渠道")
    exe = safe_target(root, "steam.exe")
    machine = None
    if exe.is_file():
      with exe.open("rb") as f:
        if f.read(2) == b"MZ":
            f.seek(0x3C)
            offset = int.from_bytes(f.read(4), "little")
            if offset <= 1024 * 1024:
                f.seek(offset)
                if f.read(4) == b"PE\0\0":
                    machine = int.from_bytes(f.read(2), "little")
    # A damaged or missing PE remains repairable against a matching Win64 baseline.
    # A valid unsupported machine is explicitly refused.
    if machine is not None and machine != 0x8664:
        raise SafetyError("首版只支持 x64 Steam；未执行 Win32／ARM64 自动修复")
    manifest = safe_target(root, "package/steam_client_win64.manifest")
    section = parse_kv(manifest.read_text(encoding="utf-8-sig"))["win64"]
    version = str(section["version"])
    if not re.fullmatch(r"\d{1,15}", version):
        raise SafetyError("本地版本格式无效")
    return version, "stable"


def snapshot(root: Path, ref: dict) -> tuple:
    result = []
    for name in sorted(ref["files"]):
        p = safe_target(root, name)
        try:
            s = p.stat()
            result.append((name, s.st_size, s.st_mtime_ns))
        except FileNotFoundError:
            result.append((name, None, None))
    for name in ("package/steam_client_win64.manifest", "package/steam_client_win64",
                 "package/steam_client_win64.installed", "package/beta"):
        p = safe_target(root, name)
        try:
            s = p.stat()
            result.append((name, s.st_size, s.st_mtime_ns))
        except FileNotFoundError:
            result.append((name, None, None))
    return tuple(result)


@dataclass
class CheckResult:
    state: str
    version: str
    latest: str = ""
    mismatches: list[str] = field(default_factory=list)
    checked: int = 0
    detail: str = ""


def verify(root: Path, ref: dict, quick=False, paths=None) -> CheckResult:
    version, _ = local_identity(root)
    if version != ref["version"]:
        return CheckResult("unknown", version, ref["version"], detail="本地版本没有匹配的可信基线")
    before = snapshot(root, ref)
    bad = []
    count = 0
    for name, info in ref["files"].items():
        if paths is not None and name not in paths:
            continue
        if quick and "/" in name:
            continue
        p = safe_target(root, name)
        count += 1
        if not p.is_file() or p.stat().st_size != info["size"] or sha256(p) != info["sha256"]:
            bad.append(name)
    if before != snapshot(root, ref) or local_identity(root)[0] != version:
        return CheckResult("updating", version, detail="校验期间文件发生变化，稍后重试")
    return CheckResult("mismatch" if bad else "clean", version, mismatches=bad, checked=count)


def atomic_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


class Repairer:
    """Bounded file restoration; caller must stop Steam and repeat verification first."""
    def __init__(self, root: Path, state: Path, client: OfficialClient, ref: dict):
        self.root, self.state, self.client, self.ref = root, state, client, ref

    def repair(self, names: list[str], assert_stopped=lambda: None, allow_version_transition=False,allow_full_version_transition=False) -> Path:
        if not names or len(names) != len(set(names)):
            raise SafetyError("修复列表为空或重复")
        if allow_version_transition and not allow_full_version_transition and any('/' in n or not n.endswith(('.exe', '.dll')) for n in names):
            raise SafetyError('版本过渡恢复仅允许根目录更新启动器及依赖')
        if any(n.lower().startswith(('steamapps/','userdata/','config/')) for n in names):
            raise SafetyError('拒绝替换游戏、用户数据或配置目录')
        if not allow_version_transition and local_identity(self.root)[0] != self.ref["version"]:
            raise SafetyError("安装版本变化，已取消修复")
        # Prepare and verify all replacements before touching installation.
        transaction = self.state / "quarantine" / (time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(4).hex())
        transaction.mkdir(parents=True)
        records = []
        for name in names:
            if name not in self.ref["files"]:
                raise SafetyError("拒绝修复基线之外的文件")
            info = self.ref["files"][name]
            target = safe_target(self.root, name)
            package = self.client.package(self.ref["packages"][info["package"]], self.root)
            stage = safe_target(transaction, "new/" + name)
            stage.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(package) as z, z.open(info["member"]) as source, stage.open("wb") as out:
                shutil.copyfileobj(source, out, 1024 * 1024)
            if stage.stat().st_size != info["size"] or sha256(stage) != info["sha256"]:
                raise SafetyError("修复文件校验失败")
            existed = target.is_file()
            oldhash = sha256(target) if existed else None
            records.append({"name": name, "existed": existed, "old_sha256": oldhash,
                            "new_sha256": info["sha256"], "applied": False})
        journal = {"root": str(self.root.absolute()), "version": self.ref["version"],
                   "status": "prepared", "files": records}
        atomic_json(transaction / "journal.json", journal)
        try:
            for record in records:
                assert_stopped()
                if not allow_version_transition and local_identity(self.root)[0] != self.ref["version"]:
                    raise SafetyError("修复期间版本变化")
                target = safe_target(self.root, record["name"])
                if target.is_file() != record["existed"] or (record["existed"] and sha256(target) != record["old_sha256"]):
                    raise SafetyError("修复期间目标文件变化")
                backup = safe_target(transaction, "old/" + record["name"])
                if record["existed"]:
                    backup.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(target, backup)
                    if sha256(backup) != record["old_sha256"]:
                        raise SafetyError("隔离备份校验失败")
                target.parent.mkdir(parents=True, exist_ok=True)
                # Replacement temporary file is on the same volume as destination.
                fd, temporary = tempfile.mkstemp(prefix=".sentinel-", dir=target.parent)
                os.close(fd)
                try:
                    shutil.copyfile(safe_target(transaction, "new/" + record["name"]), temporary)
                    if sha256(Path(temporary)) != record["new_sha256"]:
                        raise SafetyError("暂存文件校验失败")
                    safe_target(self.root, record["name"])
                    record["applied"] = True
                    atomic_json(transaction / "journal.json", journal)
                    os.replace(temporary, target)
                finally:
                    Path(temporary).unlink(missing_ok=True)
            journal["status"] = "completed"
            atomic_json(transaction / "journal.json", journal)
            return transaction
        except Exception:
            self.rollback(transaction, assert_stopped)
            raise

    def rollback(self, transaction: Path, assert_stopped=lambda: None):
        allowed = (self.state / "quarantine").resolve()
        if not transaction.resolve().is_relative_to(allowed):
            raise SafetyError("回滚路径超出隔离目录")
        journal = json.loads((transaction / "journal.json").read_text(encoding="utf-8"))
        if Path(journal["root"]).absolute() != self.root.absolute():
            raise SafetyError("回滚安装目录不匹配")
        for record in reversed(journal["files"]):
            if not record["applied"]:
                continue
            assert_stopped()
            target = safe_target(self.root, record["name"])
            current = sha256(target) if target.is_file() else None
            if current == record["old_sha256"]:
                continue
            if current != record["new_sha256"]:
                raise SafetyError("目标已被其他程序修改，拒绝覆盖回滚")
            if record["existed"]:
                backup = safe_target(transaction, "old/" + record["name"])
                if sha256(backup) != record["old_sha256"]:
                    raise SafetyError("备份被修改，拒绝回滚")
                fd, temp = tempfile.mkstemp(prefix=".sentinel-", dir=target.parent)
                os.close(fd)
                try:
                    shutil.copyfile(backup, temp)
                    os.replace(temp, target)
                finally:
                    Path(temp).unlink(missing_ok=True)
            else:
                target.unlink()
        journal["status"] = "rolled-back"
        atomic_json(transaction / "journal.json", journal)
