"""Exercise frozen releases with no Python directory on PATH; no real Steam mutations."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sentinel.selfguard import verify_distribution,certificate_digest
from sentinel.authenticode_key import CERT_SHA256
from sentinel.windows import authenticode_status

root = Path(__file__).resolve().parents[1]
env = os.environ.copy()
env["PATH"] = os.pathsep.join([str(Path(env.get("SystemRoot", r"C:\Windows")) / "System32"),
                               env.get("SystemRoot", r"C:\Windows")])
env.pop("PYTHONPATH", None)
env.pop("PYTHONHOME", None)
reports = []
import struct
distribution=root/'dist/SteamSafe'
exe=distribution/'SteamSafe.exe'
assert b'level="requireAdministrator"' in exe.read_bytes()
verified=verify_distribution(distribution,CERT_SHA256)
assert CERT_SHA256 in certificate_digest(root/'dist/SteamSafe-v0.1.2.3-Beta-Setup.exe')
assert (authenticode_status(root/'dist/SteamSafe-v0.1.2.3-Beta-Setup.exe')&0xffffffff) in (0,0x800B0109)
for name, executable in (("qa-same-code", root / "build/qa-release/SteamSafe.exe"),):
    output = root / "test-output" / ("release-v0.1.2-" + name)
    state = output / "state"
    output.mkdir(parents=True, exist_ok=True)
    test = subprocess.run([str(executable), "--self-test", "--state-dir", str(state)],
                          cwd=root, env=env, timeout=60)
    if test.returncode:
        raise RuntimeError(f"{name} self-test failed with exit {test.returncode}")
    ui = subprocess.run([str(executable), "--smoke-test", str(output / "ui"), "--state-dir", str(state)],
                        cwd=root, env=env, timeout=60)
    if ui.returncode:
        error = (state / "startup-error.txt").read_text(encoding="utf-8") if (state / "startup-error.txt").exists() else "No error log"
        raise RuntimeError(f"{name} GUI failed: {error}")
    tests = json.loads((state / "self-test.json").read_text(encoding="utf-8"))
    smoke = json.loads((output / "ui/smoke.json").read_text(encoding="utf-8"))
    if not tests["successful"] or not smoke["ok"] or not smoke["frozen"]:
        raise RuntimeError("Frozen release verification did not pass")
    reports.append({"name": name, "exe": str(executable), "tests": tests["tests"],
                    "errors": tests["errors"], "failures": tests["failures"], "skipped": tests["skipped"],
                    "gui": smoke, "bytes": executable.stat().st_size,
                    "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                    "distribution_self_check_files":verified,'admin_manifest_verified':True,
                    'distribution_exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
                    'note':'Same Python code tested using re-signed asInvoker diagnostic copy. UAC installation not performed on this host.'})
    print(f"{name}: {tests['tests']} tests and GUI passed; Python removed from PATH", flush=True)
(root / "test-output/release-verification.json").write_text(json.dumps(reports, indent=2), encoding="utf-8")
