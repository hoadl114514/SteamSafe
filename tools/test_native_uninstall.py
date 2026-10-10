"""Exercise real .NET missing-task mapping and cleanup of isolated fixture files."""
from pathlib import Path
import json, subprocess, tempfile
root = Path(__file__).resolve().parents[1]
output = root / 'build/native-uninstall-tests'
output.mkdir(parents=True, exist_ok=True)
executable = output / 'NativeUninstallTests.exe'
compiler = Path(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe')
subprocess.run([str(compiler), '/nologo', '/target:exe', '/platform:x64',
    '/reference:Microsoft.CSharp.dll', '/reference:System.Web.Extensions.dll',
    '/out:'+str(executable), str(root/'tests/NativeUninstallTests.cs'),
    str(root/'tools/UninstallMaintenance.cs'), str(root/'tools/SetupCommon.cs')], check=True)
with tempfile.TemporaryDirectory(prefix='fixture-', dir=output) as fixture:
    result = subprocess.run([str(executable), fixture], capture_output=True, text=True, timeout=30, check=True)
    report = json.loads(result.stdout)
assert report['ok'] and report['tests'] >= 21 and not report['live_task_changes']
(output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(f"Native uninstall regressions passed: {report['tests']}; no live task changes")
