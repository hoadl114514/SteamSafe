from pathlib import Path
import importlib.metadata
import shutil
import sys
import ssl
import urllib.request
import certifi

root = Path(__file__).parents[1]
target = root / "licenses"
target.mkdir(exist_ok=True)
for name in ("psutil", "cryptography", "cffi", "certifi", "pycparser", "pyinstaller", "PySide6-Essentials", "shiboken6"):
    distribution = importlib.metadata.distribution(name)
    out = target / name
    out.mkdir(exist_ok=True)
    for file in distribution.files or []:
        if any(term in str(file).lower() for term in ("license", "copying")) and distribution.locate_file(file).is_file():
            shutil.copyfile(distribution.locate_file(file), out / Path(file).name)
    (out / "PACKAGE-METADATA.txt").write_text(distribution.read_text("METADATA") or name, encoding="utf-8")
python_license = Path(sys.base_prefix) / "LICENSE.txt"
if python_license.exists():
    shutil.copyfile(python_license, target / "Python-LICENSE.txt")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=certifi.where())))
for filename in ("lgpl-3.0.txt", "gpl-3.0.txt"):
    path = target / filename
    if not path.exists():
        path.write_bytes(opener.open("https://www.gnu.org/licenses/" + filename, timeout=25).read())
print("Collected runtime license texts and package metadata")
