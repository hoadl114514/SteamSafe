"""Deterministic specs: Qt on Windows uses the OS ICU facade, not Poppler ICU."""
from pathlib import Path
from PyInstaller.__main__ import run

root = Path(__file__).resolve().parents[1]
analysis = '''
from pathlib import Path
a = Analysis(['main.py'], pathex=[], binaries=[],
    datas=[('assets','assets'), ('licenses','licenses')],
    hiddenimports=['sentinel.release_key'], hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=['tkinter','pystray','PySide6.QtNetwork','PySide6.QtQml','PySide6.QtQuick',
              'PySide6.QtOpenGL','PySide6.QtPdf','PySide6.QtSvg','PySide6.QtSql'],
    noarchive=False, optimize=0)
# System32 ICU provides the unsuffixed Windows API expected by Qt. An ambient
# Poppler distribution exports version-suffixed ICU APIs under the same filename.
# Do not redistribute/override the OS facade or unrelated tools' ICU dependencies.
a.binaries = [item for item in a.binaries
              if Path(item[0]).name.lower() not in {'icuuc.dll','icuin.dll'}
              and 'poppler' not in item[1].lower()]
pyz = PYZ(a.pure)
'''
for name, single in (("SteamSafe", False),):
    spec = analysis
    if single:
        spec += f'''
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name={name!r},
    debug=False, strip=False, upx=False, console=False,
    version='assets/version.txt', icon=['assets/app.ico'])
'''
    else:
        spec += f'''
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name={name!r}, uac_admin=True,
    debug=False, strip=False, upx=False, console=False,
    version='assets/version.txt', icon=['assets/app.ico'])
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name={name!r})
'''
    path = root / (name + ".spec")
    path.write_text(spec, encoding="utf-8")
    run(["--noconfirm", str(path)])
