# Third-party notices

SteamSafe is an independent tool, not a Valve product or endorsed by Valve. Steam is a Valve trademark. No Valve executable files are bundled in the release; the baseline contains metadata and hashes only. Runtime downloads use official Valve update servers.

Distributed runtimes and libraries retain their respective licenses. PyInstaller copies the relevant dependency metadata/licenses into its bundle where supported; the source release includes the pinned dependency list. Before public redistribution, review all licenses and code-sign the executables.

- Python: Python Software Foundation License, https://docs.python.org/3/license.html
- PySide6 / Qt: LGPLv3/GPL/commercial licensing as applicable, https://doc.qt.io/qtforpython-6/licenses.html . The portable distribution contains dynamically loaded Qt DLLs. Their license texts are supplied in `licenses/` in the release. Corresponding source: https://code.qt.io/cgit/pyside/pyside-setup.git/ and https://code.qt.io/cgit/qt/qtbase.git/ . Users may replace the compatible shared libraries and reverse engineer for debugging modifications as permitted by LGPL. The directory release is the preferred form for that purpose.
- Shiboken6: LGPL/GPL/commercial as applicable, https://code.qt.io/cgit/pyside/pyside-setup.git/
- psutil: BSD 3-Clause, https://github.com/giampaolo/psutil
- cryptography: Apache-2.0 OR BSD-3-Clause, https://github.com/pyca/cryptography
- cffi: MIT, https://cffi.readthedocs.io/en/latest/license.html
- certifi: MPL-2.0, https://github.com/certifi/python-certifi
- PyInstaller: GPL with bootloader exception permitting bundled application distribution, https://pyinstaller.org/en/stable/license.html

IsMySteamSafe (https://github.com/fenglinbei/IsMySteamSafe, fenglinbei, Apache-2.0) is referenced for client detection directions. Version 0.1.1 independently reimplements loading-path, configuration, support-route, interface-pattern and persistence checks in Python. No C# detector or full detection database is bundled. The research .reference folder is excluded from source releases.
