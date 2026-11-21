"""Build a single-file app (no Python needed to run it) with PyInstaller.

Build tool only (not a runtime dependency): ``pip install pyinstaller``. Run it on the target system - the result is
specific to the OS it was built on (Windows -> .exe, macOS -> app binary, Linux -> binary):

    python3 scripts/build_app.py

Result in ``dist/``. Without code signing (Windows) / notarization (macOS) the systems show a warning on first start.
Double-click starts the local GUI; with arguments it behaves like ``python -m nsviz``.
"""
import os
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sep = ";" if os.name == "nt" else ":"
cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--name", "nsviz",
       "--add-data", f"{root / 'nsviz' / 'assets'}{sep}nsviz/assets",
       "--add-data", f"{root / 'nsviz' / 'rules' / 'i18n'}{sep}nsviz/rules/i18n",
       # sources for the code fingerprint shown by --version and in debug output
       *[x for f in ("model.py", "project.py", "linking.py") for x in ("--add-data", f"{root / 'nsviz' / f}{sep}nsviz")],
       "--paths", str(root), str(root / "scripts" / "app_entry.py")]
sys.exit(subprocess.call(cmd, cwd=root))
