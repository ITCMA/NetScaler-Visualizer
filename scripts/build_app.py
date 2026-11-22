"""Build a self-contained app (no Python needed to run it) with PyInstaller.

Build tool only (not a runtime dependency): ``pip install pyinstaller``. Run it on the target system - the result is
specific to the OS it was built on:

    python3 scripts/build_app.py            # single file: dist/nsviz.exe (Windows)
    python3 scripts/build_app.py --bundle   # macOS only: app bundle dist-bundle/nsviz.app (double-click opens the GUI)
                                            # optional: --icon FILE.icns (made from assets/nsviz-icon.svg by scripts/make_icns.sh)

Without code signing (Windows) / notarization (macOS) the systems show a warning on first start. Double-click starts the
local GUI; with arguments the binary behaves like ``python -m nsviz``. The bundle is signed, notarized and packed into a
DMG by scripts/release_macos.sh, see docs/SIGNING.md.
"""
import os
import plistlib
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))
from nsviz import __version__  # noqa: E402  (single source of the version)

BUNDLE_ID = "net.itcma.nsviz"
bundle = "--bundle" in sys.argv[1:]
icon = sys.argv[sys.argv.index("--icon") + 1] if "--icon" in sys.argv[1:-1] else None
if bundle and sys.platform != "darwin":
    sys.exit("--bundle builds a macOS app bundle and needs macOS")

sep = ";" if os.name == "nt" else ":"
cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--name", "nsviz",
       "--add-data", f"{root / 'nsviz' / 'assets'}{sep}nsviz/assets",
       "--add-data", f"{root / 'nsviz' / 'rules' / 'i18n'}{sep}nsviz/rules/i18n",
       # sources for the code fingerprint shown by --version and in debug output
       *[x for f in ("model.py", "project.py", "linking.py") for x in ("--add-data", f"{root / 'nsviz' / f}{sep}nsviz")],
       "--paths", str(root)]
if bundle:
    # onedir inside the bundle: a onefile bundle unpacks to a temp folder on every start and is harder to sign.
    cmd += ["--windowed", "--onedir", "--osx-bundle-identifier", BUNDLE_ID,
            "--distpath", str(root / "dist-bundle"), "--workpath", str(root / "build" / "bundle")]
    if icon:
        cmd += ["--icon", str(Path(icon).resolve())]
else:
    cmd += ["--onefile"]
cmd.append(str(root / "scripts" / "app_entry.py"))
rc = subprocess.call(cmd, cwd=root)
if rc or not bundle:
    sys.exit(rc)

# Version in Info.plist, then re-seal with an ad-hoc signature (the edit invalidates PyInstaller's own ad-hoc seal).
# The release script signs the bundle with the Developer ID certificate afterwards.
app = root / "dist-bundle" / "nsviz.app"
plist_path = app / "Contents" / "Info.plist"
info = plistlib.loads(plist_path.read_bytes())
info.update({"CFBundleName": "nsviz", "CFBundleDisplayName": "nsviz", "CFBundleIdentifier": BUNDLE_ID,
             "CFBundleShortVersionString": __version__, "CFBundleVersion": __version__,
             "NSHighResolutionCapable": True})
plist_path.write_bytes(plistlib.dumps(info))
sys.exit(subprocess.call(["codesign", "--force", "--deep", "--sign", "-", str(app)]))
