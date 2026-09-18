"""PyInstaller build spec for the THEncrypterX desktop GUI (roadmap Phase 12).

Build locally with:

    pip install -e ".[gui,build]"
    pyinstaller packaging/THEncrypterX.spec

Output lands in dist/ (a single onedir bundle - faster startup than
--onefile, at the cost of being a folder/`.app` instead of one file; the
release workflow zips it per platform before uploading). On macOS this
produces THEncrypterX.app; on Windows/Linux, a THEncrypterX/ folder with an
executable inside.

This packages the GUI (main.py) only - the CLI is distributed through PyPI/
`pip install`, not as a standalone binary, since anyone running it from a
terminal already has Python. PySide6, cryptography, PyNaCl, and argon2-cffi
all have bundled hooks (from pyinstaller-hooks-contrib) that PyInstaller
picks up automatically - no hiddenimports have been needed so far. If a
future dependency needs one, add it to hiddenimports below rather than
reaching for --collect-all, which bundles far more than necessary.
"""

import os

SPEC_DIR = os.path.dirname(os.path.abspath(SPEC))
MAIN_PY = os.path.join(SPEC_DIR, "..", "main.py")

# UPX compression is deliberately off: it needs a separate binary most CI
# runners don't have preinstalled, and UPX-packed executables are a common
# false-positive trigger for antivirus/Windows Defender heuristics - a bad
# trade for a security tool, where "your antivirus flagged the encryption
# app" is exactly the kind of thing that erodes trust.
a = Analysis(
    [MAIN_PY],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="THEncrypterX",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="THEncrypterX",
)
app = BUNDLE(
    coll,
    name="THEncrypterX.app",
    icon=None,
    bundle_identifier="com.emondewan.thencrypterx",
)
