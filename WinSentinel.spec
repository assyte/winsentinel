# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller one-file build for WinSentinel.

Build with:
    python -m PyInstaller --noconfirm --clean WinSentinel.spec

The executable requests administrator rights through its embedded manifest and
bundles the CustomTkinter theme data plus the application icons.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

project_root = Path(SPECPATH)
assets_dir = project_root / "assets"

datas = [
    (str(assets_dir / "winsentinel.png"), "assets"),
    (str(assets_dir / "winsentinel.ico"), "assets"),
    (str(assets_dir / "ATTRIBUTION.md"), "assets"),
    (str(project_root / "LICENSE"), "."),
]
datas += collect_data_files("customtkinter")

a = Analysis(
    [str(project_root / "main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tests"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="WinSentinel",
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
    icon=str(assets_dir / "winsentinel.ico"),
    version=str(assets_dir / "version_info.txt"),
    uac_admin=True,
)
