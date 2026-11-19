# -*- mode: python ; coding: utf-8 -*-

import sys
import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# customtkinter ships JSON themes + assets that must be bundled
import customtkinter
ctk_path = os.path.dirname(customtkinter.__file__)
certifi_datas = collect_data_files('certifi')

_root = os.path.abspath(os.path.join(os.path.dirname(SPEC), os.pardir))
_i18n_path = os.path.join(_root, 'ui', 'i18n')
_icon_path = os.path.join(_root, 'icon.ico')
a = Analysis(
    [os.path.join(_root, 'windows.py')],
    pathex=[_root],
    binaries=[],
    datas=[
        (os.path.join(ctk_path, 'assets'), 'customtkinter/assets'),
        (_i18n_path, 'ui/i18n'),
        *collect_data_files('ui'),
        (_icon_path, '.'),
    ] + certifi_datas,
    hiddenimports=[
        'bypass',
        *collect_submodules('bypass'),
        'ui',
        *collect_submodules('ui'),
        'httpx',
        'h2',
        'pystray._win32',
        'PIL._tkinter_finder',
        'customtkinter',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.ciphers.algorithms',
        'cryptography.hazmat.primitives.ciphers.modes',
        'cryptography.hazmat.backends.openssl',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'PIL._avif',
        'PIL._webp',
        'PIL._imagingtk',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

_PIL_EXCLUDE_PYDS = {
    '_avif', '_webp', '_imagingtk',
    'FpxImagePlugin', 'MicImagePlugin',
}
a.binaries = [
    (name, path, typ)
    for name, path, typ in a.binaries
    if not any(ex in name for ex in _PIL_EXCLUDE_PYDS)
]

icon_path = _icon_path
version_path = os.path.join(os.path.dirname(SPEC), 'version_info.txt')

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='tg-ws-proxy-definitive',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path if os.path.exists(icon_path) else None,
    version=version_path if os.path.exists(version_path) else None,
)
