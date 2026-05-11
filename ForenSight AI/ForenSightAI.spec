# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['scripts\\run_application.py'],   # ✅ FIXED
    pathex=['.'],
    binaries=[],

    datas=[
        ('src', 'src'),
        ('assets', 'assets')
    ],

    hiddenimports=[
        'reportlab',
        'matplotlib',
        'matplotlib.pyplot',
        'ollama'
    ],

    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],

    excludes=[
        'pytest',
        'sphinx',
        'torch',
        'jax',
        'cupy'
    ],

    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ForenSightAI',

    icon='assets/icon.ico',   # ✅ ICON FIX

    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,

    console=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    name='ForenSightAI',
)