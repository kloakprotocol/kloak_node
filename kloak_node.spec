# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['kloak_node.py'],
    pathex=[],
    binaries=[],
    datas=[
        # Include any data files here
        # ('README.md', '.'),
    ],
    hiddenimports=[
        'kaspy',
        'kaspy.kaspa_clients',
        'kaspy.defines',
        'websockets',
        'websockets.asyncio.server',
        'cryptography',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.primitives.kdf.scrypt',
        'mnemonic',
        'ecdsa',
        'qrcode',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='KloakNode',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Set to False for GUI version
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='kloak_icon.ico',  # Add your icon file
)
