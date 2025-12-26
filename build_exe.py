"""
Build script for creating Kloak Node standalone executable
Run this to package kloak_node.py into a Windows .exe
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path


def _workspace_python() -> str:
    """Prefer the workspace .venv interpreter when present."""
    root = Path(__file__).resolve().parent
    venv_py = root / ".venv" / "Scripts" / "python.exe"
    if venv_py.exists():
        return str(venv_py)
    return sys.executable


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="build_exe.py",
        description="Build Kloak Node Windows executable (PyInstaller) using kloak_node.py",
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--onedir",
        action="store_true",
        help="Build one-folder executable using kloak_node.spec (fast startup)",
    )
    mode.add_argument(
        "--onefile",
        action="store_true",
        help="Build one-file executable (single .exe; slower startup)",
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt for build type instead of building automatically",
    )

    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Do not prompt (default). If no mode is specified, defaults to --onefile",
    )
    return parser.parse_args()

def install_pyinstaller():
    """Install PyInstaller if not already installed"""
    print("Installing PyInstaller...")
    py = _workspace_python()
    subprocess.check_call([py, "-m", "pip", "install", "pyinstaller"])

def create_spec_file():
    """Create PyInstaller spec file with proper configuration"""
    spec_content = '''# -*- mode: python ; coding: utf-8 -*-

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
'''
    
    with open('kloak_node.spec', 'w') as f:
        f.write(spec_content)
    
    print("✓ Created kloak_node.spec")

def build_executable():
    """Build the executable using PyInstaller"""
    print("\nBuilding executable...")
    print("This may take several minutes...\n")
    
    # Build using spec file
    py = _workspace_python()
    result = subprocess.run(
        [py, '-m', 'PyInstaller', '--clean', 'kloak_node.spec'],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print("\n" + "="*60)
        print("✓ BUILD SUCCESSFUL!")
        print("="*60)
        print(f"\nExecutable location: dist\\KloakNode.exe")
        print(f"Size: {os.path.getsize('dist/KloakNode.exe') / (1024*1024):.1f} MB")
        print("\nTo run:")
        print("  dist\\KloakNode.exe")
        print("\nTo distribute:")
        print("  1. Copy dist\\KloakNode.exe to any Windows machine")
        print("  2. No Python installation required")
        print("  3. User just double-clicks to run")
    else:
        print("\n❌ BUILD FAILED")
        print("\nError output:")
        print(result.stderr)
        return False
    
    return True

def create_onefile_build():
    """Create single-file executable (slower startup, easier distribution)"""
    print("\nCreating single-file executable...")
    print("This may take several minutes. PyInstaller output will appear below.\n")

    py = _workspace_python()
    
    cmd = [
        py, '-m', 'PyInstaller',
        '--onefile',
        '--name', 'KloakNode',
        '--console',
        '--clean',
        '--noconfirm',
        '--hidden-import', 'kaspy',
        '--hidden-import', 'websockets',
        '--hidden-import', 'websockets.asyncio.server',
        '--hidden-import', 'cryptography',
        '--hidden-import', 'mnemonic',
        '--hidden-import', 'ecdsa',
        '--hidden-import', 'qrcode',
        'kloak_node.py'
    ]

    # Stream output so it doesn't look like a hang.
    result = subprocess.run(cmd)

    if result.returncode != 0:
        print("\n❌ BUILD FAILED (PyInstaller exit code: %s)" % result.returncode)
        return False

    exe_path = Path("dist") / "KloakNode.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print("\n" + "=" * 60)
        print("✓ BUILD SUCCESSFUL!")
        print("=" * 60)
        print(f"\nExecutable location: {exe_path}")
        print(f"Size: {size_mb:.1f} MB")
    else:
        print("\n✓ Build completed, but dist\\KloakNode.exe was not found.")
    return True

def main():
    args = _parse_args()
    print("="*60)
    print("KLOAK NODE EXECUTABLE BUILDER")
    print("="*60)
    print()
    
    # Step 1: Install PyInstaller
    py = _workspace_python()
    try:
        subprocess.check_call([py, "-c", "import PyInstaller"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"✓ PyInstaller already installed ({py})")
    except Exception:
        install_pyinstaller()
    
    # Step 2: Choose build type
    # Default behavior: build one-file automatically (no prompt).
    if args.onedir:
        create_spec_file()
        success = build_executable()
    elif args.onefile:
        success = create_onefile_build()
    elif args.interactive:
        print("\nBuild options:")
        print("1. One-folder (faster startup, larger folder)")
        print("2. One-file (slower startup, single .exe)")
        print()

        choice = input("Choose build type (1 or 2): ").strip()
        
        if choice == "1":
            # One-folder build (recommended)
            create_spec_file()
            success = build_executable()
        elif choice == "2":
            # One-file build
            success = create_onefile_build()
        else:
            print("Invalid choice")
            raise SystemExit(2)
    else:
        # Non-interactive default (and also what --no-prompt implies)
        success = create_onefile_build()
    
    if success:
        print("\n" + "="*60)
        print("NEXT STEPS")
        print("="*60)
        print("\n1. Test the executable:")
        print("   dist\\KloakNode.exe")
        print("\n2. Create installer (optional):")
        print("   - Use Inno Setup (free)")
        print("   - Or NSIS")
        print("\n3. Sign the executable (recommended):")
        print("   - Get code signing certificate")
        print("   - Use signtool.exe")
        print("\n4. Distribute:")
        print("   - Upload to GitHub releases")
        print("   - Create download page")
        print("   - Include README")

if __name__ == "__main__":
    main()
