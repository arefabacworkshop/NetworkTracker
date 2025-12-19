#!/usr/bin/env python
"""
Build script for Network Connection Monitor
Creates a standalone Windows executable using PyInstaller.
"""

import subprocess
import sys
import os
import shutil


def main():
    print("=" * 60)
    print("Network Connection Monitor - Build Script")
    print("=" * 60)
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"[OK] PyInstaller {PyInstaller.__version__} found")
    except ImportError:
        print("[!] PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("[OK] PyInstaller installed")
    
    # Define paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    src_file = os.path.join(script_dir, "src", "app.py")
    icon_path = os.path.join(script_dir, "assets", "icon.ico")
    
    # Build command
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--name=NetworkMonitor",
        "--onefile",
        "--windowed",  # No console window
        "--noconfirm",  # Overwrite without asking
        "--clean",  # Clean cache before building
    ]
    
    # Add icon if exists
    if os.path.exists(icon_path):
        cmd.append(f"--icon={icon_path}")
        print(f"[OK] Using icon: {icon_path}")
    else:
        print("[!] No icon found at assets/icon.ico (optional)")
    
    # Add hidden imports for dnspython
    cmd.extend([
        "--hidden-import=dns",
        "--hidden-import=dns.resolver",
        "--hidden-import=dns.reversename",
        "--hidden-import=dns.rdatatype",
        "--hidden-import=dns.exception",
    ])
    
    # Add the source file
    cmd.append(src_file)
    
    print("\n[*] Building executable...")
    print(f"[*] Command: {' '.join(cmd)}\n")
    
    # Run PyInstaller
    try:
        subprocess.check_call(cmd, cwd=script_dir)
        print("\n" + "=" * 60)
        print("[SUCCESS] Build completed!")
        print(f"[*] Executable location: dist/NetworkMonitor.exe")
        print("=" * 60)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Build failed with error code {e.returncode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
