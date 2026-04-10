#!/usr/bin/env python3
"""
Basic usage example for renef Python binding

Prerequisites:
    1. Build: cd build && cmake .. && make renef_shared
    2. Deploy: make deploy
    3. Start server: adb shell /data/local/tmp/renef_server &
    4. Forward port: adb forward tcp:1907 localabstract:com.android.internal.os.RuntimeInit
"""

import sys
import os

# Add parent directory to path for local development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from renef import Renef

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <package_name|pid>")
        return 1

    target = sys.argv[1]
    r = Renef()

    if target.isdigit():
        print(f"[*] Attaching to PID {target}...")
        session = r.attach(int(target))
    else:
        print(f"[*] Spawning {target}...")
        session = r.spawn(target)

    if not session:
        print("[-] Failed to create session")
        return 1

    print(f"[+] Connected, PID: {session.pid}")

    # Test eval
    ok, out, err = session.eval("print('Hello from Python!')")
    print(f"[*] Eval output: {out}")

    # Find libc
    libc = session.Module.find("libc.so")
    if libc:
        print(f"[+] libc.so @ 0x{libc:x}")

    session.close()
    print("[+] Done")
    return 0

if __name__ == "__main__":
    sys.exit(main())
